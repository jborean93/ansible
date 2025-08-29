from __future__ import annotations

import ast
import base64
import dataclasses
import datetime
import importlib.machinery
import io
import json
import os
import os.path
import pathlib
import pickle
import pkgutil
import re
import types
import typing as t
import zipfile

from ansible import constants as C
from ansible._internal import _ansiballz, _locking
from ansible._internal._ansiballz import _builder as _ansiballz_builder
from ansible._internal._datatag._tags import Origin
from ansible._internal._templating._engine import TemplateOptions
from ansible.errors import AnsibleError
from ansible.module_utils import basic as _basic
from ansible.module_utils._internal import _dataclass_validation, _json
from ansible.module_utils._internal._ansiballz import _loader
from ansible.module_utils.common.json import Direction, get_module_encoder
from ansible.module_utils.common.yaml import yaml_load
from ansible.module_utils.datatag import deprecator_from_collection_name
from ansible.plugins.loader import module_utils_loader
from ansible.release import __author__, __version__
from ansible.utils.collection_loader._collection_finder import _get_collection_metadata, _nested_dict_get
from ansible.utils.display import Display

from . import _builder

display = Display()


REPLACER_PYTHON = b"#<<INCLUDE_ANSIBLE_MODULE_COMMON>>"
# Detect new-style Python modules by looking for required imports:
# import ansible_collections.[my_ns.my_col.plugins.module_utils.my_module_util]
# from ansible_collections.[my_ns.my_col.plugins.module_utils import my_module_util]
# import ansible.module_utils[.basic]
# from ansible.module_utils[ import basic]
# from ansible.module_utils[.basic import AnsibleModule]
# from ..module_utils[ import basic]
# from ..module_utils[.basic import AnsibleModule]
NEW_STYLE_PYTHON_MODULE_RE = re.compile(
    # Relative imports
    br'(?:from +\.{2,} *module_utils.* +import |'
    # Collection absolute imports:
    br'from +ansible_collections\.[^.]+\.[^.]+\.plugins\.module_utils.* +import |'
    br'import +ansible_collections\.[^.]+\.[^.]+\.plugins\.module_utils.*|'
    # Core absolute imports
    br'from +ansible\.module_utils.* +import |'
    br'import +ansible\.module_utils\.)'
)

# this is relative to module_utils, so fix the path
_MODULE_UTILS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'module_utils')
_SHEBANG_PLACEHOLDER = '# shebang placeholder'


@dataclasses.dataclass(frozen=True, order=True)
class _ModuleUtilsProcessEntry:
    """Represents a module/module_utils item awaiting import analysis."""

    name_parts: tuple[str, ...]
    is_ambiguous: bool = False
    child_is_redirected: bool = False
    is_optional: bool = False

    @classmethod
    def from_module(cls, module: types.ModuleType, append: str | None = None) -> t.Self:
        name = module.__name__

        if append:
            name += '.' + append

        return cls.from_module_name(name)

    @classmethod
    def from_module_name(cls, module_name: str) -> t.Self:
        return cls(tuple(module_name.split('.')))


def _strip_comments(source: str) -> str:
    # Strip comments and blank lines from the wrapper
    buf = []
    for line in source.splitlines():
        l = line.strip()
        if (not l or l.startswith('#')) and l != _SHEBANG_PLACEHOLDER:
            line = ''
        buf.append(line)
    return '\n'.join(buf)


def _read_ansiballz_code() -> str:
    code = (pathlib.Path(_ansiballz.__file__).parent / '_wrapper.py').read_text()

    if not C.DEFAULT_KEEP_REMOTE_FILES:
        # Keep comments when KEEP_REMOTE_FILES is set.  That way users will see
        # the comments with some nice usage instructions.
        # Otherwise, strip comments for smaller over the wire size.
        code = _strip_comments(code)

    return code


_ANSIBALLZ_CODE = _read_ansiballz_code()  # read during startup to prevent individual workers from doing so


def _get_ansiballz_code(shebang: str) -> str:
    code = _ANSIBALLZ_CODE
    code = code.replace(_SHEBANG_PLACEHOLDER, shebang)

    return code


class ModuleDepFinder(ast.NodeVisitor):
    # DTFIX-FUTURE: add support for ignoring imports with a "controller only" comment, this will allow replacing import_controller_module with standard imports
    def __init__(self, module_fqn, tree, is_pkg_init=False, *args, **kwargs):
        """
        Walk the ast tree for the python module.
        :arg module_fqn: The fully qualified name to reach this module in dotted notation.
            example: ansible.module_utils.basic
        :arg is_pkg_init: Inform the finder it's looking at a package init (eg __init__.py) to allow
            relative import expansion to use the proper package level without having imported it locally first.

        Save submodule[.submoduleN][.identifier] into self.submodules
        when they are from ansible.module_utils or ansible_collections packages

        self.submodules will end up with tuples like:
          - ('ansible', 'module_utils', 'basic',)
          - ('ansible', 'module_utils', 'urls', 'fetch_url')
          - ('ansible', 'module_utils', 'database', 'postgres')
          - ('ansible', 'module_utils', 'database', 'postgres', 'quote')
          - ('ansible', 'module_utils', 'database', 'postgres', 'quote')
          - ('ansible_collections', 'my_ns', 'my_col', 'plugins', 'module_utils', 'foo')

        It's up to calling code to determine whether the final element of the
        tuple are module names or something else (function, class, or variable names)
        .. seealso:: :python3:class:`ast.NodeVisitor`
        """
        super(ModuleDepFinder, self).__init__(*args, **kwargs)
        self._tree = tree  # squirrel this away so we can compare node parents to it
        self.submodules = set()
        self.optional_imports = set()
        self.module_fqn = module_fqn
        self.is_pkg_init = is_pkg_init

        self._visit_map = {
            ast.Import: self.visit_Import,
            ast.ImportFrom: self.visit_ImportFrom,
        }

        self.visit(tree)

    def generic_visit(self, node):
        """Overridden ``generic_visit`` that makes some assumptions about our
        use case, and improves performance by calling visitors directly instead
        of calling ``visit`` to offload calling visitors.
        """
        generic_visit = self.generic_visit
        visit_map = self._visit_map
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, (ast.Import, ast.ImportFrom)):
                        item.parent = node
                        visit_map[item.__class__](item)
                    elif isinstance(item, ast.AST):
                        generic_visit(item)

    visit = generic_visit

    def visit_Import(self, node):
        """
        Handle import ansible.module_utils.MODLIB[.MODLIBn] [as asname]

        We save these as interesting submodules when the imported library is in ansible.module_utils
        or ansible.collections
        """
        for alias in node.names:
            if alias.name.startswith('ansible.module_utils.') or alias.name.startswith('ansible_collections.'):
                py_mod = tuple(alias.name.split('.'))
                self.submodules.add(py_mod)
                # if the import's parent is the root document, it's a required import, otherwise it's optional
                if node.parent != self._tree:
                    self.optional_imports.add(py_mod)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """
        Handle from ansible.module_utils.MODLIB import [.MODLIBn] [as asname]

        Also has to handle relative imports

        We save these as interesting submodules when the imported library is in ansible.module_utils
        or ansible.collections
        """

        # FIXME: These should all get skipped:
        # from ansible.executor import module_common
        # from ...executor import module_common
        # from ... import executor (Currently it gives a non-helpful error)
        if node.level > 0:
            # if we're in a package init, we have to add one to the node level (and make it none if 0 to preserve the right slicing behavior)
            level_slice_offset = -node.level + 1 or None if self.is_pkg_init else -node.level
            if self.module_fqn:
                parts = tuple(self.module_fqn.split('.'))
                if node.module:
                    # relative import: from .module import x
                    node_module = '.'.join(parts[:level_slice_offset] + (node.module,))
                else:
                    # relative import: from . import x
                    node_module = '.'.join(parts[:level_slice_offset])
            else:
                # fall back to an absolute import
                node_module = node.module
        else:
            # absolute import: from module import x
            node_module = node.module

        # Specialcase: six is a special case because of its
        # import logic
        py_mod = None
        if node.names[0].name == '_six':
            self.submodules.add(('_six',))
        elif node_module.startswith('ansible.module_utils'):
            # from ansible.module_utils.MODULE1[.MODULEn] import IDENTIFIER [as asname]
            # from ansible.module_utils.MODULE1[.MODULEn] import MODULEn+1 [as asname]
            # from ansible.module_utils.MODULE1[.MODULEn] import MODULEn+1 [,IDENTIFIER] [as asname]
            # from ansible.module_utils import MODULE1 [,MODULEn] [as asname]
            py_mod = tuple(node_module.split('.'))

        elif node_module.startswith('ansible_collections.'):
            if node_module.endswith('plugins.module_utils') or '.plugins.module_utils.' in node_module:
                # from ansible_collections.ns.coll.plugins.module_utils import MODULE [as aname] [,MODULE2] [as aname]
                # from ansible_collections.ns.coll.plugins.module_utils.MODULE import IDENTIFIER [as aname]
                # FIXME: Unhandled cornercase (needs to be ignored):
                # from ansible_collections.ns.coll.plugins.[!module_utils].[FOO].plugins.module_utils import IDENTIFIER
                py_mod = tuple(node_module.split('.'))
            else:
                # Not from module_utils so ignore.  for instance:
                # from ansible_collections.ns.coll.plugins.lookup import IDENTIFIER
                pass

        if py_mod:
            for alias in node.names:
                self.submodules.add(py_mod + (alias.name,))
                # if the import's parent is the root document, it's a required import, otherwise it's optional
                if node.parent != self._tree:
                    self.optional_imports.add(py_mod + (alias.name,))

        self.generic_visit(node)


def _slurp(path):
    if not os.path.exists(path):
        raise AnsibleError("imported module support code does not exist at %s" % os.path.abspath(path))
    with open(path, 'rb') as fd:
        data = fd.read()
    return data


class ModuleUtilLocatorBase:
    def __init__(self, fq_name_parts, is_ambiguous=False, child_is_redirected=False, is_optional=False):
        self._is_ambiguous = is_ambiguous
        # a child package redirection could cause intermediate package levels to be missing, eg
        # from ansible.module_utils.x.y.z import foo; if x.y.z.foo is redirected, we may not have packages on disk for
        # the intermediate packages x.y.z, so we'll need to supply empty packages for those
        self._child_is_redirected = child_is_redirected
        self._is_optional = is_optional
        self.found = False
        self.redirected = False
        self.fq_name_parts = fq_name_parts
        self.source_code = ''
        self.output_path = ''
        self.is_package = False
        self._collection_name = None
        # for ambiguous imports, we should only test for things more than one level below module_utils
        # this lets us detect erroneous imports and redirections earlier
        if is_ambiguous and len(self._get_module_utils_remainder_parts(fq_name_parts)) > 1:
            self.candidate_names = [fq_name_parts, fq_name_parts[:-1]]
        else:
            self.candidate_names = [fq_name_parts]

    @property
    def candidate_names_joined(self):
        return ['.'.join(n) for n in self.candidate_names]

    def _handle_redirect(self, name_parts):
        module_utils_relative_parts = self._get_module_utils_remainder_parts(name_parts)

        # only allow redirects from below module_utils- if above that, bail out (eg, parent package names)
        if not module_utils_relative_parts:
            return False

        try:
            collection_metadata = _get_collection_metadata(self._collection_name)
        except ValueError as ve:  # collection not found or some other error related to collection load
            if self._is_optional:
                return False
            raise AnsibleError(
                'error processing module_util {0} loading redirected collection {1}: {2}'.format('.'.join(name_parts), self._collection_name, str(ve))
            )

        routing_entry = _nested_dict_get(collection_metadata, ['plugin_routing', 'module_utils', '.'.join(module_utils_relative_parts)])
        if not routing_entry:
            return False
        # FIXME: add deprecation warning support

        dep_or_ts = routing_entry.get('tombstone')
        removed = dep_or_ts is not None
        if not removed:
            dep_or_ts = routing_entry.get('deprecation')

        if dep_or_ts:
            removal_date = dep_or_ts.get('removal_date')
            removal_version = dep_or_ts.get('removal_version')
            warning_text = dep_or_ts.get('warning_text')

            msg = 'module_util {0} has been removed'.format('.'.join(name_parts))
            if warning_text:
                msg += ' ({0})'.format(warning_text)
            else:
                msg += '.'

            display.deprecated(  # pylint: disable=ansible-deprecated-date-not-permitted,ansible-deprecated-unnecessary-collection-name
                msg=msg,
                version=removal_version,
                removed=removed,
                date=removal_date,
                deprecator=deprecator_from_collection_name(self._collection_name),
            )
        if 'redirect' in routing_entry:
            self.redirected = True
            source_pkg = '.'.join(name_parts)
            self.is_package = True  # treat all redirects as packages
            redirect_target_pkg = routing_entry['redirect']

            # expand FQCN redirects
            if not redirect_target_pkg.startswith('ansible_collections'):
                split_fqcn = redirect_target_pkg.split('.')
                if len(split_fqcn) < 3:
                    raise Exception('invalid redirect for {0}: {1}'.format(source_pkg, redirect_target_pkg))
                # assume it's an FQCN, expand it
                redirect_target_pkg = 'ansible_collections.{0}.{1}.plugins.module_utils.{2}'.format(
                    split_fqcn[0], split_fqcn[1], '.'.join(split_fqcn[2:])  # ns  # coll  # sub-module_utils remainder
                )
            display.vvv('redirecting module_util {0} to {1}'.format(source_pkg, redirect_target_pkg))
            self.source_code = self._generate_redirect_shim_source(source_pkg, redirect_target_pkg)
            return True
        return False

    def _get_module_utils_remainder_parts(self, name_parts):
        # subclasses should override to return the name parts after module_utils
        return []

    def _get_module_utils_remainder(self, name_parts):
        # return the remainder parts as a package string
        return '.'.join(self._get_module_utils_remainder_parts(name_parts))

    def _find_module(self, name_parts):
        return False

    def _locate(self, redirect_first=True):
        for candidate_name_parts in self.candidate_names:
            if redirect_first and self._handle_redirect(candidate_name_parts):
                break

            if self._find_module(candidate_name_parts):
                break

            if not redirect_first and self._handle_redirect(candidate_name_parts):
                break

        else:  # didn't find what we were looking for- last chance for packages whose parents were redirected
            if self._child_is_redirected:  # make fake packages
                self.is_package = True
                self.source_code = ''
            else:  # nope, just bail
                return

        if self.is_package:
            path_parts = candidate_name_parts + ('__init__',)
        else:
            path_parts = candidate_name_parts
        self.found = True
        self.output_path = os.path.join(*path_parts) + '.py'
        self.fq_name_parts = candidate_name_parts

    def _generate_redirect_shim_source(self, fq_source_module, fq_target_module):
        return """
import sys
import {1} as mod

sys.modules['{0}'] = mod
""".format(
            fq_source_module, fq_target_module
        )

        # FIXME: add __repr__ impl


class LegacyModuleUtilLocator(ModuleUtilLocatorBase):
    def __init__(self, fq_name_parts, is_ambiguous=False, mu_paths=None, child_is_redirected=False):
        super(LegacyModuleUtilLocator, self).__init__(fq_name_parts, is_ambiguous, child_is_redirected)

        if fq_name_parts[0:2] != ('ansible', 'module_utils'):
            raise Exception('this class can only locate from ansible.module_utils, got {0}'.format(fq_name_parts))

        if fq_name_parts[2] == 'six':
            # FIXME: handle the ansible.module_utils.six._six case with a redirect or an internal _six attr on six itself?
            # six creates its submodules at runtime; convert all these to just 'ansible.module_utils.six'
            fq_name_parts = ('ansible', 'module_utils', 'six')
            self.candidate_names = [fq_name_parts]

        self._mu_paths = mu_paths
        self._collection_name = 'ansible.builtin'  # legacy module utils always look in ansible.builtin for redirects
        self._locate(redirect_first=False)  # let local stuff override redirects for legacy

    def _get_module_utils_remainder_parts(self, name_parts):
        return name_parts[2:]  # eg, foo.bar for ansible.module_utils.foo.bar

    def _find_module(self, name_parts):
        rel_name_parts = self._get_module_utils_remainder_parts(name_parts)

        # no redirection; try to find the module
        if len(rel_name_parts) == 1:  # direct child of module_utils, just search the top-level dirs we were given
            paths = self._mu_paths
        else:  # a nested submodule of module_utils, extend the paths given with the intermediate package names
            paths = [os.path.join(p, *rel_name_parts[:-1]) for p in self._mu_paths]  # extend the MU paths with the relative bit

        # find_spec needs the full module name
        self._info = info = importlib.machinery.PathFinder.find_spec('.'.join(name_parts), paths)
        if info is not None and info.origin is not None and os.path.splitext(info.origin)[1] in importlib.machinery.SOURCE_SUFFIXES:
            self.is_package = info.origin.endswith('/__init__.py')
            path = info.origin
        else:
            return False
        self.source_code = Origin(path=path).tag(_slurp(path))

        return True


class CollectionModuleUtilLocator(ModuleUtilLocatorBase):
    def __init__(self, fq_name_parts, is_ambiguous=False, child_is_redirected=False, is_optional=False):
        super(CollectionModuleUtilLocator, self).__init__(fq_name_parts, is_ambiguous, child_is_redirected, is_optional)

        if fq_name_parts[0] != 'ansible_collections':
            raise Exception('CollectionModuleUtilLocator can only locate from ansible_collections, got {0}'.format(fq_name_parts))
        elif len(fq_name_parts) >= 6 and fq_name_parts[3:5] != ('plugins', 'module_utils'):
            raise Exception(
                'CollectionModuleUtilLocator can only locate below ansible_collections.(ns).(coll).plugins.module_utils, got {0}'.format(fq_name_parts)
            )

        self._collection_name = '.'.join(fq_name_parts[1:3])

        self._locate()

    def _find_module(self, name_parts):
        # synthesize empty inits for packages down through module_utils- we don't want to allow those to be shipped over, but the
        # package hierarchy needs to exist
        if len(name_parts) < 6:
            self.source_code = ''
            self.is_package = True
            return True

        # NB: we can't use pkgutil.get_data safely here, since we don't want to import/execute package/module code on
        # the controller while analyzing/assembling the module, so we'll have to manually import the collection's
        # Python package to locate it (import root collection, reassemble resource path beneath, fetch source)

        collection_pkg_name = '.'.join(name_parts[0:3])
        resource_base_path = os.path.join(*name_parts[3:])

        src = None

        # look for package_dir first, then module
        src_path = os.path.join(resource_base_path, '__init__.py')

        try:
            collection_pkg = importlib.import_module(collection_pkg_name)
            pkg_path = os.path.dirname(collection_pkg.__file__)
        except (ImportError, AttributeError):
            pkg_path = None

        try:
            src = pkgutil.get_data(collection_pkg_name, src_path)
        except ImportError:
            pass

        # TODO: we might want to synthesize fake inits for py3-style packages, for now they're required beneath module_utils

        if src is not None:  # empty string is OK
            self.is_package = True
        else:
            src_path = resource_base_path + '.py'

            try:
                src = pkgutil.get_data(collection_pkg_name, src_path)
            except ImportError:
                pass

        if src is None:  # empty string is OK
            return False

        # TODO: this feels brittle and funky; we should be able to more definitively assure the source path

        if pkg_path:
            origin = Origin(path=os.path.join(pkg_path, src_path))
        else:
            # DTFIX-FUTURE: not sure if this case is even reachable
            origin = Origin(description=f'<synthetic collection package for {collection_pkg_name}!r>')

        self.source_code = origin.tag(src)
        return True

    def _get_module_utils_remainder_parts(self, name_parts):
        return name_parts[5:]  # eg, foo.bar for ansible_collections.ns.coll.plugins.module_utils.foo.bar


def _make_zinfo(filename: str, date_time: datetime.datetime, zf: zipfile.ZipFile | None = None) -> zipfile.ZipInfo:
    zinfo = zipfile.ZipInfo(
        filename=filename,
        date_time=date_time.utctimetuple()[:6],
    )

    if zf:
        zinfo.compress_type = zf.compression

    return zinfo


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class ModuleMetadata:
    @classmethod
    def __post_init__(cls):
        _dataclass_validation.inject_post_init_validation(cls)


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class ModuleMetadataV1(ModuleMetadata):
    serialization_profile: str


metadata_versions: dict[t.Any, type[ModuleMetadata]] = {
    1: ModuleMetadataV1,
}

_DEFAULT_LEGACY_METADATA = ModuleMetadataV1(serialization_profile='legacy')


def _get_module_metadata(module: ast.Module) -> ModuleMetadata:
    # experimental module metadata; off by default
    if not C.config.get_config_value('_MODULE_METADATA'):
        return _DEFAULT_LEGACY_METADATA

    metadata_nodes: list[ast.Assign] = []

    for node in module.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1:
                target = node.targets[0]

                if isinstance(target, ast.Name):
                    if target.id == 'METADATA':
                        metadata_nodes.append(node)

    if not metadata_nodes:
        return _DEFAULT_LEGACY_METADATA

    if len(metadata_nodes) > 1:
        raise ValueError('Module METADATA must defined only once.')

    metadata_node = metadata_nodes[0]

    if not isinstance(metadata_node.value, ast.Constant):
        raise TypeError(f'Module METADATA node must be {ast.Constant} not {type(metadata_node)}.')

    unparsed_metadata = metadata_node.value.value

    if not isinstance(unparsed_metadata, str):
        raise TypeError(f'Module METADATA must be {str} not {type(unparsed_metadata)}.')

    try:
        parsed_metadata = yaml_load(unparsed_metadata)
    except Exception as ex:
        raise ValueError('Module METADATA must be valid YAML.') from ex

    if not isinstance(parsed_metadata, dict):
        raise TypeError(f'Module METADATA must parse to {dict} not {type(parsed_metadata)}.')

    schema_version = parsed_metadata.pop('schema_version', None)

    if not (metadata_type := metadata_versions.get(schema_version)):
        raise ValueError(f'Module METADATA schema_version {schema_version} is unknown.')

    try:
        metadata = metadata_type(**parsed_metadata)  # type: ignore
    except Exception as ex:
        raise ValueError('Module METADATA is invalid.') from ex

    return metadata


def _recursive_finder(
    name: str,
    module_fqn: str,
    module_data: str | bytes,
    zf: zipfile.ZipFile,
    date_time: datetime.datetime,
    extension_manager: _ansiballz_builder.ExtensionManager,
) -> ModuleMetadata:
    """
    Using ModuleDepFinder, make sure we have all of the module_utils files that
    the module and its module_utils files needs. (no longer actually recursive)
    :arg name: Name of the python module we're examining
    :arg module_fqn: Fully qualified name of the python module we're scanning
    :arg module_data: string Python code of the module we're scanning
    :arg zf: An open :python:class:`zipfile.ZipFile` object that holds the Ansible module payload
        which we're assembling
    """
    # py_module_cache maps python module names to a tuple of the code in the module
    # and the pathname to the module.
    # Here we pre-load it with modules which we create without bothering to
    # read from actual files (In some cases, these need to differ from what ansible
    # ships because they're namespace packages in the module)
    # FIXME: do we actually want ns pkg behavior for these? Seems like they should just be forced to emptyish pkg stubs
    py_module_cache = {
        ('ansible',): (
            b'from pkgutil import extend_path\n'
            b'__path__=extend_path(__path__,__name__)\n'
            b'__version__="' + __version__.encode() + b'"\n__author__="' + __author__.encode() + b'"\n',
            'ansible/__init__.py',
        ),
        ('ansible', 'module_utils'): (b'from pkgutil import extend_path\n__path__=extend_path(__path__,__name__)\n', 'ansible/module_utils/__init__.py'),
    }

    module_utils_paths = [p for p in module_utils_loader._get_paths(subdirs=False) if os.path.isdir(p)]
    module_utils_paths.append(_MODULE_UTILS_PATH)

    tree = _compile_module_ast(name, module_data)
    module_metadata = _get_module_metadata(tree)
    finder = ModuleDepFinder(module_fqn, tree)

    if not isinstance(module_metadata, ModuleMetadataV1):
        raise NotImplementedError()

    profile = module_metadata.serialization_profile

    # the format of this set is a tuple of the module name and whether the import is ambiguous as a module name
    # or an attribute of a module (e.g. from x.y import z <-- is z a module or an attribute of x.y?)
    modules_to_process = [_ModuleUtilsProcessEntry(m, True, False, is_optional=m in finder.optional_imports) for m in finder.submodules]

    # include module_utils that are always required
    modules_to_process.extend(
        (
            _ModuleUtilsProcessEntry.from_module(_loader),
            _ModuleUtilsProcessEntry.from_module(_basic),
            _ModuleUtilsProcessEntry.from_module_name(_json.get_module_serialization_profile_module_name(profile, True)),
            _ModuleUtilsProcessEntry.from_module_name(_json.get_module_serialization_profile_module_name(profile, False)),
        )
    )

    modules_to_process.extend(_ModuleUtilsProcessEntry.from_module_name(name) for name in extension_manager.module_names)

    module_info: ModuleUtilLocatorBase

    # we'll be adding new modules inline as we discover them, so just keep going til we've processed them all
    while modules_to_process:
        modules_to_process.sort()  # not strictly necessary, but nice to process things in predictable and repeatable order
        entry = modules_to_process.pop(0)

        if entry.name_parts in py_module_cache:
            # this is normal; we'll often see the same module imported many times, but we only need to process it once
            continue

        if entry.name_parts[0:2] == ('ansible', 'module_utils'):
            module_info = LegacyModuleUtilLocator(
                entry.name_parts, is_ambiguous=entry.is_ambiguous, mu_paths=module_utils_paths, child_is_redirected=entry.child_is_redirected
            )
        elif entry.name_parts[0] == 'ansible_collections':
            module_info = CollectionModuleUtilLocator(
                entry.name_parts, is_ambiguous=entry.is_ambiguous, child_is_redirected=entry.child_is_redirected, is_optional=entry.is_optional
            )
        else:
            # FIXME: dot-joined result
            display.warning('ModuleDepFinder improperly found a non-module_utils import %s' % [entry.name_parts])
            continue

        # Could not find the module.  Construct a helpful error message.
        if not module_info.found:
            if entry.is_optional:
                # this was a best-effort optional import that we couldn't find, oh well, move along...
                continue
            # FIXME: use dot-joined candidate names
            msg = 'Could not find imported module support code for {0}. Looked for ({1})'.format(module_fqn, module_info.candidate_names_joined)
            raise AnsibleError(msg)

        # check the cache one more time with the module we actually found, since the name could be different than the input
        # eg, imported name vs module
        if module_info.fq_name_parts in py_module_cache:
            continue

        tree = _compile_module_ast('.'.join(module_info.fq_name_parts), module_info.source_code)
        finder = ModuleDepFinder('.'.join(module_info.fq_name_parts), tree, module_info.is_package)
        modules_to_process.extend(
            _ModuleUtilsProcessEntry(m, True, False, is_optional=m in finder.optional_imports) for m in finder.submodules if m not in py_module_cache
        )

        # we've processed this item, add it to the output list
        py_module_cache[module_info.fq_name_parts] = (module_info.source_code, module_info.output_path)

        # ensure we process all ancestor package inits
        accumulated_pkg_name = []
        for pkg in module_info.fq_name_parts[:-1]:
            accumulated_pkg_name.append(pkg)  # we're accumulating this across iterations
            normalized_name = tuple(accumulated_pkg_name)  # extra machinations to get a hashable type (list is not)
            if normalized_name not in py_module_cache:
                modules_to_process.append(_ModuleUtilsProcessEntry(normalized_name, False, module_info.redirected, is_optional=entry.is_optional))

    for py_module_name in py_module_cache:
        source_code, py_module_file_name = py_module_cache[py_module_name]

        zf.writestr(_make_zinfo(py_module_file_name, date_time, zf=zf), source_code)

        if extension_manager.debugger_enabled and (origin := Origin.get_tag(source_code)) and origin.path:
            extension_manager.source_mapping[origin.path] = py_module_file_name

        display.vvvvv("Including module_utils file %s" % py_module_file_name)

    return module_metadata


def _compile_module_ast(module_name: str, source_code: str | bytes) -> ast.Module:
    origin = Origin.get_tag(source_code) or Origin.UNKNOWN

    # compile the source, process all relevant imported modules
    try:
        tree = t.cast(ast.Module, compile(source_code, str(origin), 'exec', ast.PyCF_ONLY_AST))
    except SyntaxError as ex:
        raise AnsibleError(f"Unable to compile {module_name!r}.", obj=origin.replace(line_num=ex.lineno, col_num=ex.offset)) from ex

    return tree


def _add_module_to_zip(
    zf: zipfile.ZipFile,
    date_time: datetime.datetime,
    remote_module_fqn: str,
    b_module_data: bytes,
    module_path: str,
    extension_manager: _ansiballz_builder.ExtensionManager,
) -> None:
    """Add a module from ansible or from an ansible collection into the module zip"""
    module_path_parts = remote_module_fqn.split('.')

    # Write the module
    zip_module_path = '/'.join(module_path_parts) + '.py'
    zf.writestr(_make_zinfo(zip_module_path, date_time, zf=zf), b_module_data)

    if extension_manager.debugger_enabled:
        extension_manager.source_mapping[module_path] = zip_module_path

    existing_paths: frozenset[str]

    # Write the __init__.py's necessary to get there
    if module_path_parts[0] == 'ansible':
        # The ansible namespace is setup as part of the module_utils setup...
        start = 2
        existing_paths = frozenset()
    else:
        # ... but ansible_collections and other toplevels are not
        start = 1
        existing_paths = frozenset(zf.namelist())

    for idx in range(start, len(module_path_parts)):
        package_path = '/'.join(module_path_parts[:idx]) + '/__init__.py'
        # If a collections module uses module_utils from a collection then most packages will have already been added by recursive_finder.
        if package_path in existing_paths:
            continue
        # Note: We don't want to include more than one ansible module in a payload at this time
        # so no need to fill the __init__.py with namespace code
        zf.writestr(_make_zinfo(package_path, date_time, zf=zf), b'')


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class _CachedModule:
    """Cached Python module created by AnsiballZ."""

    # FIXME: switch this to use a locked down pickle config or don't use pickle- easy to mess up and reach objects that shouldn't be pickled

    zip_data: bytes
    metadata: ModuleMetadata
    source_mapping: dict[str, str]
    """A mapping of controller absolute source locations to target relative source locations within the AnsiballZ payload."""

    def dump(self, path: str) -> None:
        temp_path = pathlib.Path(path + '-part')

        with temp_path.open('wb') as cache_file:
            pickle.dump(self, cache_file)

        temp_path.rename(path)

    @classmethod
    def load(cls, path: str) -> t.Self:
        with pathlib.Path(path).open('rb') as cache_file:
            return pickle.load(cache_file)


class PythonModuleBuilder(_builder.ModuleBuilder):
    """Python module builder.

    The Python builder is flagged when the module contains Python import
    references to the builtin Ansible module utils.

    :param module_name: The name of the module as called in the task.
    :param module_fqn: The module's fully qualified name.
    :param path: The path to the Python module.
    :param data: The module's contents.
    :param shebang: The shebang interpreter and optional argument if present.
    """

    def __init__(
        self,
        module_name: str,
        module_fqn: str,
        path: str,
        data: bytes,
        shebang: tuple[str, str | None] | None = None,
    ) -> None:
        self.module_name = module_name
        self.module_fqn = module_fqn
        super().__init__(
            path=path,
            data=data,
            shebang=shebang,
            argument_style="embedded",
        )

    @classmethod
    def create(
        cls,
        module_name: str,
        module_fqn: str,
        path: str,
        module_data: bytes,
        shebang: tuple[str, str | None] | None = None,
    ) -> PythonModuleBuilder | None:
        can_use = False

        if REPLACER_PYTHON in module_data:
            module_data = module_data.replace(
                REPLACER_PYTHON,
                b'from ansible.module_utils.basic import *',
            )
            can_use = True
        elif NEW_STYLE_PYTHON_MODULE_RE.search(module_data):
            can_use = True

        if not can_use:
            return None

        # For backwards compat treat no shebang as '#!/usr/bin/python'
        if not shebang:
            shebang = ('/usr/bin/python', None)

        return PythonModuleBuilder(
            module_name=module_name,
            module_fqn=module_fqn,
            path=path,
            data=module_data,
            shebang=shebang,
        )

    def build_module(self, options: _builder.BuildOptions) -> _builder.BuiltModule:
        date_time = datetime.datetime.now(datetime.timezone.utc)

        if date_time.year < 1980:
            raise AnsibleError(f'Cannot create zipfile due to pre-1980 configured date: {date_time}')

        module_compression = C.config.get_config_value(
            'DEFAULT_MODULE_COMPRESSION',
            variables=options.task_vars,
        )

        try:
            compression_method = getattr(zipfile, module_compression)
        except AttributeError:
            display.warning(u'Bad module compression string specified: %s.  Using ZIP_STORED (no compression)' % module_compression)
            compression_method = zipfile.ZIP_STORED

        extension_manager = _ansiballz_builder.ExtensionManager.create(task_vars=options.task_vars)
        extension_key = '~'.join(extension_manager.extension_names) if extension_manager.extension_names else 'none'
        lookup_path = os.path.join(C.DEFAULT_LOCAL_TMP, 'ansiballz_cache')  # type: ignore[attr-defined]
        cached_module_filename = os.path.join(lookup_path, '-'.join((self.module_fqn, module_compression, extension_key)))

        os.makedirs(os.path.dirname(cached_module_filename), exist_ok=True)

        cached_module: _CachedModule | None = None

        # Optimization -- don't lock if the module has already been cached
        if os.path.exists(cached_module_filename):
            display.debug('ANSIBALLZ: using cached module: %s' % cached_module_filename)
            cached_module = _CachedModule.load(cached_module_filename)
        else:
            display.debug('ANSIBALLZ: Acquiring lock')
            lock_path = f'{cached_module_filename}.lock'
            with _locking.named_mutex(lock_path):
                display.debug(f'ANSIBALLZ: Lock acquired: {lock_path}')
                # Check that no other process has created this while we were
                # waiting for the lock
                if not os.path.exists(cached_module_filename):
                    display.debug('ANSIBALLZ: Creating module')
                    # Create the module zip data
                    zipoutput = io.BytesIO()
                    zf = zipfile.ZipFile(zipoutput, mode='w', compression=compression_method)

                    # walk the module imports, looking for module_utils to send- they'll be added to the zipfile
                    module_metadata = _recursive_finder(
                        self.module_name,
                        self.module_fqn,
                        Origin(path=self.path).tag(self._data),
                        zf,
                        date_time,
                        extension_manager,
                    )

                    display.debug('ANSIBALLZ: Writing module into payload')
                    _add_module_to_zip(zf, date_time, self.module_fqn, self._data, self.path, extension_manager)

                    zf.close()
                    zip_data = base64.b64encode(zipoutput.getvalue())

                    # Write the assembled module to a temp file (write to temp
                    # so that no one looking for the file reads a partially
                    # written file)
                    os.makedirs(lookup_path, exist_ok=True)
                    display.debug('ANSIBALLZ: Writing module')
                    cached_module = _CachedModule(zip_data=zip_data, metadata=module_metadata, source_mapping=extension_manager.source_mapping)
                    cached_module.dump(cached_module_filename)
                    display.debug('ANSIBALLZ: Done creating module')

            if not cached_module:
                display.debug('ANSIBALLZ: Reading module after lock')
                # Another process wrote the file while we were waiting for
                # the write lock.  Go ahead and read the data from disk
                # instead of re-creating it.
                try:
                    cached_module = _CachedModule.load(cached_module_filename)
                except OSError as ex:
                    raise AnsibleError(
                        'A different worker process failed to create module file. Look at traceback for that process for debugging information.'
                    ) from ex

        # FUTURE: the module cache entry should be invalidated if we got this value from a host-dependent source
        rlimit_nofile = C.config.get_config_value('PYTHON_MODULE_RLIMIT_NOFILE', variables=options.task_vars)

        if not isinstance(rlimit_nofile, int):
            rlimit_nofile = int(options.templar._engine.template(rlimit_nofile, options=TemplateOptions(value_for_omit=0)))

        if not isinstance(cached_module.metadata, ModuleMetadataV1):
            raise NotImplementedError()

        params = dict(
            ANSIBLE_MODULE_ARGS=options.module_args,
        )
        encoder = get_module_encoder(cached_module.metadata.serialization_profile, Direction.CONTROLLER_TO_MODULE)

        try:
            encoded_params = json.dumps(params, cls=encoder)
        except TypeError as ex:
            raise AnsibleError(f'Failed to serialize arguments for the {self.module_name!r} module.') from ex

        extension_manager.source_mapping = cached_module.source_mapping

        code = _get_ansiballz_code(f"#!{self.shebang[0]}")
        args = dict(
            ansible_module=self.module_name,
            module_fqn=self.module_fqn,
            profile=cached_module.metadata.serialization_profile,
            date_time=date_time,
            rlimit_nofile=rlimit_nofile,
            params=encoded_params,
            extensions=extension_manager.get_extensions(),
            zip_data=cached_module.zip_data.decode('utf-8'),
        )

        args_string = '\n'.join(f'{key}={value!r},' for key, value in args.items())

        module_metadata = cached_module.metadata
        self._data = f"""{code}


if __name__ == "__main__":
    _ansiballz_main(
{args_string}
)
""".encode(
            'utf-8'
        )
        self._data_is_modified = True

        if options.tmpdir:
            return super().build_module(options)

        else:
            return _builder.BuiltModule(
                cmd=self._get_interpreter_args(),
                in_data=self._data,
                temp_files=[],
                environment=options.environment,
                has_async=False,
                has_become=False,
                serialization_profile=cached_module.metadata.serialization_profile,
            )
