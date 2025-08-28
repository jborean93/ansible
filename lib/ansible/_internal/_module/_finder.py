from __future__ import annotations

import os.path
import re
import typing as t

from . import _builder, _python, _pwsh, _replacer

# dirname(dirname(dirname(dirname(site-packages/ansible/_internal/_module/_finder.py)) == site-packages
# Do this instead of getting site-packages from distutils.sysconfig so we work when we
# haven't been installed
_site_packages = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
_CORE_LIBRARY_PATH_RE = re.compile(r'%s/(?P<path>ansible/modules/.*)\.(py|ps1)$' % re.escape(_site_packages))
_COLLECTION_PATH_RE = re.compile(r'/(?P<path>ansible_collections/[^/]+/[^/]+/plugins/modules/.*)\.(py|ps1)$')


def get_module_data(
    name: str,
    path: str,
    *,
    platform: t.Literal["posix", "windows"] = "posix",
) -> _builder.ModuleBuilder:
    """Extracts the module's metadata for execution.

    Extracts the metadata used by Ansible for determining how the module is to
    be executed. This gives the action plugin the required information to setup
    the needed environment and perform actions like interpreter discovery or
    tempdir creation if needed.

    :param name: The name of the module from the task action.
    :param path: The path to the module file.
    :param platform: The platform the module is being executed on.
    :returns: The module metadata.
    """
    with open(path, 'rb') as f:
        # Avoiding reading the whole file until we've determined that it isn't
        # a binary to avoid loading the whole file into memory.
        module_data = f.read(1024)

        if _is_binary(module_data):
            return _builder.ModuleBuilder(
                path=path,
                data=b"",  # Binary modules are read from the path.
                shebang=None,
                argument_style="json",
            )

        if extra_data := f.read():
            module_data += extra_data

    try:
        module_fqn = _get_ansible_module_fqn(path)
    except ValueError:
        module_fqn = f"ansible.legacy.{name}"

    shebang = _extract_interpreter(module_data)

    create_kwargs: dict[str, t.Any] = {
        'path': path,
        'module_data': module_data,
        'shebang': shebang,
    }

    if py_module := _python.PythonModuleBuilder.create(**create_kwargs, module_name=name, module_fqn=module_fqn):
        return py_module
    elif pwsh_module := _pwsh.PwshModuleBuilder.create(**create_kwargs, module_fqn=module_fqn, platform=platform):
        return pwsh_module
    elif replacer_module := _replacer.ReplacerModuleData.create(**create_kwargs):
        # We should look at deprecating this method or at least expanding it to
        # allow the interpreter to specify args for pipelining when they aren't
        # optional, e.g. pwsh -Command -.
        return replacer_module
    else:
        # Default if none of the above is to use a non-pipelined version that
        # sends the module code across and invokes it with an args file.
        return _builder.ModuleBuilder(
            path=path,
            data=module_data,
            shebang=shebang,
            argument_style="json" if b'WANT_JSON' in module_data else "key_value",
        )


def _extract_interpreter(module_data: bytes) -> tuple[str, str | None] | None:
    """
    Used to extract shebang expression from binary module data and return a text
    string with the shebang interpreter, or None if no shebang is detected.

    :param module_data: The module contents.
    :returns: A tuple of the shebang interpreter and any remaining values if present.
    """
    newline_idx = module_data.find(b"\n")

    if module_data.startswith(b"#!") and newline_idx != -1:
        interpreter_line = module_data[2:newline_idx].strip().decode("utf-8")
        space_idx = interpreter_line.find(" ")
        if space_idx != -1:
            interpreter = interpreter_line[:space_idx].strip()
            interpreter_args = interpreter_line[space_idx + 1 :].strip()
        else:
            interpreter = interpreter_line
            interpreter_args = None

        return interpreter, interpreter_args

    else:
        return None


def _get_ansible_module_fqn(path: str) -> str:
    """Get the fully qualifie name for a module.

    Gets the fully qualified name for the module at the path provided.

    :param path: The path to the module file.
    :returns: The module's fully qualified name.
    """
    # We can tell the FQN for core modules and collection modules
    if (match := _CORE_LIBRARY_PATH_RE.search(path)) or (match := _COLLECTION_PATH_RE.search(path)):
        path = match.group('path')
        if '.' in path:
            # FQNs must be valid as python identifiers.  This sanity check has failed.
            # we could check other things as well
            raise ValueError('Module name (or path) was not a valid python identifier')

        return '.'.join(path.split('/'))
    else:
        raise ValueError("Unable to determine module's fully qualified name")


def _is_binary(module_data: bytes) -> bool:
    """Heuristic to classify a file as binary by sniffing a 1k header; see https://stackoverflow.com/a/7392391"""
    textchars = bytearray(set([7, 8, 9, 10, 12, 13, 27]) | set(range(0x20, 0x100)) - set([0x7F]))
    start = module_data[:1024]
    return bool(start.translate(None, textchars))
