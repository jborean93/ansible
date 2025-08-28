#!/usr/bin/env python

# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

# this script is for testing modules without running through the
# entire guts of ansible, and is very helpful for when developing
# modules
#
# example:
#    ./hacking/test-module.py -m lib/ansible/modules/command.py -a "/bin/sleep 3"
#    ./hacking/test-module.py -m lib/ansible/modules/command.py -a "/bin/sleep 3" --debugger /usr/bin/pdb
#    ./hacking/test-module.py -m lib/ansible/modules/lineinfile.py -a "dest=/etc/exports line='/srv/home hostname1(rw,sync)'" --check
#    ./hacking/test-module.py -m lib/ansible/modules/command.py -a "echo hello" -n -o "test_hello"

from __future__ import annotations

import glob
import optparse
import os
import subprocess
import sys
import traceback
import shutil

from pathlib import Path

from ansible._internal._module import _builder, _finder, _python
from ansible.release import __version__
import ansible.utils.vars as utils_vars
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.splitter import parse_kv
from ansible.plugins.loader import init_plugin_loader
from ansible.plugins.shell.sh import ShellModule as ShShellPlugin
import ansible.constants as C
from ansible.module_utils.common.text.converters import to_text
from ansible.template import Templar

import json


def parse():
    """parse command line

    :return : (options, args)"""
    parser = optparse.OptionParser()

    parser.usage = "%prog -[options] (-h for help)"

    parser.add_option('-m', '--module-path', dest='module_path',
                      help="REQUIRED: full path of module source to execute")
    parser.add_option('-a', '--args', dest='module_args', default="",
                      help="module argument string")
    parser.add_option('-D', '--debugger', dest='debugger',
                      help="path to python debugger (e.g. /usr/bin/pdb)")
    parser.add_option('-I', '--interpreter', dest='interpreter',
                      help="path to interpreter to use for this module"
                      " (e.g. ansible_python_interpreter=/usr/bin/python)",
                      metavar='INTERPRETER_TYPE=INTERPRETER_PATH',
                      default="ansible_python_interpreter=%s" %
                      (sys.executable if sys.executable else '/usr/bin/python'))
    parser.add_option('-c', '--check', dest='check', action='store_true',
                      help="run the module in check mode")
    parser.add_option('-n', '--noexecute', dest='execute', action='store_false',
                      default=True, help="do not run the resulting module")
    parser.add_option('-o', '--output', dest='filename',
                      help="Filename for resulting module",
                      default="~/.ansible_module_generated")
    options, args = parser.parse_args()
    if not options.module_path:
        parser.print_help()
        sys.exit(1)
    else:
        return options, args


def jsonify(result, format=False):
    """ format JSON output (uncompressed or uncompressed) """

    if result is None:
        return "{}"

    indent = None
    if format:
        indent = 4

    try:
        return json.dumps(result, sort_keys=True, indent=indent, ensure_ascii=False)
    except UnicodeDecodeError:
        return json.dumps(result, sort_keys=True, indent=indent)


def write_argsfile(argstring, json=False):
    """ Write args to a file for old-style module's use. """
    argspath = Path("~/.ansible_test_module_arguments").expanduser()
    if json:
        args = parse_kv(argstring)
        argstring = jsonify(args)
    argspath.write_text(argstring)
    return argspath


def get_interpreters(interpreter):
    result = dict()
    if interpreter:
        if '=' not in interpreter:
            print("interpreter must by in the form of ansible_python_interpreter=/usr/bin/python")
            sys.exit(1)
        interpreter_type, interpreter_path = interpreter.split('=')
        if not interpreter_type.startswith('ansible_'):
            interpreter_type = 'ansible_%s' % interpreter_type
        if not interpreter_type.endswith('_interpreter'):
            interpreter_type = '%s_interpreter' % interpreter_type
        result[interpreter_type] = interpreter_path
    return result


def build_module(modfile, args, interpreters, check, destfile):
    """ simulate what ansible does with new style modules """

    loader = DataLoader()

    complex_args = {}

    # default selinux fs list is pass in as _ansible_selinux_special_fs arg
    complex_args['_ansible_selinux_special_fs'] = C.DEFAULT_SELINUX_SPECIAL_FS
    complex_args['_ansible_tmpdir'] = C.DEFAULT_LOCAL_TMP
    complex_args['_ansible_keep_remote_files'] = C.DEFAULT_KEEP_REMOTE_FILES
    complex_args['_ansible_version'] = __version__

    if args.startswith("@"):
        # Argument is a YAML file (JSON is a subset of YAML)
        complex_args = utils_vars.combine_vars(complex_args, loader.load_from_file(args[1:]))
        args = ''
    elif args.startswith("{"):
        # Argument is a YAML document (not a file)
        complex_args = utils_vars.combine_vars(complex_args, loader.load(args))
        args = ''

    if args:
        parsed_args = parse_kv(args)
        complex_args = utils_vars.combine_vars(complex_args, parsed_args)

    task_vars = interpreters

    if check:
        complex_args['_ansible_check_mode'] = True

    modfile = os.path.abspath(modfile)
    modname = os.path.basename(modfile)
    modname = os.path.splitext(modname)[0]

    module_builder = _finder.get_module_data(modname, modfile)

    if module_builder.shebang:
        interpreter_key = f"ansible_{os.path.basename(module_builder.shebang[0])}_interpreter"
        if custom_interpreter := interpreters.get(interpreter_key):
            module_builder.update_shebang(custom_interpreter)

    build_options = _builder.BuildOptions(
        module_args=complex_args,
        shell=ShShellPlugin(),
        task_vars=task_vars,
        tmpdir="/tmp-fake",  # Forces non-pipelined module to be built, this path is changed after.
        templar=Templar(loader=loader),
    )

    built_module = module_builder.build_module(build_options)
    module_cmd = built_module.cmd

    module_path_idx = 1
    if module_cmd[0].startswith('/tmp-fake'):
        # Running a binary module or some unknown scenario where the
        # interpreter wasn't set so first arg is the module path.
        module_path_idx = 0

    # As we provided a fake tmpdir to the builder we need to change the cmd and
    # remote tmp listing to the user supplied file.
    modfile2_path = os.path.expanduser(destfile)
    module_cmd[module_path_idx] = modfile2_path

    print("* including generated source, if any, saving to: %s" % modfile2_path)
    if built_module.temp_files[0].data:
        # Content was dynamically generated or changed from the source.
        print("* this may offset any line numbers in tracebacks/debuggers!")
        with open(modfile2_path, 'wb') as modfile2:
            modfile2.write(built_module.temp_files[0].data)
    else:
        shutil.copyfile(built_module.temp_files[0].local_path, modfile2_path)

    # If the args are not embedded in the module the next argument should be
    # the args file.
    if len(module_cmd) > (module_path_idx + 1):
        arg_path = str(Path("~/.ansible_test_module_arguments").expanduser())
        module_cmd[module_path_idx + 1] = arg_path

        if built_module.temp_files[1].data:
            with open(arg_path, 'wb') as argfile:
                argfile.write(built_module.temp_files[1].data)
        else:
            shutil.copyfile(built_module.temp_files[1].local_path, arg_path)

    return modname, module_cmd, isinstance(module_builder, _python.PythonModuleBuilder)


def ansiballz_setup(modname, module_args):
    explode_cmd = [module_args[0], module_args[1], 'explode']
    cmd = subprocess.Popen(explode_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = cmd.communicate()
    out, err = to_text(out, errors='surrogate_or_strict'), to_text(err)
    lines = out.splitlines()
    if len(lines) != 2 or 'Module expanded into' not in lines[0]:
        print("*" * 35)
        print("INVALID OUTPUT FROM ANSIBALLZ MODULE WRAPPER")
        print(out)
        sys.exit(err)
    debug_dir = lines[1].strip()

    # All the directories in an AnsiBallZ that modules can live
    core_dirs = glob.glob(os.path.join(debug_dir, 'ansible/modules'))
    non_core_dirs = glob.glob(os.path.join(debug_dir, 'ansible/legacy'))
    collection_dirs = glob.glob(os.path.join(debug_dir, 'ansible_collections/*/*/plugins/modules'))

    # There's only one module in an AnsiBallZ payload so look for the first module and then exit
    for module_dir in core_dirs + collection_dirs + non_core_dirs:
        for dirname, directories, filenames in os.walk(module_dir):
            for filename in filenames:
                if filename == modname + '.py':
                    modfile = os.path.join(dirname, filename)
                    break

    argsfile = os.path.join(debug_dir, 'args')

    print("* ansiballz module detected; extracted module source to: %s" % debug_dir)
    return [
        module_args[0],  # Include the interpreter,
        modfile,
        argsfile,
    ]


def runtest(modname, module_args, is_python_ansiballz):
    """Test run a module, piping it's output for reporting."""
    if is_python_ansiballz:
        module_args = ansiballz_setup(modname, module_args)

    cmd = subprocess.Popen(module_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    out, err = to_text(out), to_text(err)

    try:
        print("*" * 35)
        print("RAW OUTPUT")
        print(out)
        print(err)
        results = json.loads(out)
    except Exception:
        print("*" * 35)
        print("INVALID OUTPUT FORMAT")
        print(out)
        traceback.print_exc()
        sys.exit(1)

    print("*" * 35)
    print("PARSED OUTPUT")
    print(jsonify(results, format=True))


def rundebug(debugger, modname, module_args, is_python_ansiballz):
    """Run interactively with console debugger."""

    if is_python_ansiballz:
        module_args = ansiballz_setup(modname, module_args)

    module_args.insert(0, debugger)
    subprocess.call(module_args, shell=True)


def main():

    options, args = parse()
    init_plugin_loader()
    interpreters = get_interpreters(options.interpreter)
    modname, module_args, is_python_ansiballz = build_module(options.module_path, options.module_args, interpreters, options.check, options.filename)

    if options.execute:
        if options.debugger:
            rundebug(options.debugger, modname, module_args, is_python_ansiballz)
        else:
            runtest(modname, module_args, is_python_ansiballz)


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(C.DEFAULT_LOCAL_TMP, True)
