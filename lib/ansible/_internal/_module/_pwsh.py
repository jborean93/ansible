from __future__ import annotations

import base64
import binascii
import re
import typing as t
import xml.etree.ElementTree as ET

from . import _builder
from ansible.executor.powershell import module_manifest
from ansible.plugins.shell import powershell


REPLACER_PWSH = b"# POWERSHELL_COMMON"
NEW_STYLE_PWSH_MODULE_RE = re.compile(
    # Old style PowerShell module imports
    br'#Requires -Module |'
    # For backwards compat we used this also as a check
    br'#Requires -Version |'
    # New style wrapper declarations
    br'#AnsibleRequires -(OSVersion|PowerShell|CSharpUtil|Wrapper)',
    re.IGNORECASE,
)

# Finds _x in a case insensitive way, _x is the escape sequence for a CLIXML
# str so needs to be escaped first.
_STRING_SERIAL_ESCAPE_ESCAPE = re.compile("(?i)_(x)")

# Finds C0, C1, and surrogate pairs in a unicode string for us to encode
# according to the PSRP rules.
_STRING_SERIAL_ESCAPE = re.compile("[\u0000-\u001f\u007f-\u009f\ud800-\ud8ff\udc00-\udfff\U00010000-\U0010ffff]")


class PwshModuleBuilder(_builder.ModuleBuilder):
    """PowerShell module builder.

    The PowerShell builder is flagged when the module contains either the old
    replacer '# POWERSHELL_COMMON' text or one of the new requires statements.

    :param module_fqn: The module's fully qualified name.
    :param path: The path to the PowerShell module.
    :param data: The module's contents.
    :param shebang: The shebang interpreter and optional argument if present.
    :param is_windows: Whether the target platform is Windows or not.
    :param substyle: Whether the builder is for PowerShell code or a script.
    :param chdir: The working directory to change to before executing the module or script.
    """

    def __init__(
        self,
        module_fqn: str,
        path: str,
        data: bytes,
        shebang: tuple[str, str | None] | None = None,
        is_windows: bool = True,
        substyle: t.Literal["powershell", "script"] = "powershell",
        chdir: str | None = None,
    ) -> None:
        # For backwards compat treat no shebang as '#!powershell'
        if not shebang:
            shebang = ('powershell', None)

        # If the shebang is '#!powershell' then use WinPS as the default pwsh
        # for backwards compat on Windows. This can still be overridden if
        # someone sets ansible_pwsh_interpreter. We set the public facing
        # shebang to /usr/bin/pwsh to unify the interpreter lookup var.
        self._default_pwsh = None
        if shebang[0] == 'powershell':
            shebang = ('/usr/bin/pwsh', shebang[1])
            if is_windows:
                self._default_pwsh = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            else:
                self._default_pwsh = '/usr/bin/pwsh'

        elif shebang[0] == '/usr/bin/pwsh' and is_windows:
            # /usr/bin/pwsh isn't valid on Windows so use pwsh.exe.
            self._default_pwsh = 'pwsh.exe'

        self.module_fqn = module_fqn
        self._is_windows = is_windows
        self._substyle = substyle
        self._chdir = chdir

        super().__init__(
            path,
            data,
            shebang=shebang,
            argument_style="embedded",
        )

    @classmethod
    def create(
        cls,
        module_fqn: str,
        path: str,
        module_data: bytes,
        shebang: tuple[str, str | None] | None = None,
        platform: t.Literal["windows", "posix"] = "posix",
    ) -> PwshModuleBuilder | None:
        can_use = False

        if REPLACER_PWSH in module_data:
            module_data = module_data.replace(
                REPLACER_PWSH,
                b'#AnsibleRequires -PowerShell Ansible.ModuleUtils.Legacy',
            )
            can_use = True
        elif NEW_STYLE_PWSH_MODULE_RE.search(module_data):
            can_use = True

        if not can_use:
            return None

        return PwshModuleBuilder(
            module_fqn=module_fqn,
            path=path,
            data=module_data,
            shebang=shebang,
            is_windows=platform == "windows",
        )

    def update_shebang(self, shebang: str) -> None:
        # If the shebang is being updated then we don't want to use the default
        # anymore but the user specified one. We also don't update the module
        # data in case it invalidates the signature. As we run it through the
        # wrapper it isn't important the shebang is correct in the data itself.
        self._default_pwsh = None
        self.shebang = (shebang, self.shebang[1])

    def build_module(self, options: _builder.BuildOptions) -> _builder.BuiltModule:
        # FUTURE: Add a way for pwsh modules to set this.
        serialization_profile = "legacy"
        build_has_async = True
        build_environment = {}

        cmd_args = self._get_pwsh_args()

        # The async, become, and environment handlers in the pwsh wrapper is
        # only done on Windows. POSIX uses a mechanism done outside of the
        # wrapper instead.
        wrapper_kwargs: dict[str, t.Any] = {'async_timeout': 0, 'async_dir': None, 'become_plugin': None, 'environment': {}}
        if self._is_windows:
            wrapper_kwargs['environment'] = options.environment
            wrapper_kwargs['become_plugin'] = options.become

            if options.async_opts:
                wrapper_kwargs['async_timeout'] = options.async_opts.timeout
                wrapper_kwargs['async_dir'] = options.async_opts.path
        else:
            build_has_async = False
            build_environment = options.environment

            if options.async_opts and not options.tmpdir:
                raise _builder.RequiresTmpDir()

        module_data = module_manifest._create_powershell_wrapper(
            name=self.module_fqn,
            module_data=self._data,
            module_path=self.path,
            module_args=options.module_args,
            chdir=self._chdir,
            substyle=self._substyle,
            task_vars=options.task_vars or {},
            profile=serialization_profile,
            **wrapper_kwargs,
        )

        in_data = module_data
        temp_files = []
        if options.tmpdir:
            # For non-pipelining we execute the bootstrap wrapper as an encoded
            # command still but provide the input/module data as the path to a
            # temp file.
            in_data = None
            remote_file_path = options.shell.join_path(options.tmpdir, "args")
            temp_files.append(
                _builder.TempFile(
                    remote_path=remote_file_path,
                    data=module_data,
                )
            )

            # -EncodedCommand does not support standard arguments but uses a
            # CLIXML string encoded through base64.
            enc_args = self._get_encoded_arguments(remote_file_path)
            cmd_args.extend(["-EncodedArguments", enc_args])

        return _builder.BuiltModule(
            cmd=cmd_args,
            in_data=in_data,
            temp_files=temp_files,
            environment=build_environment,
            has_async=build_has_async,
            serialization_profile=serialization_profile,
        )

    def process_result(
        self,
        rc: int,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[int, bytes, bytes]:
        # PowerShell emits CLIXML over stderr which makes understanding errors
        # difficult. We convert the stderr back to normal text here if possible.
        return (rc, stdout, powershell._replace_stderr_clixml(stderr))

    def _get_pwsh_args(self) -> list[str]:
        # PowerShell never uses the remote script path or args file even when
        # not pipelining. The wrapper is executed using an encoded command with
        # a specific set of args for PowerShell.
        if self._default_pwsh:
            pwsh_args = [self._default_pwsh]
        else:
            # We ignore the shebang args for the pwsh wrapper and just use the
            # provided interpreter.
            pwsh_args = [self.shebang[0]]

        pwsh_args.extend(['-NoProfile', '-NonInteractive'])
        if self._is_windows:
            pwsh_args.extend(['-ExecutionPolicy', 'Unrestricted'])

        # The bootstrap wrapper is not signed and can be modified as it is run.
        # We remove the lines that are comments to trim down the size and the
        # overall command line line that it takes.
        wrapper_lines = module_manifest._get_powershell_script("bootstrap_wrapper.ps1").decode("utf-8").splitlines()
        for idx, line in enumerate(wrapper_lines):
            if line.lstrip().startswith('#'):
                wrapper_lines[idx] = ""

        bootstrap_wrapper = "\n".join(wrapper_lines)
        enc_command = base64.b64encode(bootstrap_wrapper.encode('utf-16-le')).decode()
        pwsh_args.extend(['-EncodedCommand', enc_command])

        return pwsh_args

    def _get_encoded_arguments(self, *args: str) -> str:
        """Converts a list of arguments to the format needed for -EncodedArguments."""

        def rplcr(matchobj: object) -> str:
            surrogate_char = matchobj.group(0)
            byte_char = surrogate_char.encode("utf-16-be", errors="surrogatepass")
            hex_char = binascii.hexlify(byte_char).decode().upper()
            hex_split = [hex_char[i : i + 4] for i in range(0, len(hex_char), 4)]

            return "".join([f"_x{i}_" for i in hex_split])

        objs = ET.Element('Objs', xmlns="http://schemas.microsoft.com/powershell/2004/04", Version="1.1.0.1")
        obj = ET.SubElement(objs, 'Obj', RefId="0")

        tn = ET.SubElement(obj, 'TN', RefId="0")
        ET.SubElement(tn, 'T').text = "System.Collections.ArrayList"
        ET.SubElement(tn, 'T').text = "System.Object"

        lst = ET.SubElement(obj, 'LST')
        for a in args:
            # Before running the translation we need to make sure that '_x' is
            # escaped as '_x005F_x'. While MS-PSRP doesn't state this, the x is
            # case insensitive so we need to escape both '_x' and '_X'.
            a = re.sub(_STRING_SERIAL_ESCAPE_ESCAPE, "_x005F_\\1", a)

            # Escape any control or codepoints that are represented as a
            # surrogate pair in UTF-16.
            a = re.sub(_STRING_SERIAL_ESCAPE, rplcr, a)
            ET.SubElement(lst, 'S').text = a

        clixml = ET.tostring(objs, encoding='unicode')
        return base64.b64encode(clixml.encode('utf-16-le')).decode()
