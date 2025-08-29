from __future__ import annotations

import dataclasses
import json
import shlex
import typing as t

from ansible.errors import AnsibleError
from ansible.module_utils.common.json import Direction, get_module_encoder
from ansible.template import Templar
from ansible.plugins.become import BecomeBase
from ansible.plugins.shell import ShellBase
from ansible.utils.display import Display

display = Display()


class RequiresTmpDir(Exception):
    """Exception used by ModuleData.build_module to indicate that a tmpdir is required."""


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class AsyncOptions:
    """Options used for async execution."""

    timeout: int
    """The async timeout in seconds."""
    path: str
    """The async directory."""


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class BuildOptions:
    """Options used when building a module."""

    module_args: dict[str, object]
    """The module's arguments."""
    shell: ShellBase
    """The shell plugin for the target host."""
    tmpdir: str | None = None
    """If set, indicates pipelining is not available and this is the tmpdir to use."""
    become: BecomeBase | None = None
    """The become plugin if one is set for the current task."""
    async_opts: AsyncOptions | None = None
    """The current async options is enabled for the current task."""
    task_vars: dict[str, object] = dataclasses.field(default_factory=dict)
    """The task variables for the target host."""
    environment: dict[str, str] = dataclasses.field(default_factory=dict)
    """The environment variables set for the current task."""
    templar: Templar | None = None
    """The action plugins templar engine."""

    def get_tmpdir(self) -> str:
        """Gets the temp dir or requests the action plugin to create one and call again."""
        if not self.tmpdir:
            raise RequiresTmpDir()

        return self.tmpdir


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class BuiltModule:
    """The built module information."""

    cmd: list[str]
    """Command and list of arguments to run to execute the module."""
    in_data: bytes | None = None
    """Input data for stdin needed to run the module, this will only be set if pipelining is enabled."""
    temp_files: list[TempFile] = dataclasses.field(default_factory=list)
    """Temporary files the caller needs to create before running the module."""
    environment: dict[str, str] = dataclasses.field(default_factory=dict)
    """Environment variables that need to be set when starting the cmd."""
    has_async: bool = False
    """The module includes an async implementation and does not require a wrapper."""
    has_become: bool = False
    """The module includes become support and does not require a wrapper."""
    serialization_profile: str = "legacy"
    """The serialization profile used for deserializing the return data."""


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class TempFile:
    """Temporary file data for the caller to action."""

    remote_path: str
    """The remote path to create the temporary file at."""
    local_path: str | None = None
    """The local path to read the data from, if not set then `data` must be set."""
    data: bytes = b""
    """The data to write to the temporary file, if not set then `local_path` must be set."""


class ModuleBuilder:
    """Used for building Ansible modules.

    This is used to construct the necessary data and commands needed to execute
    a module. It can be subclassed by other builders to customise the build
    process for specific module types.

    :param path: The path to the local module file.
    :param data: The module data if modified from the path or required by the builder.
    :param shebang: The shebang interpreter and optional argument if present.
    :param argument_style: The method used for providing the module args.
    """

    def __init__(
        self,
        path: str,
        data: bytes = b"",
        shebang: tuple[str, str | None] | None = None,
        argument_style: t.Literal["embedded", "key_value", "json"] = "json",
    ) -> None:
        self.path = path
        self.shebang = shebang
        self.argument_style = argument_style

        self._data = data
        self._data_is_modified = False

    def update_shebang(self, shebang: str) -> None:
        """Updates the shebang interpreter to use for a module.

        :param shebang: The new shebang to use for the module.
        """
        # Only binary modules do not populate the data field. This should not
        # happen unless there is some logic bug somewhere.
        if not self._data:
            raise AnsibleError("Cannot update shebang for binary module.")

        module_lines = self._data.split(b"\n", 1)

        shebang_line = f"#!{shebang}"
        if self.shebang[1]:
            shebang_line += f" {self.shebang[1]}"
        module_lines[0] = shebang_line.encode("utf-8")

        self._data = b"\n".join(module_lines)
        self._data_is_modified = True
        self.shebang = (shebang, self.shebang[1])

    def build_module(self, options: BuildOptions) -> BuiltModule:
        """Builds the module.

        This can be overridden by subclasses to customize the build process.

        :param options: The build options.
        :returns: The built module information.
        """
        # Pipelining is never supported for these module types so always
        # request the tmpdir.
        tmpdir = options.get_tmpdir()

        temp_files = []
        remote_file_name = options.shell.get_remote_filename(self.path)
        remote_file_path = options.shell.join_path(tmpdir, f"AnsiballZ_{remote_file_name}")
        temp_files.append(
            TempFile(
                remote_path=remote_file_path,
                local_path=None if self._data_is_modified else self.path,
                data=self._data if self._data_is_modified else None,
            )
        )

        module_args: list[str] = []
        if self.argument_style != "embedded":
            if self.argument_style == "key=value":
                arg_lines = []
                for k, v in module_args.items():
                    arg_lines.append(f"{k}={shlex.quote(str(v))}")
                arg_data = " ".join(arg_lines)
            else:
                serialization_profile = "legacy"
                profile_encoder = get_module_encoder(serialization_profile, Direction.CONTROLLER_TO_MODULE)
                arg_data = json.dumps(module_args, cls=profile_encoder)

            args_file_path = options.shell.join_path(tmpdir, "args")
            temp_files.append(TempFile(remote_path=args_file_path, data=arg_data.encode("utf-8")))
            module_args.append(args_file_path)

        cmd_args = self._get_interpreter_args(
            path=remote_file_path,
            args=module_args,
        )

        return BuiltModule(
            cmd=cmd_args,
            in_data=None,
            temp_files=temp_files,
            environment=options.environment,
            has_async=False,
            has_become=False,
            serialization_profile="legacy",
        )

    def process_result(
        self,
        rc: int,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[int, bytes, bytes]:
        """Process the raw result from executing the module."""
        return (rc, stdout, stderr)

    def _get_interpreter_args(
        self,
        path: str | None = None,
        args: list[str] | None = None,
    ) -> list[str]:
        cmd_args = []
        if self.shebang:
            cmd_args.append(self.shebang[0])

            if self.shebang[1]:
                # We've historically failed ungracefully if a module shebang
                # has an arg present. Instead we ignore it and emit a warning.
                msg = (
                    f"The module shebang at {self.path!r} contains an argument and will be ignored. "
                    "This will turn into an error after the deprecation period."
                )
                display.deprecated(
                    msg=msg,
                    version='2.24',
                    help_text='Remove shebang argument from the shebang line.',
                )

        if path:
            cmd_args.append(path)

        if args:
            cmd_args.extend(args)

        return cmd_args
