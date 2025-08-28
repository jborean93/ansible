from __future__ import annotations

import json

from . import _builder
from ansible.module_utils.common.json import Direction, get_module_encoder
from ansible.release import __version__

REPLACER_JSON_ARGS = b"<<INCLUDE_ANSIBLE_MODULE_JSON_ARGS>>"
REPLACER_VERSION = b"\"<<ANSIBLE_VERSION>>\""
REPLACER_COMPLEX = b"\"<<INCLUDE_ANSIBLE_MODULE_COMPLEX_ARGS>>\""
REPLACER_SELINUX = b"<<SELINUX_SPECIAL_FILESYSTEMS>>"


class ReplacerModuleData(_builder.ModuleBuilder):
    """Module replacer builder.
    
    The module replacer  is a simple builder that replaces known identifiers
    in the module code with data like module args. The replacer builder can
    also pipeline a module if the connection supports it.
    """

    @classmethod
    def create(
        cls,
        path: str,
        module_data: bytes,
        shebang: tuple[str, str | None] | None = None,
    ) -> ReplacerModuleData:
        if REPLACER_JSON_ARGS not in module_data:
            return None

        return ReplacerModuleData(
            path=path,
            data=module_data,
            shebang=shebang,
            argument_style="embedded",
        )

    def build_module(self, options: _builder.BuildOptions) -> _builder.BuiltModule:
        serialization_profile = "legacy"

        encoder = get_module_encoder(serialization_profile, Direction.CONTROLLER_TO_MODULE)
        module_args_json = json.dumps(options.module_args, cls=encoder).encode('utf-8')

        # these strings could be included in a third-party module but
        # officially they were included in the 'basic' snippet for new-style
        # python modules (which has been replaced with something else in
        # ansiballz) If we remove them from jsonargs-style module replacer
        # then we can remove them everywhere.
        module_data = self._data
        module_data = module_data.replace(
            REPLACER_VERSION,
            repr(__version__).encode('utf-8'),
        )
        module_data = module_data.replace(
            REPLACER_COMPLEX,
            repr(module_args_json).encode('utf-8'),
        )
        module_data = module_data.replace(
            REPLACER_SELINUX,
            ','.join(C.DEFAULT_SELINUX_SPECIAL_FS).encode('utf-8'))  # type: ignore[attr-defined]

        # The main event -- substitute the JSON args string into the module
        module_data = module_data.replace(REPLACER_JSON_ARGS, module_args_json)

        syslog_facility = options.task_vars.get(
            'ansible_syslog_facility',
            C.DEFAULT_SYSLOG_FACILITY)  # type: ignore[attr-defined]
        facility = f'syslog.{syslog_facility}'.encode('utf-8')
        module_data = module_data.replace(b'syslog.LOG_USER', facility)

        self._data = module_data
        self._data_is_modified = True

        if options.tmpdir:
            return super().build_module(options)
        else:
            cmd_args = self._get_interpreter_args()
            return _builder.BuiltModule(
                cmd=cmd_args,
                in_data=self._data,
                temp_files=[],
                environment=options.environment,
                has_async=False,
                serialization_profile="legacy",
            )
