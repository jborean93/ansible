from __future__ import annotations

import dataclasses
import typing as t

from ansible.module_utils._internal import _datatag, _messages


@dataclasses.dataclass(**_datatag._tag_dataclass_kwargs)
class Deprecated(_datatag.AnsibleDatatagBase):
    msg: str
    help_text: t.Optional[str] = None
    date: t.Optional[str] = None
    version: t.Optional[str] = None
    deprecator: t.Optional[_messages.PluginInfo] = None
    formatted_traceback: t.Optional[str] = None


@dataclasses.dataclass(**_datatag._tag_dataclass_kwargs)
class NonsensitiveData(_datatag.AnsibleSingletonTagBase):
    """
    Indicates the tagged value is known-safe, nonsensitive data, such as a play recap row.

    Internal only. This tag is deliberately absent from `_common_module_response_types`, so a module cannot
    return a value tagged with it and exempt itself from masking.

    Only `Display` honours the tag; `mask_secrets` masks regardless, so registering a tagged value as a secret
    still works as expected.
    """

    def _get_tag_to_propagate(self, src: t.Any, value: object, *, value_type: t.Optional[type] = None) -> t.Self | None:
        # This tag exempts its value from secret masking, so it must never be inherited; `tag_copy` would
        # otherwise extend the exemption to derived values that were never vouched for. Returning `None` also
        # strips the tag from `value`, which fails safe: the value is masked instead.
        return None
