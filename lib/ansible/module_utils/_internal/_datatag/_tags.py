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
    For internal use (for now?).
    Indicates the tagged value is guaranteed to be safe, nonsensitive data.
    Used in places such as play recaps.
    """
    # | 🐘🐘🐘 |
    #   ^room^
    # Should it stay internal?
    # If public, should this be exposed to playbooks, or just actions/modules?
    # Where else should I put it?
    # I let register_secret override.

    def _get_tag_to_propagate(self, src: t.Any, value: object, *, value_type: t.Optional[type] = None) -> t.Self | None:
        # This tag exempts the value it is applied to from secret masking, so it must never be inherited.
        # Unconditional propagation would let `tag_copy` silently extend the exemption to derived values that
        # were never vouched for -- notably in `_secrets_object._Walker.mask`, which copies tags from the source
        # onto every value it masks. Exemption must always be an explicit decision at the point of use.

        # Returning `None` also strips the tag from `value` when `src` carries it (see `AnsibleTagHelper.tag_copy`).
        # That is intentional: discarding an exemption fails safe, since the value is masked instead.
        return None
