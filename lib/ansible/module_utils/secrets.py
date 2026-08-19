from __future__ import annotations

import typing as _t

from ansible.module_utils._internal._secrets import _secret_masker

def register_secret(value: str | int | float) -> str | int | float:
    orig_value = value
    _secret_masker.register_secret_text(str(value))
    return orig_value


def register_secrets(values: _t.Iterable[str | int | float]) -> None:
    _secret_masker.register_secret_texts([str(value) for value in values])


def mask_secrets(value: str, *, mask_placeholder: str = '<secret>') -> str:
    return _secret_masker.mask_string(value, mask_placeholder=mask_placeholder)
