from ansible.module_utils._internal._secrets import _secret_masker

def register_secret(value: str) -> str:
    return _secret_masker.register_secret_text(value)

def mask_secrets(value: str, *, mask_placeholder: str = '<secret>') -> str:
    return _secret_masker.mask_string(value, mask_placeholder=mask_placeholder)
