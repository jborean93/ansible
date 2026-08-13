from __future__ import annotations

import importlib
import json
import sys

import pytest

from ansible.module_utils._internal import _ahocorasick, _secrets

try:
    import ahocorasick as c_extension
except ImportError:
    c_extension = None

# The masking corpus is shared with the C# integration target so both runtimes
# assert the same contract against the same data.
CORPUS = "test/integration/targets/module_utils_Ansible.Secrets/files/secret_masking_corpus.json"

with open(CORPUS) as _fh:
    _CORPUS = json.load(_fh)

SENTINEL = _CORPUS["sentinel"]
CASES = _CORPUS["cases"]

# Backends the masker must satisfy identically: the pure-Python fallback always,
# the C extension when it is installed.
BACKENDS = [pytest.param(_ahocorasick, id="pure_python")]
if c_extension is not None:
    BACKENDS.append(pytest.param(c_extension, id="c_extension"))


def _mask(monkeypatch, backend, secrets, text):
    """Mask ``text`` with ``secrets`` registered, forcing ``backend`` under SecretMasker."""
    monkeypatch.setattr(_secrets, "ahocorasick", backend)
    masker = _secrets.SecretMasker()
    for secret in secrets:
        masker.register_secret_text(secret)
    return masker.mask_string(text, mask_placeholder=SENTINEL)


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_no_secret_survives(monkeypatch, backend, case):
    """Safety contract: no registered secret remains as a substring of the masked output.

    The sentinel placeholder shares no characters with the (lowercase) secrets, so a
    surviving secret can never be a false positive from the placeholder text.
    """
    masked = _mask(monkeypatch, backend, case["secrets"], case["input"])
    for secret in case["secrets"]:
        assert secret not in masked, f"secret {secret!r} survived in {masked!r}"


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_canaries_survive(monkeypatch, backend, case):
    """Anti-destruction contract: non-secret markers must survive masking verbatim."""
    masked = _mask(monkeypatch, backend, case["secrets"], case["input"])
    for canary in case["canaries"]:
        assert canary in masked, f"canary {canary!r} was destroyed in {masked!r}"


@pytest.mark.parametrize("backend", BACKENDS)
def test_register_secret_text_is_idempotent(monkeypatch, backend):
    """Registering the same secret twice tracks it once (duplicate add is a no-op)."""
    monkeypatch.setattr(_secrets, "ahocorasick", backend)
    masker = _secrets.SecretMasker()
    tracker = masker.track_new_secrets()
    masker.register_secret_text("password123")
    masker.register_secret_text("password123")
    assert tracker.flush() == frozenset({"password123"})


@pytest.mark.parametrize("backend", BACKENDS)
def test_short_secrets_are_not_registered(monkeypatch, backend):
    """Secrets shorter than the minimum length are silently skipped, so they pass through unmasked."""
    monkeypatch.setattr(_secrets, "ahocorasick", backend)
    masker = _secrets.SecretMasker()
    short = "a" * (_secrets._MINIMUM_SECRET_LENGTH - 1)
    masker.register_secret_text(short)
    text = f"XX{short}XX"
    assert masker.mask_string(text, mask_placeholder=SENTINEL) == text


@pytest.mark.parametrize("backend", BACKENDS)
def test_secrets_in_reports_registered_secrets(monkeypatch, backend):
    """secrets_in returns exactly the registered secrets found in the value."""
    monkeypatch.setattr(_secrets, "ahocorasick", backend)
    masker = _secrets.SecretMasker()
    masker.register_secret_text("alpha")
    masker.register_secret_text("bravo")
    assert masker.secrets_in("XXalphaYYbravoZZ") == frozenset({"alpha", "bravo"})


def test_import_fallback_uses_pure_python(monkeypatch):
    """When the C extension is unavailable, _secrets falls back to the pure-Python backend."""
    monkeypatch.setitem(sys.modules, "ahocorasick", None)  # force ImportError on `import ahocorasick`
    try:
        reloaded = importlib.reload(_secrets)
        assert reloaded.ahocorasick is _ahocorasick
    finally:
        monkeypatch.undo()
        importlib.reload(_secrets)  # restore real import resolution for subsequent tests
