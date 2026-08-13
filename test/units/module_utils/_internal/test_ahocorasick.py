from __future__ import annotations

import json

import pytest

from ansible.module_utils._internal import _ahocorasick as pure_python

try:
    import ahocorasick as c_extension
except ImportError:
    c_extension = None

FIXTURES = "test/units/module_utils/_internal/fixtures"


def _load(name):
    with open(f"{FIXTURES}/{name}") as f:
        return json.load(f)["cases"]


CONFORMANCE = _load("ahocorasick_conformance.json")
IMPL_SPECIFIC = _load("ahocorasick_impl_specific.json")

# Implementations that must agree on the shared behaviors below.
IMPLEMENTATIONS = [pytest.param(pure_python, id="pure_python")]
if c_extension is not None:
    IMPLEMENTATIONS.append(pytest.param(c_extension, id="c_extension"))


@pytest.mark.parametrize("module", IMPLEMENTATIONS)
def test_add_word_return_value(module):
    """add_word returns True for a newly added word and False for a duplicate."""
    automaton = module.Automaton()
    assert automaton.add_word("secret", 6) is True   # newly added
    assert automaton.add_word("secret", 6) is False  # already present
    assert automaton.add_word("other", 5) is True    # distinct word


@pytest.mark.parametrize("module", IMPLEMENTATIONS)
def test_add_empty_word_is_noop(module):
    """Adding an empty string is a no-op that returns False."""
    assert module.Automaton().add_word("", 0) is False


def _matches(module, words, text):
    """Build an automaton from ``words`` (word -> value) and return iter_long matches."""
    automaton = module.Automaton()
    for word, value in words.items():
        automaton.add_word(word, value)
    automaton.make_automaton()
    return [list(match) for match in automaton.iter_long(text)]


@pytest.mark.parametrize("case", CONFORMANCE, ids=[c["name"] for c in CONFORMANCE])
def test_pure_python_matches_reference(case):
    """Pure-Python iter_long matches the reference output (generated from the C extension)."""
    assert _matches(pure_python, case["words"], case["input"]) == case["expected"]


@pytest.mark.skipif(c_extension is None, reason="ahocorasick C extension not installed")
@pytest.mark.parametrize("case", CONFORMANCE, ids=[c["name"] for c in CONFORMANCE])
def test_c_extension_matches_reference(case):
    """The C extension still produces the reference output (guards against fixture drift)."""
    assert _matches(c_extension, case["words"], case["input"]) == case["expected"]


@pytest.mark.parametrize("case", IMPL_SPECIFIC, ids=[c["name"] for c in IMPL_SPECIFIC])
def test_pure_python_len1_divergence(case):
    """Pin the documented length-1 divergence: pure-Python yields its recorded output, not the C extension's."""
    got = _matches(pure_python, case["words"], case["input"])
    assert got == case["pure_python"]
    assert got != case["c_extension"]


@pytest.mark.skipif(c_extension is None, reason="ahocorasick C extension not installed")
@pytest.mark.parametrize("case", IMPL_SPECIFIC, ids=[c["name"] for c in IMPL_SPECIFIC])
def test_c_extension_len1_divergence(case):
    """Confirm the recorded C-extension output for the divergent cases still holds."""
    assert _matches(c_extension, case["words"], case["input"]) == case["c_extension"]
