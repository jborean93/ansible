from __future__ import annotations

import pytest

from ansible._internal._module import _interpreter_discovery
from ansible.template import Templar


@pytest.fixture
def templar():
    return Templar()


def test_no_interpreter_set(templar):
    # normally this would return /usr/bin/python, but so long as we're defaulting to auto python discovery, we'll get
    # an InterpreterDiscoveryRequiredError here instead
    with pytest.raises(_interpreter_discovery.InterpreterDiscoveryRequiredError):
        _interpreter_discovery.replace_shebang('/usr/bin/python', {}, templar)


def test_python_versioned_interpreter_no_change(templar):
    assert _interpreter_discovery.replace_shebang('/usr/bin/python3.8', {}, templar) is None


def test_non_python_interpreter_no_change(templar):
    assert _interpreter_discovery.replace_shebang('/usr/bin/ruby', {}, templar) is None


def test_interpreter_set_in_task_vars(templar):
    assert _interpreter_discovery.replace_shebang('/usr/bin/python', {'ansible_python_interpreter': '/usr/bin/pypy'}, templar) == \
        '/usr/bin/pypy'


def test_non_python_interpreter_in_task_vars(templar):
    assert _interpreter_discovery.replace_shebang('/usr/bin/ruby', {'ansible_ruby_interpreter': '/usr/local/bin/ruby'}, templar) == \
        '/usr/local/bin/ruby'


def test_interpreter_override(templar):
    actual = _interpreter_discovery.replace_shebang('/usr/bin/python', {}, templar, interpreter_override={
        'python': '/usr/local/bin/python',
    })
    assert actual == '/usr/local/bin/python'
