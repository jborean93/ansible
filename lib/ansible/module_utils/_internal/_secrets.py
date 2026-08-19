from __future__ import annotations

import re
import typing as _t

from ansible.module_utils._internal._concurrent._fork_safe_lock import ForkSafeLock

try:
    import ahocorasick
except ImportError:
    from ansible.module_utils._internal import _ahocorasick as ahocorasick


_emptyfrozenset: frozenset[str] = frozenset()  # shared frozenset optimization for no secrets found

_MINIMUM_SECRET_LENGTH = 4
_MAXIMUM_SHORT_SECRET_LENGTH = 6
_WORD_BOUNDARY_RE = re.compile(r"\W")
# FIXME: Maybe this could be configurable?  My intuition is that someone using short
# secrets either has a specialized use case and might want to configure, or is doing
# something stupid and should be forced to go the extra mile to make ansible behave
# how they want.


def _is_short_secret(length: int) -> bool:
    """A short secret is masked only when it sits at a word boundary. Its length falls in
    [_MINIMUM_SECRET_LENGTH, _MAXIMUM_SHORT_SECRET_LENGTH); longer secrets are always masked.
    """
    return _MINIMUM_SECRET_LENGTH <= length < _MAXIMUM_SHORT_SECRET_LENGTH


def _sits_at_boundary(value: str, start: int, end: int):
    at_beginning = start == 0
    at_end = end == len(value)
    boundary_left = at_beginning or _WORD_BOUNDARY_RE.match(value[start - 1]) is not None
    boundary_right = at_end or _WORD_BOUNDARY_RE.match(value[end]) is not None
    return boundary_left and boundary_right


class SecretMasker:
    def __init__(self):
        self._store = ahocorasick.Automaton()
        self._new_secret_trackers: set[NewSecretTracker] = set()
        self._lock = ForkSafeLock()

    def track_new_secrets(self) -> NewSecretTracker:
        self._new_secret_trackers.add(st := NewSecretTracker(self))
        return st

    def register_secret_text(self, secret: str) -> str:
        if len(secret) < _MINIMUM_SECRET_LENGTH:
            return secret

        with self._lock:
            if self._store.exists(secret):
                return secret

            # SDFIX: storing the raw value in the data could simplify consumption
            self._store.add_word(secret, len(secret))

            for tracker in self._new_secret_trackers:
                tracker._new_secrets.add(secret)

            return secret

    def register_secret_texts(self, secrets: _t.Iterable[str]) -> None:
        with self._lock:
            new = set()

            for secret in secrets:
                # SDFIX: silently skip too-short secrets for now; source the threshold from config.
                if len(secret) < _MINIMUM_SECRET_LENGTH or self._store.exists(secret):
                    continue
                self._store.add_word(secret, len(secret))
                new.add(secret)

            for tracker in self._new_secret_trackers:
                tracker._new_secrets.update(new)


    def _raw_spans(self, value: object) -> list[tuple[int, int]]:
        """(start, end) positions of every registered secret found in value."""
        with self._lock:
            if self._store.kind == ahocorasick.EMPTY:
                # noop - no secrets registered
                return []

            if self._store.kind != ahocorasick.AHOCORASICK:
                self._store.make_automaton()

            try:
                return [(end - length + 1, end + 1) for end, length in self._store.iter_long(value)]
            except TypeError:
                return []

    def _effective_spans(self, value: str) -> list[tuple[int, int]]:
        """Spans to redact: long secrets always, short secrets only when at a word boundary.
        """
        return [
            (start, end) for start, end in self._raw_spans(value)
            if not _is_short_secret(end - start) or _sits_at_boundary(value, start, end)
        ]

    def mask_string(self, value: str, *, mask_placeholder: str = '<secret>') -> str:
        if not value:
            return value

        spans = self._effective_spans(value)

        if not spans:
            return value

        parts = []
        value_pos = 0

        for start, end in spans:
            parts.append(value[value_pos:start])
            parts.append(mask_placeholder)
            value_pos = end

        parts.append(value[value_pos:])

        return ''.join(parts)

    def secrets_in(self, value: object) -> frozenset[str]:
        # Detection (not redaction): report every registered secret present, including short
        # ones not at a word boundary. This feeds secret propagation to child processes, which
        # must learn about a secret to mask it even if it only appears at a boundary there.
        if not value:
            return _emptyfrozenset

        spans = self._raw_spans(value)

        if not spans:
            return _emptyfrozenset

        return frozenset(value[start:end] for start, end in spans)


# usage contexts:
# primary controller (primary, no delta tracking)
# controller forked workers (init is free, track delta with bulk return and/or parent update on callback dispatch?)
# controller spawned workers (init full state ser/deser or scanned-from-args, track delta with bulk return and/or parent update on callback dispatch)
# ansible-connection stub (special case of controller spawned worker, scanned-from-args, no delta needed?)
# Python module process (init scanned-from-args, track delta with bulk return (until we support streaming responses, then opportunistic control plane updates)
# Windows/other module process (init scanned-from-args, impl TBD)


class NewSecretTracker:
    def __init__(self, masker: SecretMasker):
        self._new_secrets: set[str] = set()
        self._masker = masker

    def unregister(self):
        if self in self._masker._new_secret_trackers:
            self._masker._new_secret_trackers.remove(self)

    def flush(self) -> frozenset[str]:
        if not self._new_secrets:
            return _emptyfrozenset
        flushed = frozenset(self._new_secrets)
        self._new_secrets = set()
        return flushed


_secret_masker = SecretMasker()  # default shared instance
