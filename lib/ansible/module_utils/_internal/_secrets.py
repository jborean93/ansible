from __future__ import annotations

import typing as _t

from ansible.module_utils._internal._concurrent._fork_safe_lock import ForkSafeLock

try:
    import ahocorasick
except ImportError:
    from ansible.module_utils._internal import _ahocorasick as ahocorasick


_emptyfrozenset: frozenset[str] = frozenset()  # shared frozenset optimization for no secrets found

_MINIMUM_SECRET_LENGTH = 4


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

    def mask_string(self, value: str, *, mask_placeholder: str = '<secret>') -> str:
        if not value:
            return value

        with self._lock:
            if self._store.kind == ahocorasick.EMPTY:
                # noop - no secrets registered
                return value

            if self._store.kind != ahocorasick.AHOCORASICK:
                self._store.make_automaton()

            # iter_long masks the longest
            found = [(end - length + 1, end + 1) for end, length in self._store.iter_long(value)]

        if not found:
            return value

        parts = []
        value_pos = 0

        for start, end in found:
            parts.append(value[value_pos:start])
            parts.append(mask_placeholder)
            value_pos = end

        parts.append(value[value_pos:])

        return ''.join(parts)

    def secrets_in(self, value: object) -> frozenset[str]:
        if not value:
            return _emptyfrozenset

        with self._lock:
            if self._store.kind == ahocorasick.EMPTY:
                return _emptyfrozenset

            if self._store.kind != ahocorasick.AHOCORASICK:
                self._store.make_automaton()

            try:
                found = list(self._store.iter_long(value))
            except TypeError:
                return _emptyfrozenset

        if not found:
            return _emptyfrozenset

        return frozenset(value[e - l + 1 : e + 1] for e, l in found)


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
