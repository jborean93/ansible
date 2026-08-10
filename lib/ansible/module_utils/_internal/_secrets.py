from __future__ import annotations

import io

from ansible.module_utils._internal._concurrent._fork_safe_lock import ForkSafeLock

# SDFIX: abstraction/detection of vendored/pure-Python vs C-accelerated, and/or controller vs module
# SDFIX: what about non-Python modules?
import ahocorasick
#try:
#    import ahocorasick
#except ImportError:
#from ansible.module_utils._internal import _ahocorasick as ahocorasick


class SecretMasker:
    _emptyfrozenset: frozenset[str] = frozenset()  # shared frozenset optimization for no secrets found

    def __init__(self):
        self._store = ahocorasick.Automaton()
        self._new_secret_trackers: set[NewSecretTracker] = set()
        self._lock = ForkSafeLock()

    def track_new_secrets(self) -> NewSecretTracker:
        self._new_secret_trackers.add(st := NewSecretTracker(self))
        return st

    def register_secret_text(self, secret: str) -> str:
        # FIXME: thread safety
        # FIXME: minimum length exclusion
        # FIXME: is key obfuscation possible/worthwhile?

        with self._lock:
            if self._store.exists(secret):
                return secret

            # SDFIX: storing the raw value in the data could simplify consumption
            self._store.add_word(secret, len(secret))

            for tracker in self._new_secret_trackers:
                tracker._new_secrets.add(secret)

            return secret

    # FIXME: multi-register operation?

    def mask_string(self, value: str, *, mask_placeholder: str = '<secret>') -> str:
        with self._lock:
            if self._store.kind == ahocorasick.EMPTY:
                # noop - no secrets registered
                return value

            if built := (self._store.kind != ahocorasick.AHOCORASICK):
                self._store.make_automaton()

            # iter_long masks the longest
            found = [(end - length + 1, end + 1) for end, length in self._store.iter_long(value)]

            if not found:
                return value

            # FIXME: gap buffer, preallocation, something
            value_pos = 0
            out_buf = io.StringIO()

            for start, end in found:
                out_buf.write(value[value_pos:start])
                out_buf.write(mask_placeholder)
                value_pos = end

            out_buf.write(value[value_pos:])

            return out_buf.getvalue()
            #return "REBUILT: " if built else "" + out_buf.getvalue()

    def secrets_in(self, value: object) -> frozenset[str]:
        with self._lock:
            # SDFIX: optimize for the most likely case of "no secrets"- sniff iterator for >0 value before creating an empty frozenset
            if not value:
                return self._emptyfrozenset

            if self._store.kind == ahocorasick.EMPTY:
                return self._emptyfrozenset

            if self._store.kind != ahocorasick.AHOCORASICK:
                self._store.make_automaton()

            try:
                return frozenset(value[e - l + 1:e + 1] for e, l in self._store.iter_long(value))
            except TypeError:
                return self._emptyfrozenset


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


_secret_masker = SecretMasker()  # default shared instance
