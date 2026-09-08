"""Secret masking registry.

``SecretMasker`` is the public side: it registers secret values (length rules, trimming, de-duplication,
new-secret tracking, locking) and redacts every occurrence of them from strings. Matching is delegated to
a matcher object with a small interface (``add``, ``spans``) so the algorithm can be swapped,
for example for a compiled extension, without touching the registry semantics:

* every occurrence of every secret is found (overlapping included) and the union of the spans is
  redacted, with overlapping and adjacent spans merged into one placeholder, so no character that
  belongs to a secret occurrence is left visible and the number of secrets is not revealed
* secrets of 4-6 characters are masked only at a word boundary (both neighbours non-alphanumeric or
  the string edge); if the longest secret at a position is rejected a shorter one there may still apply

``_Fixed4Matcher`` is a custom string matcher/registry implementation tuned for Ansible.

* the matcher stores only the first ``_ANCHOR_LEN`` characters of each secret in a dictionary and uses
  a sliding window scan of the data it is attempting to mask; a hit is verified against the full secrets
  registered under that anchor with slice lookups.
* before the full comparison, ``_PROBE_LEN`` characters from the middle of the candidate are checked
  against teh middles of the registered secrets of that length, so a near-miss costs the probe rather
  than the full length whatever the secret looks like (shared prefixes and suffixes such as PEM headers
  do not help an attacker trying to overload the matching with long secrets that are not present)
"""

from __future__ import annotations

import gc as _gc
import json.encoder as _json_encoder
import typing as _t

from ansible.module_utils._internal._concurrent._fork_safe_lock import ForkSafeLock

# shared frozenset optimization for no secrets found
_emptyfrozenset: frozenset[str] = frozenset()


# If any of these are changed we need to ensure that Ansible.Secrets.cs is updated to match.
_MINIMUM_SECRET_LENGTH = 4  # below this, not registered at all
_MAXIMUM_SHORT_SECRET_LENGTH = 6  # above this, mask unconditionally
_MAXIMUM_SECRET_LENGTH = 65536  # trims to this length as a cap for registration and matching
_STRIP_CHARS = " \t\r\n"  # stripped from both ends before registration

# _AnchoredMatcher tuning; neither affects results
_ANCHOR_LEN = _MINIMUM_SECRET_LENGTH  # Keeping these two the same means we only need 1 sliding window scan
_PROBE_LEN = 8  # chars compared from the middle of a candidate before the full comparison


def _sits_at_boundary(value: str, start: int, end: int) -> bool:
    """Return True if the candidate at value[start:end] is at a word boundary."""
    at_beginning = start == 0
    at_end = end == len(value)
    boundary_left = at_beginning or not value[start - 1].isalnum()
    boundary_right = at_end or not value[end].isalnum()
    return boundary_left and boundary_right


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort spans and merge any that overlap or touch into one, so one placeholder covers them all."""
    if len(spans) < 2:
        return spans
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return merged


def _probe_span(length: int) -> tuple[int, int]:
    """(offset, size) of the probe window inside a secret of ``length``: its middle, where structured
    secrets keep their entropy, clipped to the secret for secrets shorter than the probe."""
    size = min(_PROBE_LEN, length)
    return max(0, length // 2 - size // 2), size


class AnsibleSecretMaskError(Exception):
    """Raised when secret masking fails.

    Deliberately carries no reference to the value being masked so that a masking
    failure can never leak the unmasked value through the exception itself.
    """


class _Fixed4Matcher:
    """Matcher using fixed 4-character anchors for simplicity and speed.

    Every secret is indexed by its first 4 characters. At each position in the
    text, we do exactly one hash lookup with the 4-char window, then verify
    any candidates found.
    """

    def __init__(self) -> None:
        # Map from 4-char anchor to list of (length, full_secret, probe) tuples
        # Each list is sorted by length (longest first) for leftmost-longest matching
        self._anchors: dict[str, list[tuple[int, str, str]]] = {}

        # For detection mode
        self._by_length: dict[int, set[str]] = {}
        self._probes: dict[int, set[str]] = {}

    def add(self, word: str) -> None:
        """Add a word to the matcher."""
        word_len = len(word)
        anchor = word[:_ANCHOR_LEN]

        offset, size = _probe_span(word_len)
        probe = word[offset : offset + size]

        # Store for detection mode
        self._by_length.setdefault(word_len, set()).add(word)
        self._probes.setdefault(word_len, set()).add(probe)

        if anchor not in self._anchors:
            self._anchors[anchor] = []

        # Check if already present
        for existing_len, existing_word, _probe in self._anchors[anchor]:
            if existing_len == word_len and existing_word == word:
                return

        # Add and re-sort by length (longest first)
        self._anchors[anchor].append((word_len, word, probe))
        self._anchors[anchor].sort(key=lambda x: x[0], reverse=True)

    def spans(self, value: str, boundary_check: bool) -> list[tuple[int, int]]:
        """Every verified word occurrence in ``value`` as (start, end), unsorted, overlapping allowed.

        With ``boundary_check`` the longest valid word at each start is reported (it covers any shorter
        one) and short words are subject to the boundary rule; without it every word is reported.
        """
        value_len = len(value)
        spans: list[tuple[int, int]] = []
        anchors = self._anchors

        found: set[tuple[int, int]] = set()
        for i in range(value_len - _ANCHOR_LEN + 1):
            anchor = value[i : i + _ANCHOR_LEN]  # sliding window
            candidates = anchors.get(anchor)
            if not candidates:
                continue

            if boundary_check:
                end = self._verify_longest(value, i, candidates, boundary_check)
                if end > 0:
                    spans.append((i, end))
            else:
                self._detect_all(value, i, candidates, found)

        return spans if boundary_check else list(found)

    def _verify_longest(self, value: str, start: int, candidates: list[tuple[int, str, str]], boundary_check: bool) -> int:
        """Return end index of the longest verified secret at start, or -1."""
        value_len = len(value)

        for length, word, probe in candidates:
            end = start + length
            if end > value_len:
                continue

            # Probe check
            offset, size = _probe_span(length)
            if value[start + offset : start + offset + size] != probe:
                continue

            # Full comparison
            if value[start:end] == word:
                # Boundary check for short secrets
                if boundary_check and length <= _MAXIMUM_SHORT_SECRET_LENGTH:
                    if not _sits_at_boundary(value, start, end):
                        continue
                return end

        return -1

    def _detect_all(self, value: str, start: int, candidates: list[tuple[int, str, str]], found: set[tuple[int, int]]) -> None:
        """Detect all secrets starting at start."""
        value_len = len(value)

        for length, word, probe in candidates:
            end = start + length
            if end > value_len:
                continue

            # Probe check
            offset, size = _probe_span(length)
            if value[start + offset : start + offset + size] != probe:
                continue

            # Full comparison
            if value[start:end] == word:
                found.add((start, end))


class SecretMasker:
    # Instantiating this permanently registers os.register_at_fork handlers (via
    # ForkSafeLock) that cannot be unregistered, so this is intended to be used as a
    # long-lived singleton (see the shared _secret_masker instance below).
    def __init__(self) -> None:
        self._new_secret_trackers: set[NewSecretTracker] = set()
        self._lock = ForkSafeLock()
        self._matcher = _Fixed4Matcher()
        self._secrets: set[str] = set()  # the registered secrets, as given (stripped and trimmed)
        self._forms: set[str] = set()  # every string the matcher knows: secrets and their derived forms
        # JSON-encoded form -> the secret it is the encoding of, for forms that differ from the secret
        self._json_forms: dict[str, str] = {}

    def track_new_secrets(self) -> NewSecretTracker:
        with self._lock:
            self._new_secret_trackers.add(tracker := NewSecretTracker(self))
        return tracker

    def register_secret_text(self, secret: str, /) -> str:
        """Register a secret for masking, returning the value unchanged."""
        self.register_secret_texts((secret,))

        return secret

    def register_secret_texts(self, secrets: _t.Iterable[str], /) -> None:
        """Register every secret in ``secrets`` for masking."""
        with self._lock:
            new = set()
            for secret in secrets:
                # Surrounding whitespace is not part of the secret: values often
                # arrive with a trailing newline (vaulted files, stdin) but are used
                # stripped. The stripped value matches every occurrence the original
                # would have, plus the stripped uses.
                # FUTURE: Look into string normalisation \u00e9 vs \u0065\u0301, etc. to avoid
                # leaking secrets that are equivalent but not identical. Would require logic
                # on the masking side either to normalise and mutate the input or to register
                # multiple normalised forms of each secret.
                trimmed = secret.strip(_STRIP_CHARS)[:_MAXIMUM_SECRET_LENGTH]

                if len(trimmed) < _MINIMUM_SECRET_LENGTH:
                    continue

                if self._add(trimmed):
                    new.add(trimmed)

            for tracker in self._new_secret_trackers:
                tracker._new_secrets.update(new)

    def mask_string(self, value: str, /, *, mask_placeholder: str = "$REDACTED$") -> str:
        """Masks any registered secret in the provided string with the provided placeholder. Returns the masked string."""
        if not value:
            return value

        try:
            spans = []
            with self._lock:
                if self._forms:
                    spans = self._matcher.spans(value, boundary_check=True)

            spans = _merge_spans(spans)
            if not spans:
                return value

            parts = []
            value_pos = 0

            for start, end in spans:
                parts.append(value[value_pos:start])
                parts.append(mask_placeholder)
                value_pos = end

            parts.append(value[value_pos:])

            return "".join(parts)
        except Exception:
            # We deliberately do not include the value or original exception
            # to avoid leaking secrets through the exception.
            raise AnsibleSecretMaskError("secret masking failed") from None

    def secrets_in_json(self, value: str) -> frozenset[str]:
        """Return the registered secrets present in a JSON document, as their literal values."""
        if not value:
            return _emptyfrozenset

        spans = None
        with self._lock:
            if self._forms:
                spans = self._matcher.spans(value, boundary_check=False)

        if not spans:
            return _emptyfrozenset

        # Every matched form is either a registered secret or a JSON-encoded form derived from one.
        # If it's a derived form, return the secret it was derived from. The result is a set of the
        # literal secrets the JSON represents and not how they appear in the JSON. The receiver of
        # the secrets can register them which builds the derived forms again internally.
        json_forms = self._json_forms
        return frozenset(json_forms.get(form, form) for form in (value[start:end] for start, end in spans))

    def _add(self, secret: str) -> bool:
        """Register ``secret`` (already length-checked and trimmed) and every form it can appear in.

        Returns False if ``secret`` was already registered. A form shared with another secret (a
        secret that is itself the JSON-escaped form of another) is only handed to the matcher once.
        """
        if secret in self._secrets:
            return False

        self._secrets.add(secret)

        # Majority of the output in Ansible is JSON and we use it when transferring module data to
        # the target. As JSON can escape characters we will also register the JSON encoded form of
        # the secret (without quotes). Both UTF-8 and non-ASCII escaped forms are registered as
        # the legacy module serialization profile does ensure_ascii=True while modern does not. If
        # the secret does not contain any special characters nothing extra is added to the registry.
        # FUTURE: measure the cost of deriving both forms on large registries.
        json_ascii_form = _json_encoder.encode_basestring_ascii(secret)[1:-1]
        secret_forms = {secret, json_ascii_form}
        if secret != json_ascii_form:
            # If the ASCII encoded form differs then we need to check the UTF-8 encoded form as well.
            secret_forms.add(_json_encoder.encode_basestring(secret)[1:-1])

        for form in secret_forms:
            if form != secret:
                self._json_forms[form] = secret

            if form in self._forms:
                continue
            self._forms.add(form)
            self._matcher.add(form)

        return True


class NewSecretTracker:
    """Used to track newly registered secrets once the tracker was registered."""

    def __init__(self, masker: SecretMasker):
        self._new_secrets: set[str] = set()
        self._masker = masker

    def unregister(self):
        with self._masker._lock:
            self._masker._new_secret_trackers.discard(self)

    def flush(self) -> frozenset[str]:
        with self._masker._lock:
            if not self._new_secrets:
                return _emptyfrozenset
            flushed = frozenset(self._new_secrets)
            self._new_secrets = set()
        return flushed


_secret_masker = SecretMasker()  # default shared instance
