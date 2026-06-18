"""Freshness, signature, and replay helpers for signed AAP envelopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aap.envelope import Envelope, EnvelopeError
from aap.storage import write_json_private

DEFAULT_ENVELOPE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
DEFAULT_FUTURE_SKEW_SECONDS = 5 * 60


class EnvelopePolicyError(ValueError):
    """Raised when an envelope fails freshness, signature, or replay policy."""


def parse_rfc3339(value: str) -> datetime:
    """Parse the RFC 3339 subset emitted by AAP helpers."""
    if not isinstance(value, str) or not value:
        raise EnvelopePolicyError("timestamp must be a non-empty string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise EnvelopePolicyError(f"invalid timestamp {value!r}") from e
    if parsed.tzinfo is None:
        raise EnvelopePolicyError(f"timestamp {value!r} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_envelope_iat(
    envelope: Envelope,
    *,
    now: datetime | None = None,
    max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    future_skew_seconds: int = DEFAULT_FUTURE_SKEW_SECONDS,
) -> None:
    """Reject envelopes issued too far in the future or past."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued_at = parse_rfc3339(envelope.iat)

    if issued_at > now + timedelta(seconds=future_skew_seconds):
        raise EnvelopePolicyError("envelope iat is too far in the future")
    if max_age_seconds is not None and issued_at < now - timedelta(
        seconds=max_age_seconds
    ):
        raise EnvelopePolicyError("envelope iat is too old")


def verify_envelope(
    envelope: Envelope,
    public_key: bytes,
    *,
    now: datetime | None = None,
    max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    future_skew_seconds: int = DEFAULT_FUTURE_SKEW_SECONDS,
    replay_cache: "EnvelopeReplayCache | None" = None,
) -> None:
    """Verify signature, timestamp freshness, and optional replay cache."""
    try:
        signature_ok = envelope.verify(public_key)
    except EnvelopeError as e:
        raise EnvelopePolicyError(f"envelope could not be verified: {e}") from e
    if not signature_ok:
        raise EnvelopePolicyError("envelope signature did not verify")

    validate_envelope_iat(
        envelope,
        now=now,
        max_age_seconds=max_age_seconds,
        future_skew_seconds=future_skew_seconds,
    )
    if replay_cache is not None:
        replay_cache.check_and_store(envelope_replay_key(envelope), now=now)


def envelope_replay_key(envelope: Envelope) -> str:
    if not envelope.sig:
        raise EnvelopePolicyError("unsigned envelope has no replay key")
    return f"{envelope.iss}:{envelope.sig}"


@dataclass
class EnvelopeReplayCache:
    """Simple TTL replay cache, optionally backed by a JSON file."""

    ttl_seconds: int = DEFAULT_ENVELOPE_MAX_AGE_SECONDS
    path: Path | None = None

    def __post_init__(self) -> None:
        self._seen: dict[str, str] = {}
        if self.path is not None and self.path.exists():
            try:
                data = json.loads(self.path.read_text())
            except Exception:
                data = {}
            if isinstance(data, dict):
                self._seen = {
                    str(key): str(value)
                    for key, value in data.get("seen", {}).items()
                    if isinstance(value, str)
                }

    def check_and_store(self, key: str, *, now: datetime | None = None) -> None:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self._prune(now)
        if key in self._seen:
            raise EnvelopePolicyError("envelope replay detected")
        self._seen[key] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._save()

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.ttl_seconds)
        self._seen = {
            key: value
            for key, value in self._seen.items()
            if _parse_seen_at(value) > cutoff
        }

    def _save(self) -> None:
        if self.path is None:
            return
        write_json_private(self.path, {"seen": self._seen})


def _parse_seen_at(value: str) -> datetime:
    try:
        return parse_rfc3339(value)
    except EnvelopePolicyError:
        return datetime.min.replace(tzinfo=timezone.utc)
