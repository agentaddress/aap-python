"""Tests for signed-envelope freshness and replay policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aap.envelope import Envelope
from aap.envelope_policy import (
    EnvelopePolicyError,
    EnvelopeReplayCache,
    validate_envelope_iat,
    verify_envelope,
)
from aap.keys import generate_keypair


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _envelope(iat: str) -> Envelope:
    return Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="did:web:example.com#agent",
        iat=iat,
    )


def test_validate_envelope_iat_accepts_fresh_timestamp():
    now = datetime.now(timezone.utc)
    validate_envelope_iat(_envelope(_rfc3339(now)), now=now)


def test_validate_envelope_iat_rejects_stale_timestamp():
    now = datetime.now(timezone.utc)
    with pytest.raises(EnvelopePolicyError, match="too old"):
        validate_envelope_iat(
            _envelope(_rfc3339(now - timedelta(days=31))),
            now=now,
        )


def test_validate_envelope_iat_rejects_far_future_timestamp():
    now = datetime.now(timezone.utc)
    with pytest.raises(EnvelopePolicyError, match="future"):
        validate_envelope_iat(
            _envelope(_rfc3339(now + timedelta(minutes=10))),
            now=now,
        )


def test_verify_envelope_rejects_replay():
    now = datetime.now(timezone.utc)
    private, public = generate_keypair()
    envelope = _envelope(_rfc3339(now)).sign(private)
    cache = EnvelopeReplayCache()

    verify_envelope(envelope, public, now=now, replay_cache=cache)
    with pytest.raises(EnvelopePolicyError, match="replay"):
        verify_envelope(envelope, public, now=now, replay_cache=cache)
