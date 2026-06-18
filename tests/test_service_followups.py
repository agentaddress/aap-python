"""Tests for the service_followups module — grant store + envelope builders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aap.keys import generate_keypair
from aap.messages import build_chat_envelope
from aap.payloads import ServiceFollowup, ServiceFollowupGrant

from aap.service_followups import (
    FollowupGrantStore,
    build_followup_envelope,
    build_followup_grant_envelope,
    parse_iso_duration,
)


# -- ISO 8601 duration parser ----------------------------------------------


def test_parse_iso_duration_months():
    assert parse_iso_duration("P6M") == timedelta(days=180)


def test_parse_iso_duration_years():
    assert parse_iso_duration("P1Y") == timedelta(days=365)


def test_parse_iso_duration_mixed():
    # 1 month + 2 days = 32 days
    assert parse_iso_duration("P1M2D") == timedelta(days=32)


def test_parse_iso_duration_time_component():
    assert parse_iso_duration("PT2H30M") == timedelta(hours=2, minutes=30)


def test_parse_iso_duration_rejects_garbage():
    with pytest.raises(ValueError):
        parse_iso_duration("six-months")


def test_parse_iso_duration_rejects_bare_p():
    with pytest.raises(ValueError):
        parse_iso_duration("P")


# -- envelope builders ------------------------------------------------------


def test_build_grant_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_followup_grant_envelope(
        seed=seed,
        sender_address="john^example.com",
        service_id="routine-cleaning",
        cadence_iso="P6M",
        outreach_window_before="P1M",
        valid_until="2027-05-26T00:00:00Z",
    )
    assert env.payload_type == ServiceFollowupGrant.PAYLOAD_TYPE
    assert env.payload["cadence_iso"] == "P6M"
    assert env.verify(pub)


def test_build_followup_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_followup_envelope(
        seed=seed,
        sender_address="reception^drsmith.example",
        service_id="routine-cleaning",
        grant_nonce="grant-1",
        message="Time for your next cleaning!",
        suggested_slots=["2026-11-10T09:00:00Z"],
    )
    assert env.payload_type == ServiceFollowup.PAYLOAD_TYPE
    assert env.payload["grant_nonce"] == "grant-1"
    assert env.verify(pub)


# -- FollowupGrantStore -----------------------------------------------------


def _make_grant_envelope(
    *,
    sender: str = "john^example.com",
    service_id: str = "routine-cleaning",
    cadence: str = "P6M",
    window: str = "P1M",
    valid_until: str = "2027-05-26T00:00:00Z",
    nonce: str | None = None,
    iat: str | None = None,
):
    seed, public_key = generate_keypair()
    envelope = build_followup_grant_envelope(
        seed=seed,
        sender_address=sender,
        service_id=service_id,
        cadence_iso=cadence,
        outreach_window_before=window,
        valid_until=valid_until,
        nonce=nonce,
        iat=iat,
    )
    return envelope, public_key


def test_record_issued_and_find(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, public_key = _make_grant_envelope(sender="reception^drsmith.example")
    row = store.record_issued(
        business_address="reception^drsmith.example",
        grant_envelope_json=env.to_json(),
        business_public_key=public_key,
    )
    assert row.direction == "issued"
    assert row.service_id == "routine-cleaning"

    reloaded = FollowupGrantStore.load(tmp_path)
    found = reloaded.find_issued(
        business_address="reception^drsmith.example",
        service_id="routine-cleaning",
    )
    assert found is not None
    assert found.cadence_iso == "P6M"


def test_record_received_and_find(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, public_key = _make_grant_envelope(sender="john^example.com")
    store.record_received(
        customer_address="john^example.com",
        grant_envelope_json=env.to_json(),
        customer_public_key=public_key,
    )
    found = store.find_received(
        customer_address="john^example.com",
        service_id="routine-cleaning",
    )
    assert found is not None


def test_record_rejects_non_grant_envelope(tmp_path):
    """A regular chat envelope is NOT a grant — store rejects it."""
    seed, public_key = generate_keypair()
    chat_env = build_chat_envelope(
        seed=seed,
        sender_address="john^example.com",
        text="hi",
        iat="2026-05-26T12:00:00Z",
    )
    store = FollowupGrantStore.load(tmp_path)
    with pytest.raises(ValueError, match="expected .* envelope"):
        store.record_issued(
            business_address="reception^drsmith.example",
            grant_envelope_json=chat_env.to_json(),
            business_public_key=public_key,
        )


def test_issued_and_received_for_same_peer_coexist(tmp_path):
    """A user can simultaneously have issued a grant to a business AND
    received one from that same address (if they're somehow both customer
    and business to each other). Storage keys on (direction, counterparty,
    service_id) to allow this."""
    store = FollowupGrantStore.load(tmp_path)
    issued_env, issued_public_key = _make_grant_envelope(
        sender="peer^example.com",
        nonce="issued-grant",
    )
    received_env, received_public_key = _make_grant_envelope(
        sender="peer^example.com",
        nonce="received-grant",
    )
    store.record_issued(
        business_address="peer^example.com",
        grant_envelope_json=issued_env.to_json(),
        business_public_key=issued_public_key,
    )
    store.record_received(
        customer_address="peer^example.com",
        grant_envelope_json=received_env.to_json(),
        customer_public_key=received_public_key,
    )
    assert store.find_issued(
        business_address="peer^example.com", service_id="routine-cleaning"
    ) is not None
    assert store.find_received(
        customer_address="peer^example.com", service_id="routine-cleaning"
    ) is not None


def test_re_recording_same_service_replaces(tmp_path):
    """If a customer re-grants the same service, the new grant replaces the old."""
    store = FollowupGrantStore.load(tmp_path)
    env_a, public_key_a = _make_grant_envelope(
        sender="reception^drsmith.example",
        iat=(datetime.now(timezone.utc) - timedelta(days=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    env_b, public_key_b = _make_grant_envelope(
        sender="reception^drsmith.example",
        iat=(datetime.now(timezone.utc) - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    store.record_issued(
        business_address="reception^drsmith.example",
        grant_envelope_json=env_a.to_json(),
        business_public_key=public_key_a,
    )
    store.record_issued(
        business_address="reception^drsmith.example",
        grant_envelope_json=env_b.to_json(),
        business_public_key=public_key_b,
    )
    rows = [
        r for r in store.rows
        if r.counterparty == "reception^drsmith.example"
        and r.service_id == "routine-cleaning"
    ]
    assert len(rows) == 1
    assert rows[0].issued_at == env_b.iat


def test_stamp_used_records_timestamp(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, public_key = _make_grant_envelope(sender="reception^drsmith.example")
    row = store.record_issued(
        business_address="reception^drsmith.example",
        grant_envelope_json=env.to_json(),
        business_public_key=public_key,
    )
    assert row.last_used_at is None
    assert store.stamp_used(row.nonce)
    updated = store.find_issued_by_nonce(row.nonce)
    assert updated.last_used_at is not None


def test_revoke_removes_row(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, public_key = _make_grant_envelope(sender="reception^drsmith.example")
    store.record_issued(
        business_address="reception^drsmith.example",
        grant_envelope_json=env.to_json(),
        business_public_key=public_key,
    )
    assert store.revoke(
        counterparty="reception^drsmith.example",
        service_id="routine-cleaning",
        direction="issued",
    )
    assert store.find_issued(
        business_address="reception^drsmith.example",
        service_id="routine-cleaning",
    ) is None


# -- outreach window logic --------------------------------------------------


def test_outreach_window_blocked_too_early(tmp_path):
    """A 6mo cadence with a 1mo outreach window means the business can only
    reach out between 5mo and 6mo+ after the last use. Anything earlier
    fails the window check."""
    issued_at = datetime.now(timezone.utc)
    env, public_key = _make_grant_envelope(
        sender="john^example.com",
        iat=issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    store = FollowupGrantStore.load(tmp_path)
    row = store.record_received(
        customer_address="john^example.com",
        grant_envelope_json=env.to_json(),
        customer_public_key=public_key,
    )
    # 30 days in, 6mo cadence, 1mo window → far too early
    assert not row.is_within_outreach_window(now=issued_at + timedelta(days=30))


def test_outreach_window_allowed_inside_window(tmp_path):
    """A grant issued 5+ months ago is now inside the outreach window."""
    issued_at = datetime.now(timezone.utc)
    env, public_key = _make_grant_envelope(
        sender="john^example.com",
        iat=issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    store = FollowupGrantStore.load(tmp_path)
    row = store.record_received(
        customer_address="john^example.com",
        grant_envelope_json=env.to_json(),
        customer_public_key=public_key,
    )
    assert row.is_within_outreach_window(now=issued_at + timedelta(days=160))


def test_grant_lifetime_expiry(tmp_path):
    """A grant past its valid_until is no longer in lifetime."""
    env, public_key = _make_grant_envelope(
        sender="john^example.com",
        valid_until="2020-01-01T00:00:00Z",
    )
    store = FollowupGrantStore.load(tmp_path)
    row = store.record_received(
        customer_address="john^example.com",
        grant_envelope_json=env.to_json(),
        customer_public_key=public_key,
    )
    assert not row.is_within_lifetime()


def test_record_rejects_bad_grant_signature(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, _ = _make_grant_envelope(sender="john^example.com")
    _, wrong_public_key = generate_keypair()

    with pytest.raises(ValueError, match="signature did not verify"):
        store.record_received(
            customer_address="john^example.com",
            grant_envelope_json=env.to_json(),
            customer_public_key=wrong_public_key,
        )


def test_record_rejects_grant_issuer_mismatch(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env, public_key = _make_grant_envelope(sender="mallory^example.com")

    with pytest.raises(ValueError, match="does not match"):
        store.record_received(
            customer_address="john^example.com",
            grant_envelope_json=env.to_json(),
            customer_public_key=public_key,
        )


def test_record_rejects_stale_grant(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    stale_iat = (datetime.now(timezone.utc) - timedelta(days=31)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    env, public_key = _make_grant_envelope(sender="john^example.com", iat=stale_iat)

    with pytest.raises(ValueError, match="too old"):
        store.record_received(
            customer_address="john^example.com",
            grant_envelope_json=env.to_json(),
            customer_public_key=public_key,
        )


def test_record_rejects_duplicate_grant_nonce(tmp_path):
    store = FollowupGrantStore.load(tmp_path)
    env_a, public_key_a = _make_grant_envelope(
        sender="john^example.com",
        nonce="same-grant",
    )
    env_b, public_key_b = _make_grant_envelope(
        sender="jane^example.com",
        nonce="same-grant",
    )
    store.record_received(
        customer_address="john^example.com",
        grant_envelope_json=env_a.to_json(),
        customer_public_key=public_key_a,
    )

    with pytest.raises(ValueError, match="replay"):
        store.record_received(
            customer_address="jane^example.com",
            grant_envelope_json=env_b.to_json(),
            customer_public_key=public_key_b,
        )
