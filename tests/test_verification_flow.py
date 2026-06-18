"""Tests for PendingVerifications store and verifier_relay_address helper."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


from aap.stores.verification_flow import PendingVerificationRow, PendingVerifications
from aap.verifiers import verifier_relay_address


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _row(
    otp_id: str = "otp-1",
    identifier_value: str = "alice@example.com",
) -> PendingVerificationRow:
    return PendingVerificationRow(
        otp_id=otp_id,
        identity_type="email",
        identifier_value=identifier_value,
        verifier_domain="verify.example.com",
        verification_endpoint="https://verify.example.com/start",
        expires_at="2026-12-31T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# verifier_relay_address
# ---------------------------------------------------------------------------


def test_verifier_relay_address_format() -> None:
    assert verifier_relay_address("verify.example.com") == "verifier^verify.example.com"


def test_verifier_relay_address_uses_supplied_domain() -> None:
    assert verifier_relay_address("agentaddress.org") == "verifier^agentaddress.org"


# ---------------------------------------------------------------------------
# Add + find
# ---------------------------------------------------------------------------


def test_add_and_find_by_otp_id(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    row = _row("otp-abc")
    store.add(row)
    assert store.get("otp-abc") == row


def test_find_returns_none_for_unknown(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    assert store.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


def test_remove_returns_true_when_present(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    store.add(_row("otp-1"))
    assert store.remove("otp-1") is True
    assert store.get("otp-1") is None


def test_remove_returns_false_for_unknown(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    assert store.remove("no-such-id") is False


# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------


def test_persistence_across_instances(tmp_path: Path) -> None:
    row = _row("otp-persist")
    store1 = PendingVerifications(base_dir=tmp_path)
    store1.add(row)

    store2 = PendingVerifications.load(base_dir=tmp_path)
    assert store2.get("otp-persist") == row


def test_remove_persists_across_instances(tmp_path: Path) -> None:
    store1 = PendingVerifications(base_dir=tmp_path)
    store1.add(_row("otp-r"))
    store1.remove("otp-r")

    store2 = PendingVerifications.load(base_dir=tmp_path)
    assert store2.get("otp-r") is None


# ---------------------------------------------------------------------------
# Parent dir auto-created on first save
# ---------------------------------------------------------------------------


def test_parent_dir_auto_created(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "nested"
    # Directory does NOT exist yet.
    assert not nested.exists()
    store = PendingVerifications(base_dir=nested)
    store.add(_row("otp-auto"))
    assert nested.exists()
    assert (nested / "aap-pending-verifications.json").exists()


# ---------------------------------------------------------------------------
# Multiple rows
# ---------------------------------------------------------------------------


def test_multiple_rows(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    r1 = _row("otp-1")
    r2 = _row("otp-2", identifier_value="bob@example.com")
    store.add(r1)
    store.add(r2)
    assert store.get("otp-1") == r1
    assert store.get("otp-2") == r2


def test_find_one_returns_none_with_multiple_rows(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    store.add(_row("otp-1"))
    store.add(_row("otp-2", identifier_value="bob@example.com"))
    assert store.find_one() is None


def test_find_one_returns_row_when_exactly_one(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    row = _row("otp-only")
    store.add(row)
    assert store.find_one() == row


def test_add_replaces_existing_row_for_same_identity_and_verifier(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    old = _row("otp-old")
    new = _row("otp-new")
    store.add(old)
    store.add(new)

    assert store.rows == {"otp-new": new}

    reloaded = PendingVerifications.load(base_dir=tmp_path)
    assert reloaded.rows == {"otp-new": new}


def test_find_one_prunes_expired_rows(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    live = _row("otp-live")
    store.add(
        PendingVerificationRow(
            otp_id="otp-expired",
            identity_type="email",
            identifier_value="old@example.com",
            verifier_domain="verify.example.com",
            verification_endpoint="https://verify.example.com/start",
            expires_at="2020-01-01T00:00:00Z",
        )
    )
    store.add(live)

    assert store.find_one() == live
    assert store.get("otp-expired") is None

    reloaded = PendingVerifications.load(base_dir=tmp_path)
    assert reloaded.rows == {"otp-live": live}


def test_prune_expired_removes_malformed_expiry(tmp_path: Path) -> None:
    store = PendingVerifications(base_dir=tmp_path)
    malformed = PendingVerificationRow(
        otp_id="otp-bad",
        identity_type="phone",
        identifier_value="+61400000000",
        verifier_domain="verify.example.com",
        verification_endpoint="https://verify.example.com/start",
        expires_at="not-a-date",
    )
    store.add(malformed)

    removed = store.prune_expired(
        now=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )

    assert removed == 1
    assert store.rows == {}


# ---------------------------------------------------------------------------
# Empty store
# ---------------------------------------------------------------------------


def test_load_on_missing_file(tmp_path: Path) -> None:
    store = PendingVerifications.load(base_dir=tmp_path)
    assert store.rows == {}
