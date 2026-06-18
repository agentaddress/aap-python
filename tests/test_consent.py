"""Tests for PendingConsent store."""

from __future__ import annotations

from pathlib import Path


from aap.stores.consent import PendingConsent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(peer: str = "bob^example.com") -> dict:
    return {"type": "group_invitation", "group_id": "grp-1"}


# ---------------------------------------------------------------------------
# Add + get
# ---------------------------------------------------------------------------


def test_add_and_get_returns_payload(tmp_path: Path) -> None:
    store = PendingConsent(base_dir=tmp_path)
    store.add("nonce-1", "bob^example.com", _entry())
    result = store.get("nonce-1")
    assert result is not None
    assert result["peer_address"] == "bob^example.com"
    assert result["request"]["type"] == "group_invitation"


def test_get_unknown_nonce_returns_none(tmp_path: Path) -> None:
    store = PendingConsent(base_dir=tmp_path)
    assert store.get("no-such-nonce") is None


# ---------------------------------------------------------------------------
# Resolve (clear)
# ---------------------------------------------------------------------------


def test_resolve_clears_nonce(tmp_path: Path) -> None:
    store = PendingConsent(base_dir=tmp_path)
    store.add("nonce-r", "carol^example.com", _entry())
    assert store.resolve("nonce-r") is True
    assert store.get("nonce-r") is None


def test_resolve_unknown_nonce_returns_false(tmp_path: Path) -> None:
    store = PendingConsent(base_dir=tmp_path)
    assert store.resolve("nonexistent") is False


# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------


def test_persistence_across_instances(tmp_path: Path) -> None:
    store1 = PendingConsent(base_dir=tmp_path)
    store1.add("nonce-p", "dave^example.com", _entry())

    store2 = PendingConsent.load(base_dir=tmp_path)
    result = store2.get("nonce-p")
    assert result is not None
    assert result["peer_address"] == "dave^example.com"


def test_resolve_persists_across_instances(tmp_path: Path) -> None:
    store1 = PendingConsent(base_dir=tmp_path)
    store1.add("nonce-rp", "eve^example.com", _entry())
    store1.resolve("nonce-rp")

    store2 = PendingConsent.load(base_dir=tmp_path)
    assert store2.get("nonce-rp") is None


# ---------------------------------------------------------------------------
# Parent dir auto-created on first save
# ---------------------------------------------------------------------------


def test_parent_dir_auto_created(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "nested"
    assert not nested.exists()
    store = PendingConsent(base_dir=nested)
    store.add("nonce-a", "frank^example.com", _entry())
    assert nested.exists()
    assert (nested / "aap-pending-consents.json").exists()


# ---------------------------------------------------------------------------
# Load on missing file
# ---------------------------------------------------------------------------


def test_load_on_missing_file(tmp_path: Path) -> None:
    store = PendingConsent.load(base_dir=tmp_path)
    assert store.get("anything") is None
