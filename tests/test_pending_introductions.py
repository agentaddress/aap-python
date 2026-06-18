"""Tests for aap.stores.pending_introductions."""

from __future__ import annotations

from pathlib import Path


from aap.stores.pending_introductions import PendingIntroductionRow, PendingIntroductions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(nonce: str = "nonce-1", searcher: str = "bob^example.com") -> PendingIntroductionRow:
    return PendingIntroductionRow(
        verifier_nonce=nonce,
        verifier_domain="verify.example.com",
        searcher=searcher,
        searcher_label="Bob",
        expires_at="2027-06-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Add + get
# ---------------------------------------------------------------------------


def test_add_and_get_returns_row(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    row = _row()
    store.add(row)
    result = store.get("nonce-1")
    assert result is not None
    assert result.verifier_nonce == "nonce-1"
    assert result.searcher == "bob^example.com"
    assert result.verifier_domain == "verify.example.com"


def test_get_unknown_nonce_returns_none(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    assert store.get("no-such-nonce") is None


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------


def test_resolve_removes_row(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    store.add(_row("nonce-r"))
    assert store.resolve("nonce-r") is True
    assert store.get("nonce-r") is None


def test_resolve_unknown_nonce_returns_false(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    assert store.resolve("nonexistent") is False


# ---------------------------------------------------------------------------
# most_recent_nonce
# ---------------------------------------------------------------------------


def test_most_recent_nonce_empty(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    assert store.most_recent_nonce() is None


def test_most_recent_nonce_returns_last_added(tmp_path: Path) -> None:
    store = PendingIntroductions(base_dir=tmp_path)
    store.add(_row("first"))
    store.add(_row("second"))
    assert store.most_recent_nonce() == "second"


# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------


def test_persistence_across_instances(tmp_path: Path) -> None:
    store1 = PendingIntroductions(base_dir=tmp_path)
    store1.add(_row("nonce-p"))

    store2 = PendingIntroductions.load(base_dir=tmp_path)
    result = store2.get("nonce-p")
    assert result is not None
    assert result.verifier_nonce == "nonce-p"
    assert result.searcher == "bob^example.com"


def test_resolve_persists_across_instances(tmp_path: Path) -> None:
    store1 = PendingIntroductions(base_dir=tmp_path)
    store1.add(_row("nonce-rp"))
    store1.resolve("nonce-rp")

    store2 = PendingIntroductions.load(base_dir=tmp_path)
    assert store2.get("nonce-rp") is None


# ---------------------------------------------------------------------------
# Parent dir auto-create
# ---------------------------------------------------------------------------


def test_parent_dir_auto_created(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "nested"
    assert not nested.exists()
    store = PendingIntroductions(base_dir=nested)
    store.add(_row("nonce-a"))
    assert nested.exists()
    assert (nested / "aap-pending-introductions.json").exists()


# ---------------------------------------------------------------------------
# Load on missing file
# ---------------------------------------------------------------------------


def test_load_on_missing_file(tmp_path: Path) -> None:
    store = PendingIntroductions.load(base_dir=tmp_path)
    assert store.get("anything") is None


# ---------------------------------------------------------------------------
# None searcher_label round-trips correctly
# ---------------------------------------------------------------------------


def test_none_searcher_label_round_trips(tmp_path: Path) -> None:
    row = PendingIntroductionRow(
        verifier_nonce="nonce-nil",
        verifier_domain="verify.example.com",
        searcher="carol^example.com",
        searcher_label=None,
        expires_at="2027-06-01T00:00:00Z",
    )
    store1 = PendingIntroductions(base_dir=tmp_path)
    store1.add(row)

    store2 = PendingIntroductions.load(base_dir=tmp_path)
    result = store2.get("nonce-nil")
    assert result is not None
    assert result.searcher_label is None
