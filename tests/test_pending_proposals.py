"""Tests for aap.stores.pending_proposals."""


from aap.stores.pending_proposals import (
    PendingProposalStore,
)


# ---------------------------------------------------------------------------
# Outbound
# ---------------------------------------------------------------------------


def test_empty_store_outbound(tmp_path):
    store = PendingProposalStore.load(tmp_path)
    assert store.outbound == {}


def test_record_and_take_outbound(tmp_path):
    store = PendingProposalStore.load(tmp_path)
    store.record_outbound(
        nonce="nonce-1",
        peer_address="bob^example.com",
        relationship_type="friend",
        resource=None,
        proposal_envelope_json='{"type":"proposal"}',
    )

    # File was created
    assert (tmp_path / "aap-pending-proposals.json").exists()

    # Reloaded store sees the row
    reloaded = PendingProposalStore.load(tmp_path)
    assert "nonce-1" in reloaded.outbound
    row = reloaded.outbound["nonce-1"]
    assert row.peer_address == "bob^example.com"
    assert row.relationship_type == "friend"
    assert row.resource is None

    # take_outbound pops and persists
    taken = reloaded.take_outbound("nonce-1")
    assert taken is not None
    assert taken.nonce == "nonce-1"
    assert "nonce-1" not in reloaded.outbound

    # Gone from disk too
    reloaded2 = PendingProposalStore.load(tmp_path)
    assert "nonce-1" not in reloaded2.outbound


def test_take_outbound_missing_returns_none(tmp_path):
    store = PendingProposalStore.load(tmp_path)
    assert store.take_outbound("no-such-nonce") is None


# ---------------------------------------------------------------------------
# Inbound
# ---------------------------------------------------------------------------


def test_record_and_take_inbound(tmp_path):
    store = PendingProposalStore.load(tmp_path)
    store.record_inbound(
        nonce="nonce-2",
        proposer_address="alice^example.com",
        relationship_type="colleague",
        resource="resource-a",
        proposal_envelope_json='{"type":"proposal"}',
    )

    reloaded = PendingProposalStore.load(tmp_path)
    row = reloaded.get_inbound("nonce-2")
    assert row is not None
    assert row.proposer_address == "alice^example.com"
    assert row.resource == "resource-a"

    taken = reloaded.take_inbound("nonce-2")
    assert taken is not None
    assert taken.nonce == "nonce-2"
    assert reloaded.get_inbound("nonce-2") is None


def test_most_recent_inbound_nonce(tmp_path):
    store = PendingProposalStore.load(tmp_path)
    assert store.most_recent_inbound_nonce() is None

    store.record_inbound(
        nonce="first",
        proposer_address="a^x.com",
        relationship_type="friend",
        resource=None,
        proposal_envelope_json="{}",
    )
    store.record_inbound(
        nonce="second",
        proposer_address="b^x.com",
        relationship_type="friend",
        resource=None,
        proposal_envelope_json="{}",
    )
    assert store.most_recent_inbound_nonce() == "second"


def test_parent_dir_created(tmp_path):
    """_save creates parent directories if they don't exist yet."""
    nested = tmp_path / "deep" / "dir"
    store = PendingProposalStore(base_dir=nested)
    store.record_outbound(
        nonce="n",
        peer_address="x^y.com",
        relationship_type="friend",
        resource=None,
        proposal_envelope_json="{}",
    )
    assert (nested / "aap-pending-proposals.json").exists()
