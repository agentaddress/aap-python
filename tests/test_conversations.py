"""Tests for the conversations store."""

import pytest

from aap.conversations import Conversation, ConversationStore


@pytest.fixture
def store(tmp_path):
    return ConversationStore(base_dir=tmp_path)


def test_empty_store(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    assert s.list_active() == []


def test_record_conversation(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    conv = Conversation(
        conversation_id="dinner-abc",
        purpose="Plan dinner",
        members=["chris^x.com", "james^y.com"],
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    )
    s.record(conv)
    store_file = tmp_path / "aap-conversations.json"
    assert store_file.exists()

    reloaded = ConversationStore.load(base_dir=tmp_path)
    assert len(reloaded.list_active()) == 1
    assert reloaded.get("dinner-abc").purpose == "Plan dinner"


def test_update_members(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    s.record(Conversation(
        conversation_id="x",
        purpose="t",
        members=["chris^x.com", "james^y.com"],
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))
    s.update_members("x", ["chris^x.com", "james^y.com", "alice^z.com"])
    reloaded = ConversationStore.load(base_dir=tmp_path)
    assert len(reloaded.get("x").members) == 3


def test_remove_member(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    s.record(Conversation(
        conversation_id="x",
        purpose="t",
        members=["chris^x.com", "james^y.com", "mike^z.com"],
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))
    s.remove_member("x", "mike^z.com")
    reloaded = ConversationStore.load(base_dir=tmp_path)
    assert "mike^z.com" not in reloaded.get("x").members


def test_dissolve_conversation(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    s.record(Conversation(
        conversation_id="x",
        purpose="t",
        members=["chris^x.com", "james^y.com"],
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))
    s.dissolve("x")
    assert ConversationStore.load(base_dir=tmp_path).get("x") is None


def test_other_members_excludes_self(tmp_path):
    s = ConversationStore.load(base_dir=tmp_path)
    s.record(Conversation(
        conversation_id="x",
        purpose="t",
        members=["chris^x.com", "james^y.com", "sarah^z.com"],
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))
    others = ConversationStore.load(base_dir=tmp_path).other_members("x", self_address="chris^x.com")
    assert set(others) == {"james^y.com", "sarah^z.com"}


# -- signed group-state application ---------------------------------------


def test_accept_invitation_records_conversation_and_event(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_invitation_envelope
    from aap.keys import generate_keypair

    convener_seed, convener_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    env = build_group_invitation_envelope(
        convener_seed=convener_seed,
        convener_address="mary^example.com",
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        name="Dinner",
        goal="choose a restaurant",
    )

    conv = store.accept_invitation(
        self_address="chris^example.com",
        invitation_envelope=env,
        convener_public_key=convener_public,
    )

    assert conv.conversation_id == "conv-1"
    assert conv.convener == "mary^example.com"
    assert conv.name == "Dinner"
    assert len(store.events) == 1
    with pytest.raises(ConversationPolicyError, match="replay|already exists"):
        store.accept_invitation(
            self_address="chris^example.com",
            invitation_envelope=env,
            convener_public_key=convener_public,
        )


def test_accept_invitation_rejects_wrong_issuer(tmp_path):
    from datetime import datetime, timezone

    from aap.conversations import ConversationPolicyError
    from aap.envelope import Envelope
    from aap.keys import generate_keypair
    from aap.payloads import GroupInvitation

    seed, public = generate_keypair()
    invitation = GroupInvitation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        nonce="n",
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=GroupInvitation.PAYLOAD_TYPE,
        payload=invitation.to_dict(),
        iss="attacker^example.com",
        iat=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ).sign(seed)

    with pytest.raises(ConversationPolicyError, match="issuer"):
        ConversationStore.load(base_dir=tmp_path).accept_invitation(
            self_address="chris^example.com",
            invitation_envelope=env,
            convener_public_key=public,
        )


def test_apply_membership_update_requires_current_convener_and_exact_diff(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_membership_update_envelope
    from aap.keys import generate_keypair

    convener_seed, convener_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_membership_update_envelope(
        convener_seed=convener_seed,
        convener_address="mary^example.com",
        conversation_id="conv-1",
        members=["mary^example.com", "chris^example.com", "bob^example.com"],
        added=["bob^example.com"],
        removed=[],
        convener_changed_from=None,
    )

    conv = store.apply_membership_update(
        self_address="chris^example.com",
        update_envelope=env,
        convener_public_key=convener_public,
    )

    assert conv is not None
    assert conv.members == [
        "mary^example.com",
        "chris^example.com",
        "bob^example.com",
    ]
    with pytest.raises(ConversationPolicyError, match="replay"):
        store.apply_membership_update(
            self_address="chris^example.com",
            update_envelope=env,
            convener_public_key=convener_public,
        )


def test_apply_membership_update_rejects_declared_new_convener_as_signer(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_membership_update_envelope
    from aap.keys import generate_keypair

    new_seed, new_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_membership_update_envelope(
        convener_seed=new_seed,
        convener_address="chris^example.com",
        conversation_id="conv-1",
        members=["mary^example.com", "chris^example.com"],
        added=[],
        removed=[],
        convener_changed_from="mary^example.com",
    )

    with pytest.raises(ConversationPolicyError, match="issuer|verification"):
        store.apply_membership_update(
            self_address="chris^example.com",
            update_envelope=env,
            convener_public_key=new_public,
        )


def test_apply_membership_update_allows_old_convener_signed_handoff(tmp_path):
    from aap.group_flow import build_group_membership_update_envelope
    from aap.keys import generate_keypair

    old_seed, old_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_membership_update_envelope(
        convener_seed=old_seed,
        convener_address="chris^example.com",
        signing_address="mary^example.com",
        conversation_id="conv-1",
        members=["mary^example.com", "chris^example.com"],
        added=[],
        removed=[],
        convener_changed_from="mary^example.com",
    )

    conv = store.apply_membership_update(
        self_address="chris^example.com",
        update_envelope=env,
        convener_public_key=old_public,
    )

    assert conv is not None
    assert conv.convener == "chris^example.com"


def test_apply_membership_update_rejects_bad_diff(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_membership_update_envelope
    from aap.keys import generate_keypair

    seed, public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_membership_update_envelope(
        convener_seed=seed,
        convener_address="mary^example.com",
        conversation_id="conv-1",
        members=["mary^example.com", "chris^example.com", "bob^example.com"],
        added=[],
        removed=[],
        convener_changed_from=None,
    )

    with pytest.raises(ConversationPolicyError, match="added members"):
        store.apply_membership_update(
            self_address="chris^example.com",
            update_envelope=env,
            convener_public_key=public,
        )


def test_apply_leave_removes_member_and_rejects_replay(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_leave_envelope
    from aap.keys import generate_keypair

    leaver_seed, leaver_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com", "bob^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_leave_envelope(
        leaver_seed=leaver_seed,
        leaver_address="bob^example.com",
        conversation_id="conv-1",
        reason="busy",
    )

    conv = store.apply_leave(
        self_address="chris^example.com",
        leave_envelope=env,
        leaver_public_key=leaver_public,
    )

    assert conv is not None
    assert conv.members == ["mary^example.com", "chris^example.com"]
    with pytest.raises(ConversationPolicyError, match="replay|not a group member"):
        store.apply_leave(
            self_address="chris^example.com",
            leave_envelope=env,
            leaver_public_key=leaver_public,
        )


def test_apply_leave_rejects_convener_leave_without_handoff(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import build_group_leave_envelope
    from aap.keys import generate_keypair

    convener_seed, convener_public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    env = build_group_leave_envelope(
        leaver_seed=convener_seed,
        leaver_address="mary^example.com",
        conversation_id="conv-1",
        reason=None,
    )

    with pytest.raises(ConversationPolicyError, match="hand off"):
        store.apply_leave(
            self_address="chris^example.com",
            leave_envelope=env,
            leaver_public_key=convener_public,
        )


def test_apply_complete_marks_completed_and_blocks_later_updates(tmp_path):
    from aap.conversations import ConversationPolicyError
    from aap.group_flow import (
        build_group_complete_envelope,
        build_group_membership_update_envelope,
    )
    from aap.keys import generate_keypair

    seed, public = generate_keypair()
    store = ConversationStore.load(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv-1",
        purpose="Plan dinner",
        members=["mary^example.com", "chris^example.com"],
        convener="mary^example.com",
        accepted_at="2026-06-16T00:00:00Z",
        last_message_at=None,
    ))
    complete = build_group_complete_envelope(
        convener_seed=seed,
        convener_address="mary^example.com",
        conversation_id="conv-1",
        outcome="Booked",
    )

    conv = store.apply_complete(
        complete_envelope=complete,
        convener_public_key=public,
    )

    assert conv.completed_at is not None
    update = build_group_membership_update_envelope(
        convener_seed=seed,
        convener_address="mary^example.com",
        conversation_id="conv-1",
        members=["mary^example.com", "chris^example.com", "bob^example.com"],
        added=["bob^example.com"],
        removed=[],
        convener_changed_from=None,
    )
    with pytest.raises(ConversationPolicyError, match="completed"):
        store.apply_membership_update(
            self_address="chris^example.com",
            update_envelope=update,
            convener_public_key=public,
        )


# ── broadcast_to_conversation (v0.6: no capability tokens) ────────────────


@pytest.mark.asyncio
async def test_broadcast_sends_to_each_other_member(tmp_path):
    """broadcast_to_conversation sends one envelope per other member with
    conversation_id + members. No capability_token is attached — group
    chat is authorized by recipient-side membership check."""
    from aap.conversations import (
        Conversation,
        ConversationStore,
        broadcast_to_conversation,
    )

    members = [
        "chris^x.com",
        "james^y.com",
        "sarah^z.com",
    ]
    store = ConversationStore(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="dinner-abc",
        purpose="Plan dinner",
        members=members,
        convener="chris^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))

    class FakeClient:
        def __init__(self):
            self.calls = []

        async def send_envelope(self, **kwargs):
            self.calls.append(kwargs)
            return 100 + len(self.calls)

    client = FakeClient()
    results = await broadcast_to_conversation(
        client=client,
        store=store,
        self_address="chris^x.com",
        conversation_id="dinner-abc",
        text="dinner at 7?",
    )

    assert len(client.calls) == 2
    recipients = {c["to"] for c in client.calls}
    assert recipients == {"james^y.com", "sarah^z.com"}
    for c in client.calls:
        assert c["text"] == "dinner at 7?"
        assert c["conversation_id"] == "dinner-abc"
        assert c["conversation_members"] == members
        # No capability_token kwarg under v0.6.
        assert "capability_token" not in c

    assert {r[0] for r in results} == {"james^y.com", "sarah^z.com"}
    assert all(isinstance(r[1], int) for r in results)


@pytest.mark.asyncio
async def test_broadcast_continues_after_send_error(tmp_path):
    """A failed send to one recipient must NOT prevent sends to others."""
    from aap.conversations import (
        Conversation,
        ConversationStore,
        broadcast_to_conversation,
    )

    store = ConversationStore(base_dir=tmp_path)
    store.record(Conversation(
        conversation_id="conv1",
        purpose="t",
        members=[
            "me^x.com",
            "flaky^y.com",
            "happy^z.com",
        ],
        convener="me^x.com",
        accepted_at="2026-05-22T12:00:00Z",
        last_message_at=None,
    ))

    class FakeClient:
        def __init__(self):
            self.calls = []

        async def send_envelope(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs["to"] == "flaky^y.com":
                raise RuntimeError("network error")
            return 42

    client = FakeClient()
    results = await broadcast_to_conversation(
        client=client,
        store=store,
        self_address="me^x.com",
        conversation_id="conv1",
        text="hi",
    )
    assert len(client.calls) == 2
    result_dict = dict(results)
    assert result_dict["happy^z.com"] == 42
    assert "error" in str(result_dict["flaky^y.com"]).lower()


@pytest.mark.asyncio
async def test_broadcast_unknown_conversation_raises(tmp_path):
    from aap.conversations import broadcast_to_conversation, ConversationStore

    store = ConversationStore(base_dir=tmp_path)

    class FakeClient:
        async def send_envelope(self, **kwargs):
            return 1

    with pytest.raises(ValueError, match="unknown conversation"):
        await broadcast_to_conversation(
            client=FakeClient(),
            store=store,
            self_address="me^x.com",
            conversation_id="does-not-exist",
            text="hi",
        )
