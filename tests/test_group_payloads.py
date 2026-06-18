"""Tests for the three group-conversation payload types."""

import pytest

from aap.payloads import GroupInvitation, GroupLeave, GroupMembershipUpdate


def _members_4():
    return [
        "chris^example.com",
        "james^example.com",
        "sarah^example.com",
        "mike^example.com",
    ]


# -- GroupInvitation ------------------------------------------------------


def test_group_invitation_round_trips():
    inv = GroupInvitation(
        conversation_id="dinner-abc123",
        purpose="Plan dinner Friday",
        members=_members_4(),
        convener="chris^example.com",
        nonce="random-nonce",
    )
    d = inv.to_dict()
    assert d == {
        "conversation_id": "dinner-abc123",
        "purpose": "Plan dinner Friday",
        "members": _members_4(),
        "convener": "chris^example.com",
        "nonce": "random-nonce",
    }
    assert GroupInvitation.from_dict(d) == inv


def test_group_invitation_payload_type():
    assert GroupInvitation.PAYLOAD_TYPE == "aap.group-invitation/v1"


def test_group_invitation_rejects_convener_not_in_members():
    """The convener field must appear in the members list."""
    with pytest.raises(ValueError, match="convener.*must be in members"):
        GroupInvitation.from_dict({
            "conversation_id": "x",
            "purpose": "y",
            "members": _members_4(),
            "convener": "not-a-member^example.com",
            "nonce": "n",
        })


def test_group_invitation_rejects_too_few_members():
    with pytest.raises(ValueError, match="members.*at least 2"):
        GroupInvitation.from_dict({
            "conversation_id": "x",
            "purpose": "y",
            "members": ["only-one^example.com"],
            "convener": "only-one^example.com",
            "nonce": "n",
        })


def test_group_invitation_rejects_too_many_members():
    too_many = [f"m{i}^example.com" for i in range(11)]
    with pytest.raises(ValueError, match="members.*at most 10|cap"):
        GroupInvitation.from_dict({
            "conversation_id": "x",
            "purpose": "y",
            "members": too_many,
            "convener": too_many[0],
            "nonce": "n",
        })


# -- GroupMembershipUpdate ------------------------------------------------


def test_group_membership_update_round_trips():
    upd = GroupMembershipUpdate(
        conversation_id="dinner-abc123",
        members=_members_4() + ["alice^example.com"],
        convener="chris^example.com",
        added=["alice^example.com"],
        removed=[],
        convener_changed_from=None,
        nonce="upd-nonce",
    )
    d = upd.to_dict()
    assert d["added"] == ["alice^example.com"]
    assert d["removed"] == []
    assert d["convener_changed_from"] is None
    restored = GroupMembershipUpdate.from_dict(d)
    assert restored == upd


def test_group_membership_update_with_remove():
    upd = GroupMembershipUpdate(
        conversation_id="x",
        members=_members_4()[:3],
        convener="chris^example.com",
        added=[],
        removed=["mike^example.com"],
        convener_changed_from=None,
        nonce="n",
    )
    d = upd.to_dict()
    assert d["removed"] == ["mike^example.com"]
    assert GroupMembershipUpdate.from_dict(d) == upd


def test_group_membership_update_convener_handover():
    """convener_changed_from records the previous convener when role transfers."""
    upd = GroupMembershipUpdate(
        conversation_id="x",
        members=_members_4(),
        convener="james^example.com",   # new convener
        added=[],
        removed=[],
        convener_changed_from="chris^example.com",
        nonce="n",
    )
    d = upd.to_dict()
    assert d["convener_changed_from"] == "chris^example.com"


def test_group_membership_update_payload_type():
    assert GroupMembershipUpdate.PAYLOAD_TYPE == "aap.group-membership-update/v1"


def test_group_membership_update_rejects_cap_breach():
    too_many = [f"m{i}^example.com" for i in range(11)]
    with pytest.raises(ValueError, match="members.*at most 10|cap"):
        GroupMembershipUpdate.from_dict({
            "conversation_id": "x",
            "members": too_many,
            "convener": too_many[0],
            "added": [too_many[10]],
            "removed": [],
            "convener_changed_from": None,
            "nonce": "n",
        })


# -- GroupLeave -----------------------------------------------------------


def test_group_leave_round_trips():
    leave = GroupLeave(
        conversation_id="dinner-abc123",
        nonce="leave-nonce",
        reason="Got busy",
    )
    d = leave.to_dict()
    assert d == {
        "conversation_id": "dinner-abc123",
        "nonce": "leave-nonce",
        "reason": "Got busy",
    }
    assert GroupLeave.from_dict(d) == leave


def test_group_leave_without_reason():
    leave = GroupLeave(conversation_id="x", nonce="n", reason=None)
    d = leave.to_dict()
    assert "reason" not in d
    assert GroupLeave.from_dict({"conversation_id": "x", "nonce": "n"}) == leave


def test_group_leave_requires_nonce():
    with pytest.raises(ValueError, match="nonce"):
        GroupLeave.from_dict({"conversation_id": "x"})


def test_group_leave_payload_type():
    assert GroupLeave.PAYLOAD_TYPE == "aap.group-leave/v1"
