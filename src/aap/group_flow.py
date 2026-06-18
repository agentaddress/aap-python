"""Group-envelope builders for AAP v0.4 group-conversation primitives.

Each builder takes the signing seed + identity + group payload fields and
returns a signed Envelope ready to send. v0.6 dropped capability_token
attachment — group meta-flow envelopes are routed by payload type at the
receiver's adapter dispatch and gated by friend/admin/team relationship
(invitations) or by recorded-convener identity (membership/leave).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from aap.envelope import Envelope
from aap.payloads import (
    GroupComplete,
    GroupInvitation,
    GroupLeave,
    GroupMembershipUpdate,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_group_invitation_envelope(
    *,
    convener_seed: bytes,
    convener_address: str,
    conversation_id: str,
    purpose: str,
    members: list[str],
    name: str = "",
    goal: str = "",
) -> Envelope:
    payload = GroupInvitation(
        conversation_id=conversation_id,
        purpose=purpose,
        members=list(members),
        convener=convener_address,
        nonce=secrets.token_urlsafe(12),
        name=name,
        goal=goal,
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=GroupInvitation.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=convener_address,
        iat=_now_iso(),
    )
    return env.sign(convener_seed)


def build_group_membership_update_envelope(
    *,
    convener_seed: bytes,
    convener_address: str,
    conversation_id: str,
    members: list[str],
    added: list[str],
    removed: list[str],
    convener_changed_from: str | None,
    signing_address: str | None = None,
) -> Envelope:
    payload = GroupMembershipUpdate(
        conversation_id=conversation_id,
        members=list(members),
        convener=convener_address,
        added=list(added),
        removed=list(removed),
        convener_changed_from=convener_changed_from,
        nonce=secrets.token_urlsafe(12),
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=GroupMembershipUpdate.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=signing_address or convener_address,
        iat=_now_iso(),
    )
    return env.sign(convener_seed)


def build_group_complete_envelope(
    *,
    convener_seed: bytes,
    convener_address: str,
    conversation_id: str,
    outcome: str,
) -> Envelope:
    payload = GroupComplete(
        conversation_id=conversation_id,
        outcome=outcome,
        nonce=secrets.token_urlsafe(12),
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=GroupComplete.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=convener_address,
        iat=_now_iso(),
    )
    return env.sign(convener_seed)


def build_group_leave_envelope(
    *,
    leaver_seed: bytes,
    leaver_address: str,
    conversation_id: str,
    reason: str | None,
) -> Envelope:
    payload = GroupLeave(
        conversation_id=conversation_id,
        nonce=secrets.token_urlsafe(12),
        reason=reason,
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=GroupLeave.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=leaver_address,
        iat=_now_iso(),
    )
    return env.sign(leaver_seed)
