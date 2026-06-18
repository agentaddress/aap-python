"""Active group-conversation persistence.

Stored at <base_dir>/aap-conversations.json. Tracks conversations
the local agent is currently participating in. v0.6: chat within a
group is authorized purely by membership — receivers verify the
sender is in their local conversation member list. No capability
tokens are attached to broadcast envelopes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import (
    GroupComplete,
    GroupInvitation,
    GroupLeave,
    GroupMembershipUpdate,
)
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


@dataclass
class Conversation:
    conversation_id: str
    purpose: str
    members: list[str]
    convener: str
    accepted_at: str
    last_message_at: Optional[str]
    name: Optional[str] = None
    goal: str = ""
    completed_at: Optional[str] = None

    def display_name(self) -> str:
        """Short human-readable label for this group, for use in UI and logs."""
        return self.name or self.purpose or self.conversation_id


@dataclass
class ConversationEventRecord:
    conversation_id: str
    event_type: str
    issuer: str
    nonce: str
    envelope_json: str
    recorded_at: str


class ConversationPolicyError(ValueError):
    """Raised when a signed group-conversation event is not authorized."""


@dataclass
class ConversationStore:
    conversations: list[Conversation]
    events: list[ConversationEventRecord]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-conversations.json"
        self.conversations: list[Conversation] = []
        self.events: list[ConversationEventRecord] = []

    @classmethod
    def load(cls, base_dir: Path) -> "ConversationStore":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to load %s; starting empty", store._path)
            return store
        convs = []
        for c in data.get("conversations") or []:
            # Tolerate older records that predate the `name` field.
            convs.append(Conversation(
                conversation_id=c["conversation_id"],
                purpose=c.get("purpose", ""),
                members=c.get("members", []),
                convener=c.get("convener", ""),
                accepted_at=c.get("accepted_at", ""),
                last_message_at=c.get("last_message_at"),
                name=c.get("name"),
                goal=c.get("goal", ""),
                completed_at=c.get("completed_at"),
            ))
        store.conversations = convs
        events = []
        for e in data.get("events") or []:
            events.append(ConversationEventRecord(
                conversation_id=e["conversation_id"],
                event_type=e["event_type"],
                issuer=e["issuer"],
                nonce=e["nonce"],
                envelope_json=e["envelope_json"],
                recorded_at=e.get("recorded_at", ""),
            ))
        store.events = events
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {
                "conversations": [asdict(c) for c in self.conversations],
                "events": [asdict(e) for e in self.events],
            },
        )

    def get(self, conversation_id: str) -> Optional[Conversation]:
        for c in self.conversations:
            if c.conversation_id == conversation_id:
                return c
        return None

    def list_active(self) -> list[Conversation]:
        return list(self.conversations)

    def record(self, conv: Conversation) -> None:
        # Idempotent: replace any existing entry with the same id
        self.conversations = [c for c in self.conversations if c.conversation_id != conv.conversation_id]
        self.conversations.append(conv)
        self._save()

    def update_members(self, conversation_id: str, members: list[str]) -> None:
        """Unsafe local mutation. Prefer apply_membership_update for receivers."""
        for c in self.conversations:
            if c.conversation_id == conversation_id:
                c.members = list(members)
                break
        self._save()

    def remove_member(self, conversation_id: str, member: str) -> None:
        """Unsafe local mutation. Prefer apply_leave for signed leave events."""
        for c in self.conversations:
            if c.conversation_id == conversation_id:
                c.members = [m for m in c.members if m != member]
                break
        self._save()

    def dissolve(self, conversation_id: str) -> bool:
        """Unsafe local deletion. Prefer apply_leave/apply_complete for protocol events."""
        before = len(self.conversations)
        self.conversations = [c for c in self.conversations if c.conversation_id != conversation_id]
        if len(self.conversations) < before:
            self._save()
            return True
        return False

    def accept_invitation(
        self,
        *,
        self_address: str,
        invitation_envelope: Envelope | dict[str, Any] | str,
        convener_public_key: bytes,
    ) -> Conversation:
        envelope = _coerce_envelope(invitation_envelope)
        _verify_group_envelope(
            envelope,
            GroupInvitation.PAYLOAD_TYPE,
            convener_public_key,
        )
        try:
            invitation = GroupInvitation.from_dict(envelope.payload)
        except ValueError as e:
            raise ConversationPolicyError(f"invalid group invitation: {e}") from e

        _require_issuer(envelope, invitation.convener)
        _require_self_member(self_address, invitation.members)
        self._require_fresh_event(
            invitation.conversation_id,
            GroupInvitation.PAYLOAD_TYPE,
            invitation.nonce,
        )
        if self.get(invitation.conversation_id) is not None:
            raise ConversationPolicyError(
                f"conversation {invitation.conversation_id!r} already exists"
            )

        conv = Conversation(
            conversation_id=invitation.conversation_id,
            purpose=invitation.purpose,
            members=list(invitation.members),
            convener=invitation.convener,
            accepted_at=_now_iso(),
            last_message_at=None,
            name=invitation.name or None,
            goal=invitation.goal,
        )
        self.conversations.append(conv)
        self._record_event(
            conversation_id=invitation.conversation_id,
            event_type=GroupInvitation.PAYLOAD_TYPE,
            issuer=envelope.iss,
            nonce=invitation.nonce,
            envelope=envelope,
        )
        self._save()
        return conv

    def apply_membership_update(
        self,
        *,
        self_address: str,
        update_envelope: Envelope | dict[str, Any] | str,
        convener_public_key: bytes,
    ) -> Conversation | None:
        envelope = _coerce_envelope(update_envelope)
        _verify_group_envelope(
            envelope,
            GroupMembershipUpdate.PAYLOAD_TYPE,
            convener_public_key,
        )
        try:
            update = GroupMembershipUpdate.from_dict(envelope.payload)
        except ValueError as e:
            raise ConversationPolicyError(f"invalid membership update: {e}") from e

        conv = self.get(update.conversation_id)
        if conv is None:
            raise ConversationPolicyError(
                f"unknown conversation {update.conversation_id!r}"
            )
        self._require_fresh_event(
            update.conversation_id,
            GroupMembershipUpdate.PAYLOAD_TYPE,
            update.nonce,
        )
        _require_not_completed(conv)
        _require_issuer(envelope, conv.convener)

        old_members = set(conv.members)
        new_members = set(update.members)
        if len(old_members) != len(conv.members) or len(new_members) != len(update.members):
            raise ConversationPolicyError("conversation members must be unique")
        actual_added = new_members - old_members
        actual_removed = old_members - new_members
        if set(update.added) != actual_added:
            raise ConversationPolicyError("added members do not match membership diff")
        if set(update.removed) != actual_removed:
            raise ConversationPolicyError("removed members do not match membership diff")

        if update.convener_changed_from is None:
            if update.convener != conv.convener:
                raise ConversationPolicyError(
                    "convener changed without convener_changed_from"
                )
        else:
            if update.convener_changed_from != conv.convener:
                raise ConversationPolicyError(
                    "convener_changed_from does not match current convener"
                )
            if update.convener == conv.convener:
                raise ConversationPolicyError("convener handoff did not change convener")
        if update.convener not in new_members:
            raise ConversationPolicyError("new convener must be in members")

        self._record_event(
            conversation_id=update.conversation_id,
            event_type=GroupMembershipUpdate.PAYLOAD_TYPE,
            issuer=envelope.iss,
            nonce=update.nonce,
            envelope=envelope,
        )
        if self_address not in new_members:
            self.conversations = [
                c for c in self.conversations
                if c.conversation_id != update.conversation_id
            ]
            self._save()
            return None

        conv.members = list(update.members)
        conv.convener = update.convener
        self._save()
        return conv

    def apply_leave(
        self,
        *,
        self_address: str,
        leave_envelope: Envelope | dict[str, Any] | str,
        leaver_public_key: bytes,
    ) -> Conversation | None:
        envelope = _coerce_envelope(leave_envelope)
        _verify_group_envelope(
            envelope,
            GroupLeave.PAYLOAD_TYPE,
            leaver_public_key,
        )
        try:
            leave = GroupLeave.from_dict(envelope.payload)
        except ValueError as e:
            raise ConversationPolicyError(f"invalid group leave: {e}") from e

        conv = self.get(leave.conversation_id)
        if conv is None:
            raise ConversationPolicyError(
                f"unknown conversation {leave.conversation_id!r}"
            )
        self._require_fresh_event(
            leave.conversation_id,
            GroupLeave.PAYLOAD_TYPE,
            leave.nonce,
        )
        _require_not_completed(conv)
        if envelope.iss not in conv.members:
            raise ConversationPolicyError("leaver is not a group member")
        if envelope.iss == conv.convener:
            raise ConversationPolicyError("convener must hand off before leaving")

        self._record_event(
            conversation_id=leave.conversation_id,
            event_type=GroupLeave.PAYLOAD_TYPE,
            issuer=envelope.iss,
            nonce=leave.nonce,
            envelope=envelope,
        )
        if envelope.iss == self_address:
            self.conversations = [
                c for c in self.conversations
                if c.conversation_id != leave.conversation_id
            ]
            self._save()
            return None

        conv.members = [m for m in conv.members if m != envelope.iss]
        if len(conv.members) < 2:
            self.conversations = [
                c for c in self.conversations
                if c.conversation_id != leave.conversation_id
            ]
            self._save()
            return None
        self._save()
        return conv

    def apply_complete(
        self,
        *,
        complete_envelope: Envelope | dict[str, Any] | str,
        convener_public_key: bytes,
    ) -> Conversation:
        envelope = _coerce_envelope(complete_envelope)
        _verify_group_envelope(
            envelope,
            GroupComplete.PAYLOAD_TYPE,
            convener_public_key,
        )
        try:
            complete = GroupComplete.from_dict(envelope.payload)
        except ValueError as e:
            raise ConversationPolicyError(f"invalid group complete: {e}") from e

        conv = self.get(complete.conversation_id)
        if conv is None:
            raise ConversationPolicyError(
                f"unknown conversation {complete.conversation_id!r}"
            )
        self._require_fresh_event(
            complete.conversation_id,
            GroupComplete.PAYLOAD_TYPE,
            complete.nonce,
        )
        _require_not_completed(conv)
        _require_issuer(envelope, conv.convener)

        conv.completed_at = _now_iso()
        self._record_event(
            conversation_id=complete.conversation_id,
            event_type=GroupComplete.PAYLOAD_TYPE,
            issuer=envelope.iss,
            nonce=complete.nonce,
            envelope=envelope,
        )
        self._save()
        return conv

    def _require_fresh_event(
        self,
        conversation_id: str,
        event_type: str,
        nonce: str,
    ) -> None:
        if not nonce:
            raise ConversationPolicyError("group event nonce is required")
        for event in self.events:
            if (
                event.conversation_id == conversation_id
                and event.event_type == event_type
                and event.nonce == nonce
            ):
                raise ConversationPolicyError("group event replay detected")

    def _record_event(
        self,
        *,
        conversation_id: str,
        event_type: str,
        issuer: str,
        nonce: str,
        envelope: Envelope,
    ) -> None:
        self.events.append(ConversationEventRecord(
            conversation_id=conversation_id,
            event_type=event_type,
            issuer=issuer,
            nonce=nonce,
            envelope_json=envelope.to_json(),
            recorded_at=_now_iso(),
        ))

    def other_members(self, conversation_id: str, *, self_address: str) -> list[str]:
        c = self.get(conversation_id)
        if c is None:
            return []
        return [m for m in c.members if m != self_address]


# ── Broadcast send helper ──────────────────────────────────────────────────


async def broadcast_to_conversation(
    *,
    client,
    store: ConversationStore,
    self_address: str,
    conversation_id: str,
    text: str,
) -> list[tuple[str, "int | str"]]:
    """Send a chat envelope to every other member of the conversation.

    Each broadcast envelope carries:
      - the conversation_id + the full current member list

    v0.6: no capability token; the receiver gates on conversation
    membership. Returns ``[(recipient_address, envelope_id_or_error)]``.
    Raises ``ValueError`` when the conversation_id is unknown.

    ``store`` must be a :class:`ConversationStore` loaded for the current
    agent's base directory — the caller is responsible for loading it.
    This helper performs no environment lookups.
    """
    conv = store.get(conversation_id)
    if conv is None:
        raise ValueError(f"unknown conversation {conversation_id!r}")

    others = [m for m in conv.members if m != self_address]
    results: list[tuple[str, "int | str"]] = []
    for recipient in others:
        try:
            env_id = await client.send_envelope(
                to=recipient,
                text=text,
                conversation_id=conversation_id,
                conversation_members=list(conv.members),
            )
            results.append((recipient, env_id))
        except Exception as e:
            # Capture type + repr + traceback. Some httpx / asyncio failure
            # paths surface exceptions with empty ``str(e)``, which silently
            # erased the failure signal in the previous formatting.
            err_type = type(e).__name__
            err_repr = repr(e)
            logger.warning(
                "Broadcast to %s failed: %s %s",
                recipient,
                err_type,
                err_repr,
                exc_info=True,
            )
            summary = f"{err_type}: {e}" if str(e) else err_type
            results.append((recipient, f"error: {summary}"))
    return results


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_envelope(envelope: Envelope | dict[str, Any] | str) -> Envelope:
    if isinstance(envelope, Envelope):
        return envelope
    try:
        if isinstance(envelope, str):
            return Envelope.from_json(envelope)
        return Envelope.from_dict(envelope)
    except EnvelopeError as e:
        raise ConversationPolicyError(f"invalid envelope: {e}") from e


def _verify_group_envelope(
    envelope: Envelope,
    payload_type: str,
    public_key: bytes,
) -> None:
    if envelope.payload_type != payload_type:
        raise ConversationPolicyError(
            f"expected {payload_type!r}, got {envelope.payload_type!r}"
        )
    try:
        verify_envelope(envelope, public_key)
    except EnvelopePolicyError as e:
        raise ConversationPolicyError(f"group envelope verification failed: {e}") from e


def _require_issuer(envelope: Envelope, expected_issuer: str) -> None:
    if envelope.iss != expected_issuer:
        raise ConversationPolicyError(
            f"issuer {envelope.iss!r} does not match {expected_issuer!r}"
        )


def _require_self_member(self_address: str, members: list[str]) -> None:
    if self_address not in members:
        raise ConversationPolicyError("local agent is not in group members")


def _require_not_completed(conv: Conversation) -> None:
    if conv.completed_at is not None:
        raise ConversationPolicyError(
            f"conversation {conv.conversation_id!r} is completed"
        )
