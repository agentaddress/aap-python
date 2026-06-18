"""Pending-relationship-proposal stores (outbound + inbound).

Two stores live side by side at ``<base_dir>/aap-pending-proposals.json``:

* **outbound**: proposals WE sent. When the peer's RelationshipAccept
  arrives, the adapter looks up the matching outbound row by nonce, builds
  the local RelationshipRecord, and clears the pending entry. If the peer
  declines, the row is dropped.

* **inbound**: proposals WE received. The adapter surfaces a USER REQUIRED
  prompt and parks the row here; ``/aap friend-accept <nonce>`` or
  ``/aap friend-decline <nonce>`` finds the matching row and acts on it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aap.storage import write_json_private

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class PendingOutbound:
    """A proposal we sent, awaiting the peer's accept/decline."""

    nonce: str
    peer_address: str
    relationship_type: str
    resource: Optional[str]
    proposal_envelope_json: str
    sent_at: str


@dataclass
class PendingInbound:
    """A proposal a peer sent us, awaiting our user's approval."""

    nonce: str
    proposer_address: str
    relationship_type: str
    resource: Optional[str]
    proposal_envelope_json: str
    received_at: str


@dataclass
class PendingProposalStore:
    outbound: dict[str, PendingOutbound]
    inbound: dict[str, PendingInbound]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-pending-proposals.json"
        self.outbound: dict[str, PendingOutbound] = {}
        self.inbound: dict[str, PendingInbound] = {}

    @classmethod
    def load(cls, base_dir: Path) -> "PendingProposalStore":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("failed to load %s; starting empty", store._path)
            return store
        for k, v in (data.get("outbound") or {}).items():
            try:
                store.outbound[k] = PendingOutbound(**v)
            except TypeError:
                logger.warning("skipping malformed outbound row: %r", v)
        for k, v in (data.get("inbound") or {}).items():
            try:
                store.inbound[k] = PendingInbound(**v)
            except TypeError:
                logger.warning("skipping malformed inbound row: %r", v)
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {
                "outbound": {k: asdict(v) for k, v in self.outbound.items()},
                "inbound": {k: asdict(v) for k, v in self.inbound.items()},
            },
        )

    # -- outbound CRUD ----------------------------------------------------

    def record_outbound(
        self,
        *,
        nonce: str,
        peer_address: str,
        relationship_type: str,
        resource: Optional[str],
        proposal_envelope_json: str,
    ) -> None:
        self.outbound[nonce] = PendingOutbound(
            nonce=nonce,
            peer_address=peer_address,
            relationship_type=relationship_type,
            resource=resource,
            proposal_envelope_json=proposal_envelope_json,
            sent_at=_now_iso(),
        )
        self._save()

    def take_outbound(self, nonce: str) -> Optional[PendingOutbound]:
        """Pop the matching outbound row (one-shot)."""
        row = self.outbound.pop(nonce, None)
        if row is not None:
            self._save()
        return row

    # -- inbound CRUD -----------------------------------------------------

    def record_inbound(
        self,
        *,
        nonce: str,
        proposer_address: str,
        relationship_type: str,
        resource: Optional[str],
        proposal_envelope_json: str,
    ) -> None:
        self.inbound[nonce] = PendingInbound(
            nonce=nonce,
            proposer_address=proposer_address,
            relationship_type=relationship_type,
            resource=resource,
            proposal_envelope_json=proposal_envelope_json,
            received_at=_now_iso(),
        )
        self._save()

    def get_inbound(self, nonce: str) -> Optional[PendingInbound]:
        return self.inbound.get(nonce)

    def take_inbound(self, nonce: str) -> Optional[PendingInbound]:
        row = self.inbound.pop(nonce, None)
        if row is not None:
            self._save()
        return row

    def most_recent_inbound_nonce(self) -> Optional[str]:
        if not self.inbound:
            return None
        return next(reversed(self.inbound))
