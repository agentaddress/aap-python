"""TOFU identity-binding store.

When a peer's AgentCard contains ``verified_identities`` that match a
local contact, and the user confirms the binding via the first-contact
prompt, this store records the binding so future requests from that
address render with the contact's label without re-prompting.

Storage at ``<base_dir>/aap-identity-bindings.json``.
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


@dataclass
class IdentityBinding:
    peer_address: str
    contact_id: str
    matched_identifier: dict[str, str]
    bound_at: str


@dataclass
class IdentityBindingStore:
    bindings: list[IdentityBinding]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-identity-bindings.json"
        self.bindings: list[IdentityBinding] = []

    @classmethod
    def load(cls, base_dir: Path) -> "IdentityBindingStore":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to load %s; starting empty", store._path)
            return store
        store.bindings = [
            IdentityBinding(**b) for b in data.get("bindings") or []
        ]
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {"bindings": [asdict(b) for b in self.bindings]},
        )

    def bind(
        self,
        peer_address: str,
        contact_id: str,
        matched_identifier: dict[str, str],
    ) -> IdentityBinding:
        self.bindings = [b for b in self.bindings if b.peer_address != peer_address]
        binding = IdentityBinding(
            peer_address=peer_address,
            contact_id=contact_id,
            matched_identifier=dict(matched_identifier),
            bound_at=datetime.now(timezone.utc).isoformat(),
        )
        self.bindings.append(binding)
        self._save()
        return binding

    def unbind(self, peer_address: str) -> bool:
        before = len(self.bindings)
        self.bindings = [b for b in self.bindings if b.peer_address != peer_address]
        if len(self.bindings) < before:
            self._save()
            return True
        return False

    def binding_for(self, peer_address: str) -> Optional[IdentityBinding]:
        for b in self.bindings:
            if b.peer_address == peer_address:
                return b
        return None

    def addresses_bound_to(self, contact_id: str) -> list[str]:
        return [b.peer_address for b in self.bindings if b.contact_id == contact_id]
