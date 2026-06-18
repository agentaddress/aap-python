"""Pending-consent store: nonce-keyed pending-action state.

Each entry is opaque to this class — callers stash whatever they need
under any key and look it up by nonce later. Used by the group flow to
park inbound invitations until the user accepts or declines.

Storage is a flat JSON file at ``<base_dir>/aap-pending-consents.json``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from aap.storage import write_json_private

logger = logging.getLogger(__name__)


class PendingConsent:
    """Nonce-keyed pending-action store.

    Each entry is opaque to this class — callers stash whatever they need
    under any key and look it up by nonce later.
    """

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-pending-consents.json"
        self._entries: dict[str, dict[str, Any]] = {}

    @classmethod
    def load(cls, base_dir: Path) -> "PendingConsent":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            store._entries = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to load %s; starting empty", store._path)
        return store

    def _save(self) -> None:
        write_json_private(self._path, self._entries)

    def add(
        self,
        nonce: str,
        peer_address: str,
        request_dict: dict[str, Any],
    ) -> None:
        self._entries[nonce] = {
            "peer_address": peer_address,
            "request": request_dict,
        }
        self._save()

    def get(self, nonce: str) -> Optional[dict[str, Any]]:
        return self._entries.get(nonce)

    def most_recent_nonce(self) -> Optional[str]:
        if not self._entries:
            return None
        return next(reversed(self._entries))

    def resolve(self, nonce: str) -> bool:
        """Remove the entry for *nonce*. Returns True if it was present."""
        if nonce in self._entries:
            del self._entries[nonce]
            self._save()
            return True
        return False
