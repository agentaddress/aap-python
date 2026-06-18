"""Tracks "I deliberately contacted this peer" timestamps so a business
agent we reached out to can reply within a bounded window — and so any
OTHER business can't send unsolicited chat to us.

The chat gate's "if sender has a catalog, accept" check would be a spam
vector: anyone can publish a catalog. The real signal is consent —
*we* initiated, so *they* may reply for a while.

Recorded by every outbound path that opens a conversation with a
non-relationship peer (``aap_send_message`` to a business,
``aap_send_service_request``). Consulted by the adapter's chat-gate
fallback for inbound business chat.

Storage: ``<base_dir>/aap-outbound-contacts.json``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from aap.storage import write_json_private

logger = logging.getLogger(__name__)


# How long after our last outbound a business may reply unsolicited.
DEFAULT_REPLY_WINDOW = timedelta(hours=24)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class OutboundContactStore:
    """Per-peer last-contacted-at timestamps. Update is idempotent on
    same-day calls (just rewrites the most recent ts)."""

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-outbound-contacts.json"
        self._contacts: dict[str, str] = {}

    @classmethod
    def load(cls, base_dir: Path) -> "OutboundContactStore":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("failed to load %s; starting empty", store._path)
            return store
        store._contacts = dict(data.get("contacts") or {})
        return store

    def _save(self) -> None:
        write_json_private(self._path, {"contacts": self._contacts})

    def record(self, peer_address: str, *, when: Optional[datetime] = None) -> None:
        when = when or datetime.now(timezone.utc)
        self._contacts[peer_address] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._save()

    def last_contact(self, peer_address: str) -> Optional[datetime]:
        ts = self._contacts.get(peer_address)
        if ts is None:
            return None
        try:
            return _parse_iso(ts)
        except Exception:
            return None

    def contacted_within(
        self,
        peer_address: str,
        *,
        window: timedelta = DEFAULT_REPLY_WINDOW,
        now: Optional[datetime] = None,
    ) -> bool:
        last = self.last_contact(peer_address)
        if last is None:
            return False
        now = now or datetime.now(timezone.utc)
        return (now - last) <= window
