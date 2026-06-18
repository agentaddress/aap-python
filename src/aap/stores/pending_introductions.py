"""Pending-introduction store: nonce-keyed pending discovery introductions.

Indexed by ``verifier_nonce`` because that's what the eventual
``/aap discover approve|deny <nonce>`` command resolves against.

Storage is a flat JSON file at
``<base_dir>/aap-pending-introductions.json``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from aap.storage import write_json_private

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PendingIntroductionRow:
    verifier_nonce: str
    verifier_domain: str
    searcher: str
    searcher_label: Optional[str]
    expires_at: str  # RFC 3339


@dataclass
class PendingIntroductions:
    """Persistent store of pending discovery-introduction-requests.

    Indexed by ``verifier_nonce`` because that's what the eventual
    ``/aap discover approve <nonce>`` resolves against.
    """

    rows: dict[str, PendingIntroductionRow]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-pending-introductions.json"
        self.rows: dict[str, PendingIntroductionRow] = {}

    @classmethod
    def load(cls, base_dir: Path) -> "PendingIntroductions":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to load %s; starting empty", store._path)
            return store
        for nonce, r in (data.get("rows") or {}).items():
            try:
                store.rows[nonce] = PendingIntroductionRow(**r)
            except TypeError:
                logger.warning("Skipping malformed pending-introduction row: %r", r)
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {"rows": {k: asdict(v) for k, v in self.rows.items()}},
        )

    def add(self, row: PendingIntroductionRow) -> None:
        self.rows[row.verifier_nonce] = row
        self._save()

    def get(self, verifier_nonce: str) -> Optional[PendingIntroductionRow]:
        return self.rows.get(verifier_nonce)

    def most_recent_nonce(self) -> Optional[str]:
        """Return the nonce of the most-recently-added pending introduction.

        Used by the bare-word ``approve``/``deny``/``block`` predispatch hook
        so the user can resolve the most recent prompt without typing out the
        nonce — same UX as capability-request consent (see
        ``PendingConsent.most_recent_nonce``). Relies on Python dict
        insertion-order preservation.
        """
        if not self.rows:
            return None
        return next(reversed(self.rows))

    def resolve(self, verifier_nonce: str) -> bool:
        if verifier_nonce in self.rows:
            del self.rows[verifier_nonce]
            self._save()
            return True
        return False
