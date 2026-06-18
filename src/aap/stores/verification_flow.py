"""Pending-verification store: in-flight OTP state.

The user-facing commands (``/aap verify phone``, ``/aap verify email``,
``/aap verify confirm``) live in the host's commands layer. This module
holds the :class:`PendingVerifications` store those commands share —
persistent in-flight verifications keyed by ``otp_id``.

Storage is a flat JSON file at ``<base_dir>/aap-pending-verifications.json``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aap.envelope_policy import parse_rfc3339
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PendingVerificationRow:
    otp_id: str
    identity_type: str            # "phone" | "email"
    identifier_value: str
    verifier_domain: str
    verification_endpoint: str
    expires_at: str               # RFC 3339 hint from the verifier


@dataclass
class PendingVerifications:
    """Persistent map of in-flight verifications, keyed by ``otp_id``."""

    rows: dict[str, PendingVerificationRow]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-pending-verifications.json"
        self.rows: dict[str, PendingVerificationRow] = {}

    @classmethod
    def load(cls, base_dir: Path) -> "PendingVerifications":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to load %s; starting empty", store._path)
            return store
        for otp_id, r in (data.get("rows") or {}).items():
            try:
                store.rows[otp_id] = PendingVerificationRow(**r)
            except TypeError:
                logger.warning(
                    "Skipping malformed pending verification row: %r", r
                )
        store.prune_expired()
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {"rows": {k: asdict(v) for k, v in self.rows.items()}},
        )

    def prune_expired(self, now: datetime | None = None) -> int:
        """Remove expired pending verifications and return the count removed."""
        now = now or datetime.now(timezone.utc)
        expired: list[str] = []
        for otp_id, row in self.rows.items():
            try:
                if parse_rfc3339(row.expires_at) <= now:
                    expired.append(otp_id)
            except ValueError:
                expired.append(otp_id)
        for otp_id in expired:
            del self.rows[otp_id]
        if expired:
            self._save()
        return len(expired)

    def add(self, row: PendingVerificationRow) -> None:
        self.prune_expired()
        for otp_id, existing in list(self.rows.items()):
            if (
                existing.identity_type == row.identity_type
                and existing.identifier_value == row.identifier_value
                and existing.verifier_domain == row.verifier_domain
            ):
                del self.rows[otp_id]
        self.rows[row.otp_id] = row
        self._save()

    def get(self, otp_id: str) -> Optional[PendingVerificationRow]:
        return self.rows.get(otp_id)

    def find_one(self) -> Optional[PendingVerificationRow]:
        """Convenience: when there is exactly one in-flight verification,
        return it so ``/aap verify confirm <code>`` does not need the
        otp_id. Returns None if there are zero or more than one."""
        self.prune_expired()
        if len(self.rows) == 1:
            return next(iter(self.rows.values()))
        return None

    def remove(self, otp_id: str) -> bool:
        """Remove the row with *otp_id*. Returns True if it was present."""
        if otp_id in self.rows:
            del self.rows[otp_id]
            self._save()
            return True
        return False
