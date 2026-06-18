"""Storage + lifecycle for business-initiated recurring outreach.

When a customer transacts with a business and opts into recurring reminders,
the customer's agent issues a :class:`ServiceFollowupGrant` envelope —
stored locally AND sent to the business. The business may later send one
:class:`ServiceFollowup` per cadence window referencing the grant's nonce;
the customer's adapter verifies the reference against this store before
surfacing the followup to the user.

This is the ONE residual token type the new protocol retains. Personal↔
personal traffic uses relationship records (relationships.py); customer→
business uses fresh service_request envelopes per interaction (services.py).
Only business→customer cold outreach needs a token, because the business
needs standing authority to break the silence.

Two stores live side by side:

* ``issued`` — grants WE created and sent to a business. Used (read-only)
  when an inbound ``aap.service-followup/v1`` arrives so we can validate
  the grant_nonce reference.
* ``received`` — grants a customer created and sent to US (we are the
  business). Used to authorize our outbound ``aap.service-followup/v1``
  envelopes.

Storage: ``<base_dir>/aap-followup-grants.json``.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from aap.envelope import Envelope
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import ServiceFollowup, ServiceFollowupGrant
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


_ISO_DURATION_RE = re.compile(
    r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$"
)


def parse_iso_duration(spec: str) -> timedelta:
    """Tiny subset parser for ISO 8601 durations.

    Accepts ``PnYnMnWnDTnHnMnS`` with each component optional. Years and
    months use 365- and 30-day approximations (recurring schedules don't
    need calendar precision). Raises ``ValueError`` on malformed input.
    """
    m = _ISO_DURATION_RE.match(spec)
    if not m or spec == "P":
        raise ValueError(f"invalid ISO 8601 duration: {spec!r}")
    years, months, weeks, days, hours, minutes, seconds = (
        int(g) if g else 0 for g in m.groups()
    )
    total_days = years * 365 + months * 30 + weeks * 7 + days
    return timedelta(
        days=total_days, hours=hours, minutes=minutes, seconds=seconds
    )


@dataclass(frozen=True)
class StoredFollowupGrant:
    """One row in the grant store. Holds the parsed grant fields plus the
    signed envelope JSON (which is what gets transmitted on the wire)."""

    direction: str                # "issued" | "received"
    counterparty: str             # business address (if issued) or customer (if received)
    service_id: str
    cadence_iso: str
    outreach_window_before: str
    valid_until: str
    nonce: str
    issued_at: str
    grant_envelope_json: str
    last_used_at: Optional[str] = None

    def is_within_lifetime(self, *, now: Optional[datetime] = None) -> bool:
        try:
            return _parse_iso(self.valid_until) > (now or _now_utc())
        except ValueError:
            return False

    def is_within_outreach_window(self, *, now: Optional[datetime] = None) -> bool:
        """The business may only send a followup during the window that ends
        at ``last_used_at + cadence`` (or grant issuance + cadence if never
        used) and begins ``outreach_window_before`` earlier."""
        try:
            cadence = parse_iso_duration(self.cadence_iso)
            window = parse_iso_duration(self.outreach_window_before)
        except ValueError:
            return False
        anchor = _parse_iso(self.last_used_at or self.issued_at)
        next_due = anchor + cadence
        window_start = next_due - window
        now = now or _now_utc()
        # Window stretches from window_start to next_due + (small slack). We
        # don't enforce a hard upper bound — if the business is late, that's
        # fine. Only the early-side gate matters.
        return now >= window_start


@dataclass
class FollowupGrantStore:
    rows: list[StoredFollowupGrant] = field(default_factory=list)

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-followup-grants.json"
        self.rows: list[StoredFollowupGrant] = []

    @classmethod
    def load(cls, base_dir: Path) -> "FollowupGrantStore":
        store = cls(base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("failed to load %s; starting empty", store._path)
            return store
        rows: list[StoredFollowupGrant] = []
        for r in data.get("grants") or []:
            try:
                rows.append(StoredFollowupGrant(**r))
            except TypeError:
                logger.warning("skipping malformed grant row: %r", r)
        store.rows = rows
        return store

    def _save(self) -> None:
        write_json_private(self._path, {"grants": [asdict(r) for r in self.rows]})

    # -- store --------------------------------------------------------------

    def record_issued(
        self,
        *,
        business_address: str,
        grant_envelope_json: str,
        business_public_key: bytes,
    ) -> StoredFollowupGrant:
        """Persist a grant we created for a business."""
        return self._record(
            direction="issued",
            counterparty=business_address,
            grant_envelope_json=grant_envelope_json,
            counterparty_public_key=business_public_key,
        )

    def record_received(
        self,
        *,
        customer_address: str,
        grant_envelope_json: str,
        customer_public_key: bytes,
    ) -> StoredFollowupGrant:
        """Persist a grant a customer issued to us."""
        return self._record(
            direction="received",
            counterparty=customer_address,
            grant_envelope_json=grant_envelope_json,
            counterparty_public_key=customer_public_key,
        )

    def _record(
        self,
        *,
        direction: str,
        counterparty: str,
        grant_envelope_json: str,
        counterparty_public_key: bytes,
    ) -> StoredFollowupGrant:
        env = Envelope.from_json(grant_envelope_json)
        if env.payload_type != ServiceFollowupGrant.PAYLOAD_TYPE:
            raise ValueError(
                f"expected {ServiceFollowupGrant.PAYLOAD_TYPE!r} envelope, "
                f"got {env.payload_type!r}"
            )
        if env.iss != counterparty:
            raise ValueError(
                f"grant envelope issuer {env.iss!r} does not match "
                f"counterparty {counterparty!r}"
            )
        try:
            verify_envelope(env, counterparty_public_key)
        except EnvelopePolicyError as e:
            raise ValueError(f"grant envelope failed verification: {e}") from e
        grant = ServiceFollowupGrant.from_dict(env.payload)
        if any(r.nonce == grant.nonce for r in self.rows):
            raise ValueError("follow-up grant replay detected: nonce already stored")
        row = StoredFollowupGrant(
            direction=direction,
            counterparty=counterparty,
            service_id=grant.service_id,
            cadence_iso=grant.cadence_iso,
            outreach_window_before=grant.outreach_window_before,
            valid_until=grant.valid_until,
            nonce=grant.nonce,
            issued_at=env.iat,
            grant_envelope_json=grant_envelope_json,
        )
        # Replace any existing grant with the same (counterparty, service_id)
        # — re-granting refreshes the lifecycle.
        self.rows = [
            r for r in self.rows
            if not (
                r.direction == direction
                and r.counterparty == counterparty
                and r.service_id == grant.service_id
            )
        ]
        self.rows.append(row)
        self._save()
        return row

    # -- queries ------------------------------------------------------------

    def find_issued(
        self, *, business_address: str, service_id: str
    ) -> Optional[StoredFollowupGrant]:
        for r in self.rows:
            if (
                r.direction == "issued"
                and r.counterparty == business_address
                and r.service_id == service_id
            ):
                return r
        return None

    def find_received(
        self, *, customer_address: str, service_id: str
    ) -> Optional[StoredFollowupGrant]:
        for r in self.rows:
            if (
                r.direction == "received"
                and r.counterparty == customer_address
                and r.service_id == service_id
            ):
                return r
        return None

    def find_received_by_nonce(self, nonce: str) -> Optional[StoredFollowupGrant]:
        for r in self.rows:
            if r.direction == "received" and r.nonce == nonce:
                return r
        return None

    def find_issued_by_nonce(self, nonce: str) -> Optional[StoredFollowupGrant]:
        for r in self.rows:
            if r.direction == "issued" and r.nonce == nonce:
                return r
        return None

    def stamp_used(self, nonce: str) -> bool:
        for i, r in enumerate(self.rows):
            if r.nonce == nonce:
                # Frozen dataclass — replace with updated copy.
                self.rows[i] = StoredFollowupGrant(
                    direction=r.direction,
                    counterparty=r.counterparty,
                    service_id=r.service_id,
                    cadence_iso=r.cadence_iso,
                    outreach_window_before=r.outreach_window_before,
                    valid_until=r.valid_until,
                    nonce=r.nonce,
                    issued_at=r.issued_at,
                    grant_envelope_json=r.grant_envelope_json,
                    last_used_at=_now_iso(),
                )
                self._save()
                return True
        return False

    def revoke(self, *, counterparty: str, service_id: str, direction: str) -> bool:
        before = len(self.rows)
        self.rows = [
            r for r in self.rows
            if not (
                r.direction == direction
                and r.counterparty == counterparty
                and r.service_id == service_id
            )
        ]
        if len(self.rows) < before:
            self._save()
            return True
        return False


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


def build_followup_grant_envelope(
    *,
    seed: bytes,
    sender_address: str,
    service_id: str,
    cadence_iso: str,
    outreach_window_before: str,
    valid_until: str,
    nonce: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    grant = ServiceFollowupGrant(
        service_id=service_id,
        cadence_iso=cadence_iso,
        outreach_window_before=outreach_window_before,
        valid_until=valid_until,
        nonce=nonce or secrets.token_urlsafe(12),
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=ServiceFollowupGrant.PAYLOAD_TYPE,
        payload=grant.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)


def build_followup_envelope(
    *,
    seed: bytes,
    sender_address: str,
    service_id: str,
    grant_nonce: str,
    message: str,
    suggested_slots: Optional[list[str]] = None,
    nonce: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    fu = ServiceFollowup(
        service_id=service_id,
        grant_nonce=grant_nonce,
        message=message,
        nonce=nonce or secrets.token_urlsafe(12),
        suggested_slots=list(suggested_slots or []),
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=ServiceFollowup.PAYLOAD_TYPE,
        payload=fu.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)
