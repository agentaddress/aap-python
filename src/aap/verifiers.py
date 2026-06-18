"""Trusted-verifier list management and verifier-pubkey lookup.

Two responsibilities:

1. Maintain the merged list of trusted verifiers — the standards-body
   published list (fetched from ``$AAP_TRUSTED_VERIFIERS_URL`` or the
   default ``https://api.agentaddress.org/.well-known/aap-trusted-verifiers``)
   plus any local overrides from an explicit ``overrides_path``.
   The published list is accepted only as a signed AAP envelope and cached on
   disk as that signed envelope for 24 h.

2. Resolve verifier Ed25519 public keys from the signed trust list. The key is
   used to verify signatures on attestation and discovery-response envelopes.

All cache I/O paths are injected via constructor parameters; this
module performs no environment lookups. Callers are responsible for
choosing where to store cache files.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import httpx

from aap.envelope import Envelope
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.keys import decode_b64url
from aap.storage import write_json_private
from aap.transport import require_secure_url
from aap.trusted_verifiers import VerifierTrustListEntry, parse_trusted_verifiers

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# The trust-list document — a directory of which verifiers to honor for
# which identity types. This is the TRUST LIST host (the "directory"), not
# the verifier itself; the verifier endpoint (e.g. verify.agentaddress.org)
# is discovered from inside this document, not hardcoded.
#
# Override at runtime with ``AAP_TRUSTED_VERIFIERS_URL`` if you operate
# your own list. Points at the reference deployment: relay at
# ``api.agentaddress.org``, verifier at ``verify.agentaddress.org``.
DEFAULT_TRUSTED_VERIFIERS_URL = (
    "https://api.agentaddress.org/.well-known/aap-trusted-verifiers"
)
TRUSTED_VERIFIERS_PAYLOAD_TYPE = "aap.trusted-verifiers/v1"
TRUSTED_VERIFIERS_ISSUER = "aap-trust-root^agentaddressprotocol.org"
TRUST_LIST_TTL_SECONDS = 24 * 60 * 60


# ---------------------------------------------------------------------------
# Module-level pure helpers
# ---------------------------------------------------------------------------


def _entry_from_dict(d: dict) -> VerifierTrustListEntry:
    # Validate via the upstream parser to keep enforcement consistent.
    parsed = parse_trusted_verifiers({"verifiers": [d]})
    return parsed[0]


def trusted_verifiers_supporting(
    entries: list[VerifierTrustListEntry],
    identity_type: str,
) -> list[VerifierTrustListEntry]:
    """Return entries from *entries* that support *identity_type*.

    Pure function — no I/O, no caching. Callers obtain the full entry list
    from a :class:`TrustListCache` instance and then filter here.
    """
    return [e for e in entries if identity_type in e.supported_identities]


def verifier_relay_address(verifier_domain: str) -> str:
    """Conventional AAP address for a verifier's relay agent."""
    return f"verifier^{verifier_domain}"


# ---------------------------------------------------------------------------
# TrustListCache
# ---------------------------------------------------------------------------


class TrustListCache:
    """Async fetcher + on-disk cache for the standards-body trust list.

    Designed to be a long-lived instance (one per process). Concurrent
    ``get()`` calls coalesce via an ``asyncio.Lock`` so multiple flows
    starting at once don't hammer the trust-list endpoint.

    Parameters
    ----------
    cache_path:
        Path to the on-disk JSON cache file (e.g.
        ``~/.myapp/aap-trusted-verifiers.json``).
    overrides_path:
        Path to the local overrides JSON file (e.g.
        ``~/.myapp/aap-trusted-verifiers-overrides.json``). Need not exist.
    url:
        Trust-list URL. Falls back to the ``AAP_TRUSTED_VERIFIERS_URL``
        env var, then :data:`DEFAULT_TRUSTED_VERIFIERS_URL`.
    trust_list_public_key:
        Ed25519 public key for the standards-body trust-list signer.
    client:
        Optional shared ``httpx.AsyncClient``. If omitted, one is created
        and closed with :meth:`aclose`.
    ttl_seconds:
        How long to consider the cached response fresh. Defaults to 24 h.
    """

    def __init__(
        self,
        *,
        cache_path: Path,
        overrides_path: Path,
        trust_list_public_key: bytes,
        url: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        ttl_seconds: int = TRUST_LIST_TTL_SECONDS,
    ) -> None:
        self._cache_path = cache_path
        self._overrides_path = overrides_path
        self._trust_list_public_key = trust_list_public_key
        self._url = (
            require_secure_url(url, field_name="trust-list URL")
            if url is not None
            else None
        )
        self._client = client or httpx.AsyncClient(timeout=10.0)
        self._owns_client = client is None
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()
        # In-process cache; mirrors the on-disk payload.
        self._cached_body: Optional[dict] = None
        self._cached_at: float = 0.0

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _resolved_url(self) -> str:
        # Resolved per-call so env override is picked up in tests.
        return require_secure_url(
            self._url
            or os.getenv(
                "AAP_TRUSTED_VERIFIERS_URL", DEFAULT_TRUSTED_VERIFIERS_URL
            ),
            field_name="trust-list URL",
        )

    async def get(self) -> list[VerifierTrustListEntry]:
        """Return the merged trust list (published list + local overrides).

        Network failures fall back to the on-disk cache (even if stale)
        so the agent can keep operating offline. If both fail, returns
        an empty list and logs.
        """
        body = await self._get_published_body()
        try:
            entries = (
                parse_trusted_verifiers(body) if body is not None else []
            )
        except ValueError:
            logger.exception("Trust list parse failed")
            entries = []
        return self._apply_overrides(entries, self._load_overrides())

    async def _get_published_body(self) -> Optional[dict]:
        async with self._lock:
            now = time.time()
            if (
                self._cached_body is not None
                and now - self._cached_at < self._ttl
            ):
                return self._cached_body

            disk = self._read_disk_cache()
            if disk is not None and now - disk["fetched_at"] < self._ttl:
                self._cached_body = disk["body"]
                self._cached_at = disk["fetched_at"]
                return self._cached_body

            fetched = await self._fetch_remote()
            if fetched is not None:
                self._cached_body = fetched
                self._cached_at = now
                self._write_disk_cache(fetched, now)
                return fetched

            # Network failed — fall back to whatever's on disk, even if stale.
            if disk is not None:
                logger.warning(
                    "Trust-list fetch failed; using stale on-disk cache"
                )
                self._cached_body = disk["body"]
                self._cached_at = disk["fetched_at"]
                return self._cached_body
            return None

    async def _fetch_remote(self) -> Optional[dict]:
        url = self._resolved_url()
        try:
            resp = await self._client.get(url)
        except Exception as e:
            logger.warning("Trust-list fetch error from %s: %s", url, e)
            return None
        if resp.status_code != 200:
            logger.warning(
                "Trust-list fetch HTTP %s from %s", resp.status_code, url
            )
            return None
        try:
            return self._verified_body_from_envelope(resp.text)
        except Exception as e:
            logger.warning("Trust-list response is not a trusted envelope: %s", e)
            return None

    def _read_disk_cache(self) -> Optional[dict]:
        if not self._cache_path.exists():
            return None
        try:
            data = json.loads(self._cache_path.read_text())
            if not isinstance(data, dict):
                return None
            if "envelope_json" not in data or "fetched_at" not in data:
                return None
            body = self._verified_body_from_envelope(data["envelope_json"])
            return {"fetched_at": data["fetched_at"], "body": body}
        except Exception:
            logger.warning("Trust-list disk cache unreadable", exc_info=True)
            return None

    def _write_disk_cache(self, body: dict, fetched_at: float) -> None:
        envelope_json = body["_signed_envelope_json"]
        write_json_private(
            self._cache_path,
            {"fetched_at": fetched_at, "envelope_json": envelope_json},
        )

    def _verified_body_from_envelope(self, envelope_json: str) -> dict:
        env = Envelope.from_json(envelope_json)
        if env.payload_type != TRUSTED_VERIFIERS_PAYLOAD_TYPE:
            raise ValueError("unexpected trust-list payload_type")
        if env.iss != TRUSTED_VERIFIERS_ISSUER:
            raise ValueError("unexpected trust-list issuer")
        try:
            verify_envelope(env, self._trust_list_public_key)
        except EnvelopePolicyError as e:
            raise ValueError(f"trust-list signature or freshness failed: {e}") from e
        if not isinstance(env.payload, dict):
            raise ValueError("trust-list payload must be a dict")
        parse_trusted_verifiers(env.payload)
        body = dict(env.payload)
        body["_signed_envelope_json"] = envelope_json
        return body

    def _load_overrides(self) -> dict:
        if not self._overrides_path.exists():
            return {}
        try:
            data = json.loads(self._overrides_path.read_text())
        except Exception:
            logger.warning("Overrides file unreadable; ignoring", exc_info=True)
            return {}
        return data if isinstance(data, dict) else {}

    def _apply_overrides(
        self,
        base: list[VerifierTrustListEntry],
        overrides: dict,
    ) -> list[VerifierTrustListEntry]:
        """Merge published list with local overrides.

        - ``remove`` (list of domains): drop these from the published list.
        - ``add`` (list of verifier-entry dicts): add these to the result.

        ``remove`` is applied first; ``add`` always runs. If an added entry
        duplicates a remaining domain, the override wins (replaces).
        """
        removed = set(overrides.get("remove") or [])
        pruned = [e for e in base if e.domain not in removed]
        add_specs = overrides.get("add") or []
        by_domain = {e.domain: e for e in pruned}
        for spec in add_specs:
            try:
                entry = _entry_from_dict(spec)
            except Exception:
                logger.warning(
                    "Skipping malformed override add-entry: %r", spec
                )
                continue
            by_domain[entry.domain] = entry
        return list(by_domain.values())


# ---------------------------------------------------------------------------
# VerifierPubkeyCache
# ---------------------------------------------------------------------------


class VerifierPubkeyCache:
    """In-process cache of verifier Ed25519 pubkeys.

    Looked up from the signed trust-list entry. Returns ``None`` if the domain
    isn't trusted or the signed entry carries a malformed key.

    Parameters
    ----------
    client:
        Optional shared ``httpx.AsyncClient``. If omitted, one is created
        and closed with :meth:`aclose`.
    """

    def __init__(
        self,
        *,
        cache_dir: Path,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._cache_dir = cache_dir
        self._client = client or httpx.AsyncClient(timeout=10.0)
        self._owns_client = client is None
        self._cache: dict[str, Optional[bytes]] = {}
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def get(
        self,
        domain: str,
        trust_list: list[VerifierTrustListEntry],
    ) -> Optional[bytes]:
        """Return the raw Ed25519 public-key bytes for *domain*.

        Parameters
        ----------
        domain:
            The verifier domain to look up.
        trust_list:
            Current trust-list entries (obtained from
            :class:`TrustListCache`). If *domain* is not present, returns
            ``None`` immediately.
        """
        async with self._lock:
            if domain in self._cache:
                return self._cache[domain]

        entry = next((e for e in trust_list if e.domain == domain), None)
        if entry is None:
            return None
        try:
            pubkey = decode_b64url(entry.public_key)
        except Exception:
            return None
        if len(pubkey) != 32:
            return None
        async with self._lock:
            self._cache[domain] = pubkey
        return pubkey
