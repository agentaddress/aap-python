"""In-memory correlation table for ``aap_send_service_request`` ↔
``aap.service-response/v1``.

The tool fires the request envelope and then awaits a future keyed by
the request nonce. When the adapter's ``_handle_service_response``
dispatcher matches the inbound response's ``request_nonce`` to a
registered future, it resolves it with the parsed response — the tool
returns synchronously to the LLM with the actual confirmation /
denial / pending payload, the same turn.

This is a runtime-only structure (per-process, not persisted). If the
gateway restarts mid-flight the future is lost and the LLM hits the
timeout instead. The mirror in ``_handle_service_response`` only fires
when ``resolve()`` returns False (no waiting tool) so the user is never
notified twice for the same response.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class PendingResponses:
    """Service-response correlation, keyed by request_nonce."""

    def __init__(self) -> None:
        self._futures: dict[str, asyncio.Future] = {}

    def register(self, nonce: str) -> asyncio.Future:
        """Create and store a future for ``nonce``. Replaces any prior
        registration under the same nonce (shouldn't happen in practice —
        nonces are 12-byte random)."""
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._futures[nonce] = future
        return future

    def resolve(self, nonce: str, response: dict[str, Any]) -> bool:
        """If a future is registered for ``nonce``, set its result and
        return True; otherwise return False (caller should fall back to
        mirroring the response to home channels)."""
        future = self._futures.pop(nonce, None)
        if future is None:
            return False
        if future.done():
            return False
        future.set_result(response)
        return True

    def clear(self, nonce: str) -> None:
        self._futures.pop(nonce, None)
