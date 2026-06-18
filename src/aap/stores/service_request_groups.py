"""Persistent index mapping service-request nonces to group conversation IDs.

Stored at ``<base_dir>/aap-service-request-groups.json`` so it survives
gateway restarts — the response may arrive minutes after the request was sent.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aap.storage import write_json_private

logger = logging.getLogger(__name__)


class ServiceRequestGroupIndex:
    """Persists nonce → group_conversation_id so that when a service
    response arrives asynchronously, _handle_service_response knows which
    group session to update via aap_group_send.

    Assumes a single-writer context: there is no internal locking, so
    concurrent ``record`` / ``pop`` from multiple threads or tasks risks
    lost updates via read-modify-write races.
    """

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-service-request-groups.json"

    def _load(self) -> dict[str, str]:
        try:
            with open(self._path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self, data: dict[str, str]) -> None:
        try:
            write_json_private(self._path, data)
        except OSError:
            logger.exception("Failed to save service-request-group index")

    def record(self, nonce: str, conversation_id: str) -> None:
        data = self._load()
        data[nonce] = conversation_id
        self._save(data)

    def pop(self, nonce: str) -> str | None:
        data = self._load()
        conv_id = data.pop(nonce, None)
        if conv_id is not None:
            self._save(data)
        return conv_id
