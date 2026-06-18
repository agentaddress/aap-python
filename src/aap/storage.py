"""Private local-file storage helpers for SDK-managed JSON state."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json_private(
    path: Path,
    data: Any,
    *,
    indent: int | None = 2,
    sort_keys: bool = False,
    default: Any = None,
) -> None:
    """Atomically write JSON to *path* with mode 0600.

    SDK state files can contain private keys, contact metadata, relationship
    proofs, attestations, and replay material. Relying on the process umask is
    too soft for those files, so every write goes through a private temp file
    and an atomic replace.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    text = json.dumps(data, indent=indent, sort_keys=sort_keys, default=default)
    tmp.write_text(text)
    tmp.chmod(0o600)
    tmp.replace(path)
