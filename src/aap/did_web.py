"""Minimal, strict ``did:web`` verification-key resolution for AAP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

from aap.keys import decode_b64url, encode_b64url
from aap.storage import write_json_private

MAX_DID_DOCUMENT_BYTES = 256 * 1024
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class DIDWebError(ValueError):
    """Raised when a did:web document or verification method is invalid."""


class KeyPinChanged(DIDWebError):
    """Raised when a previously pinned public key changes."""


class KeyPins:
    """TOFU pin store for public keys scoped by caller-provided identifier."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._pins: dict[str, str] = {}
        if path is not None and path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                raise DIDWebError(f"failed to load key pins from {path}") from e
            if not isinstance(data, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in data.items()
            ):
                raise DIDWebError(f"invalid key pin store at {path}")
            self._pins = dict(data)

    def check_or_pin(self, identifier: str, public_key: bytes) -> None:
        encoded = encode_b64url(public_key)
        existing = self._pins.get(identifier)
        if existing is not None and existing != encoded:
            raise KeyPinChanged(
                f"verification key changed for {identifier!r}; "
                "clear the pin only after independently verifying the rotation"
            )
        if existing is None:
            self._pins[identifier] = encoded
            self._save()

    def forget(self, identifier: str) -> bool:
        if identifier not in self._pins:
            return False
        del self._pins[identifier]
        self._save()
        return True

    def _save(self) -> None:
        if self._path is None:
            return
        write_json_private(self._path, self._pins, sort_keys=True)


def did_web_document_url(did_url: str) -> str:
    """Convert a did:web DID URL to its HTTPS DID-document URL."""
    did = did_url.split("#", 1)[0]
    if not did.startswith("did:web:"):
        raise DIDWebError(f"unsupported DID method in {did_url!r}")
    method_specific = did.removeprefix("did:web:")
    if not method_specific:
        raise DIDWebError("did:web identifier is empty")
    parts = method_specific.split(":")
    authority = unquote(parts[0])
    if not authority or "/" in authority or "@" in authority:
        raise DIDWebError(f"invalid did:web authority: {authority!r}")
    path = "/".join(parts[1:])
    if path:
        return f"https://{authority}/{path}/did.json"
    return f"https://{authority}/.well-known/did.json"


def did_web_domain(did_url: str) -> str:
    """Return the lowercase host portion of a did:web DID URL."""
    did = did_url.split("#", 1)[0]
    if not did.startswith("did:web:"):
        raise DIDWebError(f"unsupported DID method in {did_url!r}")
    authority = unquote(did.removeprefix("did:web:").split(":", 1)[0])
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        if not host or not port.isdigit():
            raise DIDWebError(f"invalid did:web authority: {authority!r}")
        authority = host
    return authority.lower()


async def resolve_did_web_key(
    did_url: str,
    *,
    client: httpx.AsyncClient,
) -> bytes:
    """Resolve an Ed25519 key authorized for assertions by a did:web document."""
    if "#" not in did_url:
        raise DIDWebError("AAP AgentCard DID must identify a verification-method fragment")
    did, _ = did_url.split("#", 1)
    url = did_web_document_url(did_url)
    try:
        response = await client.get(url)
    except httpx.HTTPError as e:
        raise DIDWebError(f"failed to fetch DID document from {url}: {e}") from e
    if response.status_code != 200:
        raise DIDWebError(f"DID document fetch returned HTTP {response.status_code} from {url}")
    if len(response.content) > MAX_DID_DOCUMENT_BYTES:
        raise DIDWebError(f"DID document from {url} exceeds {MAX_DID_DOCUMENT_BYTES} bytes")
    try:
        document = response.json()
    except (ValueError, json.JSONDecodeError) as e:
        raise DIDWebError(f"DID document from {url} is not valid JSON") from e
    if not isinstance(document, dict) or document.get("id") != did:
        raise DIDWebError(f"DID document id does not match {did!r}")

    method = _authorized_assertion_method(document, did_url)
    controller = method.get("controller")
    if controller != did:
        raise DIDWebError(
            f"verification method controller {controller!r} does not match {did!r}"
        )
    return _ed25519_public_key(method)


def _authorized_assertion_method(
    document: dict[str, Any],
    did_url: str,
) -> dict[str, Any]:
    document_id = document["id"]
    methods: dict[str, dict[str, Any]] = {}
    for value in document.get("verificationMethod") or []:
        if isinstance(value, dict) and isinstance(value.get("id"), str):
            methods[_absolute_did_url(value["id"], document_id)] = value

    for value in document.get("assertionMethod") or []:
        if isinstance(value, str) and _absolute_did_url(value, document_id) == did_url:
            method = methods.get(did_url)
            if method is None:
                raise DIDWebError(f"assertion method {did_url!r} is not defined")
            return method
        if (
            isinstance(value, dict)
            and isinstance(value.get("id"), str)
            and _absolute_did_url(value["id"], document_id) == did_url
        ):
            return value
    raise DIDWebError(f"{did_url!r} is not authorized by assertionMethod")


def _absolute_did_url(value: str, document_id: str) -> str:
    return document_id + value if value.startswith("#") else value


def _ed25519_public_key(method: dict[str, Any]) -> bytes:
    jwk = method.get("publicKeyJwk")
    multibase = method.get("publicKeyMultibase")
    if isinstance(jwk, dict):
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise DIDWebError("verification method JWK must be an Ed25519 OKP key")
        if "d" in jwk:
            raise DIDWebError("DID document must not contain private JWK material")
        x = jwk.get("x")
        if not isinstance(x, str):
            raise DIDWebError("Ed25519 JWK is missing string member 'x'")
        try:
            public_key = decode_b64url(x)
        except ValueError as e:
            raise DIDWebError("Ed25519 JWK member 'x' is invalid base64url") from e
    elif isinstance(multibase, str):
        decoded = _decode_base58btc(multibase)
        if not decoded.startswith(b"\xed\x01"):
            raise DIDWebError("publicKeyMultibase is not an Ed25519 multikey")
        public_key = decoded[2:]
    else:
        raise DIDWebError("verification method lacks supported Ed25519 key material")
    if len(public_key) != 32:
        raise DIDWebError(f"Ed25519 verification key must be 32 bytes, got {len(public_key)}")
    return public_key


def _decode_base58btc(value: str) -> bytes:
    if not value.startswith("z"):
        raise DIDWebError("publicKeyMultibase must use base58-btc")
    encoded = value[1:]
    number = 0
    try:
        for char in encoded:
            number = number * 58 + _BASE58_ALPHABET.index(char)
    except ValueError as e:
        raise DIDWebError("publicKeyMultibase contains an invalid base58 character") from e
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(encoded) - len(encoded.lstrip("1"))
    return (b"\x00" * leading_zeroes) + decoded
