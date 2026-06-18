"""Conformance vectors. These pin the wire format.

If any test in this file changes its expected value, that is a
breaking change to the wire format and requires a version bump.
"""

import json
from pathlib import Path

import pytest

from aap.envelope import Envelope
from aap.keys import decode_b64url, sign

VECTORS_PATH = Path(__file__).parent / "vectors" / "envelopes.json"


def _vectors() -> list[dict]:
    return json.loads(VECTORS_PATH.read_text())["vectors"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_canonical_bytes_match(vector):
    env = Envelope.from_dict(vector["envelope_unsigned"])
    assert env.canonical_bytes().hex() == vector["canonical_bytes_hex"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_signature_matches(vector):
    private_seed = bytes.fromhex(vector["private_seed_hex"])
    env = Envelope.from_dict(vector["envelope_unsigned"])
    signature = sign(private_seed, env.canonical_bytes())
    from aap.keys import encode_b64url
    assert encode_b64url(signature) == vector["signature_b64url"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_signed_envelope_verifies(vector):
    public_key = decode_b64url(vector["public_key_b64url"])
    env = Envelope.from_json(vector["envelope_signed_json"])
    assert env.verify(public_key) is True
