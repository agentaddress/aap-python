"""Tests for private SDK JSON file writes."""

import json
import stat

from aap.envelope import Envelope
from aap.envelope_policy import EnvelopeReplayCache
from aap.keys import generate_keypair
from aap.storage import write_json_private
from aap.stores.verification_flow import PendingVerificationRow, PendingVerifications


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_write_json_private_creates_mode_0600(tmp_path):
    path = tmp_path / "state.json"
    write_json_private(path, {"secret": "value"})

    assert json.loads(path.read_text()) == {"secret": "value"}
    assert _mode(path) == 0o600


def test_write_json_private_restricts_existing_permissive_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{}")
    path.chmod(0o644)

    write_json_private(path, {"secret": "value"})

    assert json.loads(path.read_text()) == {"secret": "value"}
    assert _mode(path) == 0o600


def test_pending_verifications_store_writes_private_file(tmp_path):
    store = PendingVerifications.load(tmp_path)
    store.add(
        PendingVerificationRow(
            otp_id="otp-1",
            identity_type="phone",
            identifier_value="+15555550100",
            verifier_domain="verify.example.com",
            verification_endpoint="https://verify.example.com/aap/verify",
            expires_at="2026-06-15T12:00:00Z",
        )
    )

    assert _mode(tmp_path / "aap-pending-verifications.json") == 0o600


def test_envelope_replay_cache_writes_private_file(tmp_path):
    seed, _public = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="test/v1",
        payload={"nonce": "n"},
        iss="alice^example.com",
        iat="2026-06-15T12:00:00Z",
    ).sign(seed)
    cache_path = tmp_path / "replay.json"

    EnvelopeReplayCache(path=cache_path).check_and_store(f"{env.iss}:{env.sig}")

    assert _mode(cache_path) == 0o600
