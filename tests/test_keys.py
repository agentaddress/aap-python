import pytest

from aap.keys import (
    decode_b64url,
    encode_b64url,
    generate_keypair,
    sign,
    verify,
)


def test_generate_keypair_returns_32_byte_seeds():
    private_seed, public_key = generate_keypair()
    assert isinstance(private_seed, bytes)
    assert isinstance(public_key, bytes)
    assert len(private_seed) == 32
    assert len(public_key) == 32


def test_sign_then_verify_roundtrip():
    private_seed, public_key = generate_keypair()
    message = b"hello"
    signature = sign(private_seed, message)
    assert len(signature) == 64
    assert verify(public_key, message, signature) is True


def test_verify_rejects_tampered_message():
    private_seed, public_key = generate_keypair()
    signature = sign(private_seed, b"hello")
    assert verify(public_key, b"goodbye", signature) is False


def test_verify_rejects_tampered_signature():
    private_seed, public_key = generate_keypair()
    signature = sign(private_seed, b"hello")
    tampered = bytes([signature[0] ^ 0xff]) + signature[1:]
    assert verify(public_key, b"hello", tampered) is False


def test_verify_rejects_wrong_key():
    private_seed_a, _ = generate_keypair()
    _, public_key_b = generate_keypair()
    signature = sign(private_seed_a, b"hello")
    assert verify(public_key_b, b"hello", signature) is False


def test_b64url_roundtrip():
    for raw in [b"", b"a", b"ab", b"abc", b"\x00\xff" * 32]:
        encoded = encode_b64url(raw)
        assert "=" not in encoded
        assert decode_b64url(encoded) == raw


def test_b64url_decode_rejects_padding():
    with pytest.raises(ValueError):
        decode_b64url("aGVsbG8=")


def test_seed_to_keypair_round_trip():
    """Given a 32-byte seed, return (seed, public_key) consistent with
    generate_keypair()."""
    from aap.keys import generate_keypair, seed_to_keypair, sign, verify
    original_seed, original_public = generate_keypair()
    recovered_seed, recovered_public = seed_to_keypair(original_seed)
    assert recovered_seed == original_seed
    assert recovered_public == original_public

    # The public key works for signature verification end-to-end
    message = b"hello"
    sig = sign(original_seed, message)
    assert verify(recovered_public, message, sig) is True


def test_seed_to_keypair_rejects_wrong_length():
    from aap.keys import seed_to_keypair
    import pytest
    with pytest.raises(ValueError, match="32 bytes"):
        seed_to_keypair(b"short")
