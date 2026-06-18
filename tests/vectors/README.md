# Conformance vectors

`envelopes.json` holds signed-envelope vectors that pin the AAP wire
format. They are intended as reference fixtures for any AAP
implementation (Python, Go, Rust, etc.) — load the unsigned envelope,
canonicalize it, sign with the documented seed, and your output should
match the recorded `canonical_bytes_hex`, `signature_b64url`, and
`envelope_signed_json`.

## When to regenerate

Regenerate when:

- A vector's contents need to change (e.g. a hostname rename, a new
  payload type, an additional vector for broader coverage).
- The canonicalization rules change (rare — that's a wire-format
  breaking change and requires a version bump).

Do **not** regenerate when adjusting Python-only behavior. The vectors
are the wire spec, not the SDK's test data.

## How to regenerate

From the repo root, with the SDK importable:

```
python tests/vectors/regenerate.py
```

The script uses the fixed test seed
`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`
(documented inside the resulting JSON) so output is fully
reproducible.

After regenerating, run `pytest tests/test_conformance.py` to confirm
the new vectors round-trip correctly.

## Adding a new vector

Add a new envelope construction to `regenerate.py`, append a
`_build_vector(...)` call to `vectors`, then re-run the script.
Conformance tests pick up new entries automatically (they iterate the
JSON file).

## Hostname convention

Vector contents use the RFC 2606 `.example` TLD (`relay.example`,
`bob.example`) so the fixtures don't ship deployment-specific brand
names.
