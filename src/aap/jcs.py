"""JCS (RFC 8785) canonicalisation.

Thin wrapper over the rfc8785 package so the rest of the library
has one import path and one place to swap implementations.
"""

import rfc8785


def canonicalize(value: object) -> bytes:
    """Canonicalise a JSON-serialisable value into RFC 8785 bytes.

    Raises:
        rfc8785.IntegerDomainError: integer out of range.
        rfc8785.CanonicalizationError: value not JSON-serialisable.
    """
    return rfc8785.dumps(value)
