"""Host policy for the trust/capability layer.

Encodes the recommended defaults from the trust spec's Host Policy table:

- Token lifetime: 30 days default; 7 days for wildcard / explicitly
  high-risk capabilities.
- Auto-renewal: allowed for low-risk if peer still approved and no scope
  expansion; high-risk always re-prompts.

v0.7.0 note: with the Rev 2 permission-identifier model, scopes no longer
carry a verb. Risk class is now sourced from the publisher's capability
catalog (``risk: high|medium|low``). Until catalog integration lands in
the adapter's risk-decisioning path, we treat only the wildcard ``*`` as
high-risk by default. Callers with catalog-derived risk classes can pass
the appropriate scopes to :func:`token_lifetime_days` directly.
"""

from __future__ import annotations

WILDCARD = "*"

DEFAULT_LIFETIME_DAYS = 30
HIGH_RISK_LIFETIME_DAYS = 7


def is_high_risk_scope(scope: str) -> bool:
    """Conservative built-in: only the wildcard is high-risk without
    catalog lookup. Catalog-aware callers should consult the publisher
    ``risk`` field directly."""
    return scope == WILDCARD


def token_lifetime_days(scopes: list[str], requested: int) -> int:
    """Clamp the requester's preferred lifetime against host policy.

    If any scope is high-risk, the entire token's lifetime is clamped to
    the high-risk cap. Otherwise the default cap applies. We always
    honor a smaller requested value.
    """
    if any(is_high_risk_scope(s) for s in scopes):
        cap = HIGH_RISK_LIFETIME_DAYS
    else:
        cap = DEFAULT_LIFETIME_DAYS
    return min(cap, max(1, requested))


def should_auto_renew(
    scopes: list[str],
    peer_currently_approved: bool,
    scope_expansion: bool,
) -> bool:
    if any(is_high_risk_scope(s) for s in scopes):
        return False
    if scope_expansion:
        return False
    if not peer_currently_approved:
        return False
    return True
