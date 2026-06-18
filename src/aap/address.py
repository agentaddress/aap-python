"""AAP address: <localpart>^<domain>.

Localpart accepts ASCII alphanumerics, '.', '-', '_'. Case-insensitive
— normalised to lowercase on parse so ``Chris-work`` and ``chris-work``
route to the same agent. Max length 64.

Domain accepts ASCII alphanumerics, '.', '-'. Normalised to lowercase
on parse (DNS labels are case-insensitive). Max length 253.

The ``^`` separator was chosen because it (a) is easy to type
(shift+6 on the number row), (b) is shell- and URL-safe in practice,
and (c) appears in neither the localpart nor the domain grammar, so
the split is unambiguous. The format intentionally does not resemble
an email address.

DNS-level checks (label length, leading/trailing hyphen, IDN punycode)
happen at resolution time, not parse time.
"""

from dataclasses import dataclass

_LOCALPART_MAX = 64
_DOMAIN_MAX = 253
# `+` is allowed in the localpart so derivative addresses like
# `chris+work^…` parse cleanly. The address-claim system uses the
# part before the first `+` as the base; for parsing purposes here `+`
# is just another permitted character.
_ALLOWED_LOCALPART_EXTRA = frozenset(".-_+")
_ALLOWED_DOMAIN_EXTRA = frozenset(".-")


def _valid_localpart_char(c: str) -> bool:
    return (c.isalnum() and c.isascii()) or (c in _ALLOWED_LOCALPART_EXTRA)


def _valid_domain_char(c: str) -> bool:
    return (c.isalnum() and c.isascii()) or (c in _ALLOWED_DOMAIN_EXTRA)


@dataclass(frozen=True)
class Address:
    localpart: str
    domain: str

    @classmethod
    def parse(cls, s: str) -> "Address":
        if "^" not in s:
            raise ValueError(f"AAP address must contain '^': {s!r}")
        localpart, domain = s.rsplit("^", 1)
        if not localpart:
            raise ValueError("localpart cannot be empty")
        if not domain:
            raise ValueError("domain cannot be empty")
        if len(localpart) > _LOCALPART_MAX:
            raise ValueError(
                f"localpart too long ({len(localpart)} > {_LOCALPART_MAX})"
            )
        if not all(_valid_localpart_char(c) for c in localpart):
            raise ValueError(f"localpart contains invalid characters: {localpart!r}")
        localpart = localpart.lower()
        if len(domain) > _DOMAIN_MAX:
            raise ValueError(f"domain too long ({len(domain)} > {_DOMAIN_MAX})")
        domain = domain.lower()
        if not all(_valid_domain_char(c) for c in domain):
            raise ValueError(f"domain contains invalid characters: {domain!r}")
        return cls(localpart=localpart, domain=domain)

    def __str__(self) -> str:
        return f"{self.localpart}^{self.domain}"
