import pytest

from aap.address import Address


def test_parse_simple_address():
    a = Address.parse("chris^chrisevans.id")
    assert a.localpart == "chris"
    assert a.domain == "chrisevans.id"


def test_str_roundtrip():
    raw = "james^bob.example"
    assert str(Address.parse(raw)) == raw


def test_localpart_allows_dots_dashes_underscores():
    a = Address.parse("bob.smith_2-a^example.com")
    assert a.localpart == "bob.smith_2-a"


def test_reject_legacy_prefix():
    with pytest.raises(ValueError):
        Address.parse("agent:chris@chrisevans.id")


def test_reject_missing_separator():
    with pytest.raises(ValueError, match="must contain '\\^'"):
        Address.parse("chrischrisevans.id")


def test_reject_empty_localpart():
    with pytest.raises(ValueError, match="localpart cannot be empty"):
        Address.parse("^chrisevans.id")


def test_reject_empty_domain():
    with pytest.raises(ValueError, match="domain cannot be empty"):
        Address.parse("chris^")


def test_parse_user_input_expands_hosted_shorthand():
    a = Address.parse_user_input("chris^")
    assert a.localpart == "chris"
    assert a.domain == "agentaddress.org"
    assert str(a) == "chris^agentaddress.org"


def test_parse_user_input_expands_case_normalized_shorthand():
    a = Address.parse_user_input(" Chris+Bot^ ")
    assert str(a) == "chris+bot^agentaddress.org"


def test_parse_user_input_preserves_explicit_domain():
    a = Address.parse_user_input("Chris^Example.COM")
    assert str(a) == "chris^example.com"


def test_parse_user_input_accepts_custom_default_domain():
    a = Address.parse_user_input("chris^", default_domain="example.com")
    assert str(a) == "chris^example.com"


def test_parse_user_input_invalid_shorthand_still_uses_strict_validation():
    with pytest.raises(ValueError, match="localpart cannot be empty"):
        Address.parse_user_input("^")
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse_user_input("chris^^")
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse_user_input("bad name^")


def test_reject_invalid_localpart_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse("chris!^chrisevans.id")


def test_address_is_hashable():
    a = Address.parse("chris^chrisevans.id")
    b = Address.parse("chris^chrisevans.id")
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_domain_is_lowercased():
    a = Address.parse("chris^CHRISEVANS.ID")
    assert a.domain == "chrisevans.id"


def test_localpart_is_lowercased():
    """Localpart is case-insensitive: Chris-work^ and chris-work^ route to the
    same agent. Mirrors the email convention most providers actually follow
    and prevents LLM capitalization from silently misrouting envelopes."""
    a = Address.parse("Chris^chrisevans.id")
    assert a.localpart == "chris"


def test_mixed_case_address_normalizes_both_parts():
    a = Address.parse("Chris-Work^AgentAddress.ORG")
    assert a.localpart == "chris-work"
    assert a.domain == "agentaddress.org"
    assert str(a) == "chris-work^agentaddress.org"


def test_case_insensitive_equality():
    """Two parses of differently-cased inputs must compare equal and hash
    identically — required for set membership in token stores keyed by Address."""
    a = Address.parse("Chris-Work^example.com")
    b = Address.parse("chris-work^example.com")
    assert a == b
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_reject_invalid_domain_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse("chris^evil .com")
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse("chris^evil/path.com")
    with pytest.raises(ValueError, match="invalid characters"):
        Address.parse("chris^:8080.com")


def test_reject_localpart_too_long():
    long_local = "a" * 65
    with pytest.raises(ValueError, match="localpart too long"):
        Address.parse(f"{long_local}^example.com")


def test_reject_domain_too_long():
    long_domain = ("a" * 60 + ".") * 5  # > 253
    with pytest.raises(ValueError, match="domain too long"):
        Address.parse(f"chris^{long_domain}com")


def test_accept_localpart_at_64():
    addr = Address.parse(f"{'a' * 64}^example.com")
    assert len(addr.localpart) == 64
