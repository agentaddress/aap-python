from aap.jcs import canonicalize


def test_canonicalize_sorts_object_keys():
    result = canonicalize({"b": 1, "a": 2})
    assert result == b'{"a":2,"b":1}'


def test_canonicalize_emits_compact_form():
    result = canonicalize({"x": [1, 2, 3]})
    assert result == b'{"x":[1,2,3]}'


def test_canonicalize_strings_are_utf8():
    result = canonicalize({"name": "café"})
    assert result == b'{"name":"caf\xc3\xa9"}'


def test_canonicalize_nested_objects_sorted():
    result = canonicalize({"outer": {"b": 1, "a": 2}})
    assert result == b'{"outer":{"a":2,"b":1}}'
