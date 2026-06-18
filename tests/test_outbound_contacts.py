"""Tests for aap.stores.outbound_contacts."""

from datetime import datetime, timedelta, timezone


from aap.stores.outbound_contacts import OutboundContactStore


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def test_empty_store(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    assert store.last_contact("nobody^x.com") is None
    assert not store.contacted_within("nobody^x.com")


def test_record_and_persist(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    t = _utc(2026, 1, 10, 12, 0, 0)
    store.record("bob^example.com", when=t)

    assert (tmp_path / "aap-outbound-contacts.json").exists()

    reloaded = OutboundContactStore.load(tmp_path)
    last = reloaded.last_contact("bob^example.com")
    assert last is not None
    assert last == t


def test_contacted_within_true(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    base = _utc(2026, 1, 10, 12, 0, 0)
    store.record("bob^example.com", when=base)

    now = base + timedelta(hours=12)
    assert store.contacted_within("bob^example.com", now=now)


def test_contacted_within_false_after_window(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    base = _utc(2026, 1, 10, 12, 0, 0)
    store.record("bob^example.com", when=base)

    now = base + timedelta(hours=25)
    assert not store.contacted_within("bob^example.com", now=now)


def test_contacted_within_custom_window(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    base = _utc(2026, 1, 10, 12, 0, 0)
    store.record("bob^example.com", when=base)

    now = base + timedelta(hours=2)
    # 1h window — should be outside
    assert not store.contacted_within(
        "bob^example.com", window=timedelta(hours=1), now=now
    )
    # 3h window — should be inside
    assert store.contacted_within(
        "bob^example.com", window=timedelta(hours=3), now=now
    )


def test_record_updates_existing(tmp_path):
    store = OutboundContactStore.load(tmp_path)
    t1 = _utc(2026, 1, 10, 12, 0, 0)
    t2 = _utc(2026, 1, 10, 18, 0, 0)
    store.record("bob^example.com", when=t1)
    store.record("bob^example.com", when=t2)

    assert store.last_contact("bob^example.com") == t2


def test_parent_dir_created(tmp_path):
    """_save creates parent directories if they don't exist yet."""
    nested = tmp_path / "deep" / "dir"
    store = OutboundContactStore(base_dir=nested)
    store.record("a^b.com")
    assert (nested / "aap-outbound-contacts.json").exists()
