"""Tests for the identity-binding (TOFU) store."""


from aap.stores.identity_bindings import IdentityBindingStore


def test_empty_store(tmp_path):
    store = IdentityBindingStore.load(tmp_path)
    assert store.binding_for("foo^x.com") is None


def test_bind_and_lookup(tmp_path):
    store = IdentityBindingStore.load(tmp_path)
    store.bind(
        peer_address="james-bot^james-bots.example",
        contact_id="james-lane",
        matched_identifier={"type": "phone", "value": "+14154442222"},
    )
    assert (tmp_path / "aap-identity-bindings.json").exists()

    reloaded = IdentityBindingStore.load(tmp_path)
    binding = reloaded.binding_for("james-bot^james-bots.example")
    assert binding is not None
    assert binding.contact_id == "james-lane"
    assert binding.matched_identifier["value"] == "+14154442222"


def test_unbind(tmp_path):
    store = IdentityBindingStore.load(tmp_path)
    store.bind(
        peer_address="x^y.com",
        contact_id="alice",
        matched_identifier={"type": "email", "value": "alice@x.com"},
    )
    assert store.binding_for("x^y.com") is not None
    store.unbind("x^y.com")
    assert store.binding_for("x^y.com") is None


def test_list_bindings_for_contact(tmp_path):
    store = IdentityBindingStore.load(tmp_path)
    store.bind(
        peer_address="bot1^example.com",
        contact_id="alice",
        matched_identifier={"type": "phone", "value": "+1"},
    )
    store.bind(
        peer_address="bot2^example.com",
        contact_id="alice",
        matched_identifier={"type": "email", "value": "a@x"},
    )
    addrs = store.addresses_bound_to("alice")
    assert set(addrs) == {"bot1^example.com", "bot2^example.com"}


def test_rebind_replaces_existing(tmp_path):
    store = IdentityBindingStore.load(tmp_path)
    store.bind(
        peer_address="x^y.com",
        contact_id="alice",
        matched_identifier={"type": "email", "value": "old@x.com"},
    )
    store.bind(
        peer_address="x^y.com",
        contact_id="bob",
        matched_identifier={"type": "email", "value": "new@x.com"},
    )
    binding = store.binding_for("x^y.com")
    assert binding is not None
    assert binding.contact_id == "bob"
    assert len([b for b in store.bindings if b.peer_address == "x^y.com"]) == 1


def test_parent_dir_created(tmp_path):
    """_save creates parent directories if they don't exist yet."""
    nested = tmp_path / "deep" / "dir"
    store = IdentityBindingStore(base_dir=nested)
    store.bind(
        peer_address="a^b.com",
        contact_id="c",
        matched_identifier={"type": "email", "value": "a@b.com"},
    )
    assert (nested / "aap-identity-bindings.json").exists()
