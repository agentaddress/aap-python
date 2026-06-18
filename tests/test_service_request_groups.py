from aap.stores.service_request_groups import ServiceRequestGroupIndex


def test_record_and_pop_roundtrip(tmp_path):
    idx = ServiceRequestGroupIndex(base_dir=tmp_path)
    idx.record("nonce-1", "conv-abc")
    assert idx.pop("nonce-1") == "conv-abc"
    assert idx.pop("nonce-1") is None  # one-shot


def test_pop_unknown_returns_none(tmp_path):
    idx = ServiceRequestGroupIndex(base_dir=tmp_path)
    assert idx.pop("missing") is None


def test_persists_across_instances(tmp_path):
    idx1 = ServiceRequestGroupIndex(base_dir=tmp_path)
    idx1.record("nonce-2", "conv-xyz")
    idx2 = ServiceRequestGroupIndex(base_dir=tmp_path)
    assert idx2.pop("nonce-2") == "conv-xyz"


def test_record_overwrites_existing_nonce(tmp_path):
    idx = ServiceRequestGroupIndex(base_dir=tmp_path)
    idx.record("nonce-3", "conv-a")
    idx.record("nonce-3", "conv-b")
    assert idx.pop("nonce-3") == "conv-b"


def test_record_creates_missing_base_dir(tmp_path):
    # First-run scenario: base_dir doesn't exist yet on a fresh install.
    # _save must create parents, otherwise the record is silently dropped.
    missing = tmp_path / "does_not_exist_yet"
    idx = ServiceRequestGroupIndex(base_dir=missing)
    idx.record("n", "c")
    assert idx.pop("n") == "c"
