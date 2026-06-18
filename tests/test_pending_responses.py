import pytest

from aap.pending_responses import PendingResponses


@pytest.mark.asyncio
async def test_register_and_resolve():
    pr = PendingResponses()
    fut = pr.register("abc")
    assert pr.resolve("abc", {"ok": True}) is True
    assert await fut == {"ok": True}


@pytest.mark.asyncio
async def test_resolve_unknown_returns_false():
    pr = PendingResponses()
    assert pr.resolve("missing", {}) is False


@pytest.mark.asyncio
async def test_resolve_already_done_returns_false():
    pr = PendingResponses()
    pr.register("abc")
    assert pr.resolve("abc", {"first": True}) is True
    # Future is already done; second resolve on same nonce returns False
    # (the resolve method pops; second call is a fresh nonce lookup that misses)
    assert pr.resolve("abc", {"second": True}) is False


@pytest.mark.asyncio
async def test_clear_removes_pending():
    pr = PendingResponses()
    pr.register("abc")
    pr.clear("abc")
    assert pr.resolve("abc", {}) is False
