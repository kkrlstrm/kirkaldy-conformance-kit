"""The kit's world for P23 (`conformance/world.py`): its semantics, the footprint of the kit's own
reads (KRK-M116), the diff over untagged changes (KRK-M114), faults, holds and the HTTP path."""
import pytest

from conformance import world as wm
from conformance.timing import VirtualClock


def _w():
    c = VirtualClock()
    w = wm.World(c)
    b = wm.connect(w.url, w.credential("b"))
    return c, w, b


def test_objects_delete_removes_links_and_restore_brings_back_existence_only():
    c, w, b = _w()
    hub = w.kit_object({"k": "hub"})
    o = b.create(fields={"a": 1}, email="x@b.example", note="n1", links=[hub])["id"]
    assert w.state[("edge", f"{o}->{hub}")]["live"] is True
    b.delete(object_id=o)
    assert w.state[("object", o)]["deleted"] is True
    assert w.state[("edge", f"{o}->{hub}")]["live"] is False
    b.restore(object_id=o)
    assert w.state[("object", o)]["deleted"] is False
    assert w.state[("edge", f"{o}->{hub}")]["live"] is False
    b.link(src=o, dst=hub)
    assert w.state[("edge", f"{o}->{hub}")]["live"] is True


def test_update_merges_fields_and_none_removes_a_member():
    c, w, b = _w()
    o = w.kit_object({"a": 1, "b": 2})
    b.update(object_id=o, fields={"a": 3, "b": None, "c": 4})
    assert w.state[("object", o)]["fields"] == {"a": 3, "c": 4}


def test_recall_is_refused_once_the_message_is_read():
    c, w, b = _w()
    w.kit_mailbox("d1@b.example", "d:1")
    m = b.deliver(to="d1@b.example", subject="s", body="hello")["id"]
    assert w.state[("mail", m)]["party"] == "d:1"
    w.read_message(m)
    with pytest.raises(wm.Refused) as e:
        b.recall(message_id=m)
    assert e.value.code == "already_read"


def test_a_void_restores_both_balances_and_is_refused_once_the_funds_moved_on():
    c, w, b = _w()
    a1, a2 = w.kit_account("a", 1000), w.kit_account("d:p", 0)
    t = b.transfer(frm=a1, to=a2, amount=300, memo="m")["id"]
    assert (w.state[("account", a1)]["balance"], w.state[("account", a2)]["balance"]) == (700, 300)
    b.reverse_transfer(transfer_id=t)
    assert (w.state[("account", a1)]["balance"], w.state[("account", a2)]["balance"]) == (1000, 0)
    assert w.state[("transfer", t)]["voided"] is True
    t2 = b.transfer(frm=a1, to=a2, amount=200, memo="m2")["id"]
    w.spend(t2, w.kit_account("d:onward", 0))
    with pytest.raises(wm.Refused) as e:
        b.reverse_transfer(transfer_id=t2)
    assert e.value.code == "funds_moved"
    with pytest.raises(wm.Refused):
        b.transfer(frm=a1, to=a2, amount=1.5)


def test_fanout_leaves_a_copy_at_the_subscriber_that_a_retraction_does_not_recall():
    c, w, b = _w()
    i = b.publish(topic="t", body="news")["id"]
    w.deliver_fanout(i, "d:sub")
    b.retract(item_id=i)
    assert w.state[("item", i)]["retracted"] is True
    assert w.holdings("d:sub")["copies"] == [{"item": i, "party": "d:sub", "body": "news"}]


def test_KRK_M116_the_kits_reads_change_nothing():
    """KRK-M116: no kit read and no read through B's interface sets read_at or adds history."""
    c, w, b = _w()
    w.kit_mailbox("d1@b.example", "d:1")
    m = b.deliver(to="d1@b.example", subject="s", body="hello")["id"]
    mk = w.mark()
    s1 = w.snapshot()
    w.entity_at(("mail", m), mk.seq)
    w.holdings("d:1")
    w.diff(mk)
    w.changes()
    assert b.read(kind="mail", eid=m)["read_at"] is None
    b.find(kind="mail", party="d:1")
    s2 = w.snapshot()
    assert s1["digest"] == s2["digest"] and w.mark().seq == mk.seq
    assert w.diff(mk) == {}


def test_KRK_M114_the_diff_covers_every_change_tagged_or_not():
    """KRK-M114: a change that carries no trial tag is in the diff all the same."""
    c, w, b = _w()
    mk = w.mark()
    b.create(fields={"note": "tagged-123"})
    b.deliver(to="nobody@d.example", subject="", body="")      # no tag at all
    kinds = sorted(k[0] for k in w.diff(mk))
    assert kinds == ["mail", "object"]


def test_history_records_each_caller_and_the_kit_clock():
    c, w, b = _w()
    w.kit_object({"k": 1})
    c.sleep(5)
    b.create(fields={})
    h = w.changes()
    assert [e["caller"] for e in h] == ["kit", "b"]
    assert h[1]["t"] - h[0]["t"] == pytest.approx(5)


def test_entity_at_and_at_time_read_the_past():
    c, w, b = _w()
    o = b.create(fields={"v": 1})["id"]
    m1 = w.mark()
    c.sleep(10)
    b.update(object_id=o, fields={"v": 2})
    assert w.entity_at(("object", o), m1.seq)["fields"] == {"v": 1}
    assert w.entity_at_time(("object", o), m1.t + 5)["fields"] == {"v": 1}
    assert w.entity_at_time(("object", o), m1.t + 11)["fields"] == {"v": 2}
    assert w.entity_at(("object", o), 0) is None


def test_faults_apply_to_b_only_until_they_end():
    c, w, b = _w()
    w.fault("down", until=c.now() + 5)
    with pytest.raises(wm.Unavailable):
        b.create(fields={})
    w.kit_call("create", fields={})                           # the kit is never faulted
    c.sleep(5)
    b.create(fields={})
    w.fault("error", until=c.now() + 1)
    with pytest.raises(wm.ServerError):
        b.create(fields={})
    c.sleep(1)
    w.fault("hang", until=c.now() + 10, hang_s=2)
    t0 = c.now()
    with pytest.raises(wm.TimedOut):
        b.create(fields={})
    assert c.now() - t0 == pytest.approx(2)
    assert [a["outcome"] for a in w.attempts] == ["down", "error", "hang"]


def test_refuse_item_refuses_one_call_once():
    c, w, b = _w()
    o = b.create(fields={})["id"]
    w.fault("refuse_item", item=o)
    with pytest.raises(wm.Refused) as e:
        b.delete(object_id=o)
    assert e.value.code == "refused_item"
    b.delete(object_id=o)


def test_slow_commits_late():
    c, w, b = _w()
    w.fault("slow", until=c.now() + 30, slow_s=2)
    t0 = c.now()
    o = b.create(fields={})["id"]
    e = next(e for e in w.changes() if e["key"] == ["object", o])
    assert e["t"] - t0 == pytest.approx(2)


def test_a_hold_answers_held_once_and_commits_nothing():
    c, w, b = _w()
    w.hold("tok-7", 30)
    with pytest.raises(wm.Held) as e:
        b.create(fields={"note": "tok-7"})
    assert e.value.retry_after_s == 30 and w.changes() == []
    assert w.held_attempts("tok-7")
    b.create(fields={"note": "tok-7"})
    assert len(w.changes()) == 1


def test_an_unknown_credential_is_refused():
    c, w, b = _w()
    with pytest.raises(wm.Refused):
        wm.connect(w.url, "wc-not-issued").create(fields={})


def test_the_http_interface_carries_the_same_calls_and_errors():
    w = wm.World()
    try:
        url = w.serve()
        b = wm.connect(url, w.credential("b"))
        assert isinstance(b, wm.HttpClient)
        o = b.create(fields={"a": 1}, note="h")["id"]
        assert w.state[("object", o)]["fields"] == {"a": 1}
        w.kit_mailbox("d@b.example", "d:1")
        m = b.deliver(to="d@b.example", subject="", body="x")["id"]
        w.read_message(m)
        with pytest.raises(wm.Refused) as e:
            b.recall(message_id=m)
        assert e.value.code == "already_read"
        w.hold("tok-h", 3)
        with pytest.raises(wm.Held) as h:
            b.create(fields={"note": "tok-h"})
        assert h.value.retry_after_s == 3
        w.fault("down")
        with pytest.raises(wm.Unavailable):
            b.create(fields={})
        assert [e["caller"] for e in w.changes()] == ["b", "b", "kit-plant"]
    finally:
        w.close()
    assert wm.local(w.url) is None
