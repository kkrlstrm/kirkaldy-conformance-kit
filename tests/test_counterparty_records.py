"""KRK-17 (P17): the stub counterparty's own record. B's log is append-only, numbered per
requester with no gap, chained, and readable in the kit's terms; B signs checkpoints of it with
a key of their own; and each record mode leaves the ground truth it declares. KRK-16's
behaviour is pinned separately (`test_receipts.py`) and is unchanged."""
import json
import random
import sqlite3

import pytest

from conformance import books
from conformance import counterparty as cp
from conformance import receipts as r
from conformance.properties.p16_effect_receipt import build_case

A_ID = "did:web:a.example"
OTHER = "did:web:other.example"


@pytest.fixture
def b(tmp_path):
    return cp.StubCounterparty(str(tmp_path / "b.sqlite"), r.Keypair.generate("b-r"), bytes(16))


def _case(b, rng, tag="t"):
    return build_case(r, rng, b.salt, "honest", tag)


def _series(b, rng, n=3):
    out = []
    for _ in range(n):
        env, exp = _case(b, rng)
        tok, rep = b.execute(env, exp, rng=rng)
        out.append((env, exp, tok))
    return out


def test_an_honest_series_is_numbered_chained_and_unchanged(b):
    rng = random.Random(1)
    series = _series(b, rng)
    rec = b.record(A_ID)
    assert [e["pair_seq"] for e in rec] == list(range(1, 10))
    assert [e["kind"] for e in rec[:3]] == ["request-received", "effect-committed",
                                            "receipt-issued"]
    assert all(books.entry_problem(e) is None for e in rec)
    assert books.chain_breaks(rec) == ([], [])
    assert b.tamper_log == []                                       # KRK-M35
    # Each receipt names B's effect entry by its log_seq, and B's log says what it signed.
    for (env, exp, tok), i in zip(series, (1, 4, 7)):
        claims = json.loads(r._b64d(tok.split(".")[1]))
        eff, iss = rec[i], rec[i + 1]
        assert eff["body"]["log_seq"] == claims["log_seq"]
        assert eff["body"]["created"] == claims["outcome"]["created"] == exp.count
        assert iss["raw_sha256"] == r.sha256_ref(tok.encode())


def test_the_log_and_bookkeeping_refuse_update_and_delete(b):
    _series(b, random.Random(2), 1)
    b.hold(A_ID, b.checkpoint(A_ID))                 # so every table has a row to refuse on
    for table in cp.APPEND_ONLY:
        for stmt in (f"UPDATE {table} SET rowid = rowid", f"DELETE FROM {table}"):
            with pytest.raises(sqlite3.DatabaseError, match="append-only"):
                with b._db() as db:
                    db.execute(stmt)
    # Item rows are B's state, not its log: a read API serves them and they may change.
    with b._db() as db:
        db.execute("UPDATE items SET verb = verb")


def test_numbering_is_per_requester_and_global_log_seq_interleaves(b):
    rng = random.Random(3)
    for who in (A_ID, OTHER, A_ID, OTHER):
        env, exp = _case(b, rng)
        b.execute(dict(env, requester=who), exp, rng=rng)
    for who in (A_ID, OTHER):
        assert [e["pair_seq"] for e in b.record(who)] == list(range(1, 7))
        assert books.chain_breaks(b.record(who)) == ([], [])
    seqs = [e["log_seq"] for e in b.log_truth() if e["peer"] == A_ID]
    assert seqs != list(range(seqs[0], seqs[0] + len(seqs)))       # other entries in between


def test_checkpoints_verify_under_their_own_key_and_cover_the_record(b):
    _series(b, random.Random(4), 2)
    tok = b.checkpoint(A_ID)
    kid, pub = b.checkpoint_public_key()
    v = books.verify_checkpoint(tok, {kid: pub})
    assert v.ok and v.claims["pair_seq"] == 6 and v.claims["peer"] == A_ID
    assert books.checkpoint_covers(b.record(A_ID), v.claims) == []
    assert not books.verify_checkpoint(tok, dict([b.public_key()])).ok   # not the receipt key
    assert b.checkpoint(OTHER) is None


def test_hold_logs_what_a_sent_and_keeps_the_bytes(b):
    _series(b, random.Random(5), 1)
    a_key = r.Keypair.generate("a-ck")
    t = books.sign_checkpoint(books.checkpoint_claims(A_ID, b.counterparty_id, 2,
                                                      "sha256:" + "a" * 64, cp._now()), a_key)
    b.hold(A_ID, t)
    last = b.record(A_ID)[-1]
    assert last["kind"] == "checkpoint-received" and last["body"] == {"pair_seq": 2,
                                                                      "head": "sha256:" + "a" * 64}
    assert b.holdings(A_ID) == [{"type": "checkpoint", "token": t}]


def _modal(b, rng, mode, **params):
    env, exp = _case(b, rng)
    b.set_record_mode(env["correlation_id"], mode, **params)
    tok, rep = b.execute(env, exp, rng=rng)
    entries = [e for e in b.record(A_ID) if e["correlation_id"] == env["correlation_id"]]
    return env, exp, tok, rep, entries


def test_receipt_contradicts_log_signs_the_count_its_log_contradicts(b):
    env, exp, tok, _, es = _modal(b, random.Random(6), "receipt_contradicts_log", k=3)
    claims = json.loads(r._b64d(tok.split(".")[1]))
    eff = next(e for e in es if e["kind"] == "effect-committed")
    assert sum(claims["outcome"][f] for f in ("created", "updated")) == exp.count
    assert eff["body"]["created"] + eff["body"]["updated"] == exp.count - 3
    assert b.store_counts(env["correlation_id"])["written"] == exp.count - 3


def test_receipt_contradicts_state_changes_the_store_and_not_the_log(b):
    env, exp, tok, _, es = _modal(b, random.Random(7), "receipt_contradicts_state", k=4)
    eff = next(e for e in es if e["kind"] == "effect-committed")
    assert eff["body"]["created"] == exp.count
    assert b.read_state(A_ID, env["correlation_id"])["written"] == exp.count - 4


def test_drop_request_and_compensating_pair(b):
    rng = random.Random(8)
    env, exp, tok, rep, es = _modal(b, rng, "drop_request")
    assert tok is None and es == [] and rep["success"] is True
    env, exp, tok, rep, es = _modal(b, rng, "compensating_pair", other_cid="extra-1")
    assert tok is None and es == []
    extra = [e for e in b.record(A_ID) if e["correlation_id"] == "extra-1"]
    assert [e["kind"] for e in extra] == ["request-received", "effect-committed"]
    assert extra[1]["body"]["created"] == exp.count


def test_join_collision_leaks_another_requesters_entries_into_the_pair(b):
    env, exp, tok, _, es = _modal(b, random.Random(9), "join_collision", other_requester=OTHER)
    peers = {e["peer"] for e in es}
    assert peers == {A_ID, OTHER}
    assert all(e["request_digest"] != r.request_digest(env) for e in es if e["peer"] == OTHER)


def test_seq_duplicate_commits_twice_and_clock_skew_moves_the_stamp(b):
    rng = random.Random(10)
    env, exp, tok, _, es = _modal(b, rng, "seq_duplicate")
    effs = [e for e in es if e["kind"] == "effect-committed"]
    assert len(effs) == 2 and len({e["request_digest"] for e in effs}) == 1
    assert b.store_counts(env["correlation_id"])["written"] == 2 * exp.count
    env, exp, tok, _, es = _modal(b, rng, "clock_skew", skew_s=-1800)
    t = books._epoch(es[0]["recorded_at"])
    assert abs(t - books._epoch(cp._now()) + 1800) < 60


def test_late_entry_vocabulary_and_declared_void(b):
    rng = random.Random(11)
    env, exp, tok, rep, es = _modal(b, rng, "late_entry")
    assert tok is None and es == []
    late = b.release(env["correlation_id"], rng)
    assert r.verify_receipt(late, dict([b.public_key()])).ok
    vocab = {"operation": {exp.operation: "people.upsert"}, "container": {"people": "contacts"}}
    env, exp, tok, _, es = _modal(b, rng, "b_vocabulary", vocabulary=vocab)
    assert (es[0]["body"]["operation"], es[0]["body"]["container"]) == ("people.upsert",
                                                                       "contacts")
    env, exp, tok, rep, es = _modal(b, rng, "declared_void")
    assert tok is None and [e["kind"] for e in es] == ["request-received", "void"]
    assert es[1]["body"]["voids"] == books.entry_digest(es[0])
    assert b.store_counts(env["correlation_id"])["written"] == 0


def test_out_of_band_and_void_append_and_change_nothing_earlier(b):
    rng = random.Random(12)
    series = _series(b, rng, 2)
    before = b.record(A_ID)
    cid = b.out_of_band(A_ID, series[0][1], series[0][0]["items"], rng)
    b.void(A_ID, series[1][0]["correlation_id"])
    after = b.record(A_ID)
    assert after[:len(before)] == before
    assert {e["correlation_id"] for e in after[len(before):]} == {cid,
                                                                  series[1][0]["correlation_id"]}
    assert b.tamper_log == []


def test_tamper_paths_land_and_are_logged(b):
    rng = random.Random(13)
    series = _series(b, rng, 3)
    kid, pub = b.checkpoint_public_key()
    held = books.verify_checkpoint(b.checkpoint(A_ID), {kid: pub}).claims
    cid = series[1][0]["correlation_id"]
    b.tamper_edit(A_ID, cid, "effect-committed", {"created": 1})
    rec = b.record(A_ID)
    assert books.chain_breaks(rec) == ([], [])                     # re-chained: looks whole
    assert [x.kind for x in books.checkpoint_covers(rec, held)] == ["changed-after-ack"]
    b.tamper_delete(A_ID, cid, "receipt-issued")
    assert [x.kind for x in books.chain_breaks(b.record(A_ID))[0]] == ["gap"]
    b.tamper_swap(A_ID, series[2][0]["correlation_id"])
    assert "renumbered" in {x.kind for x in books.chain_breaks(b.record(A_ID))[0]}
    assert [t["op"] for t in b.tamper_log] == ["edit", "delete", "swap"]
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):  # the triggers are back
        with b._db() as db:
            db.execute("DELETE FROM log")
