"""KRK-17 (P17): the kit's reading format, chain and checkpoint checks against fixed vectors, and
the kit's own reconciler against its self-test fixtures.

The reconciler is the independent third party of P17. Its self-test (KRK-M29, KRK-M29) builds a
pair of records for every planted difference with code in this file that shares nothing with the
stub counterparty or any target, and requires the reconciler to report the planted break. Each
weakness a weak reconciler could have is then applied to the kit's reconciler (`_weaken`), and
the self-test must fail under it: a self-test that a weakened reconciler also passes has shown
nothing about the reconciler."""
import json
from pathlib import Path

import pytest

from conformance import books
from conformance import receipts as r

VEC = Path(__file__).resolve().parent / "vectors" / "krk17"
ENTRIES = json.loads((VEC / "entries.json").read_text())
CHAINS = json.loads((VEC / "chains.json").read_text())
CKPTS = json.loads((VEC / "checkpoints.json").read_text())
CK_PINNED = {k: bytes.fromhex(v) for k, v in CKPTS["pinned"].items()}


# --------------------------------------------------------------------------- format


@pytest.mark.parametrize("e", ENTRIES["entries"], ids=lambda e: f"{e['side']}{e['pair_seq']}")
def test_entry_digest_matches_the_vector(e):
    assert books.entry_digest(e) == e["entry_digest"]
    assert books.entry_problem(e) is None


@pytest.mark.parametrize("case", ENTRIES["invalid"], ids=lambda c: c["name"])
def test_invalid_entries_are_refused_for_the_stated_reason(case):
    assert books.entry_problem(case["entry"]) == case["problem"]


def test_entry_digest_ignores_its_own_digest_member_and_nothing_else():
    e = dict(ENTRIES["entries"][0])
    d = e.pop("entry_digest")
    assert books.entry_digest(e) == d
    assert books.entry_digest(dict(e, recorded_at="2026-11-01T13:02:12Z")) != d


def test_action_key_is_the_same_on_both_sides():
    a = next(e for e in ENTRIES["entries"] if e["side"] == "A" and e["kind"] == "request-sent")
    b = next(e for e in ENTRIES["entries"] if e["side"] == "B" and e["kind"] == "request-received")
    assert books.action_key(a) == books.action_key(b) == (a["party"], b["party"],
                                                          a["correlation_id"], a["request_digest"])


@pytest.mark.parametrize("case", CHAINS["cases"], ids=lambda c: c["name"])
def test_chain_vectors(case):
    breaks, findings = books.chain_breaks(case["entries"])
    got = [{"kind": b.kind, "numbers": list(b.numbers), "has_key": b.key is not None}
           for b in breaks]
    assert sorted(got, key=json.dumps) == sorted(case["breaks"], key=json.dumps)
    assert [{"kind": f.kind, "side": f.side} for f in findings] == case["findings"]


@pytest.mark.parametrize("case", CKPTS["verify"], ids=lambda c: c["name"])
def test_checkpoint_verify_vectors(case):
    v = books.verify_checkpoint(case["token"], CK_PINNED)
    assert (v.ok, v.reason) == (case["ok"], case["reason"]), v.detail


@pytest.mark.parametrize("case", CKPTS["covers"], ids=lambda c: c["name"])
def test_checkpoint_cover_vectors(case):
    got = [{"kind": b.kind, "numbers": list(b.numbers)}
           for b in books.checkpoint_covers(case["entries"], case["claims"])]
    assert got == case["breaks"]


def test_signed_checkpoint_round_trips_and_is_byte_stable():
    key = r.Keypair.from_seed("k", bytes(32))
    c = books.checkpoint_claims("did:web:b.example", "did:web:a.example", 3,
                                "sha256:" + "a" * 64, "2026-11-01T13:02:12Z")
    t1, t2 = books.sign_checkpoint(c, key), books.sign_checkpoint(c, key)
    assert t1 == t2
    v = books.verify_checkpoint(t1, {"k": key.public_bytes()})
    assert v.ok and v.claims == c
    # A receipt verifier does not read a checkpoint as a receipt, nor the reverse.
    assert r.verify_receipt(t1, {"k": key.public_bytes()}).reason == "malformed"


def test_a_vector_was_not_computed_by_the_code_it_checks():
    import ast
    tree = ast.parse((VEC / "make_vectors.py").read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                for a in n.names}
    assert "books" not in imported


# --------------------------------------------------------------------------- the reconciler
# A pair of records built here, by hand, for the self-test. It shares no code with the stub
# counterparty (`conformance/counterparty.py`) or any target: it writes each side's entries
# directly in the reading format, signs B's receipts and both sides' checkpoints with fixed keys.

A_ID, B_ID, OTHER_ID = "did:web:a.example", "did:web:b.example", "did:web:other.example"
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
RK = r.Keypair.from_seed("b-receipts", bytes([1]) * 32)
BCK = r.Keypair.from_seed("b-checkpoints", bytes([2]) * 32)
ACK = r.Keypair.from_seed("a-checkpoints", bytes([3]) * 32)
T0 = 1_793_000_000


def _at(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Pair:
    """Two records of a short series of honest actions, and what each side holds of the other."""

    def __init__(self, n=4):
        self.a, self.b, self.hold_a, self.hold_b = [], [], [], []
        self.state, self.log_seq, self.t = {}, 900, T0
        self.actions = [self.act(i) for i in range(n)]

    def _add(self, side, kind, body, cid=None, rd=None, raw=None, t=None, party=None, peer=None):
        party = party or (A_ID if side == "A" else B_ID)
        peer = peer or (B_ID if side == "A" else A_ID)
        log = self.a if side == "A" else self.b
        mine = [e for e in log if e["party"] == party and e["peer"] == peer]
        e = {"schema": books.SCHEMA, "side": side, "party": party, "peer": peer,
             "pair_seq": len(mine) + 1,
             "prev_digest": books.entry_digest(mine[-1]) if mine else None,
             "kind": kind, "correlation_id": cid, "request_digest": rd, "answers": None,
             "body": body, "raw_sha256": raw, "recorded_at": _at(self.t if t is None else t)}
        log.append(e)
        return e

    def checkpoint(self, side):
        log, key, holder = ((self.b, BCK, self.hold_a) if side == "B" else (self.a, ACK, self.hold_b))
        issuer, peer = (B_ID, A_ID) if side == "B" else (A_ID, B_ID)
        last = [e for e in log if e["party"] == issuer and e["peer"] == peer][-1]
        tok = books.sign_checkpoint(books.checkpoint_claims(issuer, peer, last["pair_seq"],
                                                            books.entry_digest(last),
                                                            _at(self.t)), key)
        holder.append({"type": "checkpoint", "token": tok})
        if side == "A":
            c = books.verify_checkpoint(tok, {ACK.kid: ACK.public_bytes()}).claims
            self._add("B", "checkpoint-received", {"pair_seq": c["pair_seq"], "head": c["head"]},
                      raw=books.sha256_ref(tok.encode()))
        return tok

    def act(self, i, *, n=None, b_count=None, receipt_count=None, cid=None, b_extra=None):
        self.t += 60
        n = n or 10 + i
        items = r.items_digest(SALT, [f"p{i}-{k}@x.example" for k in range(n)])
        cid = cid or f"case-{i}"
        req = {"operation": "crm.record.push", "container": "people", "count": n,
               "items_digest": items, "expected_effect_digest": "sha256:" + f"{i:x}" * 64}
        rd = books.sha256_ref(books.canonical_json({"cid": cid, **req}))
        self._add("A", "request-sent", dict(req, approved_by="person:alice"), cid, rd)
        self._add("B", "request-received", dict(b_extra or req), cid, rd)
        self.log_seq += 1
        done = n if b_count is None else b_count
        self._add("B", "effect-committed", {"created": done, "updated": 0, "deleted": 0,
                                            "failed": 0, "items_digest": items,
                                            "log_seq": self.log_seq}, cid, rd)
        self.state[cid] = {"written": done}
        said = n if receipt_count is None else receipt_count
        claims = {"receipt_id": f"rcpt-{i}", "correlation_id": cid, "request_digest": rd,
                  "expected_effect_digest": req["expected_effect_digest"], "verdict": "executed",
                  "refusal_reason": None,
                  "outcome": {"created": said, "updated": 0, "deleted": 0, "failed": 0},
                  "items_digest": items, "counterparty": B_ID, "executed_at": _at(self.t),
                  "log_seq": self.log_seq}
        tok = r.sign_receipt(claims, RK)
        sha = books.sha256_ref(tok.encode())
        self._add("B", "receipt-issued", {"receipt_id": claims["receipt_id"],
                                          "token_sha256": sha, "verdict": "executed",
                                          "log_seq": self.log_seq,
                                          "outcome": claims["outcome"]}, cid, rd)
        self._add("A", "receipt-received", {"receipt_id": claims["receipt_id"],
                                            "verdict": "executed"}, cid, rd, raw=sha)
        self.hold_a.append({"type": "receipt", "token": tok})
        self._add("A", "settlement", {"outcome": "executed", "by": "rule:verified-receipt",
                                      "count": said, "case": f"c{i}"}, cid, rd)
        self.checkpoint("B")
        self.checkpoint("A")
        return {"cid": cid, "rd": rd, "n": n, "items": items, "req": req, "token": tok}

    def key(self, i):
        x = self.actions[i]
        return (A_ID, B_ID, x["cid"], x["rd"])

    def kw(self, **over):
        kw = dict(requester=A_ID, counterparty=B_ID, holdings_a=self.hold_a,
                  holdings_b=self.hold_b, receipt_keys={RK.kid: RK.public_bytes()},
                  b_checkpoint_keys={BCK.kid: BCK.public_bytes()},
                  a_checkpoint_keys={ACK.kid: ACK.public_bytes()}, state_b=self.state,
                  tolerance_s=300.0)
        kw.update(over)
        return kw


def _relink(log, party, peer):
    prev = None
    for i, e in enumerate(log):
        if e["party"] == party and e["peer"] == peer:
            e["prev_digest"] = prev
            prev = books.entry_digest(e)


def _find(log, kind, cid):
    return next(i for i, e in enumerate(log) if e["kind"] == kind and e["correlation_id"] == cid)


MAPPING = {"operation": {"people.upsert": "crm.record.push"}, "container": {"contacts": "people"}}


def _fixture(name):
    """(pair, reconcile kwargs, expected break kinds, expected state of the fixture action).
    The planted difference is on the last action, or on `p.planted` where a branch sets it."""
    p = Pair(3)
    kw = {}
    if name == "honest":
        p.actions.append(p.act(3))
        return p, kw, set(), "matched"
    if name == "receipt_contradicts_log":
        p.actions.append(p.act(3, b_count=11, receipt_count=13, n=13))
        return p, kw, {"statement-vs-log", "statement-vs-state"}, "break"
    if name == "receipt_contradicts_state":
        p.actions.append(p.act(3))
        p.state[p.actions[3]["cid"]] = {"written": p.actions[3]["n"] - 2}
        return p, kw, {"statement-vs-state"}, "break"
    if name == "unbacked_on_b":
        p.actions.append(p.act(3))
        p._add("B", "request-received", dict(p.actions[0]["req"], count=7), "case-oob",
               "sha256:" + "e" * 64)
        p._add("B", "effect-committed", {"created": 7, "updated": 0, "deleted": 0, "failed": 0,
                                         "items_digest": p.actions[0]["items"], "log_seq": 999},
               "case-oob", "sha256:" + "e" * 64)
        p.actions.append({"cid": "case-oob", "rd": "sha256:" + "e" * 64})
        return p, kw, {"missing-on-a"}, "break"
    if name == "unbacked_on_a":
        p.actions.append(p.act(3))
        cid, rd = "case-drop", "sha256:" + "d" * 64
        p._add("A", "request-sent", dict(p.actions[0]["req"]), cid, rd)
        p._add("A", "settlement", {"outcome": "executed", "by": "person:alice", "count": 10},
               cid, rd)
        p.actions.append({"cid": cid, "rd": rd})
        return p, kw, {"missing-on-b"}, "break"
    if name == "compensating_pair":
        p.actions.append(p.act(3))
        p._add("A", "request-sent", dict(p.actions[0]["req"]), "case-x", "sha256:" + "a" * 64)
        p._add("B", "request-received", dict(p.actions[0]["req"]), "case-y", "sha256:" + "b" * 64)
        p._add("B", "effect-committed", {"created": 10, "updated": 0, "deleted": 0, "failed": 0,
                                         "items_digest": p.actions[0]["items"], "log_seq": 998},
               "case-y", "sha256:" + "b" * 64)
        p.actions.append({"cid": "case-x", "rd": "sha256:" + "a" * 64})
        return p, kw, {"missing-on-a", "missing-on-b"}, "break"
    if name == "join_collision":
        p.actions.append(p.act(3))
        x = p.actions[3]
        p._add("B", "request-received", dict(x["req"]), x["cid"], "sha256:" + "f" * 64,
               party=B_ID, peer=OTHER_ID)
        p._add("B", "effect-committed", {"created": x["n"], "updated": 0, "deleted": 0,
                                         "failed": 0, "items_digest": x["items"], "log_seq": 997},
               x["cid"], "sha256:" + "f" * 64, party=B_ID, peer=OTHER_ID)
        return p, kw, {"join-ambiguous"}, "matched"
    if name == "b_edit_after_ack":
        p.actions.append(p.act(3))
        i = _find(p.b, "effect-committed", p.actions[1]["cid"])
        p.b[i] = dict(p.b[i], body=dict(p.b[i]["body"], created=p.actions[1]["n"] - 3))
        _relink(p.b, B_ID, A_ID)
        p.planted = 1      # B's store and read API still hold the full count
        return p, kw, {"changed-after-ack", "statement-vs-log", "statement-vs-state"}, "break"
    if name == "b_delete_after_ack":
        p.actions.append(p.act(3))
        del p.b[_find(p.b, "receipt-issued", p.actions[1]["cid"])]
        p.planted = 1      # the gap names no action: the removed entry cannot be named
        return p, kw, {"removed-after-ack", "gap"}, "matched"
    if name == "void_over_receipt":
        p.actions.append(p.act(3))
        i = _find(p.b, "effect-committed", p.actions[1]["cid"])
        x = p.actions[1]
        p._add("B", "void", {"voids": books.entry_digest(p.b[i]), "reason": "aborted"},
               x["cid"], x["rd"])
        p.planted = 1
        return p, kw, {"removed-after-ack"}, "break"
    if name == "seq_reorder":
        p.actions.append(p.act(3))
        i = _find(p.b, "effect-committed", p.actions[1]["cid"])
        p.b[i]["pair_seq"], p.b[i + 1]["pair_seq"] = p.b[i + 1]["pair_seq"], p.b[i]["pair_seq"]
        p.planted = 1      # as the chain vector "swapped-numbers", and A holds a checkpoint
        return p, kw, {"renumbered", "torn", "changed-after-ack"}, "break"
    if name == "seq_duplicate":
        p.actions.append(p.act(3))
        x = p.actions[3]
        p._add("B", "effect-committed", {"created": x["n"], "updated": 0, "deleted": 0,
                                         "failed": 0, "items_digest": x["items"], "log_seq": 996},
               x["cid"], x["rd"])
        return p, kw, {"repeated"}, "break"
    if name == "clock_skew":
        p.actions.append(p.act(3))
        i = _find(p.b, "request-received", p.actions[3]["cid"])
        for e in p.b[i:i + 3]:
            e["recorded_at"] = _at(_epoch(e["recorded_at"]) - 1800)
        _relink(p.b, B_ID, A_ID)
        return p, {"b_checkpoint_keys": {}}, set(), "explained"
    if name == "late_entry":
        p.actions.append(p.act(3))
        x = p.actions[3]
        p._add("A", "settlement", {"outcome": "not-executed", "by": "person:alice",
                                   "settles": [p.a[_find(p.a, "request-sent", x["cid"])]
                                               and books.entry_digest(
                                                   p.a[_find(p.a, "request-sent", x["cid"])])]},
               x["cid"], x["rd"])
        return p, kw, {"settlement-contradicted"}, "break"
    if name in ("translated_declared", "basis_undeclared"):
        p.actions.append(p.act(3, b_extra=None))
        i = _find(p.b, "request-received", p.actions[3]["cid"])
        p.b[i]["body"] = dict(p.b[i]["body"], operation="people.upsert", container="contacts")
        _relink(p.b, B_ID, A_ID)
        if name == "translated_declared":
            return p, {"mapping": MAPPING, "b_checkpoint_keys": {}}, set(), "explained"
        return p, {"b_checkpoint_keys": {}}, set(), "no-basis"
    if name == "declared_void":
        p.actions.append(p.act(3))
        cid, rd = "case-void", "sha256:" + "c" * 64
        p._add("A", "request-sent", dict(p.actions[0]["req"]), cid, rd)
        p._add("B", "request-received", dict(p.actions[0]["req"]), cid, rd)
        p._add("B", "void", {"voids": books.entry_digest(p.b[-1]), "reason": "aborted"}, cid, rd)
        p.actions.append({"cid": cid, "rd": rd})
        return p, kw, set(), "explained"
    if name == "a_edit_after_ack":
        p.actions.append(p.act(3))
        i = _find(p.a, "settlement", p.actions[1]["cid"])
        p.a[i] = dict(p.a[i], body=dict(p.a[i]["body"], case="c1-edited"))
        _relink(p.a, A_ID, B_ID)
        p.planted = 1
        return p, kw, {"changed-after-ack"}, "matched"
    if name == "a_delete_after_ack":
        p.actions.append(p.act(3))
        del p.a[_find(p.a, "settlement", p.actions[1]["cid"])]
        p.planted = 1
        return p, kw, {"removed-after-ack", "gap"}, "matched"
    raise KeyError(name)


def _epoch(s):
    return books._epoch(s)


SELF_TEST = ("honest", "receipt_contradicts_log", "receipt_contradicts_state", "unbacked_on_b",
             "unbacked_on_a", "compensating_pair", "join_collision", "b_edit_after_ack",
             "b_delete_after_ack", "void_over_receipt", "seq_reorder", "seq_duplicate",
             "clock_skew", "late_entry", "translated_declared", "basis_undeclared",
             "declared_void", "a_edit_after_ack", "a_delete_after_ack")


def _self_test(reconciler, name):
    """True if `reconciler` reports exactly what the fixture planted: every expected break kind
    (and no other), and the expected state for the planted action."""
    p, over, kinds, state = _fixture(name)
    got = reconciler(p.a, p.b, **p.kw(**over)).run()
    if set(got.kinds()) != kinds:
        return False, f"kinds {sorted(got.kinds())} != {sorted(kinds)}"
    planted = p.key(getattr(p, "planted", -1))
    if got.states.get(planted) != state:
        return False, f"state {got.states.get(planted)!r} != {state!r}"
    others = {k: v for k, v in got.states.items() if k != planted}
    if not kinds and any(v not in ("matched",) for v in others.values()):
        return False, f"other actions {others}"
    return True, ""


@pytest.mark.parametrize("name", SELF_TEST)
def test_the_kits_reconciler_reports_each_planted_difference(name):
    ok, why = _self_test(books.Reconciler, name)
    assert ok, why


def test_the_honest_pair_is_matched_at_the_top_grades():
    p, over, _, _ = _fixture("honest")
    got = books.reconcile(p.a, p.b, **p.kw(**over))
    assert set(got.states.values()) == {"matched"} and not got.breaks and not got.findings
    assert (got.grade_a, got.grade_b) == ("cross-held", "cross-held")


def test_a_redelivered_receipt_is_explained_not_a_break():
    p = Pair(2)
    p.hold_a.append(dict(p.hold_a[0]))
    got = books.reconcile(p.a, p.b, **p.kw())
    assert not got.breaks and got.states[p.key(0)] == "explained"
    assert got.explained[p.key(0)] == ["redelivery"]


def test_an_unverifiable_receipt_is_missing_not_a_break():
    """A receipt signed by an unpinned key is treated as absent: a finding, not a break."""
    p = Pair(2)
    other = r.Keypair.from_seed("b-receipts", bytes([9]) * 32)
    claims = json.loads(r._b64d(p.actions[0]["token"].split(".")[1]))
    p.hold_a[0] = {"type": "receipt", "token": r.sign_receipt(claims, other)}
    got = books.reconcile(p.a, p.b, **p.kw())
    assert [f.kind for f in got.findings] == ["unverifiable"] and not got.breaks


def test_a_person_settles_a_break_in_a_new_entry_that_names_both_originals():
    p, over, _, _ = _fixture("seq_duplicate")
    k = p.key(3)
    first = books.reconcile(p.a, p.b, **p.kw(**over))
    br = next(b for b in first.breaks if b.kind == "repeated")
    p._add("A", "settlement", {"outcome": "executed", "by": "person:alice",
                               "settles": list(br.sides["A"]) + list(br.sides["B"])}, k[2], k[3])
    got = books.reconcile(p.a, p.b, **p.kw(**over))
    assert got.states[k] == "settled" and "repeated" in got.kinds()
    p2, over, _, _ = _fixture("seq_duplicate")
    p2._add("A", "settlement", {"outcome": "executed", "by": "rule:auto",
                                "settles": list(br.sides["A"]) + list(br.sides["B"])}, k[2], k[3])
    assert books.reconcile(p2.a, p2.b, **p2.kw(**over)).states[k] == "break"


def test_an_unnumbered_side_is_state_only_and_says_so():
    p = Pair(2)
    a = [dict(e, pair_seq=None, prev_digest=None) for e in p.a]
    got = books.reconcile(a, p.b, **p.kw(holdings_b=[]))
    assert got.grade_a == "state-only" and "unnumbered" in {f.kind for f in got.findings}
    assert set(got.states.values()) == {"matched"}


def test_the_reconciler_reads_no_clock_for_order_or_join():
    """Shifting every B time by an hour changes nothing but the explained clock note."""
    p = Pair(3)
    for e in p.b:
        e["recorded_at"] = _at(_epoch(e["recorded_at"]) + 3600)
    _relink(p.b, B_ID, A_ID)
    got = books.reconcile(p.a, p.b, **p.kw(b_checkpoint_keys={}))
    assert not got.breaks and set(got.states.values()) == {"explained"}
    got = books.reconcile(p.a, p.b, **p.kw(b_checkpoint_keys={}, tolerance_s=None))
    assert set(got.states.values()) == {"matched"}


def test_an_a_request_inside_the_window_is_awaiting():
    p = Pair(1)
    cid, rd = "case-new", "sha256:" + "9" * 64
    e = p._add("A", "request-sent", dict(p.actions[0]["req"]), cid, rd, t=T0 + 1000)
    k = (A_ID, B_ID, cid, rd)
    assert books.reconcile(p.a, p.b, **p.kw(now=T0 + 1010, window_s=60)).states[k] == "awaiting"
    got = books.reconcile(p.a, p.b, **p.kw(now=T0 + 2000, window_s=60))
    assert got.states[k] == "break" and "missing-on-b" in got.kinds(k)
    assert e["kind"] == "request-sent"


# --------------------------------------------------------------------------- weakened copies
# Each copy skips one check that a weak reconciler skips. The self-test must fail under each
# (KRK-M29): a fixture set that a weakened reconciler also passes says nothing.


class ReceiptsAsLog(books.Reconciler):
    """B's side taken from the receipts A holds: B's own log of effects is never read."""
    def statement_vs_log(self, key, gk):
        return []

    def read_state(self, key, gk):
        return []


class NoStateRead(books.Reconciler):
    def read_state(self, key, gk):
        return []


class WalksOwnEntries(books.Reconciler):
    """Looks up each of A's actions at B, never B's actions at A."""
    def keys(self, g):
        return [k for k, gk in g.items() if gk.get("A:request-sent")]


class CountsOnly(books.Reconciler):
    """Compares A's requested total with B's committed total."""
    def missing(self, key, gk):
        return []

    def run(self):
        got = super().run()
        a = sum(e["body"].get("count", 0) for e in self.a if e["kind"] == "request-sent")
        b = sum(e["body"].get("created", 0) for e in self.b if e["kind"] == "effect-committed")
        got.breaks = [x for x in got.breaks if x.kind not in ("missing-on-a", "missing-on-b")]
        if a != b:
            got.breaks.append(books.Break("content-differs", None, {}, "totals differ"))
        return got


class CorrelationOnly(books.Reconciler):
    """Joins on the correlation id alone, so another requester's entry under the same string
    is taken as this pair's."""
    def split(self):
        self.b_in = [dict(e, peer=self.requester) if e["side"] == "B" else e for e in self.b_in]
        super().split()


class NoCheckpoints(books.Reconciler):
    """Never re-checks a record against what the other side holds of it."""
    def checkpoints(self):
        return None


class IgnoresSequence(books.Reconciler):
    def chains(self):
        return None

    def checkpoints(self):
        return None


class TrustsVoid(books.Reconciler):
    def voids(self, key, gk):
        if gk.get("B:void"):
            self.explained.setdefault(key, []).append("declared-void")
        return []


class DedupsByRequest(books.Reconciler):
    def repeated(self, key, gk):
        return []


class ForgetsSettled(books.Reconciler):
    def settlements(self, key, gk):
        return []


class ShapeOnly(books.Reconciler):
    """Compares counts and digests and ignores the operation basis."""
    def basis(self, key, gk):
        a, b = gk.get("A:request-sent", []), gk.get("B:request-received", [])
        if not a or not b:
            return None, []
        diff = [f for f in ("count", "items_digest") if a[0]["body"].get(f) != b[0]["body"].get(f)]
        return None, [self._br("content-differs", key, gk, "differ")] if diff else []


class JoinsByTime(books.Reconciler):
    """Pairs A's and B's entries by time, inside a five-minute window, instead of by key."""
    def group(self):
        g = super().group()
        out = {}
        for k, gk in g.items():
            a = gk.get("A:request-sent", [])
            b = gk.get("B:request-received", [])
            if a and b and abs(_epoch(a[0]["recorded_at"]) - _epoch(b[0]["recorded_at"])) > 300:
                out[k] = {n: v for n, v in gk.items() if n.startswith("A:")}
                out[(k[0], k[1], k[2] + "/b", k[3])] = {n: v for n, v in gk.items()
                                                        if n.startswith("B:")}
            else:
                out[k] = gk
        return out


WEAKENED = {ReceiptsAsLog: "receipt_contradicts_log", NoStateRead: "receipt_contradicts_state",
            WalksOwnEntries: "unbacked_on_b", CountsOnly: "compensating_pair",
            CorrelationOnly: "join_collision", NoCheckpoints: "a_edit_after_ack",
            IgnoresSequence: "seq_reorder", TrustsVoid: "void_over_receipt",
            DedupsByRequest: "seq_duplicate", ForgetsSettled: "late_entry",
            ShapeOnly: "basis_undeclared", JoinsByTime: "clock_skew"}


@pytest.mark.parametrize("weak", list(WEAKENED), ids=lambda w: w.__name__)
def test_the_self_test_fails_a_weakened_reconciler(weak):
    """The fixture the weakness is about catches it, and the honest pair still passes, so the
    weakness is what fails and not the copy as a whole."""
    ok, why = _self_test(weak, WEAKENED[weak])
    assert not ok, f"{weak.__name__} passed {WEAKENED[weak]}"
    assert _self_test(weak, "honest")[0]
