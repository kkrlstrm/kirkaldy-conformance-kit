"""P17 (KRK-17) toys: a target A that keeps a two-sided record and reconciles it, and copies of
it that each have one flaw.

- ``good``: keeps one log per counterparty, numbered with no gap and chained
  (`books.SCHEMA`); after every entry it writes, it signs a checkpoint of its log and sends it to
  B (`hold`); it keeps B's receipts and checkpoints raw; it completes an action only on B's
  verified, matching receipt; and it reconciles by the recommended rule (design §5.2): it reads
  B's log through the path the agreement gives (`record`), never from the receipts it holds;
  joins on the full key; walks both sides; compares contents; re-checks both logs against every
  checkpoint on every run; closes only the differences on which both sides agree about the
  effect, each with a new entry naming the rule; holds every other difference open as a break,
  alerts a person, and lets a person settle it in a new entry that names both originals. Its
  reconciler is its own code and never calls `books.Reconciler` (pattern 10: the kit's
  reconciler and the target's share no code); it uses the shared format functions only
  (`entry_digest`, `verify_checkpoint`, `receipts.verify_receipt`).
- ``bad``: one flaw from `FLAWS` (`incremental_only` by default).
- ``no-control``: has no export path, so the control cannot read its record and the probe must
  give no verdict.

| Flaw | What it does wrong | Must fail |
|---|---|---|
| ``reconciles_against_receipts`` | builds B's side from the receipts it holds, never reads B's log for effects | ``receipt_contradicts_log``, ``seq_duplicate`` (B's second effect is in no receipt) |
| ``no_state_read`` | never reads B's state | ``receipt_contradicts_state`` |
| ``walks_own_entries`` | looks up its own actions at B, never B's actions at A | ``unbacked_on_b``, ``compensating_pair`` |
| ``trusts_own_done`` | an action it settled as executed is matched when B has nothing for it | ``unbacked_on_a`` |
| ``counts_only`` | finds missing actions by comparing totals | ``compensating_pair`` (and reads a false break on ``declared_void``, information) |
| ``joins_on_correlation_only`` | joins on the correlation id alone, last entry wins | ``join_collision`` |
| ``incremental_only`` | reconciles only B's entries and checkpoints new since its last run | ``b_edit_after_ack``, ``b_delete_after_ack``, ``seq_reorder`` |
| ``ignores_sequence`` | never checks B's numbering or chain | ``b_delete_after_ack``, ``seq_reorder`` |
| ``trusts_void`` | any void explains its action | ``void_over_receipt`` |
| ``dedups_by_request`` | a second effect for one request is a redelivery | ``seq_duplicate`` |
| ``mutable_record`` | sends B nothing to hold, so an insider's edit of its own log leaves no trace | ``a_edit_after_ack`` (a removal still leaves a gap in its own numbering, which its export shows) |
| ``loses_entry_on_crash`` | sets the status before writing the settling entry | ``torn_write`` |
| ``joins_by_time_window`` | pairs its requests with B's by time, inside its tolerance | ``clock_skew`` |
| ``settles_and_forgets`` | never re-examines an action a person settled | ``late_entry`` |
| ``matches_by_shape`` | compares counts and digests and ignores the operation basis | ``basis_undeclared`` |
| ``overwrite_loser`` | settles by rewriting its own entries to the settled account | every break variant (``overwrote``) |
| ``silent_break`` | records a break and tells nobody | every break variant (``found_silent``) |
| ``record_settles_effect`` | reads an effect as settled once every break about it is settled for the record, outcome or not | every effect check (``closed_without_outcome``) |

The correct toy reads an effect (`effect_state`) from its case's status, except while a break
about the effect (`p17.HOLDS_EFFECT`) is open, or a person settled one without an outcome and no
person has given one since: then the effect is open and the case is not closed. A person's
outcome on any break about the case (``executed`` or ``not-executed``) settles the case that way.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from conformance import books, receipts

FLAWS = ("reconciles_against_receipts", "no_state_read", "walks_own_entries", "trusts_own_done",
         "counts_only", "joins_on_correlation_only", "incremental_only", "ignores_sequence",
         "trusts_void", "dedups_by_request", "mutable_record", "loses_entry_on_crash",
         "joins_by_time_window", "settles_and_forgets", "matches_by_shape", "overwrite_loser",
         "silent_break", "record_settles_effect")
BAD_DEFAULT = "incremental_only"
DEADLINE_S = 30.0
WINDOW_S = 30.0
TOLERANCE_S = 300.0
EXPLAINED = ("redelivery", "declared-void", "clock-skew", "mapping")
OUTCOMES = ("executed", "not-executed")
HOLDS_EFFECT = ("missing-on-a", "missing-on-b", "content-differs", "statement-vs-log",
                "statement-vs-state", "changed-after-ack", "removed-after-ack", "repeated",
                "settlement-contradicted")
"""The toy's own list of break kinds that hold an effect (`p17.HOLDS_EFFECT`; a test checks they
agree). The toy keeps its own copy, as a product would."""


class ToyCrash(RuntimeError):
    """The toy's process dying between two writes (`crash_between`)."""


def _wall() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _claims(token: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(receipts._b64d(token.split(".")[1]))
    except Exception:
        return None


def _epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


class ToyRecords:
    name = "toy-records"

    def __init__(self, variant: str = "good", flaw: Optional[str] = None) -> None:
        assert variant in ("good", "bad", "no-control"), variant
        if variant == "bad" and flaw is None:
            flaw = BAD_DEFAULT
        assert flaw is None or (variant == "bad" and flaw in FLAWS), (variant, flaw)
        self.variant, self.flaw = variant, flaw
        self.config = f"bad:{flaw}" if flaw else variant
        self.me = "did:web:a.example"
        self.key = receipts.Keypair.generate("a-checkpoints-toy")
        self.pinned: Dict[str, bytes] = {}
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.clock = 0.0
        self.crash_armed: Dict[str, bool] = {}
        self.crashes: Dict[str, bool] = {}
        self.decisions = 0

    # Target ---------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def implements(self):
        return ["P17"]

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    # KRK-16 driving -------------------------------------------------------------------------

    def pin_counterparty_key(self, kid: str, public_key: bytes) -> None:
        self.pinned[kid] = bytes(public_key)

    def bind_counterparty_record(self, peer: str, agreement: Dict[str, Any]) -> str:
        self.peers[peer] = {"agreement": agreement, "log": [], "held": [], "at": {},
                            "breaks": {}, "seen_b": 0, "seen_ck": 0, "settled_keys": set(),
                            "explained": {}, "states": {}}
        return "kept the agreement: B's keys, the declared mapping, and its record paths"

    def submit(self, envelope: Dict[str, Any], expected: Any) -> str:
        peer = envelope["counterparty"]
        case_id = f"case-{len(self.cases) + 1}"
        rd = receipts.request_digest(envelope)
        self.cases[case_id] = {"peer": peer, "cid": envelope["correlation_id"], "rd": rd,
                               "expected": expected, "status": "awaiting-receipt",
                               "grade": None, "submitted_at": self.clock}
        self._write(peer, "request-sent", envelope["correlation_id"], rd,
                    {"operation": expected.operation, "container": expected.container,
                     "count": expected.count, "items_digest": expected.items_digest,
                     "expected_effect_digest": expected.digest(), "case": case_id,
                     "approved_by": "person:approver@a.example"})
        return case_id

    def deliver(self, case_id: str, receipt: Optional[str],
                executor_report: Optional[Dict[str, Any]]) -> None:
        c = self.cases[case_id]
        self._repair(case_id)
        if receipt is None:
            return
        p = self.peers[c["peer"]]
        sha = receipts.sha256_ref(receipt.encode("utf-8"))
        if not any(h["token"] == receipt for h in p["held"]):
            p["held"].append({"type": "receipt", "token": receipt})
            cl = _claims(receipt) or {}
            self._write(c["peer"], "receipt-received", c["cid"], c["rd"],
                        {"receipt_id": cl.get("receipt_id"), "verdict": cl.get("verdict"),
                         "log_seq": cl.get("log_seq")}, raw=sha)
        if c["status"] in ("done", "not-executed"):
            return
        if self._matches(c, receipt):
            self._complete(case_id, c, "rule:verified-receipt", "signed-by-B")
        else:
            c["status"] = "blocked"

    def deliver_checkpoint(self, case_id: str, token: str) -> None:
        peer = self.cases[case_id]["peer"]
        p = self.peers[peer]
        if any(h["token"] == token for h in p["held"]):
            return
        p["held"].append({"type": "checkpoint", "token": token})
        cl = _claims(token) or {}
        self._write(peer, "checkpoint-received", None, None,
                    {"pair_seq": cl.get("pair_seq"), "head": cl.get("head")},
                    raw=receipts.sha256_ref(token.encode("utf-8")))

    def status(self, case_id: str) -> str:
        self._repair(case_id)
        return self.cases[case_id]["status"]

    def evidence_grade(self, case_id: str) -> Optional[str]:
        return self.cases[case_id]["grade"]

    def receipt_deadline_s(self) -> float:
        return DEADLINE_S

    def elapse(self, seconds: float) -> None:
        self.clock += seconds

    def _matches(self, c: Dict[str, Any], token: str) -> bool:
        v = receipts.verify_receipt(token, self.pinned)
        if not v.ok:
            return False
        cl, exp = v.claims, c["expected"]
        out = cl["outcome"]
        return (cl["request_digest"] == c["rd"] and cl["correlation_id"] == c["cid"]
                and cl["expected_effect_digest"] == exp.digest() and cl["verdict"] == "executed"
                and out["created"] + out["updated"] + out["deleted"] == exp.count
                and not out["failed"] and cl["items_digest"] == exp.items_digest)

    def _complete(self, case_id: str, c: Dict[str, Any], by: str, grade: str,
                  outcome: str = "executed") -> None:
        body = {"outcome": outcome, "by": by, "case": case_id,
                **({"count": c["expected"].count} if outcome == "executed" else {})}
        status = "done" if outcome == "executed" else "not-executed"
        if self.crash_armed.pop(case_id, False):
            self.crashes[case_id] = True
            if self.flaw == "loses_entry_on_crash":
                c.update(status=status, grade=grade)       # the status first, then the crash
                raise ToyCrash("died between setting the status and writing the entry")
            self._write(c["peer"], "settlement", c["cid"], c["rd"], body)
            raise ToyCrash("died between writing the entry and setting the status")
        self._write(c["peer"], "settlement", c["cid"], c["rd"], body)
        c.update(status=status, grade=grade)

    def _repair(self, case_id: str) -> None:
        """After a crash, the status follows the log: the settling entry was written first."""
        c = self.cases[case_id]
        if c["status"] in ("done", "not-executed"):
            return
        for e in self.peers.get(c["peer"], {}).get("log", []):
            if e["kind"] == "settlement" and e["body"].get("case") == case_id:
                c["status"] = "done" if e["body"]["outcome"] == "executed" else "not-executed"

    # The log ----------------------------------------------------------------------------------

    def _write(self, peer: str, kind: str, cid: Optional[str], rd: Optional[str],
               body: Dict[str, Any], raw: Optional[str] = None) -> Dict[str, Any]:
        p = self.peers[peer]
        log = p["log"]
        e = {"schema": books.SCHEMA, "side": "A", "party": self.me, "peer": peer,
             "pair_seq": (log[-1]["pair_seq"] + 1) if log else 1,
             "prev_digest": books.entry_digest(log[-1]) if log else None, "kind": kind,
             "correlation_id": cid, "request_digest": rd, "answers": None, "body": body,
             "raw_sha256": raw, "recorded_at": _wall()}
        log.append(e)
        p["at"][books.entry_digest(e)] = self.clock
        if self.flaw != "mutable_record":
            claims = books.checkpoint_claims(self.me, peer, e["pair_seq"], books.entry_digest(e),
                                             _wall())
            p["agreement"]["hold"](books.sign_checkpoint(claims, self.key))
        return e

    def export(self, peer: str) -> List[Dict[str, Any]]:
        if self.variant == "no-control":
            raise RuntimeError("this toy has no export path")
        return [dict(e) for e in self.peers[peer]["log"]]

    def export_raw(self, peer: str) -> bytes:
        return b"\n".join(receipts.canonical_json(e) for e in self.export(peer))

    def holdings(self, peer: str) -> List[Dict[str, Any]]:
        return [dict(h) for h in self.peers[peer]["held"]]

    def checkpoint_key(self) -> Tuple[str, bytes]:
        return self.key.kid, self.key.public_bytes()

    def record_grade(self) -> str:
        return "cross-held"

    def reconciles(self) -> bool:
        return True

    def settlement_rule(self) -> Dict[str, Any]:
        return {"closes_by_rule": list(EXPLAINED),
                "presumption": "B's log for what B did; A's record for what A asked",
                "window_s": WINDOW_S, "tolerance_s": TOLERANCE_S}

    # Target-side hooks ------------------------------------------------------------------------

    def operator_write(self, peer: str, entry_digest: str,
                       change: Optional[Dict[str, Any]]) -> str:
        """An insider with write access to the toy's store: edits or deletes the entry in place
        and re-links the entries after it, so the toy's own chain looks whole. It cannot reach
        what B holds."""
        log = self.peers[peer]["log"]
        i = next(i for i, e in enumerate(log) if books.entry_digest(e) == entry_digest)
        if change is None:
            del log[i]
            what = "removed"
        else:
            log[i] = dict(log[i], body=dict(log[i]["body"], **change))
            what = "changed"
        prev = books.entry_digest(log[i - 1]) if i else None
        for e in log[i:]:
            if e["pair_seq"] != 1:
                e["prev_digest"] = prev
            prev = books.entry_digest(e)
        return what

    def crash_between(self, case_id: str, step: str) -> str:
        self.crash_armed[case_id] = True
        return f"armed: the next settlement of {case_id} dies between its two writes"

    def crashed(self, case_id: str) -> bool:
        return bool(self.crashes.get(case_id))

    def _tick(self) -> int:
        """The order of a person's decisions in this toy."""
        self.decisions += 1
        return self.decisions

    def reconcile_attempt_as_person(self, case_id: str, outcome: str, by: str) -> str:
        c = self.cases[case_id]
        self._complete(case_id, c, by, "person", outcome)
        c["outcome_seq"] = self._tick()
        return f"{by} settled {case_id} as {outcome}"

    # The toy's reconciler (its own code) ------------------------------------------------------

    def reconcile(self, peer: str) -> str:
        p = self.peers[peer]
        ag = p["agreement"]
        b_all = list(ag["record"]())
        mine = p["log"]
        rkeys = dict(self.pinned)
        ckeys = dict([ag["checkpoint_key"]])
        found: Dict[str, Dict[str, Any]] = {}
        p["explained"] = {}

        def raise_(kind, key, entries, detail):
            ref = f"{kind}|{books.key_str(key) if key else ''}|{','.join(sorted(entries))[:80]}"
            found[ref] = {"ref": ref, "key": books.key_str(key) if key else None, "kind": kind,
                          "entries": sorted(entries), "detail": detail}

        incremental = self.flaw == "incremental_only"
        new_b = [e for e in b_all if e["pair_seq"] > p["seen_b"]] if incremental else b_all
        b_mine = [e for e in b_all if e["peer"] == self.me]
        if self.flaw == "joins_on_correlation_only":
            b_mine = [dict(e, peer=self.me) for e in b_all]
        # B's numbering and chain
        if self.flaw != "ignores_sequence":
            seqs = sorted(e["pair_seq"] for e in b_mine)
            nums = set(seqs)
            low = p["seen_b"] if incremental else 0
            for n in range(max(low, 1), (max(seqs) if seqs else 0) + 1):
                if n not in nums:
                    raise_("gap", None, [str(n)], f"B has no entry {n}")
            if len(seqs) != len(nums):
                raise_("renumbered", None, ["dup"], "B numbers two entries alike")
            by_n = {e["pair_seq"]: e for e in b_mine}
            for e in b_mine:
                n = e["pair_seq"]
                if incremental and n <= p["seen_b"]:
                    continue
                if n > 1 and (n - 1) in by_n and e["prev_digest"] != books.entry_digest(by_n[n - 1]):
                    other = {books.entry_digest(x) for x in b_mine}
                    raise_("renumbered" if e["prev_digest"] in other else "torn",
                           books.action_key(e) if e["correlation_id"] else None,
                           [books.entry_digest(e)], f"B's entry {n} does not link to {n - 1}")
            # B's record against the checkpoints of B's that the toy holds
            cks = [h["token"] for h in p["held"] if h["type"] == "checkpoint"]
            for tok in (cks[p["seen_ck"]:] if incremental else cks):
                v = books.verify_checkpoint(tok, ckeys)
                if not v.ok:
                    continue
                n, head = v.claims["pair_seq"], v.claims["head"]
                if n not in by_n:
                    raise_("removed-after-ack", None, [str(n)], f"B's entry {n} is gone")
                elif books.entry_digest(by_n[n]) != head:
                    raise_("changed-after-ack", None, [head], f"B's entry {n} changed")
            p["seen_ck"] = len(cks)
        # The toy's own log against what B holds of it (B logs each checkpoint it receives)
        if self.flaw != "mutable_record":
            mine_by_n = {e["pair_seq"]: e for e in mine}
            for e in b_mine:
                if e["kind"] != "checkpoint-received":
                    continue
                n, head = e["body"]["pair_seq"], e["body"]["head"]
                if n not in mine_by_n:
                    raise_("removed-after-ack", None, [head], f"my entry {n} is gone")
                elif books.entry_digest(mine_by_n[n]) != head:
                    raise_("changed-after-ack", None, [head], f"my entry {n} changed")
            for n in range(1, (max(mine_by_n) if mine_by_n else 0) + 1):
                if n not in mine_by_n:
                    raise_("gap", None, [f"a{n}"], f"my entry {n} is missing")
        # Receipts held, verified
        rcpts: Dict[Tuple, List[Dict[str, Any]]] = {}
        shas: Dict[str, int] = {}
        for h in p["held"]:
            if h["type"] != "receipt":
                continue
            v = receipts.verify_receipt(h["token"], rkeys)
            if not v.ok:
                continue
            c = v.claims
            k = (self.me, peer, c["correlation_id"], c["request_digest"])
            rcpts.setdefault(k, []).append(c)
        # Per action
        groups: Dict[Tuple, Dict[str, List[Dict[str, Any]]]] = {}
        b_digest = {books.entry_digest(e): e for e in b_all}
        by_cid = {e["correlation_id"]: books.action_key(e) for e in mine
                  if e["kind"] == "request-sent"}

        def join(k):
            """The key this toy joins on: the full key, or (flaw) whatever key A used for the
            correlation id, last entry wins."""
            if self.flaw == "joins_on_correlation_only":
                return by_cid.get(k[2], (self.me, peer, k[2], k[3]))
            return k

        for e in mine + b_mine:
            if e["kind"] == "void" and e["body"]["voids"] in b_digest:
                k = join(books.action_key(b_digest[e["body"]["voids"]]))
            elif e["correlation_id"] and e["request_digest"]:
                k = join(books.action_key(e))
            else:
                continue
            groups.setdefault(k, {}).setdefault(f"{e['side']}{e['kind']}", []).append(e)
        if self.flaw == "joins_on_correlation_only":
            rc2: Dict[Tuple, List[Dict[str, Any]]] = {}
            for k, v in rcpts.items():
                rc2.setdefault(join(k), []).extend(v)
            rcpts = rc2
        for e in [x for x in b_all if x["peer"] != self.me]:
            if self.flaw != "joins_on_correlation_only" and any(
                    m.get("correlation_id") == e["correlation_id"] for m in mine):
                raise_("join-ambiguous", books.action_key(e), [books.entry_digest(e)],
                       "another requester's entry under my correlation id")
        if self.flaw == "counts_only":
            a_tot = sum(e["body"]["count"] for e in mine if e["kind"] == "request-sent")
            b_tot = sum(e["body"]["created"] + e["body"]["updated"] for e in b_mine
                        if e["kind"] == "effect-committed")
            if a_tot > b_tot:
                raise_("missing-on-b", None, ["totals"], "B committed less than A asked")
            if b_tot > a_tot:
                raise_("missing-on-a", None, ["totals"], "B committed more than A asked")
        tol = self.settlement_rule()["tolerance_s"]
        for k, g in groups.items():
            if self.flaw == "settles_and_forgets" and k in p["settled_keys"]:
                continue
            if incremental and not any(e in new_b for es in g.values() for e in es
                                       if e["side"] == "B") and not any(
                    p["at"].get(books.entry_digest(e), -1) >= 0 and e["side"] == "A"
                    and books.entry_digest(e) not in p.get("done_a", set())
                    for es in g.values() for e in es):
                continue
            areq = g.get("Arequest-sent", [])
            breq = g.get("Brequest-received", [])
            beff = g.get("Beffect-committed", [])
            bany = breq + beff + g.get("Breceipt-issued", [])
            held = rcpts.get(k, [])
            dig = lambda es: [books.entry_digest(e) for e in es]
            if self.flaw == "reconciles_against_receipts":
                beff = [{"body": {**c["outcome"], "items_digest": c["items_digest"],
                                  "log_seq": c["log_seq"]}} for c in held]
                bany = bany or beff
            if self.flaw == "joins_by_time_window" and areq and breq and abs(
                    _epoch(areq[0]["recorded_at"]) - _epoch(breq[0]["recorded_at"])) > tol:
                raise_("missing-on-b", k, dig(areq), "no B entry inside my time window")
                raise_("missing-on-a", k, dig(breq), "no A entry inside my time window")
                continue
            if areq and not bany:
                own = [s for s in g.get("Asettlement", []) if s["body"]["outcome"] == "executed"]
                if self.clock - p["at"].get(books.entry_digest(areq[0]), 0) < WINDOW_S:
                    p["explained"][k] = "awaiting"
                elif self.flaw == "counts_only" or (self.flaw == "trusts_own_done" and own):
                    pass
                elif any(c["verdict"] == "executed" for c in held):
                    raise_("removed-after-ack", k, dig(areq), "B signed for it; B has nothing")
                else:
                    raise_("missing-on-b", k, dig(areq), "B has nothing for my request")
            if (bany and not areq and self.flaw not in ("walks_own_entries", "counts_only")):
                raise_("missing-on-a", k, dig(breq + beff), "B has an action I never asked for")
            if areq and breq:
                ab, bb = dict(areq[0]["body"]), dict(breq[0]["body"])
                basis = True
                if self.flaw != "matches_by_shape":
                    for f in ("operation", "container"):
                        if bb[f] != ab[f]:
                            m = (ag.get("mapping") or {}).get(f, {})
                            if bb[f] in m:
                                bb[f] = m[bb[f]]
                                p["explained"][k] = "mapping"
                            else:
                                basis = False
                if not basis:
                    p["explained"][k] = "no-basis"
                    raise_("no-basis", k, dig(areq + breq), "no declared mapping")
                elif any(bb.get(f) != ab.get(f) for f in ("count", "items_digest")):
                    raise_("content-differs", k, dig(areq + breq), "request differs")
                if abs(_epoch(areq[0]["recorded_at"]) - _epoch(breq[0]["recorded_at"])) > tol:
                    p["explained"].setdefault(k, "clock-skew")
            if len(beff) > 1 and self.flaw != "dedups_by_request":
                raise_("repeated", k, dig(beff), "B committed twice")
            for c in held:
                if c["verdict"] != "executed":
                    continue
                hit = [e for e in beff if e["body"].get("log_seq") == c["log_seq"]]
                said = (c["outcome"]["created"], c["outcome"]["updated"], c["outcome"]["deleted"])
                if bany and (not hit or (hit[0]["body"]["created"], hit[0]["body"]["updated"],
                                         hit[0]["body"]["deleted"]) != said):
                    raise_("statement-vs-log", k, dig(beff), "receipt and B's log differ")
                if self.flaw != "no_state_read":
                    st = ag["read_state"](k[2])
                    if st["written"] != sum(said):
                        raise_("statement-vs-state", k, dig(beff), "receipt and B's state differ")
            for v in g.get("Bvoid", []):
                if self.flaw == "trusts_void" or not any(c["verdict"] == "executed" for c in held):
                    if not beff or self.flaw == "trusts_void":
                        p["explained"][k] = "declared-void"
                else:
                    raise_("removed-after-ack", k, dig([v]), "B voids what it signed for")
            for s in g.get("Asettlement", []):
                if (books.by_person(s["body"]["by"]) and s["body"]["outcome"] == "not-executed"
                        and (any(e["body"]["created"] + e["body"]["updated"] for e in beff)
                             or any(c["verdict"] == "executed" for c in held))):
                    raise_("settlement-contradicted", k, dig([s] + beff),
                           "B's record contradicts a person's settlement")
        p["seen_b"] = max([e["pair_seq"] for e in b_mine] or [0])
        p["done_a"] = {books.entry_digest(e) for e in mine}
        # Keep what a person settled; raise an alert for each new break.
        old = p["breaks"]
        for ref, br in found.items():
            if ref in old and old[ref]["state"] == "settled":
                continue
            if br["kind"] == "no-basis":
                br.update(state="break", settled_by=None)
                old[ref] = br
                continue
            br.update(state="break", settled_by=None)
            if ref not in old and self.flaw != "silent_break":
                alert = self._write(peer, "alert", None, None,
                                    {"break": br["kind"], "entries": br["entries"], "ref": ref})
                br["alert"] = books.entry_digest(alert)
            elif ref in old:
                br["alert"] = old[ref].get("alert")
            old[ref] = br
        for ref in list(old):
            if ref not in found and old[ref]["state"] == "break" and not incremental:
                del old[ref]            # resolved: B's entry arrived, or the window was open
        for k, why in p["explained"].items():
            if why in EXPLAINED and not any(b["key"] == books.key_str(k) for b in old.values()):
                g = groups.get(k, {})
                named = [books.entry_digest(e) for es in g.values() for e in es]
                if not any(e["kind"] == "settlement" and e["body"].get("rule") == why
                           and e["correlation_id"] == k[2] for e in mine):
                    self._write(peer, "settlement", k[2], k[3],
                                {"outcome": "explained", "by": f"rule:{why}", "rule": why,
                                 "settles": named})
        states = {}
        for k in groups:
            ks = books.key_str(k)
            mine_b = [b for b in old.values() if b["key"] == ks]
            if any(b["state"] == "break" and b["kind"] == "no-basis" for b in mine_b):
                states[ks] = "no-basis"
            elif any(b["state"] == "break" for b in mine_b):
                states[ks] = "break"
            elif mine_b:
                states[ks] = "settled"
            elif p["explained"].get(k) == "awaiting":
                states[ks] = "awaiting"
            elif p["explained"].get(k):
                states[ks] = "explained"
            else:
                states[ks] = "matched"
        p["states"] = states
        return f"reconciled {len(groups)} actions; {len(old)} breaks"

    def breaks(self, peer: str) -> List[Dict[str, Any]]:
        return [dict(b) for b in self.peers[peer]["breaks"].values() if b["kind"] != "no-basis"]

    def states(self, peer: str) -> Dict[str, str]:
        return dict(self.peers[peer]["states"])

    def flagged(self, peer: str, ref: str) -> Tuple[bool, str]:
        b = self.peers[peer]["breaks"].get(ref) or {}
        return (bool(b.get("alert")), f"alert entry {b.get('alert')}" if b.get("alert")
                else "no alert")

    def effect_state(self, case_ref: str) -> Dict[str, Any]:
        """The toy's reading of a case's effect (module docstring)."""
        c = self.cases[case_ref]
        key = books.key_str((self.me, c["peer"], c["cid"], c["rd"]))
        mine = [b for b in self.peers[c["peer"]]["breaks"].values()
                if b["key"] == key and b["kind"] in HOLDS_EFFECT]
        if self.flaw == "record_settles_effect":
            waiting = [b for b in mine if b["state"] == "break"]
        else:
            # A person's outcome counts only if given after the break was settled: an earlier
            # decision (made before B's late entry, say) is what the break disagrees with.
            waiting = [b for b in mine if b["state"] == "break"
                       or (b.get("outcome") is None
                           and c.get("outcome_seq", -1) < b.get("settled_seq", 0))]
        if waiting:
            return {"effect": "open", "closed": False,
                    "product": {"status": c["status"], "held_by": sorted(b["ref"] for b in waiting)}}
        effect = {"done": "done", "not-executed": "not-done"}.get(c["status"], "open")
        return {"effect": effect, "closed": c["status"] in ("done", "not-executed"),
                "product": {"status": c["status"]}}

    def settle_as_person(self, peer: str, ref: str, decision: str, by: str) -> str:
        p = self.peers[peer]
        br = p["breaks"][ref]
        named = [d for d in br["entries"] if d.startswith("sha256:")]
        key = tuple(br["key"].split("|")) if br["key"] else None
        cid, rd = (key[2], key[3]) if key else (None, None)
        if decision in OUTCOMES and br["kind"] in HOLDS_EFFECT:
            # A person's outcome about the effect settles the case that way.
            br["outcome"] = decision
            for case in self.cases.values():
                if case["peer"] == peer and case["cid"] == cid and case["rd"] == rd:
                    case.update(outcome_seq=self._tick(), grade="person",
                                status="done" if decision == "executed" else "not-executed")
        br["settled_seq"] = self._tick()
        if self.flaw == "overwrite_loser":
            # Rewrite this side's entries of the action to the settled account.
            for e in p["log"]:
                if e["correlation_id"] == cid and e["kind"] in ("request-sent", "settlement"):
                    e["body"] = dict(e["body"], settled=decision)
            br.update(state="settled", settled_by=by)
            return f"{by} settled {ref} by rewriting the entries"
        s = self._write(peer, "settlement", cid or None, rd or None,
                        {"outcome": decision, "by": by, "settles": named, "break": br["kind"]})
        br.update(state="settled", settled_by=by, settlement=books.entry_digest(s))
        if key:
            p["settled_keys"].add(tuple(None if x == "" else x for x in key))
        return f"{by} settled {ref} in entry {books.entry_digest(s)}"


def make(flaw: Optional[str] = None) -> ToyRecords:
    return ToyRecords("bad", flaw) if flaw else ToyRecords("good")
