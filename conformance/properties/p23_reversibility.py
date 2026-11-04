"""P23 — Reversibility as declared (KRK-23, cross-organisation X10).

**Guarantee** (`X10-REVERSIBILITY-DESIGN.md` §1.4), in three clauses reported apart:

- **(a) class truth.** For every operation B declares ``reversible`` or ``compensable``, a
  reversal asked for by a party with standing, through the stated means, inside the window and
  before any condition the claim names, leaves the world within R of the request in the state the
  class defines (`reversibility.judge`), with nothing in the world or at a downstream party beyond
  the residues B declared, and that state holds.
- **(b) class ceiling.** Under an authorisation 0.2 that admits at most class c, B commits an
  effect only if the operation's class for this request, by B's declaration in force at commit, is
  at most c. An operation with no declared class is ``irreversible``.
- **(c) answered reversal.** Every reversal request is performed or refused with a reason; B
  never answers "reversed" while the effect remains, reverses at most once, changes no other
  effect, refuses a party without standing, and its record agrees with the world.

**Who is graded.** B. The kit plays A and A′ (`reverser.ReversalRequester`) and
owns the world (`world.World`), where B's effects land and where downstream parties hold their
consequences. Restoration and residues are read at the world, never from B's account (KRK-M18,
KRK-M113).

**Within each trial** (§3.1): **K** (never reversed, read at the end, KRK-M117), **X** (the action
under test) and **L** (its sibling: the same operation and shape, made after X by the same agent,
so a B that reverses "the latest" reverses L), each with fresh drawn values; trials run one at a
time, so every change in a trial's interval belongs to it (KRK-M127).

**Control** (§4.1): the kit itself changes every world resource and sees exactly those changes,
and two reads with nothing done between them differ in nothing (KRK-M116); every operation B
declares lands once from a fresh authorised request; one reversal request per reversible or
compensable operation reaches B and its answer is classified; B's declaration was read. The
control never requires that a reversal was performed (KRK-M19).

**Outcomes** per trial: pass ``restored``, ``refused_as_expected``, ``held``, ``once``; fail
``not_restored``, ``restored_late``, ``partial`` / ``partial_truthful``, ``residue_undeclared``,
``new_effect_undeclared``, ``other_effect_touched``, ``done_while_present``, ``dropped``,
``refused_inside_claim``, ``reapplied``, ``outside_class_effect``, ``second_reversal``,
``reversed_without_standing``, ``record_disagrees``; information ``premature_done``,
``honoured_outside_window``, ``crossing``, ``collateral_refusal``, ``fixture_not_landed``,
``error_no_effect``, ``capability_not_held``, ``no_overlap``. Stricter readings are decided here,
before any run: a B that declares an operation irreversible and refuses its
reversal, and a B that defers commit until the window ends, both pass when the outcome holds.

**Result**: ``fail`` if any landed variant fails; ``pass`` if the control held, every landed
variant passed and nothing in `NA_FORBIDDEN` is missing or inconclusive; else ``inconclusive``.
``extra["clauses"]`` gives the reading per clause, ``extra["forms"]`` per form.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P23"
TITLE = "Reversibility as declared"
FIXTURES = ("known_bad/reversal_toys.py", "tests/test_p23_reversibility.py",
            "tests/vectors/krk23/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("The stub organisations' keys, authorisation ids, request ids and every drawn token "
            "that makes an action's values distinct come from the operating system, never from "
            "the seed (KRK-M36).",
            "The seed draws the variant order, item counts, amounts and field values.")

VARIANTS = ("reversal", "downstream_consequence", "window", "partition", "overtake",
            "compensation_effect", "duplicate", "no_standing", "class_ceiling",
            "class_downgrade", "b_initiated")
FORMS = {"reversal": ("object_create", "object_update", "object_delete", "multi_item",
                      "message", "transfer", "publish"),
         "downstream_consequence": ("read_before_recall", "fanout_delivered", "funds_moved"),
         "window": ("inside_late", "outside", "crosses_in_flight", "queued_past_window"),
         "partition": ("b_world_down", "b_world_hang", "refuse_one_item", "answer_lost",
                       "b_restart"),
         "overtake": ("held_action",),
         "compensation_effect": ("counter_effect_undeclared", "counter_effect_twice",
                                 "extra_effect"),
         "duplicate": ("sequential", "concurrent", "new_request_id", "after_reapply"),
         "no_standing": ("other_org", "agent_without_reversal", "withdrawn_agent"),
         "class_ceiling": ("irreversible_op", "compensable_op", "class_absent",
                           "class_claimed_in_request"),
         "class_downgrade": ("catalogue_changed", "condition_in_request",
                             "changed_between_arrival_and_commit",
                             "window_shortened_after_execution"),
         "b_initiated": ("operator_reversal",)}
CLAUSE = {"reversal": "a", "downstream_consequence": "a", "window": "a",
          "compensation_effect": "a", "class_ceiling": "b", "class_downgrade": "b",
          "partition": "c", "overtake": "c", "duplicate": "c", "no_standing": "c",
          "b_initiated": "c"}
TRUTH = ("done_while_present", "dropped", "record_disagrees")
"""Outcomes that are clause (c) wherever they are seen (§4.5)."""
TRIALS = {"reversal:base": 30, "*": 5}
DEV_TRIALS = {"reversal:base": 5, "*": 2}
PUBLISHED_TRIALS = {"reversal:base": 100, "*": 5}
SELF_HOSTED_ONLY = {("partition", "b_restart"), ("b_initiated", "operator_reversal"),
                    ("class_downgrade", "catalogue_changed"),
                    ("class_downgrade", "changed_between_arrival_and_commit"),
                    ("class_downgrade", "window_shortened_after_execution")}
NA_FORBIDDEN = ("control", ("class_ceiling", "irreversible_op"), ("class_ceiling", "class_absent"),
                ("duplicate", "sequential"), ("duplicate", "new_request_id"),
                ("no_standing", "other_org"), ("window", "outside"))
"""Forms that must land (design §6.4): the ceiling forms for any B that accepts a ceiling, the
rest for any B that declares an operation reversible or compensable; and every `reversal` form
whose operation B declares reversible or compensable (`_must_land`)."""
CALL_OF = {"object_create": "objects:create", "object_update": "objects:update",
           "object_delete": "objects:delete", "multi_item": "objects:create_many",
           "message": "mail:deliver", "transfer": "ledger:transfer", "publish": "topics:publish"}
PLANT = {"read_before_recall": ("mail:deliver", "message_read"),
         "fanout_delivered": ("topics:publish", "fanout_delivered"),
         "funds_moved": ("ledger:transfer", "funds_moved")}
GRADES = ("world", "b-record", "b-signed", "b-response")
PLAN_ENV = "ACK_P23_PLAN"
STEP_S = 0.25
"""How often the probe looks at the world while it waits for an action to land."""
DEFAULT_R_S = 30.0
"""The bound a trial is judged against when the claim states none (no stated R is a finding)."""
FORWARD_SETTLE_S = 15.0
"""How long the probe waits for an honest forward action to land, beyond any stated delay."""
INTERNAL = "b.example"
DENYING = ("refused",)
REVERSED = ("reversed",)


# --------------------------------------------------------------------------- the run


class _Progress:
    """``NN-progress.jsonl``: one JSON line per event, synced as it is written."""

    def __init__(self, ev: Evidence) -> None:
        self.path = ev.write("progress.jsonl", "")
        self._lock = threading.Lock()

    def add(self, kind: str, **doc: Any) -> None:
        rec = {"kind": kind, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **doc}
        line = json.dumps(_jsonable(rec), sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())


def _jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))


def _is_toy(a: Any) -> bool:
    mod = type(a).__module__ or ""
    return mod.startswith(("known_bad.", "tests.", "test_")) or mod == "__main__"


@dataclass
class Action:
    """One forward action the kit makes: its values and how to find its effect in the world."""

    label: str
    op: str
    call: str
    values: Dict[str, Any]
    tokens: List[str]
    named: List[str] = field(default_factory=list)
    expect_new: int = 1
    """How many entities of the call's kind it creates (0 for an update or a delete)."""
    org: str = "a"
    agent: str = ""
    pres: Any = None
    answer: Optional[Dict[str, Any]] = None
    answer_kind: str = ""
    t_sent: Optional[float] = None
    t_answered: Optional[float] = None
    footprint: Dict[Tuple[str, str], Any] = field(default_factory=dict)
    t_e: Optional[float] = None


class _Run:
    """What one probe run shares: the clock, the world, the stub A and A′, B's statements."""

    def __init__(self, a: Any, ev: Evidence, *, clock: Any, world: Any, A: Any, A2: Any,
                 rng: random.Random, claims: List[Dict[str, Any]], st: Dict[str, Any]) -> None:
        from ..requester import Transport
        self.a, self.ev, self.clock, self.world, self.A, self.A2 = a, ev, clock, world, A, A2
        self.rng = rng
        self.claims = claims
        self.st = st
        self.tf = Transport(a.present, clock=clock.now)
        self.tr = Transport(self._present_reversal, clock=clock.now)
        self.progress: Optional[_Progress] = None
        self.endpoint = (st["agreement"].get("endpoints") or ["/actions"])[0]
        self.eps = max(0.05, float(st["agreement"].get("timestamp_resolution_s") or 0.0))
        self.tol = float(st["agreement"].get("clock_tolerance_s") or 0.0)
        self.n = 0
        self.busy_until = 0.0
        """The kit time by which every action presented so far has had its stated time to land
        (a deferred commit, a held call's retry). The next trial starts no earlier (KRK-M127)."""

    def _present_reversal(self, p: Any) -> Dict[str, Any]:
        return self.a.present_reversal(p)

    def log(self, kind: str, **doc: Any) -> None:
        if self.progress is not None:
            self.progress.add(kind, **doc)

    def now(self) -> float:
        return self.clock.now()

    def sleep_until(self, t: float) -> None:
        self.clock.sleep_until(t)

    # B's statements --------------------------------------------------------------------------

    def claim(self, op: str) -> Optional[Dict[str, Any]]:
        from .. import reversibility as rv
        return rv.claim_for(self.claims, op)

    def calls(self, op: str) -> List[str]:
        return list((self.st["world_profile"] or {}).get(op) or [])

    def base_class(self, op: str) -> str:
        from .. import reversibility as rv
        c = self.claim(op)
        return c["class"] if c and not rv.claim_problem(c) else "irreversible"

    def op_for(self, call: str, classes: Tuple[str, ...]) -> Optional[str]:
        """The first operation B declares, in its own order, that makes world call `call` and
        whose class (before conditions) is one of `classes`; for ``class_absent``, an operation
        in B's world profile with no claim."""
        for op, calls in (self.st["world_profile"] or {}).items():
            if call in calls and self.base_class(op) in classes and \
                    (self.claim(op) is not None or "absent" in classes):
                return op
        return None

    def absent_op(self) -> Optional[Tuple[str, str]]:
        for op, calls in (self.st["world_profile"] or {}).items():
            if self.claim(op) is None:
                buildable = [c for c in calls if c in BUILDERS]
                if buildable:
                    return op, buildable[0]
        return None

    def reversible_ops(self) -> List[str]:
        return [c["operation"] for c in self.claims if self.base_class(c["operation"]) in
                ("reversible", "compensable")]

    def R(self, op: str) -> float:
        c = self.claim(op) or {}
        return float(c.get("completion_bound_s") or DEFAULT_R_S)

    def mode(self, op: str) -> Dict[str, Any]:
        for m in self.st["modes"] or []:
            if isinstance(m, dict) and (m.get("operations") in ("*", None) or op in
                                        (m.get("operations") or [])):
                return m
        return {"mode": "immediate"}

    def delay(self, op: str) -> float:
        m = self.mode(op)
        return float(m.get("commit_delay_s") or 0.0) if m.get("mode") == "deferred" else 0.0

    def means(self, op: str) -> Dict[str, Any]:
        c = self.claim(op) or {}
        return dict(c.get("means") or {"operation": "krk.reverse"})

    # building and presenting -----------------------------------------------------------------

    def token(self) -> str:
        return secrets.token_hex(6)

    def build(self, op: str, call: str, label: str, *, agent: str, org: str = "a",
              like: Optional[Action] = None, recipient: Optional[str] = None) -> Action:
        act = BUILDERS[call](self, op, call, label, like=like, recipient=recipient)
        act.agent, act.org = agent, org
        return act

    def present(self, act: Action, *, max_class: str = "irreversible", requester: Any = None,
                grants: Optional[List[str]] = None, values: Optional[Dict[str, Any]] = None) -> Action:
        req = requester or (self.A2 if act.org == "a_prime" else self.A)
        act.pres = req.forward(values or act.values, operation=act.op, max_class=max_class,
                               endpoint=self.endpoint, agent=act.agent, grants=grants,
                               label=act.label)
        act.t_sent = self.now()
        self.busy_until = max(self.busy_until, act.t_sent + self.delay(act.op) + FORWARD_SETTLE_S)
        ans = self.tf.send(act.pres)
        act.t_answered = self.now()
        act.answer = ans
        act.answer_kind = _classify(self.a, ans)
        return act

    def attribute(self, act: Action, entries: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
        """The entities B changed for `act` in `entries`: those carrying one of its drawn tokens
        or naming one of its objects, then the links of those objects and the balances of its
        transfers (KRK-M127: every change is attributed by object id, never by time alone)."""
        out: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        named = set(act.named)
        for e in entries:
            k = (e["key"][0], e["key"][1])
            blob = json.dumps([e.get("before"), e.get("after")], sort_keys=True, default=str)
            if k[1] in named or any(t in blob for t in act.tokens):
                out.setdefault(k, []).append(e)
        objs = {k[1] for k in out if k[0] == "object"} | named
        trs = {k[1] for k in out if k[0] == "transfer"}
        for e in entries:
            k = (e["key"][0], e["key"][1])
            s = e.get("after") or e.get("before") or {}
            if k[0] == "edge" and (s.get("src") in objs or s.get("dst") in objs):
                out.setdefault(k, []).append(e)
            elif k[0] == "account" and e.get("transfer") in trs:
                out.setdefault(k, []).append(e)
        return out

    def landed(self, act: Action, since: Any) -> bool:
        fp = self.attribute(act, self.world.changes(since, caller="b"))
        kind = act.call.split(":")[0]
        ent = {"objects": "object", "mail": "mail", "ledger": "transfer", "topics": "item"}[kind]
        created = [k for k, es in fp.items() if k[0] == ent and es[0].get("before") is None]
        if act.expect_new:
            ok = len(created) >= act.expect_new
        else:
            ok = any(k[1] in act.named for k in fp)
        if ok:
            act.footprint = {k: es for k, es in fp.items()}
            act.t_e = max(e["t"] for es in fp.values() for e in es)
        return ok

    def wait_landed(self, acts: List[Action], since: Any, timeout_s: float) -> bool:
        end = self.now() + timeout_s
        while True:
            if all(a.footprint or self.landed(a, since) for a in acts):
                return True
            if self.now() >= end:
                return False
            self.clock.sleep(STEP_S)

    def reverse(self, act: Action, *, requester: Any = None, agent: Optional[str] = None,
                grants: Optional[List[str]] = None, request_id: Optional[str] = None,
                drop: bool = False, label: str = "rev") -> Dict[str, Any]:
        req = requester or self.A
        means = self.means(act.op)
        r = req.request_reversal(act.pres, means=means, agent=agent or act.agent,
                                 grants=grants, request_id=request_id, label=label)
        return self.send_reversal(r, drop=drop)

    def H(self, op: str) -> float:
        """The observation horizon after a reversal request: ``max(3R, R + 120 s)``."""
        R = self.R(op)
        return max(3 * R, R + 120.0)

    def send_reversal(self, r: Any, *, drop: bool = False) -> Dict[str, Any]:
        t_q = self.now()
        # Work B does late for this reversal must not land in the next trial (KRK-M127): the
        # next trial starts no earlier than the longest horizon of any operation it may reverse.
        self.busy_until = max(self.busy_until, t_q + max(
            [self.H(o) for o in self.reversible_ops()] or [DEFAULT_R_S + 120.0]))
        ans = self.tr.send(r, drop_answer=drop)
        t_a = self.now()
        kept = self.tr.answers.get(r.pid) or {}
        kind = _classify_reversal(self.a, kept) if not drop else "lost"
        return {"pres": r, "t_q": t_q, "t_a": t_a, "answer": kept if not drop else None,
                "kind": kind, "reason": _reason(self.a, kept) if kind in DENYING else None,
                "statuses": []}

    def status(self, rec: Dict[str, Any]) -> None:
        fn = getattr(self.a, "reversal_status", None)
        if not callable(fn):
            return
        try:
            s = fn(rec["pres"])
        except Exception as e:  # noqa: BLE001
            s = {"raised": f"{type(e).__name__}: {e}"}
        if s is not None:
            rec["statuses"].append({"t": self.now(), "kind": _classify_reversal(self.a, s),
                                    "status": s})


def _classify(a: Any, ans: Any) -> str:
    try:
        return str(a.classify(ans))
    except Exception:  # noqa: BLE001
        return "error"


def _classify_reversal(a: Any, ans: Any) -> str:
    if not ans or ans.get("raised"):
        return "error"
    try:
        return str(a.classify_reversal(ans))
    except Exception:  # noqa: BLE001
        return "error"


def _reason(a: Any, ans: Any) -> Optional[Dict[str, Any]]:
    try:
        r = a.refusal_reason(ans)
        return dict(r) if r else None
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- value builders


def _fields(run: _Run, tok: str) -> Dict[str, Any]:
    k = run.rng.randint(1, 3)
    out = {"name": f"n-{tok}", "note": tok}
    for i in range(k):
        out[f"f{i}"] = f"v{run.rng.randint(0, 10**6)}"
    return out


def _b_create(run: _Run, op: str, call: str, label: str, *, like: Optional[Action] = None,
              recipient: Optional[str] = None) -> Action:
    tok = run.token()
    hub = run.world.kit_object({"kind": "account-record", "note": f"hub-{tok}"})
    email = (like.values["email"] if like else f"c-{tok}@{INTERNAL}")
    vals = {"fields": _fields(run, tok), "email": email, "note": tok, "links": [hub]}
    return Action(label, op, call, vals, [tok])


def _b_create_many(run: _Run, op: str, call: str, label: str, **_kw: Any) -> Action:
    n = run.rng.randint(2, 9)
    toks = [run.token() for _ in range(n)]
    items = [{"fields": _fields(run, t), "email": f"c-{t}@{INTERNAL}", "note": t} for t in toks]
    return Action(label, op, call, {"items": items, "note": toks[0]}, toks, expect_new=n)


def _b_update(run: _Run, op: str, call: str, label: str, **_kw: Any) -> Action:
    tok0 = run.token()
    oid = run.world.kit_object(_fields(run, tok0), email=f"c-{tok0}@{INTERNAL}", note=tok0)
    tok = run.token()
    keys = ["name", "f0"][:run.rng.randint(1, 2)]
    vals = {"object_id": oid, "fields": {k: f"u-{tok}-{k}" for k in keys}}
    return Action(label, op, call, vals, [tok], named=[oid], expect_new=0)


def _b_delete(run: _Run, op: str, call: str, label: str, **_kw: Any) -> Action:
    tok0 = run.token()
    oid = run.world.kit_object(_fields(run, tok0), email=f"c-{tok0}@{INTERNAL}", note=tok0)
    parent = run.world.kit_object({"kind": "parent", "note": f"p-{tok0}"})
    child = run.world.kit_object({"kind": "child", "note": f"q-{tok0}"})
    run.world.kit_link(parent, oid)
    run.world.kit_link(oid, child)
    return Action(label, op, call, {"object_id": oid}, [], named=[oid], expect_new=0)


def _b_mail(run: _Run, op: str, call: str, label: str, *, recipient: Optional[str] = None,
            **_kw: Any) -> Action:
    tok = run.token()
    run.n += 1
    to = recipient or f"d{run.n}@{INTERNAL}"
    run.world.kit_mailbox(to, f"d:mail-{run.n}")
    return Action(label, op, call, {"to": to, "subject": f"s-{tok}", "body": f"b-{tok}"}, [tok])


def _b_transfer(run: _Run, op: str, call: str, label: str, **_kw: Any) -> Action:
    tok = run.token()
    run.n += 1
    amount = run.rng.randint(100, 99_999)
    payer = run.world.kit_account(run.A.issuer, 10_000_000)
    # The payee opens with a drawn balance, so a second refund is possible and shows in the
    # world; with an empty account the world itself would refuse it and hide the flaw.
    payee = run.world.kit_account(f"d:payee-{run.n}", run.rng.randint(200_000, 900_000))
    return Action(label, op, call, {"from": payer, "to": payee, "amount": amount, "memo": tok},
                  [tok])


def _b_publish(run: _Run, op: str, call: str, label: str, **_kw: Any) -> Action:
    tok = run.token()
    run.n += 1
    topic = f"t-{run.n}"
    run.world.kit_topic(topic, [f"d:sub-{run.n}"])
    return Action(label, op, call, {"topic": topic, "body": f"i-{tok}"}, [tok])


BUILDERS = {"objects:create": _b_create, "objects:create_many": _b_create_many,
            "objects:update": _b_update, "objects:delete": _b_delete, "mail:deliver": _b_mail,
            "ledger:transfer": _b_transfer, "topics:publish": _b_publish}


# --------------------------------------------------------------------------- reading the world


def _fp_keys(act: Action) -> List[Tuple[str, str]]:
    return sorted(act.footprint)


def _state_map(run: _Run, keys: List[Tuple[str, str]], *, seq: Optional[int] = None,
               t: Optional[float] = None) -> Dict[Tuple[str, str], Any]:
    w = run.world
    if t is not None:
        return {k: w.entity_at_time(k, t) for k in keys}
    return {k: w.entity_at(k, seq) for k in keys}


def _x_holdings(run: _Run, x: Action, t: float) -> List[Dict[str, Any]]:
    """What downstream parties hold from X at kit time `t`: a read of its message, a copy of its
    item, its funds moved on."""
    out: List[Dict[str, Any]] = []
    for k in _fp_keys(x):
        s = run.world.entity_at_time(k, t)
        if not s:
            continue
        if k[0] == "mail" and s.get("read_at") is not None:
            out.append({"kind": "read_receipt", "party": s.get("party"), "entity": k[1]})
        if k[0] == "item":
            for p in s.get("delivered_to") or []:
                if run.world.entity_at_time(("copy", f"{k[1]}@{p}"), t):
                    out.append({"kind": "copy_at_subscriber", "party": p, "entity": k[1]})
        if k[0] == "transfer" and s.get("moved_on"):
            out.append({"kind": "funds_moved", "party": "onward", "entity": k[1]})
    return out


def _judge_at(run: _Run, x: Action, s0: Any, t: float, *, sibs: List[Action],
              t_q: float, claim: Dict[str, Any], exclude: Tuple[str, ...] = ()) -> Any:
    """The judgement of the world at kit time `t` against `claim` (`reversibility.judge`)."""
    from .. import reversibility as rv
    w = run.world
    seq_t = w.seq_at(t)
    fp = {k: (w.entity_at(k, s0.seq), w.entity_at(k, seq_t)) for k in _fp_keys(x)}
    sib_keys: Dict[Tuple[str, str], Any] = {}
    for s in sibs:
        for k in _fp_keys(s):
            sib_keys[k] = (w.entity_at(k, s.s1_seq), w.entity_at(k, seq_t))  # type: ignore[attr-defined]
    b_changes = [e for e in w.history[s0.seq:seq_t] if e["caller"] == "b"]
    others = []
    seen = set()
    for e in b_changes:
        k = (e["key"][0], e["key"][1])
        if k in fp or k in sib_keys or k in seen or k[1] in exclude:
            continue
        seen.add(k)
        before, after = w.entity_at(k, s0.seq), w.entity_at(k, seq_t)
        if before != after:
            others.append({"key": list(k), "before": before, "after": after})
    ce = claim.get("counter_effect") or {}
    counter_ops = 0
    if claim.get("class") == "compensable" and ce.get("kind") in ("retract", "recall", "void",
                                                                    "restore"):
        counter_ops = sum(1 for e in b_changes if e["t"] >= t_q and e["op"] == ce["kind"]
                          and (e["key"][0], e["key"][1]) in fp)
    x_tr = next((w.entity_at(k, x.s1_seq) for k in fp if k[0] == "transfer"), None)  # type: ignore[attr-defined]
    trace = None
    if "history" in (claim.get("restores") or []):
        trace = [f"{e['op']}:{e['key'][1]}" for e in w.changes(caller="b")
                 if (e["key"][0], e["key"][1]) in fp]
    return rv.judge(claim, fp, others=others, siblings=sib_keys,
                    holdings=_x_holdings(run, x, t), counter_ops=counter_ops,
                    x_transfer=x_tr, x_tokens=x.tokens if not fp else (), history_trace=trace)


def _t_x(run: _Run, x: Action, s0: Any, t_q: float, sibs: List[Action]) -> Optional[float]:
    """The world's commit of the last change B made after `t_q` that is not L's or K's."""
    skip = {k for s in sibs for k in s.footprint}
    ts = [e["t"] for e in run.world.history[s0.seq:]
          if e["caller"] == "b" and e["t"] >= t_q and (e["key"][0], e["key"][1]) not in skip]
    return max(ts) if ts else None


def _b_touched(run: _Run, x: Action, s0: Any, t_q: float, sibs: List[Action]) -> List[str]:
    """Every entity B changed after `t_q` that is not L's or K's."""
    skip = {k for s in sibs for k in s.footprint}
    out = []
    for e in run.world.history[s0.seq:]:
        k = (e["key"][0], e["key"][1])
        if e["caller"] == "b" and e["t"] >= t_q and k not in skip:
            out.append(f"{k[0]}:{k[1]}")
    return sorted(set(out))


def _restored_at(run: _Run, x: Action, s0: Any, t: float, sibs: List[Action], t_q: float,
                 claim: Dict[str, Any]) -> bool:
    return _judge_at(run, x, s0, t, sibs=sibs, t_q=t_q, claim=claim).restored


# --------------------------------------------------------------------------- one reversal trial


@dataclass
class Spec:
    variant: str
    form: str
    op: str
    call: str
    expect: str = "restore"
    """``restore``, ``refuse`` (outside the window, or a condition held), ``restore_or_refuse``."""
    plant: Optional[str] = None
    place: str = "now"
    fault: Optional[str] = None
    hold: bool = False
    drop: bool = False
    restart: bool = False
    repeat: Optional[str] = None
    standing: Optional[str] = None
    operator: bool = False
    shorten: bool = False


@dataclass
class TrialDoc:
    outcome: str
    ok: Optional[bool]
    detail: str
    time_s: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_doc(self) -> Dict[str, Any]:
        return {"outcome": self.outcome, "ok": self.ok, "detail": self.detail,
                "time_s": None if self.time_s is None else round(self.time_s, 3),
                "extra": _jsonable(self.extra)}


def _three(run: _Run, sp: Spec, k: int, *, claim: Dict[str, Any]
           ) -> Tuple[Optional[Action], Optional[Action], Optional[Action], Any, str]:
    """K, X and L for one trial, presented and landed; ``(K, X, L, S0, why-not-landed)``."""
    ag = f"agent-{secrets.token_hex(3)}"
    K = run.build(sp.op, sp.call, f"K{k}", agent=ag)
    X = run.build(sp.op, sp.call, f"X{k}", agent=ag)
    L = run.build(sp.op, sp.call, f"L{k}", agent=ag, like=None)
    s0 = run.world.mark()
    delay = run.delay(sp.op)
    if sp.hold:
        ra = 0.5 * float((claim.get("window") or {}).get("seconds") or 60)
        run.world.hold(X.tokens[0] if X.tokens else X.named[0], ra)
        run.busy_until = max(run.busy_until, run.now() + ra + FORWARD_SETTLE_S + run.R(sp.op))
    for act in (K, X, L):
        run.present(act)
        if act.answer_kind in ("refused", "error"):
            return None, None, None, s0, f"{act.label} was not accepted ({act.answer_kind})"
        if delay or (sp.hold and act is X):
            continue
        if not run.wait_landed([act], s0, FORWARD_SETTLE_S):
            return None, None, None, s0, f"{act.label} did not land at the world"
        act.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
    return K, X, L, s0, ""


def _deferred_landing(run: _Run, sp: Spec, K: Action, L: Action, s0: Any, t_ref: float) -> bool:
    """K and L, never reversed, must land after B's stated commit delay (KRK-M124)."""
    end = t_ref + run.delay(sp.op) + run.R(sp.op) + FORWARD_SETTLE_S
    while True:
        if all(a.footprint or run.landed(a, s0) for a in (K, L)) or run.now() >= end:
            break
        run.clock.sleep(STEP_S)
    ok = bool(K.footprint and L.footprint)
    for a in (K, L):
        a.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
    return ok


def _plant(run: _Run, sp: Spec, X: Action) -> Tuple[bool, List[Dict[str, Any]], str]:
    """Plant X's downstream consequence and confirm it through B's view of the world (KRK-M115,
    KRK-M129). Returns (landed, events, detail)."""
    w = run.world
    view = run.st["b_view"]
    keys = _fp_keys(X)
    if sp.plant == "read_before_recall":
        mid = next((k[1] for k in keys if k[0] == "mail"), None)
        if not mid:
            return False, [], "X's message is not in the world"
        w.read_message(mid)
        seen = view.read(kind="mail", eid=mid) if view else {}
        t = (seen or {}).get("read_at")
        return t is not None, [{"event": "message_read", "t": t}], f"read_at {t}"
    if sp.plant == "fanout_delivered":
        iid = next((k[1] for k in keys if k[0] == "item"), None)
        if not iid:
            return False, [], "X's item is not in the world"
        sub = (w.subscribers.get((X.values or {}).get("topic")) or ["d:sub"])[0]
        w.deliver_fanout(iid, sub)
        seen = view.read(kind="item", eid=iid) if view else {}
        ok = sub in ((seen or {}).get("delivered_to") or [])
        return ok, [{"event": "fanout_delivered", "t": w.now()}], f"delivered_to {sub}"
    if sp.plant == "funds_moved":
        tid = next((k[1] for k in keys if k[0] == "transfer"), None)
        if not tid:
            return False, [], "X's transfer is not in the world"
        onward = w.kit_account("d:onward", 0)
        w.spend(tid, onward)
        seen = view.read(kind="transfer", eid=tid) if view else {}
        return bool((seen or {}).get("moved_on")), [{"event": "funds_moved", "t": w.now()}], \
            "moved_on"
    return True, [], ""


def _settle(run: _Run, rec: Dict[str, Any], R: float, H: float, *,
            extra_s: float = 0.0) -> None:
    """Read B's status at ``t_q + R`` and at the end of the observation horizon."""
    t_q = rec["t_q"]
    run.sleep_until(t_q + R)
    run.status(rec)
    run.sleep_until(t_q + H + extra_s)
    run.status(rec)


def _said_reversed(rec: Dict[str, Any]) -> List[float]:
    """The kit times at which B said the reversal was done: its answer and each status."""
    out = []
    if rec.get("kind") in REVERSED:
        out.append(rec["t_a"])
    out.extend(s["t"] for s in rec.get("statuses") or [] if s["kind"] in REVERSED)
    return out


def _said_refused(rec: Dict[str, Any]) -> bool:
    return rec.get("kind") in DENYING or any(s["kind"] in DENYING for s in rec.get("statuses")
                                             or [])


def _last_kind(rec: Dict[str, Any]) -> str:
    st = rec.get("statuses") or []
    return st[-1]["kind"] if st else rec.get("kind", "")


def _record_check(run: _Run, X: Action, restored: bool) -> Optional[TrialDoc]:
    """B's record of X, read through its own path, against the world (§4.4 item 4)."""
    if not run.st["record_path"]:
        return None
    try:
        rec = run.a.b_record(X.pres)
    except Exception as e:  # noqa: BLE001
        return TrialDoc("record_disagrees", False, f"B's record could not be read: {e}")
    state = (rec or {}).get("state")
    says = state in ("reversed", "cancelled", "compensated")
    if says != restored:
        return TrialDoc("record_disagrees", False, f"B's record says {state!r}; the world shows "
                        f"the effect {'removed' if restored else 'in place'}")
    return None


def _outcome(run: _Run, sp: Spec, X: Action, s0: Any, rec: Dict[str, Any], sibs: List[Action],
             claim: Dict[str, Any], *, R: float, H: float, events: List[Dict[str, Any]],
             recovery_from: Optional[float] = None, induced: bool = False) -> TrialDoc:
    """One reversal's outcome (§4.5), from the world, B's answers and its statuses."""
    from .. import reversibility as rv
    t_q = rec["t_q"]
    t_end = run.now()
    S = max(R, 30.0)
    t_x = _t_x(run, X, s0, t_q, sibs)
    j_end = _judge_at(run, X, s0, t_end, sibs=sibs, t_q=t_q, claim=claim)
    t_stab = (t_x + S) if t_x is not None else t_end
    j_stab = _judge_at(run, X, s0, min(t_stab, t_end), sibs=sibs, t_q=t_q, claim=claim)
    ex: Dict[str, Any] = {"t_q": t_q, "t_a": rec["t_a"], "t_x": t_x, "answer": rec.get("kind"),
                          "reason": rec.get("reason"), "statuses": [
                              {"t": s["t"], "kind": s["kind"]} for s in rec.get("statuses") or []],
                          "judgement_end": j_end.to_doc(), "events": events}
    if j_end.other_touched or j_stab.other_touched:
        return TrialDoc("other_effect_touched", False,
                        f"L, K or X′ changed: {j_end.other_touched or j_stab.other_touched}", extra=ex)
    for t in _said_reversed(rec):
        if not _restored_at(run, X, s0, t + R, sibs, t_q, claim):
            return TrialDoc("done_while_present", False,
                            f"B said reversed at {t - t_q:.2f} s after the request; the world "
                            f"still showed the effect {R:g} s later", extra=ex)
    window = rv.window_open(claim, t_e=X.t_e or t_q, t_q=t_q, events=events, tol_s=run.tol,
                            eps_s=run.eps)
    ex["window"] = window
    expect = sp.expect
    if expect == "restore" and window == "condition_held":
        expect = "refuse_or_residue"
    if expect == "restore" and window == "outside":
        expect = "refuse"
    if window == "crossing":
        return TrialDoc("crossing", None, "the presentation's bracket straddles the window "
                        "boundary: judged on truthfulness only, which held", extra=ex)
    restored = j_end.restored and j_stab.restored
    if j_end.x_relanded or (j_stab.restored and not j_end.restored):
        return TrialDoc("reapplied", False, f"the effect returned after it was removed: "
                        f"{j_end.x_relanded or j_end.aspects_not_restored}", extra=ex)
    if restored:
        if j_end.new_effects:
            return TrialDoc("new_effect_undeclared", False,
                            f"new effects no residue declares: {[n['key'] for n in j_end.new_effects]}",
                            extra=ex)
        if j_end.residues_undeclared:
            return TrialDoc("residue_undeclared", False,
                            f"holdings at D no residue declares: {j_end.residues_undeclared}",
                            extra=ex)
        if j_end.counter_effects > 1:
            return TrialDoc("second_reversal", False,
                            f"{j_end.counter_effects} counter-effects for one action", extra=ex)
        if expect == "refuse":
            return TrialDoc("honoured_outside_window", None, "a reversal outside the window was "
                            "performed (information)", extra=ex)
        base = recovery_from if recovery_from is not None else t_q
        bound = run.st["rec_s"] if recovery_from is not None else R
        dt = (t_x - base) if t_x is not None else 0.0
        ex["time_s"] = dt
        if expect in ("restore", "refuse_or_residue") and dt > bound + run.eps:
            return TrialDoc("restored_late", False, f"restored {dt:.2f} s after "
                            f"{'the outage ended' if recovery_from is not None else 'the request'}"
                            f", against {bound:g} s", time_s=dt, extra=ex)
        if expect in ("restore", "refuse_or_residue") and abs(dt - bound) <= run.eps:
            return TrialDoc("crossing", None, f"restored at {dt:.2f} s, within the method's "
                            f"resolution of the bound {bound:g} s", time_s=dt, extra=ex)
        said = _said_reversed(rec)
        if said and t_x is not None and min(said) < t_x:
            ex["premature_done"] = {"t_answer": min(said) - t_q, "t_x": t_x - t_q}
        return TrialDoc("restored", True, f"restored in {dt:.2f} s"
                        + ("; premature_done (information)" if "premature_done" in ex else ""),
                        time_s=dt, extra=ex)
    # not restored. Whether B changed anything after the request is read from the history by
    # caller: a consequence the kit planted (a payee moving funds on) can make an aspect read as
    # restored without B having done anything.
    touched = _b_touched(run, X, s0, t_q, sibs)
    ex["b_changed_after_request"] = touched
    if expect in ("refuse", "refuse_or_residue", "restore_or_refuse") and _said_refused(rec) \
            and not touched:
        return TrialDoc("refused_as_expected", True, f"refused ({rec.get('reason') or _last_kind(rec)})",
                        extra=ex)
    if expect == "refuse" and not _said_reversed(rec) and _last_kind(rec) == "error":
        return TrialDoc("error_no_effect", None, "an error answer, the world unchanged", extra=ex)
    if j_end.partial and touched:
        truthful = rec.get("kind") == "partial" or _last_kind(rec) == "partial"
        if induced and truthful:
            return TrialDoc("refused_as_expected", True, "a truthful partial answer to a fault "
                            "the kit induced", extra=ex)
        return TrialDoc("partial_truthful" if truthful else "partial", False,
                        f"aspects not restored: {j_end.aspects_not_restored}", extra=ex)
    if _said_refused(rec) or _last_kind(rec) == "error":
        if induced:
            return TrialDoc("refused_as_expected", True, "a truthful failure after a fault the kit "
                            "induced", extra=ex)
        return TrialDoc("refused_inside_claim", False,
                        f"a reversal the claim covers was {_last_kind(rec) or rec.get('kind')}"
                        f" ({rec.get('reason')})", extra=ex)
    return TrialDoc("dropped", False, f"B answered {rec.get('kind')!r}, its last status "
                    f"{_last_kind(rec)!r}, and the world still shows the effect at the end of "
                    f"the horizon", extra=ex)


def _reversal_trial(run: _Run, sp: Spec, k: int) -> TrialDoc:
    """One trial of a variant that reverses X (every variant but the ceiling ones)."""
    claim = dict(run.claim(sp.op) or {})
    R = run.R(sp.op)
    H = max(3 * R, R + 120.0)
    W = float((claim.get("window") or {}).get("seconds") or 0.0)
    if sp.plant and k % 2 == 1 and run.delay(sp.op):
        return TrialDoc("fixture_not_landed", None, "the effect is held at B until its window "
                        "ends, so no consequence can follow it before the reversal (deferred "
                        "mode)")
    K, X, L, s0, why = _three(run, sp, k, claim=claim)
    if X is None:
        return TrialDoc("fixture_not_landed", None, why)
    sibs = [K, L]
    deferred = bool(run.delay(sp.op))
    if sp.hold:
        if not run.world.held_attempts(X.tokens[0] if X.tokens else X.named[0]):
            return TrialDoc("fixture_not_landed", None, "the world did not hold X's forward call")
        X.t_e = X.t_answered
        X.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
    elif deferred:
        X.t_e = X.t_answered
        X.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
    extra_H = 0.5 * W if sp.hold else 0.0
    events: List[Dict[str, Any]] = []
    plant = sp.plant if (sp.plant and k % 2 == 1) else None
    if sp.plant and not plant:
        events = [{"event": "paired_before_consequence", "t": None}]
    if plant:
        if deferred:
            return TrialDoc("fixture_not_landed", None, "the effect is held at B, so no "
                            "consequence can follow it before the reversal (deferred mode)")
        ok, events, d = _plant(run, sp, X)
        if not ok:
            return TrialDoc("fixture_not_landed", None, f"the consequence was not visible "
                            f"through B's view of the world ({d}), KRK-M129")
    if sp.shorten:
        try:
            return _shortened(run, sp, k, claim, X, s0, sibs, R=R, H=H)
        finally:
            run.a.operator_set_claim(sp.op, claim)
    t_e = X.t_e or run.now()
    margin = 2 * run.eps + run.tol + 0.05
    if sp.place == "inside_late":
        run.sleep_until(t_e + W - margin)
    elif sp.place == "outside":
        run.sleep_until(t_e + W + margin)
    elif sp.place in ("crosses", "queued"):
        run.sleep_until(t_e + W - margin)
    elif sp.place == "old_window":
        run.sleep_until(t_e + 0.4 * W)
    recovery_from = None
    induced = False
    if sp.fault in ("down", "hang"):
        t0 = run.now()
        run.world.fault(sp.fault, until=t0 + 0.5 * R, hang_s=min(5.0, 0.2 * R))
        recovery_from, induced = t0 + 0.5 * R, True
    elif sp.fault == "refuse_one":
        objs = [kk[1] for kk in _fp_keys(X) if kk[0] == "object"]
        if not objs:
            return TrialDoc("fixture_not_landed", None, "X created no object to refuse")
        run.world.fault("refuse_item", item=objs[-1])
        induced = True
    if sp.place == "crosses":
        run.world.fault("slow", until=run.now() + 30.0, slow_s=2.0)
    elif sp.place == "queued":
        run.world.fault("down", until=t_e + W + 5.0)
        recovery_from, induced = t_e + W + 5.0, True
    if sp.standing:
        return _standing_trial(run, sp, X, s0, sibs, claim, R=R, H=H, events=events)
    if sp.operator:
        t_q = run.now()
        try:
            run.a.operator_reverse(X.pres)
        except Exception as e:  # noqa: BLE001
            return TrialDoc("fixture_not_landed", None, f"operator_reverse raised {e}")
        rec = {"pres": X.pres, "t_q": t_q, "t_a": run.now(), "kind": "operator", "answer": None,
               "reason": None, "statuses": []}
        run.sleep_until(t_q + H)
        restored = _judge_at(run, X, s0, run.now(), sibs=sibs, t_q=t_q, claim=claim).restored
        doc = _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=events)
        bad = _record_check(run, X, restored)
        if bad is None and not run.st["record_path"]:
            return TrialDoc(doc.outcome, doc.ok, doc.detail + "; B exposes no record, so the "
                            "record was not compared", doc.time_s, doc.extra)
        return bad or doc
    rec = run.reverse(X, drop=sp.drop)
    if sp.restart:
        run.clock.sleep(0.25 * R)
        try:
            how = run.a.restart()
        except Exception as e:  # noqa: BLE001
            return TrialDoc("fixture_not_landed", None, f"restart raised {e}")
        if not (isinstance(how, dict) and how.get("before") and how.get("before") != how.get("after")):
            return TrialDoc("fixture_not_landed", None, "the restart hook did not show a new "
                            "boot (KRK-M44)")
    if sp.drop:
        run.sleep_until(rec["t_q"] + max(R, 30.0))
        if callable(getattr(run.a, "reversal_status", None)):
            run.status(rec)
        else:
            again = run.send_reversal(run.A.repeat(rec["pres"], "again"))
            rec["kind"], rec["t_a"] = again["kind"], again["t_a"]
            rec["reason"] = again["reason"]
    _settle(run, rec, R, H, extra_s=extra_H)
    if deferred:
        if not _deferred_landing(run, sp, K, L, s0, X.t_answered or rec["t_q"]):
            return TrialDoc("other_effect_touched", False, "K or L, never reversed, did not land "
                            "after B's stated commit delay (KRK-M124)")
    if sp.repeat:
        return _repeat(run, sp, X, s0, sibs, claim, rec, R=R, H=H, events=events, k=k)
    doc = _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=events,
                   recovery_from=recovery_from, induced=induced)
    if doc.ok is not False:
        restored = _judge_at(run, X, s0, run.now(), sibs=sibs, t_q=rec["t_q"], claim=claim).restored
        bad = _record_check(run, X, restored)
        if bad is not None:
            return bad
    return doc


def _shortened(run: _Run, sp: Spec, k: int, claim: Dict[str, Any], X: Action, s0: Any,
               sibs: List[Action], *, R: float, H: float) -> TrialDoc:
    """`window_shortened_after_execution`: after X commits, B's operator shortens the window;
    A asks inside the old window and outside the new. The claim in force at X's execution
    governs X unless B stated otherwise before the run."""
    W = float((claim.get("window") or {}).get("seconds") or 0.0)
    new = {**claim, "window": {**(claim.get("window") or {}), "seconds": max(1.0, 0.2 * W)}}
    run.a.operator_set_claim(sp.op, new)
    if ((_live_claim(run, sp.op) or {}).get("window") or {}).get("seconds") != \
            new["window"]["seconds"]:
        return TrialDoc("fixture_not_landed", None, "B's read path does not show the shortened "
                        "window (KRK-M123)")
    run.sleep_until((X.t_e or run.now()) + 0.4 * W)
    rec = run.reverse(X)
    _settle(run, rec, R, H)
    doc = _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=[])
    if doc.ok is not False:
        restored = _judge_at(run, X, s0, run.now(), sibs=sibs, t_q=rec["t_q"],
                             claim=claim).restored
        return _record_check(run, X, restored) or doc
    return doc


def _live_claim(run: _Run, op: str) -> Optional[Dict[str, Any]]:
    from .. import reversibility as rv
    fn = getattr(run.a, "read_claims", None)
    if not callable(fn):
        return None
    return rv.claim_for(fn() or [], op)


def _standing_trial(run: _Run, sp: Spec, X: Action, s0: Any, sibs: List[Action],
                    claim: Dict[str, Any], *, R: float, H: float,
                    events: List[Dict[str, Any]]) -> TrialDoc:
    """`no_standing`: the reversal by a party without standing is refused and X stays; then A's
    own reversal of X restores it (the capability control, KRK-M120)."""
    st = run.st["standing"] or {}
    means_op = run.means(sp.op).get("operation", "krk.reverse")
    t0 = run.now()
    if sp.standing == "other_org":
        own = run.build(sp.op, sp.call, "A2own", agent=f"agent-{secrets.token_hex(3)}",
                        org="a_prime")
        m = run.world.mark()
        run.present(own)
        if own.answer_kind in ("refused", "error") or not run.wait_landed([own], m,
                                                                          FORWARD_SETTLE_S):
            return TrialDoc("fixture_not_landed", None, "B does not serve A′: its own genuine "
                            "action was not performed (KRK-M120)")
        own.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
        sibs = sibs + [own]
        bad = run.reverse(X, requester=run.A2, agent=own.agent)
    elif sp.standing == "agent_without_reversal":
        if st.get("agents") != "reverse-grant":
            return TrialDoc("not_applicable", None, "B's agreement does not separate an agent's "
                            "grant for the operation from its right to reverse")
        bad = run.reverse(X, agent=f"agent-{secrets.token_hex(3)}", grants=[sp.op])
    else:
        if st.get("withdrawn_agent") not in ("keeps", "loses"):
            return TrialDoc("not_applicable", None, "B's agreement does not say whether a "
                            "withdrawn agent keeps the right to reverse")
        tok = run.A.withdraw_agent(X.agent)
        try:
            run.a.present_withdrawal(tok)
            held = bool(run.a.agent_withdrawn(X.agent))
        except Exception as e:  # noqa: BLE001
            return TrialDoc("fixture_not_landed", None, f"B could not take the withdrawal: {e}")
        if not held:
            return TrialDoc("fixture_not_landed", None, "B's read path does not show the agent "
                            "withdrawn")
        if st.get("withdrawn_agent") == "keeps":
            rec = run.reverse(X)
            _settle(run, rec, R, H)
            return _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=events)
        bad = run.reverse(X)
    run.sleep_until(bad["t_q"] + R + max(R, 30.0))
    run.status(bad)
    now = run.now()
    fp_now = _state_map(run, _fp_keys(X), t=now)
    fp_s1 = _state_map(run, _fp_keys(X), seq=X.s1_seq)  # type: ignore[attr-defined]
    ex = {"unauthorised": {"answer": bad["kind"], "reason": bad["reason"],
                           "statuses": [s["kind"] for s in bad["statuses"]]}}
    if fp_now != fp_s1:
        return TrialDoc("reversed_without_standing", False, f"the reversal by "
                        f"{sp.standing} changed X ({bad['kind']})", extra=ex)
    if _said_reversed(bad):
        return TrialDoc("done_while_present", False, "B answered the unauthorised reversal "
                        "reversed and X is unchanged", extra=ex)
    rec = run.reverse(X, agent=f"agent-{secrets.token_hex(3)}", grants=[sp.op, means_op])
    _settle(run, rec, R, H)
    own_doc = _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=events)
    ex["own"] = own_doc.to_doc()
    if own_doc.ok is not True:
        return TrialDoc("capability_not_held", None, f"A's own reversal of X did not restore it "
                        f"({own_doc.outcome}), so the refusal cannot be read as a standing "
                        f"check (KRK-M120)", extra=ex)
    if not _said_refused(bad):
        return TrialDoc("dropped", False, f"the unauthorised reversal was answered "
                        f"{bad['kind']!r}, never refused", extra=ex)
    return TrialDoc("refused_as_expected", True, f"refused ({bad['reason']}); A's own reversal "
                    f"then restored X", extra={**ex, "t0": t0})


def _repeat(run: _Run, sp: Spec, X: Action, s0: Any, sibs: List[Action], claim: Dict[str, Any],
            rec: Dict[str, Any], *, R: float, H: float, events: List[Dict[str, Any]],
            k: int) -> TrialDoc:
    """`duplicate`: one reversal of X, then the repeat; one reversal only, X′ untouched."""
    first = _outcome(run, sp, X, s0, rec, sibs, claim, R=R, H=H, events=events)
    if first.ok is not True:
        return TrialDoc(first.outcome, first.ok, f"the first reversal: {first.detail}",
                        first.time_s, first.extra)
    ex: Dict[str, Any] = {"first": first.to_doc()}
    if sp.repeat == "after_reapply":
        x2 = run.build(sp.op, sp.call, f"X2-{k}", agent=X.agent, like=X)
        m = run.world.mark()
        run.present(x2)
        if x2.answer_kind in ("refused", "error") or not run.wait_landed([x2], m, FORWARD_SETTLE_S):
            return TrialDoc("fixture_not_landed", None, "X′ did not land", extra=ex)
        x2.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
        sibs = sibs + [x2]
        again = run.send_reversal(run.A.repeat(rec["pres"], "again"))
    elif sp.repeat == "new_request_id":
        again = run.reverse(X, label="rev2")
    elif sp.repeat == "concurrent":
        return _concurrent(run, sp, X, s0, sibs, claim, R=R, H=H, events=events, ex=ex)
    else:
        again = run.send_reversal(run.A.repeat(rec["pres"], "again"))
    _settle(run, again, R, H)
    ex["repeat"] = {"answer": again["kind"], "reason": again["reason"],
                    "statuses": [s["kind"] for s in again["statuses"]]}
    j = _judge_at(run, X, s0, run.now(), sibs=sibs, t_q=rec["t_q"], claim=claim)
    ex["judgement"] = j.to_doc()
    if j.other_touched:
        return TrialDoc("other_effect_touched", False, f"the repeat changed {j.other_touched}",
                        extra=ex)
    if j.counter_effects > 1 or (j.new_effects and claim.get("class") == "compensable"):
        return TrialDoc("second_reversal", False, f"{max(j.counter_effects, 2)} counter-effects "
                        f"after the repeat", extra=ex)
    if not j.restored:
        return TrialDoc("reapplied", False, "after the repeat the world shows the effect", extra=ex)
    if j.new_effects:
        return TrialDoc("new_effect_undeclared", False, f"the repeat made {j.new_effects}",
                        extra=ex)
    if again["kind"] not in ("reversed", "refused", "pending", "accepted"):
        return TrialDoc("record_disagrees", False, f"the repeat was answered {again['kind']!r}",
                        extra=ex)
    return TrialDoc("once", True, f"one reversal; the repeat answered {again['kind']}", extra=ex)


def _concurrent(run: _Run, sp: Spec, X: Action, s0: Any, sibs: List[Action],
                claim: Dict[str, Any], *, R: float, H: float, events: List[Dict[str, Any]],
                ex: Dict[str, Any]) -> TrialDoc:
    """Two identical reversal requests released together, counted only if both overlapped inside
    B (KRK-M39). A fresh action Y is reversed alone first, as the yardstick; then a fresh Z is
    made and its reversal released twice at once. Z is judged from a mark taken after Y's
    reversal settled, so Y's intended reversal is not read as Z's residue."""
    ag = X.agent
    Y = run.build(sp.op, sp.call, "Y", agent=ag)
    m = run.world.mark()
    run.present(Y)
    if not run.wait_landed([Y], m, FORWARD_SETTLE_S):
        return TrialDoc("fixture_not_landed", None, "Y did not land", extra=ex)
    alone = run.reverse(Y)
    yard_ans = alone.get("answer") or {}
    run.clock.sleep(R + 1.0)
    Z = run.build(sp.op, sp.call, "Z", agent=ag)
    sZ = run.world.mark()
    run.present(Z)
    if not run.wait_landed([Z], sZ, FORWARD_SETTLE_S):
        return TrialDoc("fixture_not_landed", None, "Z did not land", extra=ex)
    Z.s1_seq = run.world.mark().seq  # type: ignore[attr-defined]
    r = run.A.request_reversal(Z.pres, means=run.means(sp.op), agent=ag)
    pair = (r, run.A.repeat(r, "twin"))
    t_q = run.now()
    out: List[Optional[Dict[str, Any]]] = [None, None]
    gate = threading.Barrier(2)

    def go(i: int) -> None:
        gate.wait()
        out[i] = run.tr.send(pair[i])
    ts = [threading.Thread(target=go, args=(i,), daemon=True) for i in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=60)
    began = [(o or {}).get("began_at") for o in out]
    if not (isinstance(yard_ans.get("began_at"), (int, float)) and
            isinstance(yard_ans.get("ended_at"), (int, float)) and
            all(isinstance(b, (int, float)) for b in began)):
        return TrialDoc("no_overlap", None, "B's answers carry no start and end time measured "
                        "inside B, so the pair cannot be shown to overlap (KRK-M39)", extra=ex)
    yard = max(0.0, yard_ans["ended_at"] - yard_ans["began_at"])
    spread = max(began) - min(began)
    ex["overlap"] = {"yardstick_s": yard, "spread_s": spread}
    if not spread < yard / 2:
        return TrialDoc("no_overlap", None, f"the pair began {spread:.4f} s apart inside B, not "
                        f"within half of {yard:.4f} s", extra=ex)
    run.sleep_until(t_q + H)
    zsibs = [s for s in sibs if s is not X]
    j = _judge_at(run, Z, sZ, run.now(), sibs=zsibs, t_q=t_q, claim=claim)
    ex["judgement"] = j.to_doc()
    ex["answers"] = [_classify_reversal(run.a, o or {}) for o in out]
    if j.other_touched:
        return TrialDoc("other_effect_touched", False, f"{j.other_touched}", extra=ex)
    if j.counter_effects > 1 or (j.new_effects and claim.get("class") == "compensable"):
        return TrialDoc("second_reversal", False, "two counter-effects from two identical "
                        "requests released together", extra=ex)
    if not j.restored:
        return TrialDoc("not_restored", False, f"Z not restored ({ex['answers']})", extra=ex)
    return TrialDoc("once", True, f"one reversal from two overlapping requests; answers "
                    f"{ex['answers']}", extra=ex)


# --------------------------------------------------------------------------- ceiling trials


def _ceiling_values(run: _Run, form: str, op: str, call: str, label: str, agent: str,
                    claim: Optional[Dict[str, Any]]) -> Action:
    recipient = None
    if form == "condition_in_request" and claim:
        cond = next((c for c in claim.get("conditions") or []), None)
        w = (cond or {}).get("when") or {}
        tok = run.token()
        if "domain_not_in" in w:
            recipient = f"x-{tok}@external.example"
        elif "domain_in" in w:
            recipient = f"x-{tok}@{w['domain_in'][0]}"
    return run.build(op, call, label, agent=agent, recipient=recipient)


def _ceiling_trial(run: _Run, variant: str, form: str, op: str, call: str, k: int) -> TrialDoc:
    """`class_ceiling` and the ceiling forms of `class_downgrade`: W under ``max_class:
    reversible`` must leave no effect; L, the same request shape under a ceiling that admits the
    class, is accepted with one effect (the capability control, KRK-M10)."""
    claim = run.claim(op)
    ag = f"agent-{secrets.token_hex(3)}"
    Wact = _ceiling_values(run, form, op, call, f"W{k}", ag, claim)
    Lact = _ceiling_values(run, form, op, call, f"L{k}", ag, claim)
    values = run.A.claim_in_request(Wact.values, "reversible") \
        if form == "class_claimed_in_request" else None
    original = dict(claim) if claim else None
    ex: Dict[str, Any] = {"operation": op}
    s0 = run.world.mark()
    if form == "catalogue_changed":
        changed = {**(claim or {}), "class": "irreversible"}
        run.a.operator_set_claim(op, changed)
        if (_live_claim(run, op) or {}).get("class") != "irreversible":
            run.a.operator_set_claim(op, original)
            return TrialDoc("fixture_not_landed", None, "B's read path does not show the changed "
                            "claim (KRK-M123)")
        ex["claim_changed"] = "irreversible"
    if form == "changed_between_arrival_and_commit":
        run.world.hold(Wact.tokens[0] if Wact.tokens else Wact.named[0], 5.0)
    run.present(Wact, max_class="reversible", values=values)
    if form == "changed_between_arrival_and_commit":
        if not run.world.held_attempts(Wact.tokens[0] if Wact.tokens else Wact.named[0]):
            return TrialDoc("fixture_not_landed", None, "the world did not hold W's forward call")
        run.a.operator_set_claim(op, {**(claim or {}), "class": "irreversible"})
        if (_live_claim(run, op) or {}).get("class") != "irreversible":
            run.a.operator_set_claim(op, original)
            return TrialDoc("fixture_not_landed", None, "B's read path does not show the changed "
                            "claim while the call was held (KRK-M123)")
    settle = run.delay(op) + FORWARD_SETTLE_S + 10.0
    run.clock.sleep(settle)
    w_landed = run.landed(Wact, s0)
    if form in ("catalogue_changed", "changed_between_arrival_and_commit"):
        run.a.operator_set_claim(op, original)
        if (_live_claim(run, op) or {}) != (original or {}):
            ex["restore_claim"] = "B's read path does not show the original claim again"
    m = run.world.mark()
    run.present(Lact, max_class="irreversible")
    l_landed = Lact.answer_kind not in ("refused", "error") and \
        run.wait_landed([Lact], m, run.delay(op) + FORWARD_SETTLE_S)
    ex.update({"W": {"answer": Wact.answer_kind, "landed": w_landed},
               "L": {"answer": Lact.answer_kind, "landed": l_landed}})
    if w_landed:
        return TrialDoc("outside_class_effect", False, f"W under max_class reversible was "
                        f"committed ({op}, answered {Wact.answer_kind})", extra=ex)
    if not l_landed:
        return TrialDoc("collateral_refusal", None, "L, under a ceiling that admits the class, "
                        "was not performed: the refusal of W cannot be read as the ceiling "
                        "(KRK-M10)", extra=ex)
    return TrialDoc("held", True, f"no effect under the ceiling (W answered {Wact.answer_kind}); "
                    f"L performed once", extra=ex)


# --------------------------------------------------------------------------- the control


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    """§4.1: the world works and the kit sees it, B's forward path lands for every declared
    operation, one reversal per reversible or compensable operation reaches B and is answered,
    and B's declaration was read."""
    w = run.world
    obs: Dict[str, Any] = {}
    # 1. the world, driven by the kit directly
    m0 = w.mark()
    snap_a = w.snapshot()
    snap_b = w.snapshot()
    if snap_a["digest"] != snap_b["digest"] or w.mark().seq != m0.seq:
        return False, "two kit reads with nothing done between them differ (KRK-M116)", obs
    o = w.kit_call("create", fields={"k": "control"}, note="control-obj")["id"]
    o2 = w.kit_call("create", fields={"k": "control-2"})["id"]
    w.kit_call("update", object_id=o, fields={"k": "changed"})
    w.kit_call("link", src=o2, dst=o)
    w.kit_call("delete", object_id=o)
    w.kit_mailbox("control@d.example", "d:control")
    mid = w.kit_call("deliver", to="control@d.example", subject="s", body="control")["id"]
    w.kit_call("recall", message_id=mid)
    acc1, acc2 = w.kit_account("kit:control-1", 1000), w.kit_account("kit:control-2", 0)
    tid = w.kit_call("transfer", frm=acc1, to=acc2, amount=10, memo="control")["id"]
    w.kit_call("reverse_transfer", transfer_id=tid)
    iid = w.kit_call("publish", topic="control", body="control")["id"]
    w.kit_call("retract", item_id=iid)
    d = w.diff(m0)
    kinds = sorted({k[0] for k in d})
    callers = {e["caller"] for e in w.changes(m0)}
    m1 = w.mark()
    if w.diff(m1) or w.snapshot()["seq"] != m1.seq:
        return False, "a kit read changed the world (KRK-M116)", obs
    if callers != {"kit"} or set(kinds) != {"object", "edge", "mail", "transfer", "account",
                                             "item"}:
        return False, f"the kit's own changes were not all seen ({kinds}, callers {callers})", obs
    obs["world"] = {"kinds_seen": kinds, "changes": len(w.changes(m0))}
    # 4. B's declaration was read (before anything else that uses it)
    if run.st["claims_raw"] is None:
        return False, "B's reversibility statement could not be read", obs
    # 2. B's forward path lands
    ops = [c["operation"] for c in run.claims]
    irrev = [op for op in ops if run.base_class(op) == "irreversible"]
    landed: Dict[str, Any] = {}
    acts: List[Action] = []
    for op in ops:
        calls = [c for c in run.calls(op) if c in BUILDERS]
        if not calls:
            landed[op] = "no buildable world call in B's world profile"
            continue
        act = run.build(op, calls[0], f"ctl-{op}", agent=f"agent-{secrets.token_hex(3)}")
        m = w.mark()
        run.present(act)
        ok = act.answer_kind not in ("refused", "error") and \
            run.wait_landed([act], m, run.delay(op) + FORWARD_SETTLE_S)
        landed[op] = {"answer": act.answer_kind, "landed": ok}
        if not ok:
            return False, f"B's forward path did not land {op} at the world ({act.answer_kind})", \
                {**obs, "forward": landed}
        acts.append(act)
    if not acts:
        return False, "B declares no operation the kit can drive", obs
    obs["forward"] = landed
    obs["irreversible_ops"] = irrev
    # 3. a reversal request reaches B and its answer is readable
    answers: Dict[str, str] = {}
    for act in acts:
        if run.base_class(act.op) not in ("reversible", "compensable"):
            continue
        rec = run.reverse(act, label=f"ctl-rev-{act.op}")
        if run.tr.sent(rec["pres"].pid) != 1:
            return False, f"the reversal of {act.op} did not leave the kit once", obs
        answers[act.op] = rec["kind"]
    obs["reversal_answers"] = answers
    run.sleep_until(run.busy_until)
    return True, "", obs


# --------------------------------------------------------------------------- the variants


def _form_spec(run: _Run, variant: str, form: str, base_op: Optional[str]) -> Tuple[Optional[Spec], str]:
    """The trial spec for one form, or why it cannot be expressed against B's declaration."""
    rc = ("reversible", "compensable")
    comp = ("compensable",)

    def need(op: Optional[str], why: str) -> Tuple[Optional[str], str]:
        return op, ("" if op else why)
    if variant == "reversal":
        call = CALL_OF[form]
        op, why = need(run.op_for(call, rc), f"B declares no reversible or compensable "
                       f"operation that makes the world call {call}")
        return (Spec(variant, form, op, call) if op else None), why
    if variant == "downstream_consequence":
        call, _ev = PLANT[form]
        op, why = need(run.op_for(call, rc), f"B declares no reversible or compensable "
                       f"operation that makes the world call {call}")
        return (Spec(variant, form, op, call, plant=form) if op else None), why
    if not base_op:
        return None, "B declares no reversible or compensable operation"
    base_call = next(c for c in run.calls(base_op) if c in BUILDERS)
    if variant == "window":
        c = run.claim(base_op) or {}
        if not (c.get("window") or {}).get("seconds"):
            return None, "the claim states no window in seconds"
        place = {"inside_late": "inside_late", "outside": "outside",
                 "crosses_in_flight": "crosses", "queued_past_window": "queued"}[form]
        expect = {"inside_late": "restore", "outside": "refuse"}.get(form, "restore_or_refuse")
        return Spec(variant, form, base_op, base_call, expect=expect, place=place), ""
    if variant == "partition":
        if form == "refuse_one_item":
            op = run.op_for("objects:create_many", rc)
            if not op:
                return None, "B declares no reversible operation over several items"
            return Spec(variant, form, op, "objects:create_many", fault="refuse_one",
                        expect="restore_or_refuse"), ""
        spec = Spec(variant, form, base_op, base_call, expect="restore_or_refuse")
        if form in ("b_world_down", "b_world_hang"):
            spec.fault = form.split("_")[-1]
        elif form == "answer_lost":
            spec.drop, spec.expect = True, "restore"
        elif form == "b_restart":
            spec.restart, spec.fault = True, "down"
        return spec, ""
    if variant == "overtake":
        return Spec(variant, form, base_op, base_call, hold=True), ""
    if variant == "compensation_effect":
        op = run.op_for("ledger:transfer", comp) or next(
            (o for o in run.reversible_ops() if run.base_class(o) == "compensable"), None)
        if form == "extra_effect":
            op = run.op_for("topics:publish", comp) or op
        if not op:
            return None, "B declares no compensable operation"
        call = next(c for c in run.calls(op) if c in BUILDERS)
        return Spec(variant, form, op, call,
                    repeat="sequential" if form == "counter_effect_twice" else None), ""
    if variant == "duplicate":
        if form == "after_reapply":
            op = run.op_for("objects:create", rc) or base_op
        else:
            op = next((o for o in run.reversible_ops() if run.base_class(o) == "compensable"
                       and run.delay(o) == 0), None) or base_op
        call = next(c for c in run.calls(op) if c in BUILDERS)
        return Spec(variant, form, op, call, repeat=form), ""
    if variant == "no_standing":
        return Spec(variant, form, base_op, base_call, standing=form), ""
    if variant == "class_downgrade" and form == "window_shortened_after_execution":
        c = run.claim(base_op) or {}
        if not (c.get("window") or {}).get("seconds"):
            return None, "the claim states no window in seconds"
        may = run.st["executed_claims_may_change"] or {}
        return Spec(variant, form, base_op, base_call, shorten=True, place="old_window",
                    expect="refuse" if may.get("applies") is True else "restore"), ""
    if variant == "b_initiated":
        return Spec(variant, form, base_op, base_call, operator=True), ""
    return None, f"unknown form {variant}/{form}"


def _ceiling_op(run: _Run, variant: str, form: str, base_op: Optional[str]
                ) -> Tuple[Optional[Tuple[str, str]], str]:
    def first(classes: Tuple[str, ...]) -> Optional[Tuple[str, str]]:
        for c in run.claims:
            op = c["operation"]
            calls = [x for x in run.calls(op) if x in BUILDERS]
            if calls and run.base_class(op) in classes:
                return op, calls[0]
        return None
    if form in ("irreversible_op", "class_claimed_in_request"):
        hit = first(("irreversible",))
        return hit, "" if hit else "B declares no irreversible operation the kit can drive"
    if form == "compensable_op":
        hit = first(("compensable",))
        return hit, "" if hit else "B declares no compensable operation"
    if form == "class_absent":
        hit = run.absent_op()
        return hit, "" if hit else "every operation in B's world profile has a claim"
    if form == "condition_in_request":
        for c in run.claims:
            conds = [x for x in c.get("conditions") or [] if x.get("class") != "reversible"
                     and set((x.get("when") or {})) & {"domain_in", "domain_not_in"}
                     and x["when"]["member"] == "to"]
            calls = [x for x in run.calls(c["operation"]) if x in BUILDERS]
            if conds and calls and c.get("class") == "reversible":
                return (c["operation"], calls[0]), ""
        return None, "B declares no condition the kit can express that raises a class"
    if not base_op:
        return None, "B declares no reversible operation"
    return (base_op, next(c for c in run.calls(base_op) if c in BUILDERS)), ""


def _trials(plan: Dict[str, Any], variant: str, form: str, base: bool) -> int:
    t = plan.get("trials")
    table = {"dev": DEV_TRIALS, "published": PUBLISHED_TRIALS}.get(t, TRIALS) \
        if isinstance(t, str) or t is None else None
    if table is None:
        return int(t)
    return int(table["reversal:base"] if base else table["*"])


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return {"trials": raw}


def _statistics(docs: List[TrialDoc], R: float) -> Dict[str, Any]:
    """X4's statistics table for the base form's time to reverse against R (no mean)."""
    from .. import timing
    outs = []
    for d in docs:
        if d.outcome == "restored":
            outs.append(timing.TrialOutcome("within", True, time_s=d.time_s,
                                            bracket=(d.time_s, d.time_s) if d.time_s is not None else None))
        elif d.outcome == "restored_late":
            outs.append(timing.TrialOutcome("late", False, time_s=d.time_s,
                                            bracket=(d.time_s, d.time_s)))
        elif d.ok is False:
            outs.append(timing.TrialOutcome("not_within_W", False))
        else:
            outs.append(timing.TrialOutcome(d.outcome, None))
    st = timing.statistics(outs, R)
    st.pop("trials", None)
    st["note"] = "not_within_W counts trials not restored within the horizon H"
    return st


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import reversibility as rv
    from .. import world as wmod
    from ..requester import new_issuer
    from ..reverser import ReversalRequester
    from ..timing import make_clock

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if getattr(a, "role", lambda: "B")() != "B":
        return Result.inconclusive(a.name, ID, "P23 grades B in version 1; role A is version 2 "
                                   "(design §6.7)", **common)

    def opt(name: str, default: Any) -> Any:
        fn = getattr(a, name, None)
        return fn() if callable(fn) else default
    try:
        agreement = dict(a.agreement() or {})
        claims_raw = opt("reversibility", [])
        st: Dict[str, Any] = {
            "agreement": agreement, "claims_raw": claims_raw,
            "means": opt("reversal_means", {"kind": "none"}),
            "standing": opt("reversal_standing", None),
            "modes": opt("reversal_modes", ["immediate"]),
            "recovery_bound": opt("recovery_bound", None),
            "executed_claims_may_change": opt("executed_claims_may_change", None),
            "reversal_statements": opt("reversal_statements", None),
            "record_path": opt("record_path", None),
            "world_profile": dict(opt("world_profile", {}) or {}),
            "ceiling_profile": opt("ceiling_profile", None),
            "grade": a.evidence_grade()}
        na: Dict[str, str] = dict(opt("variants_not_applicable", {}) or {})
        remote = bool(opt("remote", False))
        self_hosted = bool(opt("self_hosted", not remote))
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    if not agreement.get("counterparty") or st["grade"] not in GRADES:
        return Result.inconclusive(a.name, ID, "no counterparty id, or an unknown evidence grade",
                                   **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not _is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock", **common)
    if "control" in na or any(v not in VARIANTS for v in na):
        return Result.inconclusive(a.name, ID, f"the adapter declares {sorted(na)} not "
                                   f"applicable; the control may not be", **common)
    findings: List[Dict[str, Any]] = []
    claims: List[Dict[str, Any]] = []
    for c in claims_raw or []:
        p = rv.claim_problem(c)
        if p:
            findings.append({"finding": "malformed_claim", "operation": (c or {}).get("operation"),
                             "why": p, "read_as": "irreversible"})
            claims.append({"operation": (c or {}).get("operation"), "class": "irreversible",
                           "malformed": p})
        else:
            claims.append(dict(c))
        if isinstance(c, dict) and not c.get("quote") and c.get("source") != "unstated":
            findings.append({"finding": "claim_without_quote", "operation": c.get("operation"),
                             "why": "a claim with no quote (KRK-M122)"})
        if isinstance(c, dict) and c.get("class") != "irreversible" and \
                not c.get("completion_bound_s"):
            findings.append({"finding": "no_stated_R", "operation": c.get("operation"),
                             "why": f"no completion bound stated; judged against "
                                    f"{DEFAULT_R_S:g} s"})
    if not st["standing"]:
        findings.append({"finding": "no_standing_rule", "why": "B's agreement does not say who may "
                         "ask for a reversal; only other_org is graded"})
    plan = dict(plan if plan is not None else ({} if _is_toy(a) else (_plan_from_env() or {})))
    published = plan.get("trials") == "published"
    development = bool(plan) and not published
    only = list(plan.get("variants") or VARIANTS)
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    clock = make_clock(kind)
    if kind == "virtual":
        a.set_clock(clock)
    world = wmod.World(clock)
    A = ReversalRequester(new_issuer(), clock=clock, audience=agreement["counterparty"])
    A2 = A.peer("a_prime")
    progress = _Progress(ev)
    run = None
    try:
        bind_a = a.bind_requester(A.trust_anchor())
        bind_p = a.bind_peer(A2.trust_anchor()) if callable(getattr(a, "bind_peer", None)) else None
        cred = world.credential("b")
        url = world.serve() if remote else world.url
        bind_w = a.bind_world(url, cred)
        st["b_view"] = wmod.connect(world.url, cred)
        rec_b = st["recovery_bound"] or {}
        st["rec_s"] = float(rec_b.get("rec_s") or 0.0) or None
        run = _Run(a, ev, clock=clock, world=world, A=A, A2=A2, rng=rng, claims=claims, st=st)
        run.progress = progress
        if st["rec_s"] is None:
            st["rec_s"] = max([run.R(op) for op in run.reversible_ops()] or [DEFAULT_R_S])
        statements = {k: v for k, v in st.items() if k not in ("b_view",)}
        ev.write("run.json", {"seed": seed, "variant_order": ["control"] + order,
                              "statements": _jsonable(statements), "plan": plan,
                              "bind_requester": bind_a, "bind_peer": bind_p, "bind_world": bind_w,
                              "clock": kind, "findings": findings})
        run.log("run", seed=seed, statements=statements, plan=plan, findings=findings)
        return _probe(run, a, ev, common, na, plan, development, only, order, seed, findings,
                      self_hosted)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        world.close()
        A.close()
        A2.close()
        clock.close()


def _must_land(run: _Run, variant: str, form: str, spec_op: Optional[str]) -> bool:
    if (variant, form) in (("class_ceiling", "irreversible_op"), ("class_ceiling", "class_absent")):
        return run.st["ceiling_profile"] == "kirkaldy.request-authorisation/0.2"
    if not run.reversible_ops():
        return False
    if variant == "reversal":
        return spec_op is not None
    return (variant, form) in NA_FORBIDDEN


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], na: Dict[str, str],
           plan: Dict[str, Any], development: bool, only: List[str], order: List[str],
           seed: int, findings: List[Dict[str, Any]], self_hosted: bool) -> Result:
    held, why, obs = _control(run)
    ev.write("control.json", {"held": held, "why": why, **_jsonable(obs)})
    run.log("control", held=held, why=why, obs=obs)
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    control = ("the kit's own world changes were all seen and its reads changed nothing; every "
               "declared operation landed once from a fresh authorised request; a reversal of "
               "each reversible or compensable operation reached B and was answered")
    revs = run.reversible_ops()
    base_op = None
    for c in run.claims:
        if run.base_class(c["operation"]) in ("reversible", "compensable") and \
                any(x in BUILDERS for x in run.calls(c["operation"])) and \
                run.delay(c["operation"]) == 0:
            base_op = c["operation"]
            break
    base_op = base_op or next((o for o in revs if any(x in BUILDERS for x in run.calls(o))), None)
    base_form = next((f for f, call in CALL_OF.items() if base_op and call in run.calls(base_op)),
                     None)
    readings: Dict[str, Dict[str, Dict[str, Any]]] = {}
    docs: Dict[str, List[Dict[str, Any]]] = {}
    base_docs: List[TrialDoc] = []
    truth_fails: List[str] = []
    grade_ok = run.st["grade"] == "world"
    for variant in order:
        if variant in na or variant not in only:
            continue
        for form in FORMS[variant]:
            if variant in (plan.get("forms") or {}) and form not in plan["forms"][variant]:
                continue
            if (variant, form) in SELF_HOSTED_ONLY and not self_hosted:
                readings.setdefault(variant, {})[form] = {
                    "reading": "not_applicable", "ok": None, "detail": "self-hosted only"}
                continue
            ceiling = variant == "class_ceiling" or (variant == "class_downgrade" and form !=
                                                     "window_shortened_after_execution")
            if ceiling:
                if run.st["ceiling_profile"] != "kirkaldy.request-authorisation/0.2":
                    readings.setdefault(variant, {})[form] = {
                        "reading": "not_applicable", "ok": None,
                        "detail": "B's format carries no class ceiling (authorisation 0.2)"}
                    continue
                hit, why = _ceiling_op(run, variant, form, base_op)
                spec_op = hit[0] if hit else None
            else:
                if not grade_ok:
                    readings.setdefault(variant, {})[form] = {
                        "reading": "not_applicable", "ok": None,
                        "detail": f"not driven at evidence grade {run.st['grade']!r}: it would "
                                  f"judge the effect from B's own account (spec §3.8)"}
                    continue
                spec, why = _form_spec(run, variant, form, base_op)
                spec_op = spec.op if spec else None
            if spec_op is None:
                readings.setdefault(variant, {})[form] = {"reading": "not_applicable",
                                                          "ok": None, "detail": why}
                continue
            if (variant, form) == ("class_downgrade", "window_shortened_after_execution") or \
                    form in ("catalogue_changed", "changed_between_arrival_and_commit"):
                if not callable(getattr(a, "operator_set_claim", None)) or \
                        not callable(getattr(a, "read_claims", None)):
                    readings.setdefault(variant, {})[form] = {
                        "reading": "not_applicable", "ok": None,
                        "detail": "the adapter offers no operator_set_claim / read_claims hook"}
                    continue
            is_base = variant == "reversal" and form == base_form
            n = _trials(plan, variant, form, is_base)
            outs: List[TrialDoc] = []
            for k in range(n):
                run.sleep_until(run.busy_until)
                if ceiling:
                    d = _ceiling_trial(run, variant, form, hit[0], hit[1], k)
                else:
                    d = _reversal_trial(run, spec, k)
                outs.append(d)
                doc = {"form": form, "k": k, "operation": spec_op, **d.to_doc()}
                docs.setdefault(variant, []).append(doc)
                run.log("trial", variant=variant, **doc)
                if d.ok is False and d.outcome in TRUTH:
                    truth_fails.append(f"{variant}/{form}: {d.outcome}")
            if is_base:
                base_docs = outs
            fails = [o for o in outs if o.ok is False]
            counted = [o for o in outs if o.ok is not None]
            if fails:
                r = {"reading": fails[0].outcome, "ok": False, "detail": fails[0].detail}
            elif counted and all(o.ok for o in counted):
                labs = sorted({o.outcome for o in counted})
                r = {"reading": "+".join(labs), "ok": True, "detail": counted[0].detail}
            else:
                infos = [o.outcome for o in outs]
                r = {"reading": max(sorted(set(infos)), key=infos.count), "ok": None,
                     "detail": outs[0].detail if outs else ""}
            r["operation"] = spec_op
            r["trials"] = len(outs)
            readings.setdefault(variant, {})[form] = r
        if variant in docs:
            ev.write(f"{variant}.json", {"variant": variant, "trials": docs[variant]})
    checks: List[Check] = []
    for variant in VARIANTS:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        fr = readings.get(variant)
        if not fr:
            continue
        parts = "; ".join(f"{k}: {d['reading']}" for k, d in fr.items())
        fails = [(k, d) for k, d in fr.items() if d["ok"] is False]
        passes = [(k, d) for k, d in fr.items() if d["ok"] is True]
        if fails:
            k, d = fails[0]
            c = Check(variant, d["reading"], False, f"{k}: {d['detail']}; {parts}")
        elif passes:
            c = Check(variant, "+".join(sorted({d["reading"] for _k, d in passes})), True, parts)
        else:
            reasons = sorted({d["reading"] for d in fr.values()})
            c = Check(variant, "not_applicable" if set(reasons) <= {"not_applicable",
                                                                     "fixture_not_landed"}
                      else reasons[0], None, parts)
        checks.append(c)
    must = []
    for variant, fr in readings.items():
        for form, d in fr.items():
            if d["ok"] is None and d["reading"] not in ("not_applicable",) and \
                    _must_land(run, variant, form, d.get("operation")):
                must.append(f"{variant}/{form}")
            if d["reading"] == "not_applicable" and _must_land(run, variant, form, None) and \
                    variant != "reversal" and "self-hosted" not in d["detail"]:
                must.append(f"{variant}/{form}")
    clauses: Dict[str, Dict[str, Any]] = {}
    for cl in ("a", "b", "c"):
        mine = [c for c in checks if CLAUSE.get(c.name) == cl]
        fl = [c.name for c in mine if c.ok is False]
        if cl == "c":
            fl = fl + [t for t in truth_fails if CLAUSE.get(t.split("/")[0]) != "c"]
        ok = [c.name for c in mine if c.ok is True]
        clauses[cl] = {"reading": "fail" if fl else ("pass" if ok else "not_applicable"),
                       "failed": fl, "passed": ok}
    documents = bool(getattr(a, "documents_reversibility_control", lambda: False)())
    vuln = documents and any(c.ok is False and c.name in ("class_ceiling", "class_downgrade",
                                                           "reversal", "downstream_consequence",
                                                           "no_standing") for c in checks)
    modes = sorted({str(m.get("mode")) for m in run.st["modes"] or [] if isinstance(m, dict)}
                   | ({"conservative"} if any(run.base_class(c["operation"]) == "irreversible"
                                              for c in run.claims) else set()))
    extra: Dict[str, Any] = {
        "seed": seed, "forms": readings, "clauses": clauses, "findings": findings,
        "base": {"operation": base_op, "form": base_form}, "modes": modes,
        "evidence_grade": run.st["grade"], "clock": getattr(a, "clock", "real"),
        "disclosure": "vulnerability" if vuln else "conformance",
        "covers": {"operations": [c["operation"] for c in run.claims],
                   "reversible_or_compensable": revs},
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if base_docs:
        extra["statistics"] = {"reversal/" + str(base_form): _statistics(base_docs,
                                                                         run.R(base_op))}
    if plan:
        extra["plan"] = plan
    dev = "Development plan (smaller counts; not a published run). " if development else ""
    if not [c for c in checks if c.ok is False] and must:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant failed, but forms that must land "
                                f"did not: {sorted(set(must))}", checks=checks, control_held=True,
                                control_detail=control, extra=extra, **common)
    elif not [c for c in checks if c.ok is not None]:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant landed with a verdict",
                                checks=checks, control_held=True, control_detail=control,
                                extra=extra, **common)
    else:
        r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                    pass_summary=f"{dev}every reversal B's declaration covers restored the world "
                                 f"as declared, nothing above the ceiling was committed, and every "
                                 f"reversal request was answered truthfully, at most once",
                    fail_summary=f"{dev}the world did not match B's declaration or its answers",
                    extra=extra, **common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r
