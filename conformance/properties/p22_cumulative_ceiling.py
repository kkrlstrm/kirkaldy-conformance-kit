"""P22 — Cumulative ceiling across counterparties (KRK-22, cross-organisation X9).

**Guarantee.** The total of the effects committed under a root and under every authority
delegated from it, summed over every counterparty, endpoint, session and retry, never exceeds the
root's cumulative ceiling, in every limit and window, under the stated reversal rule.

**Question.** Does the total effect, counted where effects land at every counterparty, stay
within the root's cumulative ceiling, however the agent spreads, races, retries, reverses or
re-delegates its spending, and when a counterparty cannot reach the party that keeps the account?

**Who is graded**. No counterparty alone can keep a ceiling across counterparties
that share no state, so the property is graded per role, each in its own run, with the kit
playing every other party correctly so that a fail names the party at fault:

- **Role A, the holder** (`role_ceiling.Holder`): the kit plays the principal, the agent and every
  spender (`ledger.StubSpender`, each with its own key, store and recorder prefix). The holder
  passes if the effects its issuances allow, committed by spenders that honour them exactly,
  total at most the ceiling.
- **Role B, a spender** (`role_ceiling.SpenderB`): the kit plays A (`issuer.StubIssuer`), the
  holder (`ledger.StubHolder`, correct) and stub B2. B passes if its own effects total at most
  what the holder confirmed to it, and the root's total stays within the ceiling.

**Counts judge; times place** (§4.4). Every verdict is a sum of effects at the kit's recorder,
read through `ceiling.charges` / `ceiling.judge`; the holder's own account and the spenders'
answers are information, never a verdict (KRK-M96). Timed forms place fixtures on the kit's clock
(X4's harness, `timing`), with margins larger than the stated tolerances.

**Every trial** has a fresh principal, agent and ceiling (KRK-M100) and a sibling root L, with
its own principal, agent and ceiling (KRK-M109), whose ceiling is twenty times W's, running the
same plan interleaved with W. L must be accepted in full, or the trial gives no reading
(``collateral_refusal``; in a concurrent round ``capacity_refused``, KRK-M110). Before presenting,
`truth` checks the fixture means what it says: W's plan crosses C, every spend lies inside every
per-request limit (KRK-M97), and, in role A's cross-spender variants, no spender's own total is
above C/2 where the total crosses C (§3.3). A concurrent round counts only with overlap shown
(KRK-M98): every presentation sent before the first answer, and, where the target
gives its own times, P18's rule (`p18_payload_bound.overlapped`). The 95% bound from N clean
overlapping rounds is reported (the rule of three), never "race-free".

**Outcomes.** Per trial: ``held`` (pass), ``over_ceiling`` (fail), ``over_share`` (fail, role B);
information ``collateral_refusal``, ``capacity_refused``, ``no_overlap``, ``stub_refused``,
``fixture_not_landed``, ``over_counted``, ``ledger_behind``, ``refused_within_ceiling``,
``headroom_stuck``, ``never_frees``, ``offline_window``. Per variant: ``held`` if every counted
trial held, a fail on any ``over_ceiling`` or ``over_share``. **Result**: ``fail`` if any landed
variant fails; ``pass`` if the control held, every landed variant passed and every form in
`NA_FORBIDDEN` gave a verdict; otherwise ``inconclusive``.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import ceiling, ledger
from ..role_ceiling import opt
from ..evidence import Evidence
from ..result import Check, Result, verdict
from . import p18_payload_bound as p18

ID = "P22"
TITLE = "Cumulative ceiling across counterparties"
FIXTURES = ("known_bad/ceiling_toys.py", "tests/test_p22_cumulative_ceiling.py",
            "tests/vectors/krk22/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("Ceiling ids, grant ids, reservation ids, share ids, request refs and every key "
            "come from the operating system, never from the seed (KRK-M36, M100).",
            "The seed draws the variant order, the ceilings, the amounts, the splits and the "
            "crossing points (§4.7).")

ROLES = ("A", "B")
VARIANTS = ("sum_across_bs", "sum_one_b", "concurrent", "retry", "reversal",
            "reservation_expiry", "units", "redelegated", "window", "partition")
FORMS = {"sum_across_bs": ("sequential", "many_small", "exact", "fresh_ceiling"),
         "sum_one_b": ("sessions", "endpoints", "restart"),
         "concurrent": ("two_bs", "n_way", "slow_effect", "endpoints", "with_other_spenders",
                        "share_elsewhere"),
         "retry": ("second_authorisation", "retry_at_other_b", "dedup_mismatch",
                   "release_after_commit", "double_count"),
         "reversal": ("confirmed", "claimed", "cancel_then_commit", "restores_share",
                      "negative_spend"),
         "reservation_expiry": ("commit_after_expiry", "freed_early", "freed_on_silence",
                                "no_expiry"),
         "units": ("other_currency", "minor_units", "two_limits", "count_unit", "fraction",
                   "large_integer"),
         "redelegated": ("child_fresh_ceiling", "siblings", "holder_hop", "reissued_root",
                         "regrant"),
         "window": ("boundary", "issuer_ahead", "spender_clock", "rolling"),
         "partition": ("holder_unreachable", "offline_within_share", "report_lost",
                       "late_capture", "split_holder")}
ROLE_FORMS = {
    "A": {"sum_across_bs": ("sequential", "many_small", "exact", "fresh_ceiling"),
          "sum_one_b": ("sessions", "restart"),
          "concurrent": ("two_bs", "n_way", "slow_effect"),
          "retry": ("second_authorisation", "retry_at_other_b", "dedup_mismatch",
                    "double_count"),
          "reversal": ("confirmed", "claimed", "cancel_then_commit", "negative_spend"),
          "reservation_expiry": ("freed_early", "freed_on_silence", "no_expiry"),
          "units": FORMS["units"],
          "redelegated": FORMS["redelegated"],
          "window": ("boundary", "spender_clock", "rolling"),
          "partition": ("report_lost", "late_capture", "split_holder")},
    "B": {"sum_across_bs": ("sequential", "many_small", "exact", "fresh_ceiling"),
          "sum_one_b": ("sessions", "endpoints", "restart"),
          "concurrent": ("endpoints", "with_other_spenders", "share_elsewhere"),
          "retry": ("release_after_commit", "double_count"),
          "reversal": ("restores_share", "negative_spend"),
          "reservation_expiry": ("commit_after_expiry",),
          "units": FORMS["units"],
          "redelegated": ("child_fresh_ceiling", "siblings", "holder_hop", "reissued_root"),
          "window": ("boundary", "issuer_ahead", "rolling"),
          "partition": ("holder_unreachable", "offline_within_share")}}
"""The [A] / [B] marks of design §3.1."""
MECHS = {
    ("A", "cancel_then_commit"): ("reservation",),
    ("A", "freed_early"): ("reservation",), ("A", "freed_on_silence"): ("reservation",),
    ("A", "no_expiry"): ("reservation",), ("A", "report_lost"): ("reservation",),
    ("A", "late_capture"): ("reservation",),
    ("B", "commit_after_expiry"): ("reservation",),
    ("B", "release_after_commit"): ("reservation",),
    ("B", "with_other_spenders"): ("reservation", "online"),
    ("B", "holder_unreachable"): ("reservation", "online"),
    ("B", "share_elsewhere"): ("allocation",), ("B", "offline_within_share"): ("allocation",),
    ("B", "restores_share"): ("allocation",),
    ("B", "child_fresh_ceiling"): ("allocation",), ("B", "siblings"): ("allocation",),
    ("B", "holder_hop"): ("allocation",), ("B", "reissued_root"): ("allocation",),
    ("B", "boundary"): ("allocation",), ("B", "issuer_ahead"): ("allocation",),
    ("B", "rolling"): ("allocation",),
}
"""Forms that land only under some mechanisms; elsewhere they are not applicable, with the
reason (design §2.3, §6.4's note)."""
K = {"two_bs": 2, "n_way": 8, "endpoints": 4, "with_other_spenders": 2}
CONCURRENT = ("two_bs", "n_way", "endpoints", "with_other_spenders")
"""The concurrent variant's racing forms. ``sum_one_b`` has a sequential form also named
``endpoints``, so a form is racing only under ``concurrent`` (`_racing`)."""


def _racing(variant: str, form: str) -> bool:
    return variant == "concurrent" and form in CONCURRENT
TIMED_VARIANTS = ("reservation_expiry", "window", "partition")
TRIALS = {"*": 5, "concurrent": 30, "timed": 5}
DEV_TRIALS = {"*": 3, "concurrent": 10, "timed": 2}
NA_FORBIDDEN = {
    "A": ("control", ("sum_across_bs", "sequential"), ("sum_one_b", "sessions"),
          ("concurrent", "two_bs"), ("concurrent", "slow_effect"),
          ("retry", "retry_at_other_b"), ("reversal", "claimed"),
          ("units", "other_currency")),
    "B": ("control", ("sum_across_bs", "sequential"), ("sum_one_b", "sessions"),
          ("units", "other_currency")),
}
VULNERABLE = {("sum_across_bs", None), ("sum_one_b", None), ("redelegated", None),
              ("retry", "second_authorisation"), ("retry", "retry_at_other_b"),
              ("retry", "dedup_mismatch"), ("reversal", "claimed"),
              ("reversal", "negative_spend"), ("concurrent", None)}
"""Where an excess over a documented hard limit is vulnerability-class."""
PLAN_ENV = "ACK_P22_PLAN"
SPENDERS = ("B1", "B2", "B3", "B4")
L_FACTOR = 20
CUR = "EUR"
MU = 2
B_NAME_DEFAULT = "did:web:b.example"
B2_NAME = "did:web:b2.example"
B_PRIME = "did:web:b-prime.example"
WINDOW_MIN_S = 20.0
WINDOW_MAX_S = 3600.0
SILENT_S = 0.3
"""How long after a reservation the agent asks for its headroom in ``freed_on_silence`` and
``report_lost``, as a share of the reservation's expiry."""
EPSILON_S = 0.05
"""A wait for a stated time ends this long after it (`timing.EPSILON_MIN_S`), so a time stated
to the millisecond is not crossed by rounding (KRK-M112)."""


def _amount(v: int, cur: str = CUR, mu: int = MU) -> Dict[str, Any]:
    return {"value": int(v), "currency": cur, "minor_units": int(mu)}


def amount_limit(v: int, cur: str = CUR, mu: int = MU) -> Dict[str, Any]:
    return {"kind": "amount", "value": int(v), "currency": cur, "minor_units": int(mu)}


def count_limit(v: int, unit: str = "message") -> Dict[str, Any]:
    return {"kind": "count", "value": int(v), "unit": unit}


def pay(v: int, cur: str = CUR, mu: int = MU, *, count: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
    out: Dict[str, Any] = {"op": "pay", "amount": _amount(v, cur, mu)}
    if count is not None:
        out["count"] = count
    return out


# --------------------------------------------------------------------------- the fixture


@dataclass
class Spend:
    at: str
    values: Dict[str, Any]
    l: str = "accept"
    """``accept``: L's copy must be accepted; ``any``: refused for a reason other than the
    ceiling (another currency, a negative amount, a conflict), so L's answer is not read."""
    session: Optional[str] = None
    endpoint: Optional[str] = None
    auth: Optional[str] = None
    """Which authority the agent presents (a key into the trial's authorities); None: the
    root."""
    tag: str = ""


@dataclass
class Fixture:
    variant: str
    form: str
    role: str
    C: int
    limits: List[Dict[str, Any]]
    window: Optional[Dict[str, Any]] = None
    rule: str = "gross"
    plan: List[Spend] = field(default_factory=list)
    """The spends `truth` checks (sequential plans; timed forms add their own steps)."""
    share: Optional[int] = None
    """Role B: what the holder confirms to B up front (allocation) or what stub B2 spends."""
    meta: Dict[str, Any] = field(default_factory=dict)


def _draw(rng: random.Random, lo: float, hi: float, C: int) -> int:
    return max(1, int(C * rng.uniform(lo, hi)))


def fixture(variant: str, form: str, rng: random.Random, *, role: str, mechanism: str,
            limits: Optional[List[Dict[str, Any]]] = None, window: Any = None,
            rule: str = "gross") -> Fixture:
    """The drawn plan for one trial of `variant`/`form` (design §3.1). Amounts, splits and the
    crossing point are drawn per trial (X3 §13 item 4)."""
    C = rng.randrange(60_000, 140_000) // 100 * 100
    lims = limits or [amount_limit(C)]
    f = Fixture(variant, form, role, C, lims, window, rule)
    d = lambda lo, hi: _draw(rng, lo, hi, C)  # noqa: E731
    if role == "A":
        if variant == "sum_across_bs" and form in ("sequential", "fresh_ceiling"):
            f.plan = [Spend(b, pay(d(0.40, 0.50))) for b in ("B1", "B2", "B3")]
        elif (variant, form) == ("sum_across_bs", "many_small"):
            f.plan = [Spend(SPENDERS[i % 3], pay(d(0.09, 0.11))) for i in range(20)]
        elif (variant, form) == ("sum_across_bs", "exact"):
            parts = _split(C, 6, rng)
            f.plan = [Spend(SPENDERS[i % 3], pay(p)) for i, p in enumerate(parts)]
            f.plan.append(Spend("B1", pay(1)))
        elif variant == "sum_one_b":
            f.plan = [Spend("B1", pay(d(0.40, 0.48)),
                            session=f"s{i % 2 + 1}" if form == "sessions" else None)
                      for i in range(3)]
    else:
        S = d(0.45, 0.55)
        f.share = S
        if variant == "sum_across_bs" and form in ("sequential", "fresh_ceiling"):
            f.plan = [Spend("B", pay(_draw(rng, 0.38, 0.45, S))) for _ in range(3)]
        elif (variant, form) == ("sum_across_bs", "many_small"):
            f.plan = [Spend("B", pay(_draw(rng, 0.22, 0.27, S))) for _ in range(6)]
        elif (variant, form) == ("sum_across_bs", "exact"):
            f.plan = [Spend("B", pay(p)) for p in _split(S, 3, rng)] + [Spend("B", pay(1))]
        elif variant == "sum_one_b":
            f.plan = [Spend("B", pay(_draw(rng, 0.38, 0.45, S)),
                            session=f"s{i % 2 + 1}" if form == "sessions" else None,
                            endpoint=(f"e{i % 2 + 1}" if form == "endpoints" else None))
                      for i in range(3)]
    return f


def _split(total: int, n: int, rng: random.Random, spread: float = 0.2) -> List[int]:
    """`n` positive parts summing exactly to `total`, each drawn within `spread` of an even
    part."""
    base = total // n
    parts = [max(1, int(base * rng.uniform(1 - spread, 1 + spread))) for _ in range(n - 1)]
    parts.append(total - sum(parts))
    if parts[-1] <= 0:
        return [base] * (n - 1) + [total - base * (n - 1)]
    return parts


def truth(f: Fixture) -> Dict[str, Any]:
    """The kit's own expectation for a sequential plan, checked before presenting (§6.4): W's
    plan crosses C, every spend lies inside every per-request limit (here C), in role A's
    cross-spender variants no spender's own total exceeds C/2 where the total crosses C, and in
    role B the target's spends exceed what it is confirmed and stay below C. Raises if not: the
    fixture would not mean what it says (KRK-M97)."""
    if not f.plan:
        return {"checked": False}
    lim = f.limits[0]
    vals = [ceiling.quantity(s.values, lim) for s in f.plan]
    if any(v is None or v < 0 for v in vals):
        raise ValueError(f"{f.variant}/{f.form}: a planned spend cannot be counted")
    C = ceiling.limit_value(lim)
    if any(v > C for v in vals):
        raise ValueError(f"{f.variant}/{f.form}: a spend is above the per-request limit")
    out: Dict[str, Any] = {"checked": True, "C": C, "planned": sum(vals)}
    if f.role == "A":
        if sum(vals) <= C:
            raise ValueError(f"{f.variant}/{f.form}: W's plan does not cross C")
        if f.variant == "sum_across_bs":
            run, per = 0, {}
            for s, v in zip(f.plan, vals):
                run += v
                per[s.at] = per.get(s.at, 0) + v
                if run > C:
                    if max(per.values()) * 2 > C + 2 * ceiling.scaled(1, lim["minor_units"]):
                        raise ValueError(f"{f.variant}/{f.form}: a spender is above C/2 where "
                                         f"the total crosses C")
                    out["per_spender_at_crossing"] = dict(per)
                    break
    else:
        S = ceiling.scaled(f.share or 0, lim["minor_units"])
        if not (sum(vals) > S) or sum(vals) >= C:
            raise ValueError(f"{f.variant}/{f.form}: B's plan must exceed its share and stay "
                             f"below C")
        out["share"] = S
    return out


# --------------------------------------------------------------------------- one run


class _Progress:
    """``NN-progress.jsonl``: one line per event, flushed as it is written."""

    def __init__(self, ev: Evidence) -> None:
        self.path = ev.write("progress.jsonl", "")
        import threading
        self._lock = threading.Lock()

    def add(self, kind: str, **doc: Any) -> None:
        rec = {"kind": kind, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **doc}
        line = json.dumps(rec, sort_keys=True, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()


@dataclass
class _Side:
    """W or L within one trial."""

    name: str
    C: int
    limits: List[Dict[str, Any]]
    window: Any
    rule: str
    root: Any = None
    """Role A: the holder's root id; role B: a `ledger.Grant3`."""
    auths: Dict[str, Any] = field(default_factory=dict)
    """Authority key -> holder id (A) or Grant3 (B)."""
    cids: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    """Authority key -> the kit's ceiling ids for it (root and every ancestor, KRK-M111)."""
    ceilings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    issuance: List[Dict[str, Any]] = field(default_factory=list)
    expect: List[str] = field(default_factory=list)
    """Refs the target authorised or accepted, whose effect must land (L only)."""
    required: List[str] = field(default_factory=list)
    """Refs L must have accepted (L only): every spend but those `_Trial.optional` names."""
    optional: List[str] = field(default_factory=list)
    answers: List[Dict[str, Any]] = field(default_factory=list)
    agent: str = ""
    principal: str = ""
    share: Any = None
    """Role B: the share the holder allocated B (allocation)."""
    share_cid: Optional[str] = None
    """Role B: the kit's pseudo-ceiling for B's share (``share:<id>``): B's own part."""
    b2_share: Any = None


class _Run:
    def __init__(self, a: Any, ev: Evidence, *, role: str, clock: Any, recorder: Any,
                 prefix: str, rng: random.Random, plan: Dict[str, Any], terms: Dict[str, Any],
                 profile: Dict[str, Any], mechanism: str, topology: str,
                 bindings: Dict[str, str], A: Any) -> None:
        self.a, self.ev, self.role, self.clock = a, ev, role, clock
        self.recorder, self.prefix, self.rng, self.plan = recorder, prefix, rng, plan
        self.terms, self.profile, self.mechanism = terms, profile, mechanism
        self.topology, self.bindings, self.A = topology, bindings, A
        self.spenders: Dict[str, ledger.StubSpender] = {}
        self.H: Optional[ledger.StubHolder] = None
        self.B2: Optional[ledger.StubSpender] = None
        self.b_name = B_NAME_DEFAULT
        self.endpoints: List[str] = ["default"]
        self.progress: Optional[_Progress] = None
        self.rec_idx = 0
        self.yardstick: Optional[float] = None
        self.exposes_times = False
        self.max_in_flight = 1
        from ..requester import Transport
        self.transport = Transport(self._present, clock=time.perf_counter)
        self.calls: Dict[str, Callable[[], Dict[str, Any]]] = {}

    def log(self, kind: str, **doc: Any) -> None:
        if self.progress is not None:
            self.progress.add(kind, **doc)

    def _present(self, p: Any) -> Dict[str, Any]:
        return self.calls.pop(p.pid)()

    def call(self, fn: Callable[[], Dict[str, Any]], *, tag: str = "") -> Dict[str, Any]:
        """One request leaving the kit, through the transport (no retry, logged)."""
        from ..authz import Presentation
        pid = f"p-{secrets.token_hex(6)}"
        self.calls[pid] = fn
        ans = self.transport.send(Presentation(pid, tag or "-", None, b"{}", None, {}))
        return ans or {}

    def together(self, fns: List[Callable[[], Dict[str, Any]]]
                 ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Release `fns` together, each on its own thread behind a barrier (X3's
        `Transport.release_together`). Returns the answers and the wire entries."""
        from ..authz import Presentation
        ps = []
        for fn in fns:
            pid = f"p-{secrets.token_hex(6)}"
            self.calls[pid] = fn
            ps.append(Presentation(pid, "-", None, b"{}", None, {}))
        n0 = len(self.transport.wire_log)
        ans = self.transport.release_together(tuple(ps), delay_s=0.0)
        wire = [e for e in self.transport.wire_log[n0:]]
        return ans, wire

    def wall_offset(self) -> float:
        """kit wall clock minus kit monotonic clock."""
        return self.clock.wall() - self.clock.now()

    def effects(self) -> List[Dict[str, Any]]:
        out, self.rec_idx = self.recorder.effects_after(self.rec_idx, self.prefix)
        return out


def _cls(run: _Run, ans: Dict[str, Any]) -> str:
    """The adapter's reading of an answer (`role_ceiling.CLASSES`)."""
    try:
        return str(run.a.classify(ans))
    except Exception:  # noqa: BLE001
        return "error"


# --------------------------------------------------------------------------- a trial


class _Trial:
    """One trial: W and L, the plan steps, then the charges and the readings."""

    def __init__(self, run: _Run, f: Fixture, k: int) -> None:
        self.run, self.f, self.k = run, f, k
        self.t0 = run.clock.now()
        self.events: List[Dict[str, Any]] = []
        self.rounds: List[Dict[str, Any]] = []
        self.info: Dict[str, Any] = {}
        self.not_landed: Optional[str] = None
        self.stub_refused: List[str] = []
        self.refused_fit: List[str] = []
        self.W = _Side("W", f.C, [dict(x) for x in f.limits], f.window, f.rule)
        self.L = _Side("L", f.C * L_FACTOR, [_scale_limit(x) for x in f.limits], _scale_window(
            f.window), f.rule)

    # opening ---------------------------------------------------------------------------------

    def open(self, *, wait: bool = True) -> None:
        for side in self.sides():
            self._open_side(side)
        if wait:
            prop = float((self.run.terms.get("propagation_s") or {}).get("value", 0.0)
                         if isinstance(self.run.terms.get("propagation_s"), dict)
                         else self.run.terms.get("propagation_s") or 0.0)
            if prop > 0:
                self.run.clock.sleep(prop + EPSILON_S)
            rb = getattr(self.run.a, "read_back", None)
            if callable(rb) and self.run.role == "A":
                for side in self.sides():
                    self.info.setdefault("read_back", {})[side.name] = rb(side.root)

    def sides(self) -> List[_Side]:
        return [self.W, self.L]

    def _open_side(self, s: _Side) -> None:
        run = self.run
        s.principal = f"p-{secrets.token_hex(4)}@a.example"
        s.agent = f"agent-{secrets.token_hex(4)}"
        cid = ledger.new_ceiling_id()
        window = dict(s.window) if s.window else None
        anchor_kit = None
        if window and window["kind"] == "fixed":
            anchor_kit = run.clock.now()
            window["anchor_ms"] = int(run.clock.wall() * 1000)
            s.window = window
        s.ceilings[cid] = {"limits": s.limits, "window": window, "anchor_kit": anchor_kit
                           if anchor_kit is not None else run.clock.now()}
        if window and window["kind"] == "fixed":
            s.ceilings[cid]["anchor_kit"] = anchor_kit
        if run.role == "A":
            s.root = run.a.open_root(s.principal, s.limits, window=window, rule=s.rule)
        else:
            assert run.H is not None
            s.root = run.H.open_root(s.principal, s.limits, window=window, rule=s.rule,
                                     agent=s.agent)
            # the kit's own ceiling id is the holder's (the kit signed the root)
            kc = s.root.ceiling_ids[0]
            s.ceilings = {kc: {**s.ceilings[cid], "limits": s.limits}}
            cid = kc
        s.auths["root"] = s.root
        s.cids["root"] = (cid,)
        self.log("open", side=s.name, ceiling_id=cid, limits=s.limits, window=window,
                 rule=s.rule)

    def log(self, op: str, **doc: Any) -> None:
        e = {"op": op, "t": round(self.run.clock.now() - self.t0, 4), **doc}
        self.events.append(e)

    def track(self, s: _Side, ref: str, accepted: bool) -> None:
        """L's bookkeeping: every L spend is required unless `optional` names it; an
        accepted one must land at the recorder."""
        if s.name != "L":
            return
        if ref not in s.required:
            s.required.append(ref)
        if accepted and ref not in s.expect:
            s.expect.append(ref)

    def optional(self, s: _Side, ref: str) -> None:
        """L's spend `ref` may be refused for a reason other than the ceiling (another
        currency, a negative amount, a conflict, an address): its answer is not read."""
        if s.name == "L" and ref not in s.optional:
            s.optional.append(ref)

    # role A: one spend --------------------------------------------------------------------------

    def ask(self, s: _Side, at: str, values: Dict[str, Any], *, ref: Optional[str] = None,
            auth: str = "root", session: Optional[str] = None, drop: bool = False,
            present: bool = True) -> Dict[str, Any]:
        """Role A: the agent asks the holder for authority to spend `values` at `at` (bearer)
        or sends the spend through it (forwarding); then, bearer, presents the issuance to the
        stub spender. Returns ``{"ref", "cls", "answer", "issuance", "stub"}``."""
        run = self.run
        ref = ref or f"rq-{secrets.token_hex(8)}"
        s.issuance.append({"ref": ref, "ceiling_ids": list(s.cids[auth]), "at": at})
        authority = s.auths[auth]
        kw: Dict[str, Any] = {"request_id": ref, "agent": s.agent}
        if session is not None and "sessions" in (run.profile.get("features") or []):
            kw["session"] = session

        def go() -> Dict[str, Any]:
            return run.a.request(authority, run.spenders[at].name, values, **kw)
        ans = run.call(go, tag=f"{s.name}:{at}")
        cls = _cls(run, ans)
        out = {"ref": ref, "cls": cls, "answer": ans, "issuance": None, "stub": None, "at": at,
               "side": s.name}
        body = ans.get("body") if isinstance(ans.get("body"), dict) else {}
        out["issuance"] = body.get("issuance")
        self.log("ask", side=s.name, at=at, ref=ref, cls=cls, auth=auth, dropped=drop,
                 reason=str(body.get("reason", ""))[:120])
        self.track(s, ref, cls == "authorised")
        if run.topology != "forwarding" and present and cls == "authorised" and \
                out["issuance"]:
            out["stub"] = self.present(s, at, out["issuance"], values, ref)
        return out

    def present(self, s: _Side, at: str, issuance: str, values: Dict[str, Any], ref: str
                ) -> Dict[str, Any]:
        st = self.run.spenders[at]
        ans = st.present({"issuance": issuance, "values": values, "ref": ref})
        body = ans.get("body") or {}
        if body.get("stub_refused"):
            self.stub_refused.append(ref)
        self.log("present", side=s.name, at=at, ref=ref, code=body.get("code"),
                 reason=str(body.get("reason", ""))[:120])
        return ans

    # role B: one spend at B, or by stub B2 -----------------------------------------------------

    def spend_b(self, s: _Side, values: Dict[str, Any], *, ref: Optional[str] = None,
                endpoint: Optional[str] = None, session: Optional[str] = None,
                auth: str = "root", share: Any = "own") -> Dict[str, Any]:
        """Role B: present one spend at B, under `auth` (a grant 0.3 chain) and, for an
        allocation B, the share (`share`: ``own`` is B's, or a `Grant3`)."""
        run = self.run
        ref = ref or f"rq-{secrets.token_hex(8)}"
        s.issuance.append({"ref": ref, "ceiling_ids": self.b_cids(s, auth), "at": "B"})
        p = self.presentation(s, values, ref=ref, endpoint=endpoint, session=session,
                              auth=auth, share=share)
        ans = run.call(lambda: run.a.present(p, session=session), tag=f"{s.name}:B")
        cls = _cls(run, ans)
        self.log("spend_b", side=s.name, ref=ref, endpoint=p.endpoint, session=session,
                 cls=cls, auth=auth)
        self.track(s, ref, cls == "authorised")
        return {"ref": ref, "cls": cls, "answer": ans}

    def b_cids(self, s: _Side, auth: str = "root") -> List[str]:
        """What one of B's spends counts against: the chain's ceilings and, for an
        allocation B, B's own share (its part, design §4.5 ``over_share``)."""
        return list(s.cids[auth]) + ([s.share_cid] if s.share_cid else [])

    def presentation(self, s: _Side, values: Dict[str, Any], *, ref: str,
                     endpoint: Optional[str], session: Optional[str], auth: str,
                     share: Any) -> Any:
        from ..authz import Presentation
        from ..receipts import canonical_json
        g = s.auths[auth]
        hdr = {"KRK-Grant": g.chain[0], "KRK-Grant-Chain": ",".join(g.chain[1:])}
        sh = s.share if share == "own" else share
        if sh is not None:
            hdr["KRK-Share"] = sh.token
        if session:
            hdr["KRK-Session"] = session
        body = {**values, "ref": ref}
        try:
            raw = canonical_json(body)
        except Exception:  # noqa: BLE001
            raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ep = endpoint or self.run.endpoints[0]
        return Presentation(f"p-{secrets.token_hex(6)}", ep, None, raw, None, hdr)

    def b2(self, s: _Side, values: Dict[str, Any], *, auth: str = "root",
           ref: Optional[str] = None) -> Dict[str, Any]:
        """Role B: stub B2 spends `values` under the kit's holder, as its mechanism does: under
        its share (allocation), or with a reservation the agent asks for (reservation,
        online)."""
        run = self.run
        assert run.H is not None and run.B2 is not None
        ref = ref or f"rq-{secrets.token_hex(8)}"
        s.issuance.append({"ref": ref, "ceiling_ids": list(s.cids[auth]), "at": "B2"})
        if run.mechanism == "allocation":
            tok = s.b2_share.token if s.b2_share is not None else None
            if tok is None:
                return {"ref": ref, "cls": "refused"}
            ans = run.B2.present({"issuance": tok, "values": values, "ref": ref})
        else:
            g = s.auths[auth]
            try:
                route = run.H.authorise if run.mechanism == "online" else run.H.reserve
                r = route({"chain": list(g.chain), "spender": run.B2.name, "values": values,
                           "request_id": ref})
            except ledger.Unreachable:
                r = ledger._answer("unreachable")
            body = r.get("body") or {}
            if body.get("code") != "authorised":
                self.log("b2", side=s.name, ref=ref, code=body.get("code"))
                self.track(s, ref, False)
                return {"ref": ref, "cls": "refused"}
            ans = run.B2.present({"issuance": body["issuance"], "values": values, "ref": ref})
        code = (ans.get("body") or {}).get("code")
        if (ans.get("body") or {}).get("stub_refused"):
            self.stub_refused.append(ref)
        self.log("b2", side=s.name, ref=ref, code=code)
        self.track(s, ref, code in ("executed", "queued"))
        return {"ref": ref, "cls": "authorised" if code in ("executed", "queued") else
                "refused"}

    def setup_b(self, share_w: Optional[int], *, b2_rest: bool = True, wait: bool = True
                ) -> None:
        """Role B: the holder confirms B its part. Allocation: a share of `share_w` (W) and the
        same scaled for L, and stub B2 a share of the rest, which B2 spends. Reservation and
        online: stub B2 spends the rest of the root first, so B's spends over `share_w` would
        also overspend the root."""
        run = self.run
        assert run.H is not None
        for s in self.sides():
            S = share_w if s.name == "W" else share_w * L_FACTOR if share_w else None
            if S is None:
                continue
            S = min(S, _whole(s.limits[0]))
            lim0 = s.limits[0]
            if run.mechanism == "allocation":
                s.share = run.H.allocate(s.root, run.b_name, _share_limits(s.limits, S))
                if s.share is not None:
                    sh = s.share.claims["constraints"]["cumulative"]["share"]
                    s.share_cid = f"share:{sh['share_id']}"
                    root_c = s.ceilings[s.cids["root"][0]]
                    s.ceilings[s.share_cid] = {"limits": [dict(x) for x in sh["limits"]],
                                               "window": root_c.get("window"),
                                               "anchor_kit": root_c.get("anchor_kit")}
                rest = _whole(lim0) - S
                if rest > 0 and b2_rest:
                    s.b2_share = run.H.allocate(s.root, run.B2.name, _share_limits(
                        s.limits, rest, rest_of=S))
                    self.log("share", side=s.name, b=S, b2=rest)
                    if s.name == "W":
                        self.b2(s, pay(rest, lim0["currency"], lim0["minor_units"]))
                else:
                    self.log("share", side=s.name, b=S)
            elif b2_rest:
                rest = _whole(lim0) - S
                if s.name == "W" and rest > 0:
                    self.b2(s, pay(rest, lim0["currency"], lim0["minor_units"]))
        prop = _terms(run, "propagation_s", 0.0)
        if wait and run.mechanism == "allocation" and prop > 0:
            self.sleep(prop + EPSILON_S)               # the share is in force (KRK-M112)

    # time -----------------------------------------------------------------------------------

    def sleep(self, s: float) -> None:
        if s > 0:
            self.run.clock.sleep(s)

    def sleep_until(self, t_kit: float) -> None:
        self.run.clock.sleep_until(t_kit)

    def kit_of_wall_ms(self, ms: int) -> float:
        return ms / 1000.0 - self.run.wall_offset()


def _whole(lim: Dict[str, Any]) -> int:
    return int(lim["value"])


def _share_limits(limits: List[Dict[str, Any]], amount: int, *, rest_of: Optional[int] = None
                  ) -> List[Dict[str, Any]]:
    """A share of every limit of the root: `amount` of the first (an amount), and of each count
    limit the same part, at least one (or, with `rest_of`, what that part leaves)."""
    out = []
    a0 = limits[0]
    for i, lim in enumerate(limits):
        if i == 0:
            out.append({**lim, "value": int(amount)})
            continue
        if lim["kind"] == "count":
            part = max(1, lim["value"] * 2 // 3)
            v = part if rest_of is None else max(0, lim["value"] - part)
            out.append({**lim, "value": int(v)})
        else:
            out.append({**lim, "value": int(lim["value"] * amount // max(1, a0["value"]))})
    return out


def _scale_limit(lim: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(lim)
    if out["value"] * L_FACTOR <= ceiling.MAX_SAFE:
        out["value"] = out["value"] * L_FACTOR
    else:
        out["value"] = ceiling.MAX_SAFE
    return out


def _scale_window(w: Any) -> Any:
    return dict(w) if w else None


# --------------------------------------------------------------------------- the forms


def _frac(C: int, x: float) -> int:
    return max(1, int(C * x))


def run_form(tr: _Trial, variant: str, form: str) -> None:
    """Drive one trial of `variant`/`form` (design §3.1), W and L interleaved."""
    fn = FORM_FNS[(tr.run.role, variant, form)]
    fn(tr)


def _seq(tr: _Trial, wait: bool = True) -> None:
    tr.open(wait=wait)
    for sp in tr.f.plan:
        for s in tr.sides():
            if tr.run.role == "A":
                r = tr.ask(s, sp.at, sp.values, session=sp.session)
            else:
                r = tr.spend_b(s, sp.values, endpoint=sp.endpoint, session=sp.session)
            if s.name == "W" and tr.f.form == "exact" and sp is not tr.f.plan[-1] and \
                    r["cls"] != "authorised" and tr.run.role == "A":
                tr.refused_fit.append(r["ref"])


def _a_sum_across(tr: _Trial) -> None:
    _seq(tr, wait=tr.f.form != "fresh_ceiling")


def _a_sessions(tr: _Trial) -> None:
    _seq(tr)


def _a_restart(tr: _Trial) -> None:
    tr.open()
    plan = tr.f.plan
    for i, sp in enumerate(plan):
        if i == len(plan) // 2 + (len(plan) % 2):
            tr.info["restart"] = tr.run.a.restart()
            tr.log("restart")
        for s in tr.sides():
            tr.ask(s, sp.at, sp.values)


def _b_sum(tr: _Trial) -> None:
    tr.open(wait=tr.f.form != "fresh_ceiling")
    tr.setup_b(tr.f.share, wait=tr.f.form != "fresh_ceiling")
    for i, sp in enumerate(tr.f.plan):
        if tr.f.form == "restart" and i == len(tr.f.plan) // 2 + 1:
            tr.info["restart"] = tr.run.a.restart()
            tr.log("restart")
        for s in tr.sides():
            tr.spend_b(s, sp.values, endpoint=sp.endpoint, session=sp.session)


# concurrent ------------------------------------------------------------------------------------


def _round_a(tr: _Trial, spends: List[Tuple[str, Dict[str, Any]]]) -> None:
    """One concurrent round of requests for authority at the holder (role A), W's then L's,
    each released together; then each issuance presented."""
    run = tr.run
    for s in tr.sides():
        fns, refs = [], []
        for at, v in spends:
            ref = f"rq-{secrets.token_hex(8)}"
            refs.append((ref, at, v))
            s.issuance.append({"ref": ref, "ceiling_ids": list(s.cids["root"]), "at": at})
            fns.append((lambda at=at, v=v, ref=ref, s=s: run.a.request(
                s.root, run.spenders[at].name, v, request_id=ref, agent=s.agent)))
        ans, wire = run.together(fns)
        over = _overlap(run, ans, wire)
        accepted = 0
        for (ref, at, v), a in zip(refs, ans):
            cls = _cls(run, a)
            body = a.get("body") if isinstance(a.get("body"), dict) else {}
            tr.log("ask", side=s.name, at=at, ref=ref, cls=cls, round=True)
            tr.track(s, ref, cls == "authorised")
            if cls == "authorised":
                accepted += 1
                if run.topology != "forwarding" and body.get("issuance"):
                    tr.present(s, at, body["issuance"], v, ref)
        tr.rounds.append({"side": s.name, "k": len(spends), "accepted": accepted, **over})


def _overlap(run: _Run, ans: List[Dict[str, Any]], wire: List[Dict[str, Any]]
             ) -> Dict[str, Any]:
    """KRK-M98: (a) every presentation sent before the first answer arrived; (b) where the
    target gives its own begin times, P18's rule against the uncontended duration."""
    sent = [e.get("t_sent") for e in wire]
    answered = [e.get("t_answered") for e in wire]
    a_ok = bool(sent) and None not in sent and None not in answered and \
        max(sent) < min(answered)
    out: Dict[str, Any] = {"sent_before_answer": a_ok, "max_in_flight": run.max_in_flight}
    began = []
    for a in ans:
        b = (a.get("body") or {}) if isinstance(a, dict) else {}
        if isinstance(b.get("began"), (int, float)):
            began.append(float(b["began"]))
    if run.exposes_times and began and run.yardstick:
        spread = max(began) - min(began)
        out.update(spread_s=round(spread, 6), yardstick_s=round(run.yardstick, 6),
                   p18_overlapped=p18.overlapped(spread, run.yardstick))
        ok = a_ok and out["p18_overlapped"]
        out["evidence"] = "sent before any answer, and the target's own times"
    else:
        ok = a_ok
        out["evidence"] = "sent before any answer only (the target gives no times)"
    out["overlapped"] = bool(ok and run.max_in_flight >= len(wire))
    return out


def _a_two_bs(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.6)
    _round_a(tr, [("B1", pay(v)), ("B2", pay(v))])


def _a_n_way(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.3)
    _round_a(tr, [(SPENDERS[i % 4], pay(v)) for i in range(8)])


def _a_slow_effect(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    for st in run.spenders.values():
        st.effect_delay_s = 3.0
    try:
        vals = [pay(_draw(run.rng, 0.42, 0.48, tr.f.C)) for _ in range(3)]
        for i, b in enumerate(("B1", "B2", "B3")):
            for s in tr.sides():
                tr.ask(s, b, vals[i])
            tr.sleep(0.2)
        tr.sleep(3.5)
    finally:
        for st in run.spenders.values():
            st.effect_delay_s = 0.0


def _b_endpoints_round(tr: _Trial) -> None:
    tr.open()
    tr.setup_b(tr.f.share)
    run = tr.run
    eps = (run.endpoints * 4)[:4] if len(run.endpoints) > 1 else []
    S = tr.f.share or 0
    v = _frac(S, 0.6)
    for s in tr.sides():
        fns, refs = [], []
        for i in range(4):
            ref = f"rq-{secrets.token_hex(8)}"
            s.issuance.append({"ref": ref, "ceiling_ids": tr.b_cids(s), "at": "B"})
            p = tr.presentation(s, pay(v), ref=ref, endpoint=eps[i], session=None,
                                auth="root", share="own")
            refs.append(ref)
            fns.append(lambda p=p: run.a.present(p, session=None))
        ans, wire = run.together(fns)
        over = _overlap(run, ans, wire)
        acc = 0
        for ref, a in zip(refs, ans):
            cls = _cls(run, a)
            tr.log("spend_b", side=s.name, ref=ref, cls=cls, round=True)
            tr.track(s, ref, cls == "authorised")
            if cls == "authorised":
                acc += 1
        tr.rounds.append({"side": s.name, "k": 4, "accepted": acc, **over})


def _b_with_other_spenders(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    first = _frac(tr.f.C, 0.4)
    for s in tr.sides():
        if s.name == "W":
            tr.b2(s, pay(first))
    rem = tr.f.C - first
    v = _frac(rem, 0.6)
    for s in tr.sides():
        ref_b = f"rq-{secrets.token_hex(8)}"
        s.issuance.append({"ref": ref_b, "ceiling_ids": tr.b_cids(s), "at": "B"})
        p = tr.presentation(s, pay(v), ref=ref_b, endpoint=None, session=None, auth="root",
                            share=None)
        ref2 = f"rq-{secrets.token_hex(8)}"
        fns = [lambda p=p: run.a.present(p, session=None),
               lambda s=s, ref2=ref2: _b2_call(tr, s, pay(v), ref2)]
        ans, wire = run.together(fns)
        over = _overlap(run, ans[:1] + [{}], wire)
        cls = _cls(run, ans[0])
        tr.log("spend_b", side=s.name, ref=ref_b, cls=cls, round=True)
        tr.track(s, ref_b, cls == "authorised")
        tr.track(s, ref2, (ans[1].get("body") or {}).get("code") in ("executed", "queued"))
        if s.name == "L":
            tr.optional(s, ref_b if cls != "authorised" else ref2)
        tr.rounds.append({"side": s.name, "k": 2, "accepted": int(cls == "authorised") + int(
            (ans[1].get("body") or {}).get("code") in ("executed", "queued")), **over})


def _b2_call(tr: _Trial, s: _Side, values: Dict[str, Any], ref: str) -> Dict[str, Any]:
    run = tr.run
    assert run.H is not None and run.B2 is not None
    s.issuance.append({"ref": ref, "ceiling_ids": list(s.cids["root"]), "at": "B2"})
    route = run.H.authorise if run.mechanism == "online" else run.H.reserve
    r = route({"chain": list(s.root.chain), "spender": run.B2.name, "values": values,
               "request_id": ref})
    body = r.get("body") or {}
    if body.get("code") != "authorised":
        return {"status": 403, "body": {"code": "refused"}}
    return run.B2.present({"issuance": body["issuance"], "values": values, "ref": ref})


def _b_share_elsewhere(tr: _Trial) -> None:
    tr.open()
    tr.setup_b(tr.f.share)
    S = tr.f.share or 0
    # B spends its own share in full; then B2's share (genuinely B2's) is presented at B
    for s in tr.sides():
        tr.spend_b(s, pay(S))
    v = _frac(tr.f.C - S, 0.8)
    for s in tr.sides():
        r = tr.spend_b(s, pay(v), share=s.b2_share)
        tr.optional(s, r["ref"])             # refused for its address, not the ceiling


# retry -----------------------------------------------------------------------------------------


def _a_second_authorisation(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.6)
    for s in tr.sides():
        ref = f"rq-{secrets.token_hex(8)}"
        r1 = tr.ask(s, "B1", pay(v), ref=ref, drop=True, present=False)
        r2 = tr.ask(s, "B2", pay(v), ref=ref, present=False)
        for r in (r1, r2):
            if r["cls"] == "authorised" and r["issuance"] and tr.run.topology != "forwarding":
                tr.present(s, r["at"], r["issuance"], pay(v), ref)


def _a_retry_at_other_b(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.6)
    for s in tr.sides():
        r1 = tr.ask(s, "B1", pay(v))
        tr.log("answer-dropped", side=s.name, ref=r1["ref"])
        cancel = getattr(tr.run.a, "cancel", None)
        if callable(cancel):
            tr.info.setdefault("cancel", []).append(cancel(s.root, r1["issuance"] or r1["ref"]))
        r2 = tr.ask(s, "B2", pay(v))
        tr.optional(s, r2["ref"])


def _a_dedup_mismatch(tr: _Trial) -> None:
    tr.open()
    v1, v2 = _frac(tr.f.C, 0.55), _frac(tr.f.C, 0.6)
    for s in tr.sides():
        ref = f"rq-{secrets.token_hex(8)}"
        tr.ask(s, "B1", pay(v1), ref=ref)
        tr.ask(s, "B2", pay(v2), ref=ref)


def _a_double_count(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.4)
    for s in tr.sides():
        ref = f"rq-{secrets.token_hex(8)}"
        tr.ask(s, "B1", pay(v), ref=ref, drop=True, present=False)
        tr.ask(s, "B1", pay(v), ref=ref)
    w = _frac(tr.f.C, 0.5)
    for s in tr.sides():
        r = tr.ask(s, "B2", pay(w))
        if s.name == "W" and r["cls"] != "authorised":
            tr.refused_fit.append(r["ref"])


def _b_release_after_commit(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    assert run.H is not None
    v = _frac(tr.f.C, 0.6)
    run.H.fail_next_captures(run.b_name, 1)
    tr.spend_b(tr.W, pay(v))
    run.H.fail_next_captures(run.b_name, 0)
    tr.spend_b(tr.L, pay(v))
    tr.sleep(1.0)
    for s in tr.sides():
        r = tr.b2(s, pay(v))
        tr.optional(s, r["ref"])


def _b_double_count(tr: _Trial) -> None:
    tr.open()
    tr.setup_b(tr.f.share)
    S = tr.f.share or 0
    v = _frac(S, 0.4)
    for s in tr.sides():
        ref = f"rq-{secrets.token_hex(8)}"
        tr.spend_b(s, pay(v), ref=ref)
        tr.spend_b(s, pay(v), ref=ref)
    w = _frac(S, 0.5)
    for s in tr.sides():
        r = tr.spend_b(s, pay(w))
        if s.name == "W" and r["cls"] != "authorised":
            tr.refused_fit.append(r["ref"])


# reversal --------------------------------------------------------------------------------------


def _a_confirmed(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    C = tr.f.C
    a, b = _draw(run.rng, 0.45, 0.5, C), _draw(run.rng, 0.35, 0.4, C)
    rev = _frac(C, 0.4)
    e = C - (a + b - rev) - max(1, C // 100)
    for s in tr.sides():
        r1 = tr.ask(s, "B1", pay(a))
        tr.ask(s, "B2", pay(b))
        if r1["cls"] == "authorised" and r1["issuance"]:
            st = run.spenders["B1"]
            claims = _issuance_claims(r1["issuance"])
            rid = (claims or {}).get("reservation_id") or _share_id(claims) or r1["ref"]
            cids = (claims or {}).get("ceiling_ids") or []
            st.reverse(r1["ref"], pay(rev), ref=rid, ceiling_ids=cids,
                       quantity=[{"kind": "amount", "value": rev, "currency": CUR,
                                  "minor_units": MU}])
            tr.log("reverse", side=s.name, ref=r1["ref"], value=rev)
    for s in tr.sides():
        tr.ask(s, "B3", pay(e))
    tr.info["rule"] = tr.f.rule


def _issuance_claims(tok: Any) -> Optional[Dict[str, Any]]:
    from .. import standing
    c = standing.peek(tok)
    return c or None


def _share_id(c: Optional[Dict[str, Any]]) -> Optional[str]:
    sh = (((c or {}).get("constraints") or {}).get("cumulative") or {}).get("share")
    return sh.get("share_id") if isinstance(sh, dict) else None


def _a_claimed(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    C = tr.f.C
    a, b = _draw(run.rng, 0.45, 0.5, C), _draw(run.rng, 0.35, 0.4, C)
    rev = _frac(C, 0.4)
    e = C - (a + b - rev) - max(1, C // 100)
    claim = getattr(run.a, "claim_reversal", None)
    for s in tr.sides():
        r1 = tr.ask(s, "B1", pay(a))
        tr.ask(s, "B2", pay(b))
        if callable(claim) and s.name == "W":
            tr.info.setdefault("claim", []).append(claim(s.root, r1["ref"], pay(rev)))
            tr.log("claim_reversal", side=s.name, ref=r1["ref"], value=rev)
    for s in tr.sides():
        tr.ask(s, "B3", pay(e))
    tr.info["recorder_reversals_before_judging"] = "checked in the judgement (KRK-M104)"


def _a_cancel_then_commit(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    cancel = getattr(run.a, "cancel", None)
    held = {}
    for s in tr.sides():
        r1 = tr.ask(s, "B1", pay(v), present=False)
        held[s.name] = r1
        if callable(cancel) and s.name == "W":
            tr.info.setdefault("cancel", []).append(cancel(s.root, r1["issuance"] or r1["ref"]))
            tr.log("cancel", side=s.name, ref=r1["ref"])
    for s in tr.sides():
        tr.ask(s, "B2", pay(v))
    for s in tr.sides():
        r1 = held[s.name]
        if r1["cls"] == "authorised" and r1["issuance"]:
            tr.present(s, "B1", r1["issuance"], pay(v), r1["ref"])


def _a_negative(tr: _Trial) -> None:
    tr.open()
    v, n = _frac(tr.f.C, 0.6), _frac(tr.f.C, 0.5)
    for s in tr.sides():
        tr.ask(s, "B1", pay(v))
        r = tr.ask(s, "B2", pay(-n))
        tr.optional(s, r["ref"])
        tr.ask(s, "B3", pay(v))


def _b_restores_share(tr: _Trial) -> None:
    tr.open()
    tr.setup_b(tr.f.share)
    run = tr.run
    S = tr.f.share or 0
    a = _frac(S, 0.55)
    b = S - a
    rev = _frac(S, 0.3)
    rv = getattr(run.a, "reverse", None)
    for s in tr.sides():
        r1 = tr.spend_b(s, pay(a))
        tr.spend_b(s, pay(b))
        if callable(rv):
            tr.info.setdefault("reverse", []).append(rv(r1["ref"], pay(rev)))
            tr.log("reverse", side=s.name, ref=r1["ref"], value=rev)
    for s in tr.sides():
        tr.spend_b(s, pay(rev))


def _b_negative(tr: _Trial) -> None:
    tr.open()
    tr.setup_b(tr.f.share)
    S = tr.f.share or 0
    v, n = _frac(S, 0.6), _frac(S, 0.5)
    for s in tr.sides():
        tr.spend_b(s, pay(v))
        r = tr.spend_b(s, pay(-n))
        tr.optional(s, r["ref"])
        tr.spend_b(s, pay(v))


# reservation expiry ---------------------------------------------------------------------------


def _terms(run: _Run, name: str, default: float) -> float:
    v = run.terms.get(name)
    if isinstance(v, dict):
        v = v.get("value")
    return float(default if v is None else v)


def _expiry_kit(tr: _Trial, issuance: Any) -> Optional[float]:
    c = _issuance_claims(issuance) or {}
    na = c.get("not_after")
    return None if na is None else tr.kit_of_wall_ms(int(na))


def _a_freed_early(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    lag = _terms(run, "capture_lag_s", 0.0)
    st = run.spenders["B1"]
    held = {}
    for s in tr.sides():
        held[s.name] = tr.ask(s, "B1", pay(v), present=False)
    E = _expiry_kit(tr, held["W"]["issuance"])
    if E is None or lag <= 0.4:
        tr.not_landed = "no reservation expiry, or no capture lag, stated"
        return
    tr.sleep_until(E - 1.0)
    st.set_report("deliver", delay_s=min(lag, 1.0) + 0.5)
    try:
        for s in tr.sides():
            r = held[s.name]
            if r["cls"] == "authorised":
                tr.present(s, "B1", r["issuance"], pay(v), r["ref"])
        tr.sleep_until(E + 0.2)
        for s in tr.sides():
            r2 = tr.ask(s, "B2", pay(v))
            tr.optional(s, r2["ref"])
        tr.sleep(2.0)
    finally:
        st.set_report("deliver")


def _a_freed_on_silence(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    held = {}
    for s in tr.sides():
        held[s.name] = tr.ask(s, "B1", pay(v), present=False)
    E = _expiry_kit(tr, held["W"]["issuance"])
    if E is None:
        tr.not_landed = "the reservation states no expiry"
        return
    span = E - run.clock.now()
    tr.sleep(span * 0.6)
    for s in tr.sides():
        r2 = tr.ask(s, "B2", pay(v))
        tr.optional(s, r2["ref"])
    tr.sleep(span * 0.1)
    for s in tr.sides():
        r = held[s.name]
        if r["cls"] == "authorised":
            tr.present(s, "B1", r["issuance"], pay(v), r["ref"])


def _a_no_expiry(tr: _Trial) -> None:
    tr.open()
    v = _frac(tr.f.C, 0.3)
    for s in tr.sides():
        r = tr.ask(s, "B1", pay(v))
        if s.name == "W":
            c = _issuance_claims(r["issuance"]) or {}
            tr.info["never_frees"] = r["cls"] == "authorised" and "not_after" in c and \
                c.get("not_after") is None


def _b_commit_after_expiry(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    assert run.H is not None
    v = _frac(tr.f.C, 0.6)
    tau_b = _terms(run, "tolerance_s", 0.0)
    wait = run.H.expiry_s + max(run.H.tolerance_s + run.H.capture_lag_s, tau_b) + 2.0
    ref = f"rq-{secrets.token_hex(8)}"
    run.recorder.hold(ref, wait)
    tr.spend_b(tr.W, pay(v), ref=ref)
    tr.spend_b(tr.L, pay(v))
    tr.sleep(run.H.expiry_s + run.H.tolerance_s + run.H.capture_lag_s + 0.5)
    tr.b2(tr.W, pay(v))
    tr.sleep(wait + 1.0)
    held = run.recorder.held(run.prefix)
    tr.info["held"] = len([h for h in held if (h.get("effect") or {}).get("ref") == ref])
    if not tr.info["held"]:
        tr.not_landed = "B's effect call was not held by the recorder"


# units -----------------------------------------------------------------------------------------


def _units(tr: _Trial) -> None:
    run = tr.run
    f = tr.f
    form = f.form
    C = f.C if run.role == "A" else int(f.share or 0)
    seq: List[Spend] = []
    if form == "other_currency":
        seq = [Spend("B1", pay(_frac(C, 0.5))), Spend("B2", pay(_frac(C, 0.3), "USD"), l="any")]
    elif form == "minor_units":
        x = _frac(C, 0.6) // 100 * 100
        seq = [Spend("B1", pay(x)), Spend("B2", pay(x // 100, CUR, 0))]
    elif form == "two_limits":
        n = 4 if run.role == "A" else 3
        seq = [Spend(SPENDERS[i % 3], pay(_frac(C, 0.2), count={"value": 1, "unit": "message"}))
               for i in range(n)]
    elif form == "count_unit":
        seq = [Spend("B1", pay(_frac(C, 0.2), count={"value": 1, "unit": "recipient"}), l="any")]
    elif form == "fraction":
        p = _split(C, 2, run.rng)
        seq = [Spend("B1", pay(p[0])), Spend("B2", pay(p[1])), Spend("B3", pay(5, CUR, 3))]
    elif form == "large_integer":
        p = _split(C, 3, run.rng)
        seq = [Spend(SPENDERS[i], pay(x)) for i, x in enumerate(p)] + [
            Spend("B1", pay(1, CUR, 3), l="any")]
    tr.open()
    if run.role == "B":
        tr.setup_b(f.share)
    for sp in seq:
        for s in tr.sides():
            if run.role == "A":
                r = tr.ask(s, sp.at, sp.values)
            else:
                r = tr.spend_b(s, sp.values)
            if sp.l == "any":
                tr.optional(s, r["ref"])


def units_fixture(form: str, rng: random.Random, role: str) -> Tuple[int, List[Dict[str, Any]]]:
    """The ceiling for a units form: ``large_integer`` at 2^53 - 1 minor units; ``two_limits``
    and ``count_unit`` add a count limit; the rest one amount."""
    C = rng.randrange(60_000, 140_000) // 100 * 100
    if form == "large_integer":
        C = ceiling.MAX_SAFE
        return C, [amount_limit(C)]
    if form == "two_limits":
        return C, [amount_limit(C), count_limit(3)]
    if form == "count_unit":
        return C, [amount_limit(C), count_limit(5)]
    return C, [amount_limit(C)]


# redelegated -----------------------------------------------------------------------------------


def _a_redelegated(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    form = tr.f.form
    C = tr.f.C
    v = _frac(C, 0.7)
    a = run.a
    for s in tr.sides():
        own = s.limits if form in ("child_fresh_ceiling", "siblings") else None
        kids = []
        if form in ("child_fresh_ceiling", "siblings", "holder_hop"):
            n = 2 if form == "siblings" else 1
            for i in range(n):
                cid = a.delegate(s.root, f"agent-{secrets.token_hex(4)}", own,
                                 holder_hop=form == "holder_hop")
                key = f"child{i}"
                s.auths[key] = cid
                own_cid = ledger.new_ceiling_id()
                if own is not None:
                    s.ceilings[own_cid] = {"limits": own, "window": None}
                    s.cids[key] = s.cids["root"] + (own_cid,)
                else:
                    s.cids[key] = s.cids["root"]
                kids.append(key)
            if form != "siblings":
                tr.ask(s, "B1", pay(v))
            for i, key in enumerate(kids):
                tr.ask(s, SPENDERS[1 + i], pay(v), auth=key)
        elif form == "reissued_root":
            tr.ask(s, "B1", pay(_frac(C, 0.6)))
            new = a.reissue(s.root)
            s.auths["re"] = new
            s.cids["re"] = s.cids["root"]
            tr.ask(s, "B2", pay(_frac(C, 0.6)), auth="re")
        elif form == "regrant":
            parts = _split(C, 2, run.rng)
            tr.ask(s, "B1", pay(parts[0]))
            tr.ask(s, "B2", pay(parts[1]))
            new = a.regrant(s.root, s.agent)
            s.auths["re"] = new
            s.cids["re"] = s.cids["root"]
            tr.ask(s, "B3", pay(_frac(C, 0.5)), auth="re")


def _b_redelegated(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    form = tr.f.form
    tr.setup_b(tr.f.share)
    S = tr.f.share or 0
    v = _frac(S, 0.7)
    for s in tr.sides():
        own = None
        kids = []
        if form in ("child_fresh_ceiling", "siblings", "holder_hop"):
            n = 2 if form == "siblings" else 1
            org = None
            for i in range(n):
                if form in ("child_fresh_ceiling", "siblings"):
                    own = ledger.cumulative(ledger.new_ceiling_id(), s.limits, rule=s.rule,
                                            holder=run.H.holder_ref())
                g = ledger.delegate(run.A, s.root, f"agent-{secrets.token_hex(4)}", own=own,
                                    holder_hop=form == "holder_hop", org=org)
                run.H.learn(g)
                key = f"child{i}"
                s.auths[key] = g
                s.cids[key] = g.ceiling_ids
                if own is not None:
                    s.ceilings[own["ceiling_id"]] = {"limits": own["limits"], "window": None}
                kids.append(key)
            if form != "siblings":
                tr.spend_b(s, pay(v))
            for key in kids:
                tr.spend_b(s, pay(v), auth=key)
        elif form == "reissued_root":
            tr.spend_b(s, pay(_frac(S, 0.6)))
            g = ledger.reissue(run.A, s.root)
            s.auths["re"] = g
            s.cids["re"] = s.cids["root"]
            tr.spend_b(s, pay(_frac(S, 0.6)), auth="re")


# windows ---------------------------------------------------------------------------------------


def _period(run: _Run) -> float:
    lo = float(run.profile.get("min_window_s") or WINDOW_MIN_S)
    return max(WINDOW_MIN_S, lo)


def window_of(form: str, run: _Run) -> Dict[str, Any]:
    P = int(round(_period(run)))
    if form == "rolling":
        return {"kind": "rolling", "period_s": P}
    return {"kind": "fixed", "period_s": P, "anchor_ms": 0}


def _a_window(tr: _Trial) -> None:
    run = tr.run
    tr.open()
    C = tr.f.C
    P = float(tr.f.window["period_s"])
    a0 = tr.W.ceilings[tr.W.cids["root"][0]].get("anchor_kit") or run.clock.now()
    m = 2.0 + _terms(run, "tolerance_s", 0.0)
    if tr.f.form == "boundary":
        v = _frac(C, 0.8)
        tr.sleep_until(a0 + P - m)
        for s in tr.sides():
            r = tr.ask(s, "B1", pay(v))
            if s.name == "W" and r["cls"] != "authorised":
                tr.refused_fit.append(r["ref"])
        tr.sleep_until(a0 + P + m)
        for s in tr.sides():
            r = tr.ask(s, "B2", pay(v))
            if s.name == "W" and r["cls"] != "authorised":
                tr.refused_fit.append(r["ref"])
        tr.sleep_until(a0 + 2 * P + m)
        for s in tr.sides():
            tr.ask(s, "B3", pay(v))
        tr.sleep(1.0)
        for s in tr.sides():
            tr.ask(s, "B1", pay(_frac(C, 0.3)))
    elif tr.f.form == "spender_clock":
        d = P / 2
        for st in run.spenders.values():
            st.set_clock_offset(d)
        try:
            v = _frac(C, 0.8)
            tr.sleep_until(a0 + P - m - 2.0)
            for s in tr.sides():
                tr.ask(s, "B1", pay(v))
            tr.sleep(1.0)
            for s in tr.sides():
                tr.ask(s, "B2", pay(v))
        finally:
            for st in run.spenders.values():
                st.set_clock_offset(0.0)
    elif tr.f.form == "rolling":
        v = _frac(C, 0.9)
        t1 = run.clock.now() + P - m
        tr.sleep_until(t1)
        for s in tr.sides():
            tr.ask(s, "B1", pay(v))
        tr.sleep(2 * m)
        for s in tr.sides():
            tr.ask(s, "B2", pay(v))


def _b_window(tr: _Trial) -> None:
    run = tr.run
    assert run.H is not None
    form = tr.f.form
    if form == "issuer_ahead":
        d = float(tr.f.window["period_s"]) / 2
        run.H.set_clock_offset(d)
    try:
        tr.open()
        tr.setup_b(tr.f.share, b2_rest=False)
        S = tr.f.share or 0
        P = float(tr.f.window["period_s"])
        a0 = tr.W.ceilings[tr.W.cids["root"][0]].get("anchor_kit") or run.clock.now()
        m = 2.0 + _terms(run, "tolerance_s", 0.0)
        if form == "boundary":
            v = _frac(S, 0.8)
            tr.sleep_until(a0 + P - m)
            for s in tr.sides():
                r = tr.spend_b(s, pay(v))
                if s.name == "W" and r["cls"] != "authorised":
                    tr.refused_fit.append(r["ref"])
            tr.sleep_until(a0 + P + m)
            for s in tr.sides():
                r = tr.spend_b(s, pay(v))
                if s.name == "W" and r["cls"] != "authorised":
                    tr.refused_fit.append(r["ref"])
            tr.sleep(1.0)
            for s in tr.sides():
                tr.spend_b(s, pay(_frac(S, 0.3)))
        elif form == "issuer_ahead":
            v = _frac(S, 0.8)
            half = P / 2
            for s in tr.sides():
                tr.spend_b(s, pay(_frac(S, 0.05)))
            tr.sleep_until(a0 + half - m)
            for s in tr.sides():
                tr.spend_b(s, pay(v))
            tr.sleep_until(a0 + half + m)
            for s in tr.sides():
                tr.spend_b(s, pay(v))
        elif form == "rolling":
            v = _frac(S, 0.9)
            tr.sleep_until(run.clock.now() + P - m)
            for s in tr.sides():
                tr.spend_b(s, pay(v))
            tr.sleep(2 * m)
            for s in tr.sides():
                tr.spend_b(s, pay(v))
    finally:
        run.H.set_clock_offset(0.0)


# partition -------------------------------------------------------------------------------------


def _b_holder_unreachable(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    assert run.H is not None
    C = tr.f.C
    for s in tr.sides():
        tr.spend_b(s, pay(_frac(C, 0.2)))
    t_o = run.clock.now()
    n_o = len(run.H.log())
    run.H.set_reachable(run.b_name, "down")
    tr.info["t_o"] = round(t_o - tr.t0, 4)
    try:
        tr.b2(tr.W, pay(_frac(C, 0.75)))
        refused_since = None
        for i in range(3):
            for s in tr.sides():
                r = tr.spend_b(s, pay(_frac(C, 0.25)))
                tr.optional(s, r["ref"])
                if s.name == "W" and r["cls"] != "authorised" and refused_since is None:
                    refused_since = run.clock.now() - t_o
            tr.sleep(0.5)
        log = run.H.log()[n_o:]
        seen = [e for e in log if e.get("spender") == run.b_name and e.get("reach") == "up"]
        if seen:
            tr.not_landed = "B reached the holder during the partition (KRK-M107)"
        tr.info["offline_window"] = {"refused_from_s": refused_since,
                                     "duration_s": round(run.clock.now() - t_o, 3)}
    finally:
        run.H.set_reachable(run.b_name, "up")


def _b_offline_within_share(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    assert run.H is not None
    tr.setup_b(tr.f.share)
    S = tr.f.share or 0
    run.H.set_reachable(run.b_name, "down")
    try:
        for i in range(3):
            for s in tr.sides():
                tr.spend_b(s, pay(_frac(S, 0.4)))
            tr.sleep(0.5)
        tr.info["offline_window"] = {"spent_offline": True}
    finally:
        run.H.set_reachable(run.b_name, "up")


def _a_report_lost(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    st = run.spenders["B1"]
    st.set_report("drop")
    try:
        held = {}
        for s in tr.sides():
            held[s.name] = tr.ask(s, "B1", pay(v))
        E = _expiry_kit(tr, held["W"]["issuance"])
        span = (E - run.clock.now()) if E is not None else 10.0
        tr.sleep(span * 0.6)
        for s in tr.sides():
            r2 = tr.ask(s, "B2", pay(v))
            tr.optional(s, r2["ref"])
    finally:
        st.set_report("deliver")
    tr.info["dropped"] = len(st.dropped)


def _a_late_capture(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    st = run.spenders["B1"]
    held = {}
    for s in tr.sides():
        held[s.name] = tr.ask(s, "B1", pay(v), present=False)
    E = _expiry_kit(tr, held["W"]["issuance"])
    lag = _terms(run, "capture_lag_s", 0.0)
    if E is None or lag < 1.0:
        tr.not_landed = "no expiry, or a capture lag under a second, stated"
        return
    tr.sleep_until(E - 1.0)
    st.set_report("hold-until-heal")
    try:
        for s in tr.sides():
            r = held[s.name]
            if r["cls"] == "authorised":
                tr.present(s, "B1", r["issuance"], pay(v), r["ref"])
        tr.sleep_until(E + 0.2)
        for s in tr.sides():
            r2 = tr.ask(s, "B2", pay(v))
            tr.optional(s, r2["ref"])
        tr.sleep_until(E + min(lag, 1.5) - 0.5)
    finally:
        st.set_report("deliver")
    tr.log("healed")
    tr.sleep(0.3)
    for s in tr.sides():
        r3 = tr.ask(s, "B3", pay(v))
        tr.optional(s, r3["ref"])


def _a_split_holder(tr: _Trial) -> None:
    tr.open()
    run = tr.run
    v = _frac(tr.f.C, 0.6)
    run.a.partition_replicas(True)
    try:
        for b in ("B1", "B2"):
            for s in tr.sides():
                r = tr.ask(s, b, pay(v))
                tr.optional(s, r["ref"])
    finally:
        run.a.partition_replicas(False)
    tr.info["l_any"] = "availability during a split is not read from L"


FORM_FNS: Dict[Tuple[str, str, str], Callable[[_Trial], None]] = {}
for _f in FORMS["sum_across_bs"]:
    FORM_FNS[("A", "sum_across_bs", _f)] = _a_sum_across
    FORM_FNS[("B", "sum_across_bs", _f)] = _b_sum
FORM_FNS[("A", "sum_one_b", "sessions")] = _a_sessions
FORM_FNS[("A", "sum_one_b", "restart")] = _a_restart
for _f in FORMS["sum_one_b"]:
    FORM_FNS[("B", "sum_one_b", _f)] = _b_sum
FORM_FNS.update({
    ("A", "concurrent", "two_bs"): _a_two_bs, ("A", "concurrent", "n_way"): _a_n_way,
    ("A", "concurrent", "slow_effect"): _a_slow_effect,
    ("B", "concurrent", "endpoints"): _b_endpoints_round,
    ("B", "concurrent", "with_other_spenders"): _b_with_other_spenders,
    ("B", "concurrent", "share_elsewhere"): _b_share_elsewhere,
    ("A", "retry", "second_authorisation"): _a_second_authorisation,
    ("A", "retry", "retry_at_other_b"): _a_retry_at_other_b,
    ("A", "retry", "dedup_mismatch"): _a_dedup_mismatch,
    ("A", "retry", "double_count"): _a_double_count,
    ("B", "retry", "release_after_commit"): _b_release_after_commit,
    ("B", "retry", "double_count"): _b_double_count,
    ("A", "reversal", "confirmed"): _a_confirmed, ("A", "reversal", "claimed"): _a_claimed,
    ("A", "reversal", "cancel_then_commit"): _a_cancel_then_commit,
    ("A", "reversal", "negative_spend"): _a_negative,
    ("B", "reversal", "restores_share"): _b_restores_share,
    ("B", "reversal", "negative_spend"): _b_negative,
    ("A", "reservation_expiry", "freed_early"): _a_freed_early,
    ("A", "reservation_expiry", "freed_on_silence"): _a_freed_on_silence,
    ("A", "reservation_expiry", "no_expiry"): _a_no_expiry,
    ("B", "reservation_expiry", "commit_after_expiry"): _b_commit_after_expiry,
    ("A", "partition", "report_lost"): _a_report_lost,
    ("A", "partition", "late_capture"): _a_late_capture,
    ("A", "partition", "split_holder"): _a_split_holder,
    ("B", "partition", "holder_unreachable"): _b_holder_unreachable,
    ("B", "partition", "offline_within_share"): _b_offline_within_share,
})
for _f in FORMS["units"]:
    FORM_FNS[("A", "units", _f)] = _units
    FORM_FNS[("B", "units", _f)] = _units
for _f in FORMS["redelegated"]:
    FORM_FNS[("A", "redelegated", _f)] = _a_redelegated
    FORM_FNS[("B", "redelegated", _f)] = _b_redelegated
for _f in FORMS["window"]:
    FORM_FNS[("A", "window", _f)] = _a_window
    FORM_FNS[("B", "window", _f)] = _b_window


# --------------------------------------------------------------------------- judging a trial


@dataclass
class Outcome:
    outcome: str
    ok: Optional[bool]
    detail: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_doc(self) -> Dict[str, Any]:
        return {"outcome": self.outcome, "ok": self.ok, "detail": self.detail,
                **({"extra": self.extra} if self.extra else {})}


def _side_effects(effects: List[Dict[str, Any]], side: _Side) -> List[Dict[str, Any]]:
    refs = {str(e["ref"]) for e in side.issuance}
    out = []
    for e in effects:
        body = e.get("effect") if isinstance(e.get("effect"), dict) else {}
        r = str(body.get("ref", ""))
        rv = str(body.get("reverses", ""))
        if r in refs or (body.get("kind") == "reversal" and rv in refs):
            out.append(e)
    return out


def _unattributed(effects: List[Dict[str, Any]], tr: _Trial) -> List[Dict[str, Any]]:
    refs = {str(e["ref"]) for s in tr.sides() for e in s.issuance}
    out = []
    for e in effects:
        body = e.get("effect") if isinstance(e.get("effect"), dict) else {}
        if str(body.get("ref", "")) not in refs and str(body.get("reverses", "")) not in refs:
            out.append(e)
    return out


def judge_trial(tr: _Trial, effects: List[Dict[str, Any]]) -> Outcome:
    """The trial's reading from the recorder alone (§2.6, §4.5)."""
    run = tr.run
    f = tr.f
    w_eff = _side_effects(effects, tr.W) + _unattributed(effects, tr)
    l_eff = _side_effects(effects, tr.L)
    tol = _terms(run, "tolerance_s", 0.0)
    lag = _terms(run, "commit_lag_s", 0.0)
    over = {}
    os_ = run.profile.get("overshoot_kit")
    if os_:
        for cid in tr.W.ceilings:
            for i in range(len(tr.W.ceilings[cid]["limits"])):
                over[f"{cid}/{i}"] = int(os_)
    chs = ceiling.charges(w_eff, tr.W.issuance, bindings=run.bindings, ceilings=tr.W.ceilings,
                          default_ceiling_ids=tr.W.cids["root"])
    j = ceiling.judge(chs, tr.W.ceilings, rule=f.rule, tolerance_s=tol, commit_lag_s=lag,
                      overshoot=over)
    extra: Dict[str, Any] = {"totals": {cid: [str(x) for x in v] for cid, v in
                                        j["totals"].items()},
                             "where": j["where"], "uncountable": j["uncountable"],
                             "windows": j["windows"], "effects_w": len(w_eff),
                             "effects_l": len(l_eff)}
    if tr.info:
        extra["info"] = tr.info
    if tr.rounds:
        extra["rounds"] = tr.rounds
    if tr.not_landed:
        return Outcome("fixture_not_landed", None, tr.not_landed, extra)
    if tr.stub_refused:
        return Outcome("stub_refused", None, f"a stub spender refused what the holder allowed "
                                              f"({len(tr.stub_refused)}; KRK-M99)", extra)
    # L accepted in full (KRK-M97, M109, M110)
    l_refs = {str((e.get("effect") or {}).get("ref")) for e in l_eff}
    missing = [r for r in tr.L.expect if r not in l_refs and r not in tr.L.optional]
    refused = [r for r in tr.L.required if r not in tr.L.expect and r not in tr.L.optional]
    if missing:
        return Outcome("collateral_refusal", None, f"L's spends {missing[:3]} were accepted "
                                                   f"but did not land", extra)
    if refused and not tr.info.get("l_any"):
        kind = "capacity_refused" if tr.rounds else "collateral_refusal"
        return Outcome(kind, None, f"L, under a ceiling {L_FACTOR}x W's, had {len(refused)} "
                                   f"spend(s) refused", extra)
    if tr.rounds and not all(r.get("overlapped") for r in tr.rounds if r["side"] == "W"):
        return Outcome("no_overlap", None, "the round's presentations did not overlap "
                                           "(KRK-M98)", extra)
    if not j["within"]:
        bad = [cid for cid, ex in j["excess"].items() if any(ex)]
        bad += [cid for cid in tr.W.ceilings if cid not in bad and any(
            ch for ch in chs if cid in ch.ceiling_ids and ch.effect_ref in j["uncountable"])]
        lim_txt = "; ".join(f"{cid}: {[x for x in j['excess'][cid] if x]}" for cid in bad)
        why = f"over {lim_txt or 'a ceiling'}"
        if j["uncountable"]:
            why += f"; effects the ceiling cannot count were committed: {j['uncountable'][:3]}"
        root_over = any(not c.startswith("share:") for c in bad)
        if run.role == "B" and run.H is not None:
            extra["attribution"] = _attribution(tr, chs)
        if root_over:
            return Outcome("over_ceiling", False, f"W's total above its ceiling: {why}", extra)
        return Outcome("over_share", False, f"B's total above its share: {why}", extra)
    if run.role == "B" and run.H is not None and not tr.W.share_cid:
        att = _attribution(tr, chs)
        extra["attribution"] = att
        if att["over"] or att["uncountable"]:
            return Outcome("over_share", False, f"B's total {att['totals']} above what the "
                                                f"holder confirmed to it {att['confirmed']}",
                           extra)
    info = []
    held_acc = _holder_account(tr, j)
    if held_acc:
        extra["holder_account"] = held_acc
        info.append(held_acc["reading"])
    if tr.refused_fit:
        info.append("refused_within_ceiling")
    if tr.info.get("never_frees"):
        info.append("never_frees")
    if tr.info.get("offline_window"):
        info.append("offline_window")
    return Outcome("held", True, "W's total within its ceiling" + (
        f" (information: {', '.join(info)})" if info else ""), {**extra, "information": info})


def _attribution(tr: _Trial, chs: List[ceiling.Charge]) -> Dict[str, Any]:
    run = tr.run
    assert run.H is not None
    cid = tr.W.cids["root"][0]
    conf = run.H.confirmations(run.b_name)
    att = ceiling.attribution(chs, conf, run.b_name, limits=tr.W.limits, ceiling_id=cid,
                              rule=tr.f.rule)
    return {k: (list(map(str, v)) if isinstance(v, list) else v) for k, v in att.items()} | {
        "over": att["over"], "uncountable": att["uncountable"]}


def _holder_account(tr: _Trial, j: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Role A: the holder's own account beside the recorder's (information, KRK-M96)."""
    run = tr.run
    if run.role != "A":
        return None
    acc_fn = getattr(run.a, "account", None)
    if not callable(acc_fn):
        return None
    try:
        acc = acc_fn(tr.W.root)
    except Exception as e:  # noqa: BLE001
        return {"reading": "account_unreadable", "error": str(e)[:100]}
    if not isinstance(acc, dict) or "used" not in acc:
        return None
    rec = j["totals"][tr.W.cids["root"][0]]
    used = [int(x) for x in acc["used"]]
    if any(u > r for u, r in zip(used, rec)):
        return {"reading": "over_counted", "holder": [str(x) for x in used],
                "recorder": [str(x) for x in rec],
                "amount": [str(max(0, u - r)) for u, r in zip(used, rec)]}
    if any(u < r for u, r in zip(used, rec)):
        return {"reading": "ledger_behind", "holder": [str(x) for x in used],
                "recorder": [str(x) for x in rec]}
    return None


# --------------------------------------------------------------------------- the controls


def _control_a(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    """Role A (§4.1): N stub spenders bound; a root whose ceiling is N times twice the largest
    per-spender total planned; a sequential spend at every spender and one concurrent round of
    two; every one authorised, executed by its stub exactly once with the quantity sent, and
    the kit's account equal to the planned sum. Requires no refusal, no account, no
    reservation and no stated mechanism (KRK-M19)."""
    q = 1000
    C = len(run.spenders) * 2 * 2 * q
    f = Fixture("control", "-", "A", C, [amount_limit(C)])
    tr = _Trial(run, f, 0)
    tr.sides = lambda: [tr.W]  # type: ignore[assignment]
    tr.open()
    run.rec_idx = len(run.recorder.state.records)
    durs = []
    for b in run.spenders:
        t = time.perf_counter()
        r = tr.ask(tr.W, b, pay(q))
        body = (r.get("answer") or {}).get("body") or {}
        if isinstance(body.get("began"), (int, float)) and isinstance(body.get("ended"),
                                                                      (int, float)):
            durs.append(float(body["ended"]) - float(body["began"]))
        else:
            durs.append(time.perf_counter() - t)
        if r["cls"] != "authorised":
            return False, f"the holder did not authorise a fresh spend at {b}: {r['answer']}", {}
        if run.topology != "forwarding":
            body = (r.get("stub") or {}).get("body") or {}
            if body.get("code") not in ("executed", "queued"):
                return False, (f"stub {b} could not act on the holder's issuance: "
                               f"{body.get('reason')}"), {}
    _round_a(tr, [("B1", pay(q)), ("B2", pay(q))])
    if tr.rounds and tr.rounds[0]["accepted"] != 2:
        return False, "the control's concurrent round was not authorised in full", {}
    effects = run.effects()
    w = _side_effects(effects, tr.W)
    if len(w) != len(run.spenders) + 2:
        return False, f"the recorder shows {len(w)} effects for {len(run.spenders) + 2} spends", {}
    chs = ceiling.charges(w, tr.W.issuance, bindings=run.bindings, ceilings=tr.W.ceilings)
    acc = ceiling.account(chs, ceilings=tr.W.ceilings)
    want = ceiling.scaled(q, MU) * (len(run.spenders) + 2)
    got = acc[tr.W.cids["root"][0]]["totals"][0]
    if got != want:
        return False, f"the kit's account {got} differs from the planned {want}", {}
    run.yardstick = statistics.median(durs) if durs else None
    return True, "", {"durations_s": durs, "events": tr.events}


def _control_b(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    """Role B (§4.1): the kit plays the issuer, the holder and stub B2. On a root with a large
    ceiling, B is given a share (allocation) or obtains reservations on request (reservation,
    online); a fresh spend at every endpoint B declares is accepted with one effect each and the
    kit's account agrees. Requires no refusal and no reading of the cumulative member."""
    q = 1000
    C = 100 * q * max(1, len(run.endpoints))
    f = Fixture("control", "-", "B", C, [amount_limit(C)], share=C // 2)
    tr = _Trial(run, f, 0)
    tr.sides = lambda: [tr.W]  # type: ignore[assignment]
    tr.open()
    tr.setup_b(C // 2, b2_rest=False)
    run.rec_idx = len(run.recorder.state.records)
    durs = []
    for ep in run.endpoints:
        t = time.perf_counter()
        r = tr.spend_b(tr.W, pay(q), endpoint=ep)
        durs.append(time.perf_counter() - t)
        if r["cls"] != "authorised":
            return False, f"B did not accept a fresh spend at endpoint {ep}: {r['answer']}", {}
    effects = run.effects()
    w = _side_effects(effects, tr.W)
    if len(w) != len(run.endpoints):
        return False, f"the recorder shows {len(w)} effects for {len(run.endpoints)} spends", {}
    chs = ceiling.charges(w, tr.W.issuance, bindings=run.bindings, ceilings=tr.W.ceilings)
    acc = ceiling.account(chs, ceilings=tr.W.ceilings)
    want = ceiling.scaled(q, MU) * len(run.endpoints)
    if acc[tr.W.cids["root"][0]]["totals"][0] != want:
        return False, "the kit's account differs from the planned sum", {}
    run.yardstick = statistics.median(durs) if durs else None
    return True, "", {"durations_s": durs}


# --------------------------------------------------------------------------- the probe


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    if raw.strip().startswith("{"):
        return json.loads(raw)
    with open(raw, encoding="utf-8") as fh:
        return json.load(fh)


def _trials(plan: Dict[str, Any], variant: str, form: str) -> int:
    t = plan.get("trials") or TRIALS
    if t == "dev":
        t = DEV_TRIALS
    elif t == "published":
        t = TRIALS
    if _racing(variant, form):
        return int(t.get("concurrent", 30))
    if variant in TIMED_VARIANTS or form == "fresh_ceiling":
        return int(t.get("timed", 5))
    return int(t.get(variant, t.get("*", 5)))


def _is_toy(a: Any) -> bool:
    mod = type(a).__module__ or ""
    return mod.startswith(("known_bad.", "tests.", "test_")) or mod == "__main__"


def _applicable(run: _Run, variant: str, form: str) -> Optional[str]:
    """Why `form` does not land for this target, or None."""
    role, mech = run.role, run.mechanism
    if form not in ROLE_FORMS[role].get(variant, ()):
        return "not a form of this role (design §3.1)"
    allowed = MECHS.get((role, form))
    if allowed and mech not in allowed:
        return f"needs a {'/'.join(allowed)} mechanism; the target states {mech}"
    feats = set(run.profile.get("features") or [])
    a = run.a
    if role == "A":
        if variant == "redelegated":
            if form in ("child_fresh_ceiling", "siblings") and "delegation" not in feats:
                return "the holder issues no delegations"
            if form == "holder_hop" and "holder-hops" not in feats:
                return "the holder takes no holder-signed hop"
            if form == "reissued_root" and not callable(getattr(a, "reissue", None)):
                return "the holder states no reissue"
            if form == "regrant" and not callable(getattr(a, "regrant", None)):
                return "the holder states no regrant"
        if form == "restart" and not callable(getattr(a, "restart", None)):
            return "not self-hosted (no restart)"
        if form == "split_holder":
            reps = getattr(a, "replicas", None)
            if not callable(reps) or len(reps() or []) < 2:
                return "the holder states no replicas"
        if form in ("confirmed", "claimed") and "reversals" not in feats:
            return "the holder states no reversal path"
        if form in ("retry_at_other_b", "cancel_then_commit") and \
                not callable(getattr(a, "cancel", None)):
            return "the agent has no way to cancel at this holder"
    else:
        if form == "restart" and not callable(getattr(a, "restart", None)):
            return "not self-hosted (no restart)"
        if variant == "sum_one_b" and form == "endpoints" and len(run.endpoints) < 2:
            return "B declares one endpoint"
        if form == "endpoints" and len(run.endpoints) < 2:
            return "B declares one endpoint"
        if form == "restores_share" and not callable(getattr(a, "reverse", None)):
            return "B states no reversal path"
        if form == "holder_hop" and not run.profile.get("holder_hops"):
            return "B accepts no holder-signed hop"
    if variant == "window":
        kinds = run.profile.get("windows") or []
        need = "rolling" if form == "rolling" else "fixed"
        if need not in kinds:
            return f"the target's format states no {need} window (a format gap)"
        if float(run.profile.get("min_window_s") or WINDOW_MIN_S) > WINDOW_MAX_S:
            return "the shortest window is longer than an hour: not driven in version 1"
    if variant == "units":
        lk = run.profile.get("limit_kinds") or ["amount"]
        if form in ("two_limits", "count_unit") and "count" not in lk:
            return "the target's format states no count limit (a format gap)"
    if variant == "reversal" and form == "confirmed" and \
            not set(run.profile.get("reversals") or ["gross"]):
        return "no reversal rule"
    return None


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from ..issuer import StubIssuer
    from ..mockserver import MockServer
    from ..requester import new_issuer

    from ..timing import make_clock

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    try:
        role = str(a.role())
        if role not in ROLES:
            return Result.inconclusive(a.name, ID, f"role must be A or B, not {role!r}", **common)
        mechanism = str(a.mechanism())
        profile = dict(opt(a, "ceiling_profile", {}) or {})
        terms = dict(opt(a, "terms", {}) or {})
        bindings = dict(opt(a, "constraint_bindings", {}) or {})
        grade = str(a.evidence_grade())
        topology = str(getattr(a, "topology", lambda: "bearer")())
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    if mechanism not in ceiling.MECHANISMS:
        return Result.inconclusive(a.name, ID, f"unknown mechanism {mechanism!r}", **common)
    if grade != "recorder":
        return Result.inconclusive(a.name, ID, f"P22's verdicts need the recorder grade; the "
                                   f"target offers {grade!r} (§4.6)", **common)
    if role == "B" and not profile:
        return Result.not_applicable(a.name, ID, "B reads no cumulative member: its format "
                                     "cannot state a cumulative ceiling",
                                     **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not _is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock", **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    forbidden = {x if isinstance(x, str) else x[0] for x in NA_FORBIDDEN[role]}
    if any(v in forbidden or v not in VARIANTS for v in na):
        return Result.inconclusive(a.name, ID, f"the adapter declares {sorted(na)} not "
                                   f"applicable; {sorted(forbidden)} may not be", **common)
    plan = dict(plan if plan is not None else ({} if _is_toy(a) else (_plan_from_env() or {})))
    development = bool(plan) and plan.get("trials") not in (None, "published")
    only = list(plan.get("variants") or VARIANTS)
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    clock = make_clock(kind)
    if kind == "virtual" and callable(getattr(a, "set_clock", None)):
        a.set_clock(clock)
    recorder = MockServer(clock=clock.now)
    A = StubIssuer(new_issuer(), clock=clock, ttl_s=3600)
    A.serve_local()
    prefix = f"/p22/{run_tag}{secrets.token_hex(4)}"
    progress = _Progress(ev)
    run = _Run(a, ev, role=role, clock=clock, recorder=recorder, prefix=prefix, rng=rng,
               plan=plan, terms=terms, profile=profile, mechanism=mechanism,
               topology=topology, bindings=bindings, A=A)
    run.progress = progress
    run.exposes_times = bool(getattr(a, "exposes_times", lambda: False)())
    run.max_in_flight = int(opt(a, "max_in_flight", 1) or 1)
    stubs: List[Any] = []
    try:
        if role == "A":
            hk = a.holder_keys()
            for b in SPENDERS:
                st = ledger.StubSpender(f"did:web:{b.lower()}-{secrets.token_hex(3)}.example",
                                        recorder_url=recorder.url + prefix + "/" + b,
                                        clock=clock, profile="forwarding" if topology ==
                                        "forwarding" else "kirkaldy")
                st.serve_local() if kind == "virtual" else st.serve()
                st.bind_holder(hk, None, deliver=(lambda route, s, a=a: a.deliver(route, s))
                               if callable(getattr(a, "deliver", None)) else None)
                a.bind_spender(st.name, st.url, st.anchor())
                run.spenders[b] = st
                stubs.append(st)
        else:
            run.endpoints = list(opt(a, "endpoints", ["default"]) or ["default"])
            ident = dict(opt(a, "spender_identity", {}) or {})
            run.b_name = str(ident.get("name") or B_NAME_DEFAULT)
            H = ledger.StubHolder(A, mechanism=mechanism if mechanism in (
                "allocation", "reservation", "online") else "reservation",
                expiry_s=float(plan.get("expiry_s") or 20.0), tolerance_s=1.0,
                capture_lag_s=2.0, clock=clock)
            H.serve_local() if kind == "virtual" else H.serve()
            run.H = H
            stubs.append(H)
            B2 = ledger.StubSpender(B2_NAME, recorder_url=recorder.url + prefix + "/B2",
                                    clock=clock)
            B2.bind_holder(H.anchor(), H.url)
            H.bind_spender(B2.name, B2.anchor())
            run.B2 = B2
            stubs.append(B2)
            H.bind_spender(run.b_name, dict(ident.get("keys") or {}))
            a.bind_requester(A.trust_anchor_x1(), A.source_url)
            a.bind_holder(H.anchor(), H.url)
            a.bind_recorder(recorder.url + prefix + "/B")
        statements = {"role": role, "mechanism": mechanism, "topology": topology,
                      "ceiling_profile": profile, "terms": terms,
                      "constraint_bindings": bindings, "evidence_grade": grade,
                      "max_in_flight": run.max_in_flight, "exposes_times": run.exposes_times,
                      "documents_hard_limit": opt(a, "documents_hard_limit", None)}
        ev.write("run.json", {"seed": seed, "variant_order": ["control"] + order,
                              "statements": json.loads(json.dumps(statements, default=str)),
                              "plan": plan, "clock": kind})
        progress.add("run", seed=seed, statements=statements, plan=plan)
        return _probe(run, a, ev, common, na, plan, development, only, order, seed)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        for s in stubs:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        recorder.close()
        A.close()
        clock.close()


def _make_fixture(run: _Run, variant: str, form: str, k: int = 0) -> Fixture:
    """The fixture of trial `k` of `form`. ``reversal/confirmed`` takes the target's declared
    reversal rules in turn, trial by trial (gross first), so every declared rule is judged in
    every run: a seeded draw of the rule left a holder that nets under ``gross`` unexercised
    whenever every trial drew ``net-recorded`` (KRK-M210)."""
    rng = run.rng
    rule = "gross"
    if variant == "units":
        C, lims = units_fixture(form, rng, run.role)
        f = Fixture(variant, form, run.role, C, lims)
        if run.role == "B":
            f.share = _draw(rng, 0.45, 0.55, C)
        return f
    window = None
    if variant == "window":
        window = window_of(form, run)
    if (variant, form) == ("reversal", "claimed"):
        rules = run.profile.get("reversals") or ["gross"]
        rule = "net-recorded" if "net-recorded" in rules else "gross"
    if (variant, form) == ("reversal", "confirmed"):
        rules = sorted(run.profile.get("reversals") or ["gross"])
        rule = rules[k % len(rules)]
    f = fixture(variant, form, rng, role=run.role, mechanism=run.mechanism, window=window,
                rule=rule)
    if window is not None:
        f.window = window
    if run.role == "B" and f.share is None:
        f.share = _draw(rng, 0.45, 0.55, f.C)
    return f


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], na: Dict[str, str],
           plan: Dict[str, Any], development: bool, only: List[str], order: List[str],
           seed: int) -> Result:
    held, why, obs = _control_a(run) if run.role == "A" else _control_b(run)
    ev.write("control.json", {"held": held, "why": why, **{k: v for k, v in obs.items()
                                                            if k != "events"}})
    run.log("control", held=held, why=why)
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    control = ("fresh spends at every stub spender, sequential and one concurrent round, each "
               "authorised and executed once, the kit's account equal to the plan"
               if run.role == "A" else
               "fresh spends at every endpoint B declares accepted with one effect each, the "
               "kit's account equal to the plan")
    readings: Dict[str, Dict[str, Any]] = {}
    gaps: List[Dict[str, str]] = []
    docs: Dict[str, List[Dict[str, Any]]] = {}
    race: Dict[str, Any] = {}
    info_seen: Dict[str, List[str]] = {}
    for variant in order:
        if variant in na or variant not in only:
            continue
        for form in FORMS[variant]:
            if variant in (plan.get("forms") or {}) and form not in plan["forms"][variant]:
                continue
            if form not in ROLE_FORMS[run.role].get(variant, ()):
                continue
            why_na = _applicable(run, variant, form)
            if why_na:
                lab = "format_gap" if "format gap" in why_na else "not_applicable"
                readings.setdefault(variant, {})[form] = {"reading": lab, "ok": None,
                                                          "detail": why_na}
                if lab == "format_gap":
                    gaps.append({"variant": variant, "form": form, "why": why_na})
                continue
            outs: List[Outcome] = []
            n = _trials(plan, variant, form)
            attempts = n * 2 if _racing(variant, form) else n
            k = 0
            clean = 0
            while k < attempts and clean < n:
                f = _make_fixture(run, variant, form, k)
                try:
                    tv = truth(f)
                except ValueError as e:
                    raise RuntimeError(f"fixture check failed: {e}")
                tr = _Trial(run, f, k)
                run.rec_idx = len(run.recorder.state.records)
                try:
                    run_form(tr, variant, form)
                except Exception as e:  # noqa: BLE001
                    tr.not_landed = f"the trial raised {type(e).__name__}: {e}"
                run.clock.sleep(0.05)
                effects = run.effects()
                o = judge_trial(tr, effects)
                if not o.extra.get("truth"):
                    o.extra["truth"] = tv
                outs.append(o)
                if o.ok is not None:
                    clean += 1
                doc = {"form": form, "k": k, "outcome": o.to_doc(), "events": tr.events}
                docs.setdefault(variant, []).append(doc)
                run.log("trial", variant=variant, form=form, k=k, outcome=o.outcome,
                        ok=o.ok, detail=o.detail[:200])
                for i in (o.extra.get("information") or []):
                    info_seen.setdefault(f"{variant}/{form}", [])
                    if i not in info_seen[f"{variant}/{form}"]:
                        info_seen[f"{variant}/{form}"].append(i)
                k += 1
                if o.ok is False:
                    break
            fails = [o for o in outs if o.ok is False]
            counted = [o for o in outs if o.ok is not None]
            if fails:
                r = {"reading": fails[0].outcome, "ok": False, "detail": fails[0].detail}
            elif counted and len(counted) >= n:
                r = {"reading": "held", "ok": True, "detail": counted[0].detail}
            elif counted and not _racing(variant, form) and variant not in TIMED_VARIANTS:
                r = {"reading": "held", "ok": True, "detail": counted[0].detail}
            else:
                infos = [o.outcome for o in outs] or ["inconclusive"]
                r = {"reading": "inconclusive" if counted else max(sorted(set(infos)),
                                                                   key=infos.count),
                     "ok": None, "detail": f"{len(counted)} clean of {n} needed; "
                     f"{outs[0].detail if outs else ''}"}
            if _racing(variant, form):
                N = len(counted)
                race[f"{variant}/{form}"] = {"overlapping_rounds": N, "attempts": len(outs),
                                             "bound_95": (f"at most {3 / N:.3f} of rounds "
                                                          f"would overspend" if N and not fails
                                                          else None)}
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
        elif any(d["reading"] == "inconclusive" for d in fr.values()):
            c = Check(variant, "inconclusive", None, parts)
        elif passes:
            c = Check(variant, "held", True, parts)
        else:
            labs = {d["reading"] for d in fr.values()}
            c = Check(variant, "format_gap" if labs == {"format_gap"} else "not_applicable",
                      None, parts)
        checks.append(c)
    must = []
    for x in NA_FORBIDDEN[run.role]:
        if isinstance(x, str):
            continue
        v, fm = x
        if v not in only or v in na:
            continue
        d = readings.get(v, {}).get(fm)
        if d is None:
            if (plan.get("forms") or {}).get(v) is not None:
                continue
            must.append(f"{v}/{fm}")
            continue
        if d["ok"] is None and d["reading"] != "format_gap":
            must.append(f"{v}/{fm}")
    fails = [c for c in checks if c.ok is False]
    hard = opt(a, "documents_hard_limit", None)
    vuln = bool(hard) and any((c.name, None) in VULNERABLE or any(
        (c.name, fm) in VULNERABLE and readings.get(c.name, {}).get(fm, {}).get("ok") is False
        for fm in FORMS[c.name]) for c in fails)
    extra: Dict[str, Any] = {
        "seed": seed, "role": run.role, "mechanism": run.mechanism, "topology": run.topology,
        "ceiling_profile": run.profile, "terms": run.terms, "forms": readings,
        "format_gaps": gaps, "race": race, "information": info_seen,
        "disclosure": "vulnerability" if vuln else "conformance",
        "evidence_grade": "recorder", "clock": getattr(a, "clock", "real"),
        "overshoot": run.profile.get("overshoot"),
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if plan:
        extra["plan"] = plan
    dev = "Development plan (smaller counts; not a published run). " if development else ""
    gap_txt = (f" Format gaps (findings, never a pass): "
               f"{', '.join(g['variant'] + '/' + g['form'] for g in gaps)}." if gaps else "")
    who = "holder (role A)" if run.role == "A" else "spender (role B)"
    if not fails and must:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant failed, but forms that must give "
                                f"a verdict did not: {must}.{gap_txt}", checks=checks,
                                control_held=True, control_detail=control, extra=extra,
                                **common)
    elif not [c for c in checks if c.ok is not None]:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant landed with a verdict.{gap_txt}",
                                checks=checks, control_held=True, control_detail=control,
                                extra=extra, **common)
    else:
        r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                    pass_summary=f"{dev}the {who} kept every root within its cumulative "
                                 f"ceiling, counted at the recorder.{gap_txt}",
                    fail_summary=f"{dev}effects under a root exceeded its cumulative ceiling "
                                 f"({who})",
                    extra=extra, **common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r
