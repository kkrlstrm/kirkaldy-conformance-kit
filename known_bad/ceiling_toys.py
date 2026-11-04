"""Known-bad and known-good toys for P22 (KRK-22, cumulative ceiling across counterparties).

Two families, one per role (`X9-CUMULATIVE-CEILING-DESIGN.md` §4.8), each with a real recorder
path: in role A the effects are the kit's stub spenders' (`ledger.StubSpender`), in role B the
toy spender posts each effect to the kit's recorder itself. They run on X4's virtual clock.

**`ToyHolder`** (role A, `role_ceiling.Holder`, in process). ``good``: reservations, checked and
recorded atomically, idempotent by request id (the same id with other bytes is refused), each
counted until its spender's signed release or its expiry plus its tolerance plus the capture lag,
reversals freeing headroom only under ``net-recorded`` and only on the spender's statement, every
ancestor's ceiling charged, exact units, windows by its own clock against absolute anchors, and a
durable store shared by its replicas. ``good-allocation`` (an even static split into shares),
``good-online`` (charged at once), ``good-forwarding`` (the holder charges, then forwards to the
spender), ``good-strict`` (an even split, refusing anything beyond each spender's part),
``slow-good`` (answers slowly; must still pass), ``no-control`` (signs its issuances with a key it
never states, so no stub spender can act and the control cannot hold).

**`ToySpender`** (role B, `role_ceiling.SpenderB`, in process). ``good``: reservations, asked of
the kit's holder before every commit and checked again at commit, never releasing what it
committed, committing nothing unconfirmed while the holder is unreachable, idempotent by request
ref. ``good-allocation``: a durable counter per share shared by its endpoints, refusing shares
addressed to others. ``good-strict`` (allocation, stops at 95% of its share, a choice it
states), ``slow-good``, ``no-control`` (the executor posts elsewhere).

Each flaw is a behaviour (KRK-M47): it reads or keeps the account wrongly; none is built by
removing members from what it was sent. Races are deterministic: ``check_then_set`` yields
between its check and its record, so an overlapping round always shows the flaw; the correct toys
hold one lock across both. ``charges_retries`` over-counts and must read ``over_counted`` (role A)
or ``refused_within_ceiling`` (role B), never a fail.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

from conformance import ceiling, ledger, standing
from conformance.receipts import Keypair

SERVICE_S = 0.004
"""Every toy request takes this long (real time), inside its lock for a correct toy: an
uncontended request's duration is the overlap yardstick (P18's rule)."""
SLOW_S = 0.02
EXPIRY_S = 20.0
TOLERANCE_S = 1.0
CAPTURE_LAG_S = 2.0
PROPAGATION_S = 2.0
"""What the ``lazy_ceiling`` toys state as their propagation time, and how long they ignore a new
ceiling for."""
B_NAME = "did:web:b.example"

FLAWS_A = ("per_b_counter", "off_by_one", "lazy_ceiling", "per_session_counter",
           "memory_counter", "check_then_set", "count_after_effect", "fresh_on_retry",
           "frees_on_agent_claim", "dedup_client_key", "nets_under_gross",
           "trusts_agent_reversal", "frees_on_cancel", "accepts_negative", "frees_at_expiry",
           "frees_on_silence", "ignores_currency", "ignores_minor_units", "first_limit_only",
           "unknown_unit_free", "float_sum", "counter_per_grant", "counter_per_issuer",
           "counter_per_grant_id", "resets_on_regrant", "fixed_for_rolling",
           "window_from_spender_time", "frees_on_missing_report", "drops_late_capture",
           "per_replica_account")
INFO_A = ("charges_retries",)
FAILS_A = {"per_b_counter": ("sum_across_bs", "sequential"),
           "off_by_one": ("sum_across_bs", "exact"),
           "lazy_ceiling": ("sum_across_bs", "fresh_ceiling"),
           "per_session_counter": ("sum_one_b", "sessions"),
           "memory_counter": ("sum_one_b", "restart"),
           "check_then_set": ("concurrent", "two_bs"),
           "count_after_effect": ("concurrent", "slow_effect"),
           "fresh_on_retry": ("retry", "second_authorisation"),
           "frees_on_agent_claim": ("retry", "retry_at_other_b"),
           "dedup_client_key": ("retry", "dedup_mismatch"),
           "nets_under_gross": ("reversal", "confirmed"),
           "trusts_agent_reversal": ("reversal", "claimed"),
           "frees_on_cancel": ("reversal", "cancel_then_commit"),
           "accepts_negative": ("reversal", "negative_spend"),
           "frees_at_expiry": ("reservation_expiry", "freed_early"),
           "frees_on_silence": ("reservation_expiry", "freed_on_silence"),
           "ignores_currency": ("units", "other_currency"),
           "ignores_minor_units": ("units", "minor_units"),
           "first_limit_only": ("units", "two_limits"),
           "unknown_unit_free": ("units", "count_unit"),
           "float_sum": ("units", "large_integer"),
           "counter_per_grant": ("redelegated", "child_fresh_ceiling"),
           "counter_per_issuer": ("redelegated", "holder_hop"),
           "counter_per_grant_id": ("redelegated", "reissued_root"),
           "resets_on_regrant": ("redelegated", "regrant"),
           "fixed_for_rolling": ("window", "rolling"),
           "window_from_spender_time": ("window", "spender_clock"),
           "frees_on_missing_report": ("partition", "report_lost"),
           "drops_late_capture": ("partition", "late_capture"),
           "per_replica_account": ("partition", "split_holder")}
ALSO_FAILS_A = {
    "per_b_counter": {("sum_across_bs", "*"), ("concurrent", "*"), ("units", "*"),
                      ("redelegated", "*"), ("reversal", "*"), ("retry", "*"),
                      ("reservation_expiry", "*"), ("partition", "*"), ("window", "*")},
    "off_by_one": {("units", "fraction"), ("units", "large_integer"), ("units", "two_limits")},
    "check_then_set": {("concurrent", "n_way")},
    "count_after_effect": {("concurrent", "*"), ("reservation_expiry", "freed_early"),
                           ("reservation_expiry", "freed_on_silence"),
                           ("partition", "report_lost"), ("partition", "late_capture"),
                           ("reversal", "cancel_then_commit")},
    "fresh_on_retry": {("retry", "dedup_mismatch")},
    "dedup_client_key": {("retry", "second_authorisation")},
    "frees_on_agent_claim": {("reversal", "claimed"), ("reversal", "cancel_then_commit")},
    "frees_at_expiry": {("partition", "late_capture")},
    "frees_on_silence": {("reservation_expiry", "freed_early"), ("partition", "report_lost"),
                         ("partition", "late_capture")},
    "frees_on_missing_report": {("reservation_expiry", "freed_early"),
                                ("reservation_expiry", "freed_on_silence"),
                                ("partition", "late_capture")},
    "first_limit_only": {("units", "count_unit")},
    "float_sum": {("units", "fraction")},
    "counter_per_grant": {("redelegated", "siblings")},
    "counter_per_grant_id": {("redelegated", "regrant")},
}
"""Forms other than its own that a flaw is stated to fail (§3.3: a weak check fails more than
one); ``*`` is every form of the variant. The tests check that a flaw fails nothing else."""

FLAWS_B = ("per_request_only", "own_total_against_root", "off_by_one", "lazy_ceiling",
           "per_session_counter", "per_endpoint_counter", "memory_counter",
           "commits_unconfirmed", "ignores_spender", "releases_after_commit",
           "restores_share_on_reversal", "accepts_negative", "commits_after_expiry",
           "ignores_currency", "ignores_minor_units", "first_limit_only", "unknown_unit_free",
           "float_sum", "counter_per_grant", "counter_per_issuer", "counter_per_grant_id",
           "fixed_for_rolling", "window_from_issuer_time", "fails_open_unreachable",
           "counter_from_holder")
INFO_B = ("charges_retries",)
FAILS_B = {"per_request_only": ("sum_across_bs", "sequential"),
           "own_total_against_root": ("sum_across_bs", "sequential"),
           "off_by_one": ("sum_across_bs", "exact"),
           "lazy_ceiling": ("sum_across_bs", "fresh_ceiling"),
           "per_session_counter": ("sum_one_b", "sessions"),
           "per_endpoint_counter": ("sum_one_b", "endpoints"),
           "memory_counter": ("sum_one_b", "restart"),
           "commits_unconfirmed": ("concurrent", "with_other_spenders"),
           "ignores_spender": ("concurrent", "share_elsewhere"),
           "releases_after_commit": ("retry", "release_after_commit"),
           "restores_share_on_reversal": ("reversal", "restores_share"),
           "accepts_negative": ("reversal", "negative_spend"),
           "commits_after_expiry": ("reservation_expiry", "commit_after_expiry"),
           "ignores_currency": ("units", "other_currency"),
           "ignores_minor_units": ("units", "minor_units"),
           "first_limit_only": ("units", "two_limits"),
           "unknown_unit_free": ("units", "count_unit"),
           "float_sum": ("units", "large_integer"),
           "counter_per_grant": ("redelegated", "child_fresh_ceiling"),
           "counter_per_issuer": ("redelegated", "holder_hop"),
           "counter_per_grant_id": ("redelegated", "reissued_root"),
           "fixed_for_rolling": ("window", "rolling"),
           "window_from_issuer_time": ("window", "issuer_ahead"),
           "fails_open_unreachable": ("partition", "holder_unreachable"),
           "counter_from_holder": ("partition", "offline_within_share")}
ALSO_FAILS_B = {
    "per_request_only": {("*", "*")},
    "own_total_against_root": {("*", "*")},
    "commits_unconfirmed": {("sum_across_bs", "*"), ("sum_one_b", "*"), ("units", "*"),
                            ("concurrent", "*"), ("partition", "holder_unreachable"),
                            ("reversal", "negative_spend")},
    "off_by_one": {("units", "fraction"), ("units", "large_integer"), ("units", "two_limits")},
    "per_endpoint_counter": {("concurrent", "endpoints")},
    "counter_from_holder": {("concurrent", "endpoints")},
    "first_limit_only": {("units", "count_unit")},
    "float_sum": {("units", "fraction")},
    "counter_per_grant": {("redelegated", "siblings")},
    "lazy_ceiling": {("window", "issuer_ahead")},
}
MECH_B = {f: "allocation" for f in FLAWS_B}
MECH_B.update({f: "reservation" for f in ("per_request_only", "own_total_against_root",
                                           "commits_unconfirmed", "releases_after_commit",
                                           "commits_after_expiry", "fails_open_unreachable")})
MECH_B["charges_retries"] = "allocation"
GOOD_A = ("good", "good-allocation", "good-online", "good-forwarding", "good-strict",
          "slow-good")
GOOD_B = ("good", "good-allocation", "good-strict", "slow-good")
FAILS = {**{f"A:{k}": v for k, v in FAILS_A.items()}, **{f"B:{k}": v for k, v in
                                                         FAILS_B.items()}}


def _answer(code: str, reason: str = "", **more: Any) -> Dict[str, Any]:
    return ledger._answer(code, reason, **more)


@contextmanager
def _nothing() -> Iterator[None]:
    yield


def _c(clock: Any) -> Any:
    if clock is None:
        from conformance.timing import RealClock
        return RealClock()
    return clock


# --------------------------------------------------------------------------- reading amounts


def toy_quantity(values: Dict[str, Any], lim: Dict[str, Any], flaw: Optional[str]
                 ) -> Optional[int]:
    """What a toy counts for `values` against `lim`, with its flaw's reading; None refuses."""
    v = dict(values or {})
    a = v.get("amount")
    if lim["kind"] == "amount" and isinstance(a, dict):
        a = dict(a)
        if flaw == "ignores_currency":
            a["currency"] = lim["currency"]
        if flaw == "ignores_minor_units":
            a["minor_units"] = lim["minor_units"]
        if flaw == "float_sum" and isinstance(a.get("value"), int) and \
                a.get("currency") == lim["currency"]:
            x = float(a["value"]) * 10.0 ** (lim["minor_units"] - int(a["minor_units"]))
            return ceiling.scaled(int(round(x)), lim["minor_units"])
        v["amount"] = a
    if lim["kind"] == "count":
        c = v.get("count")
        if flaw == "unknown_unit_free" and isinstance(c, dict) and c.get("unit") != lim["unit"]:
            return 0
    q = ceiling.quantity(v, lim)
    if q is None:
        return None
    if q < 0 and flaw != "accepts_negative":
        return None
    return q


def stated_quantity(values: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The request's own quantity, as it states it, for an issuance: the stub spender executes
    exactly what the issuance allows (KRK-M99), so the issuance says what the holder allowed,
    in the request's own units, whatever the holder counted."""
    out: List[Dict[str, Any]] = []
    a = (values or {}).get("amount")
    if isinstance(a, dict) and set(a) == {"value", "currency", "minor_units"}:
        out.append({"kind": "amount", **a})
    c = (values or {}).get("count")
    if isinstance(c, dict) and set(c) == {"value", "unit"}:
        out.append({"kind": "count", **c})
    return out


# --------------------------------------------------------------------------- role A: the holder


class ToyHolder:
    """A holder (role A, in process). Module docstring."""

    name = "toy-holder"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *,
                 mechanism: Optional[str] = None, clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "per_b_counter"
        if flaw is not None and flaw not in FLAWS_A + INFO_A:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.flaw = flaw
        self.config = config if flaw is None else (f"bad:{flaw}" if flaw in FLAWS_A
                                                    else f"info:{flaw}")
        base = {"good-allocation": "allocation", "good-online": "online",
                "good-forwarding": "forwarding"}.get(config, "reservation")
        self._mech = mechanism or base
        self.strict = config in ("good-strict",)
        self.slow = config == "slow-good"
        self.no_control = config == "no-control"
        self.clock = clock
        self._clock: Any = None
        self.key = Keypair.generate(f"toy-holder-{secrets.token_hex(3)}")
        self.hidden = Keypair.generate(f"toy-hidden-{secrets.token_hex(3)}")
        self._lock = threading.RLock()
        self.spenders: Dict[str, Dict[str, Any]] = {}
        self.auths: Dict[str, Dict[str, Any]] = {}
        self.ceilings: Dict[str, Dict[str, Any]] = {}
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.by_request: Dict[str, Dict[str, Any]] = {}
        self.shares: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.partitioned = False
        self._rr: Dict[str, int] = {}
        self.log: List[Dict[str, Any]] = []

    # statements ------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-holder {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P22": "toy: 'the total under a root never exceeds its ceiling'"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def role(self) -> str:
        return "A"

    def mechanism(self) -> str:
        return self._mech

    def topology(self) -> str:
        return "forwarding" if self._mech == "forwarding" else "bearer"

    def ceiling_profile(self) -> Dict[str, Any]:
        feats = ["delegation", "holder-hops", "reversals", "sessions"]
        return {"limit_kinds": ["amount", "count"], "currencies": ["EUR", "USD"],
                "windows": ["fixed", "rolling"] if self._mech == "reservation" else [],
                "reversals": ["gross", "net-recorded"], "features": feats,
                "min_window_s": 20, "holder_hops": True}

    def constraint_bindings(self) -> Dict[str, str]:
        return {}

    def terms(self) -> Dict[str, Any]:
        prop = PROPAGATION_S if self.flaw == "lazy_ceiling" else 0.0
        return {"expiry_s": {"value": EXPIRY_S, "source": "documented"},
                "tolerance_s": {"value": TOLERANCE_S, "source": "documented"},
                "capture_lag_s": {"value": CAPTURE_LAG_S, "source": "documented"},
                "commit_lag_s": {"value": 0.0, "source": "documented"},
                "propagation_s": {"value": prop, "source": "documented"}}

    def evidence_grade(self) -> str:
        return "recorder"

    def max_in_flight(self) -> int:
        return 16

    def exposes_times(self) -> bool:
        return True

    def documents_hard_limit(self) -> Dict[str, Any]:
        return {"quote": "toy: 'a hard cumulative limit'", "url": "known_bad/ceiling_toys.py"}

    def replicas(self) -> List[str]:
        return ["r1", "r2"]

    def set_clock(self, clock: Any) -> None:
        self._clock = clock

    def _now(self) -> float:
        return _c(self._clock).now() if self._clock else time.monotonic()

    def _wall(self) -> float:
        return _c(self._clock).wall()

    def holder_keys(self) -> Dict[str, bytes]:
        return {self.key.kid: self.key.public_bytes()}

    def bind_spender(self, name: str, url: str, key: Dict[str, bytes]) -> str:
        self.spenders[name] = {"url": url, "keys": dict(key)}
        return f"pinned {name}"

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"authorised": "authorised", "executed": "authorised", "queued": "authorised",
                "refused": "refused", "conflict": "refused",
                "rate-limited": "rate-limited"}.get(code, "error")

    # roots ---------------------------------------------------------------------------------

    def _new_ceiling(self, limits: List[Dict[str, Any]], window: Any, rule: str) -> str:
        cid = ledger.new_ceiling_id()
        w = dict(window) if window else None
        self.ceilings[cid] = {"limits": [dict(x) for x in limits], "window": w, "rule": rule,
                              "opened": self._now(), "opened_wall": self._wall()}
        return cid

    def open_root(self, principal: str, limits: List[Dict[str, Any]], *, window: Any = None,
                  rule: Optional[str] = None) -> str:
        with self._lock:
            cid = self._new_ceiling(limits, window, rule or "gross")
            rid = f"root-{secrets.token_hex(6)}"
            self.auths[rid] = {"cids": [cid], "principal": principal, "signer": "org",
                               "root": rid}
            return rid

    def read_back(self, root: str) -> Dict[str, Any]:
        return {"in_force": root in self.auths}

    def delegate(self, root: str, child_agent: str, limits: Optional[List[Dict[str, Any]]] = None,
                 *, holder_hop: bool = False) -> str:
        with self._lock:
            p = self.auths[root]
            cids = list(p["cids"])
            if self.flaw == "counter_per_issuer" and holder_hop:
                c0 = self.ceilings[cids[0]]
                cids = [self._new_ceiling(c0["limits"], c0["window"], c0["rule"])]
            if limits is not None:
                own = self._new_ceiling(limits, None, self.ceilings[cids[0]]["rule"])
                cids = [own] if self.flaw == "counter_per_grant" else cids + [own]
            cid = f"child-{secrets.token_hex(6)}"
            self.auths[cid] = {"cids": cids, "principal": p["principal"],
                               "signer": "holder" if holder_hop else "org", "root": p["root"]}
            return cid

    def reissue(self, root: str) -> str:
        with self._lock:
            p = self.auths[root]
            cids = list(p["cids"])
            if self.flaw == "counter_per_grant_id":
                c0 = self.ceilings[cids[0]]
                cids = [self._new_ceiling(c0["limits"], c0["window"], c0["rule"])]
            nid = f"root-{secrets.token_hex(6)}"
            self.auths[nid] = {**p, "cids": cids, "root": nid}
            return nid

    def regrant(self, root: str, agent: str) -> str:
        with self._lock:
            p = self.auths[root]
            if self.flaw == "resets_on_regrant":
                cid = p["cids"][0]
                lims = self.ceilings[cid]["limits"]
                used = self._used(cid, None)
                if all(u >= ceiling.limit_value(l) for u, l in zip(used, lims)):
                    for e in self.entries.values():
                        if cid in e["cids"]:
                            e["state"] = "released"
            return self.reissue(root) if self.flaw != "resets_on_regrant" else \
                self._same(root)

    def _same(self, root: str) -> str:
        nid = f"root-{secrets.token_hex(6)}"
        self.auths[nid] = {**self.auths[root], "root": nid}
        return nid

    # the account ---------------------------------------------------------------------------

    def _q(self, cid: str, values: Dict[str, Any]) -> Optional[List[int]]:
        out = []
        lims = self.ceilings[cid]["limits"]
        for i, lim in enumerate(lims):
            if self.flaw == "first_limit_only" and i > 0:
                out.append(0)
                continue
            q = toy_quantity(values, lim, self.flaw)
            if q is None:
                return None
            out.append(q)
        return out

    def _sweep(self) -> None:
        now = self._wall()
        for e in self.entries.values():
            if e["state"] != "held" or e.get("not_after") is None:
                continue
            na = e["not_after"]
            if self.flaw == "frees_at_expiry":
                free_at = na
            elif self.flaw == "frees_on_silence":
                free_at = e["t_h"] + EXPIRY_S * 0.5
            elif self.flaw == "frees_on_missing_report":
                free_at = e["t_h"] + CAPTURE_LAG_S
            else:
                free_at = na + TOLERANCE_S + CAPTURE_LAG_S
            if now > free_at:
                e["state"] = "expired"

    def _window_of(self, cid: str, t: float) -> Optional[Tuple[float, float]]:
        c = self.ceilings[cid]
        w = c.get("window")
        if not w:
            return None
        P = float(w["period_s"])
        if w["kind"] == "rolling" and self.flaw != "fixed_for_rolling":
            return t - P, t + 1e-9
        a = (w["anchor_ms"] / 1000.0) if w["kind"] == "fixed" else c["opened_wall"]
        k = (t - a) // P
        return a + k * P, a + (k + 1) * P

    def _key_ok(self, e: Dict[str, Any], key: Dict[str, Any]) -> bool:
        if self.flaw == "per_b_counter" and e["spender"] != key.get("spender"):
            return False
        if self.flaw == "per_session_counter" and e.get("session") != key.get("session"):
            return False
        if self.flaw == "per_replica_account" and key.get("replica"):
            # each replica keeps its own account while split: r1 holds the store as it was,
            # r2 only what it charged itself since the split
            at_r2 = bool(e.get("in_partition")) and e.get("replica") == "r2"
            return at_r2 if key["replica"] == "r2" else not at_r2
        return True

    def _used(self, cid: str, at: Optional[float], key: Optional[Dict[str, Any]] = None
              ) -> List[int]:
        lims = self.ceilings[cid]["limits"]
        rule = self.ceilings[cid]["rule"]
        tot = [0] * len(lims)
        win = self._window_of(cid, at) if at is not None else None
        for e in self.entries.values():
            if cid not in e["cids"] or e["state"] in ("released", "expired"):
                continue
            if self.flaw == "count_after_effect" and e["state"] == "held":
                continue
            if key is not None and not self._key_ok(e, key):
                continue
            if win is not None and not (win[0] <= e["t_h"] < win[1]):
                continue
            for i in range(len(lims)):
                tot[i] += e["q"][cid][i]
                if rule == "net-recorded" or self.flaw == "nets_under_gross":
                    tot[i] -= e["reversed"].get(cid, [0] * len(lims))[i]
        return tot

    def _fits(self, cids: List[str], q: Dict[str, List[int]], key: Dict[str, Any]) -> bool:
        now = self._wall()
        for cid in cids:
            c = self.ceilings[cid]
            if self.flaw == "lazy_ceiling" and self._now() - c["opened"] < PROPAGATION_S:
                continue
            lims = c["limits"]
            u = self._used(cid, now if c.get("window") else None, key)
            for i, lim in enumerate(lims):
                cap = ceiling.limit_value(lim)
                if self.flaw == "off_by_one":
                    cap += ceiling.scaled(1, lim["minor_units"]) if lim["kind"] == "amount" \
                        else 1
                if self.strict:
                    cap = cap // max(1, len(self.spenders))
                    u = self._per_spender(cid, key.get("spender"),
                                          now if c.get("window") else None)
                if q[cid][i] < 0 and self.flaw != "accepts_negative":
                    return False
                if u[i] + q[cid][i] > cap:
                    return False
        return True

    def _per_spender(self, cid: str, spender: Optional[str], at: Optional[float]) -> List[int]:
        lims = self.ceilings[cid]["limits"]
        tot = [0] * len(lims)
        win = self._window_of(cid, at) if at is not None else None
        for e in self.entries.values():
            if cid not in e["cids"] or e["state"] in ("released", "expired") or \
                    e["spender"] != spender:
                continue
            if win is not None and not (win[0] <= e["t_h"] < win[1]):
                continue
            for i in range(len(lims)):
                tot[i] += e["q"][cid][i]
        return tot

    # the agent's requests -----------------------------------------------------------------

    def _service(self) -> None:
        time.sleep(SLOW_S if self.slow else SERVICE_S)

    def request(self, root: str, spender: str, values: Dict[str, Any], *, request_id: str,
                agent: str, session: Optional[str] = None) -> Dict[str, Any]:
        began = time.perf_counter()
        ans = self._request(root, spender, values, request_id=request_id, session=session)
        ans.setdefault("body", {})
        ans["body"]["began"] = began
        ans["body"]["ended"] = time.perf_counter()
        return ans

    def _replica(self, root: str) -> Optional[str]:
        """While split, a root's requests alternate between the replicas."""
        if not self.partitioned:
            return None
        n = self._rr.get(root, 0) + 1
        self._rr[root] = n
        return "r1" if n % 2 else "r2"

    def _request(self, root: str, spender: str, values: Dict[str, Any], *, request_id: str,
                 session: Optional[str]) -> Dict[str, Any]:
        auth = self.auths.get(root)
        if auth is None:
            return _answer("refused", "no such root")
        replica = self._replica(root)
        if replica == "r2" and self.flaw != "per_replica_account":
            self._service()
            return _answer("refused", "this replica cannot reach the account store")
        dig = ledger.request_digest(values)
        lock = _nothing() if self.flaw == "check_then_set" else self._lock
        with lock:
            with self._lock:
                self._sweep()
                prev = self.by_request.get(request_id)
                if prev is not None and self.flaw == "fresh_on_retry":
                    # a fresh authority for every retry, charged once: the account is right,
                    # the authorities are not
                    return self._issue(auth, spender, values, request_id, dig, session,
                                       replica, charge=False)
                if prev is not None:
                    same = prev["digest"] == dig and prev["spender"] == spender
                    if same and self.flaw == "charges_retries":
                        e = self.entries[prev["entry"]]
                        ph = dict(e, id=ledger.new_id("rs"), phantom=True)
                        self.entries[ph["id"]] = ph
                    if same or self.flaw == "dedup_client_key":
                        if not same:
                            return self._issue(auth, spender, values, request_id, dig,
                                               session, replica, charge=False)
                        return dict(prev["answer"])
                    self._service()
                    return _answer("conflict", "the same request id with other bytes")
                if self._mech == "allocation":
                    return self._share(auth, spender)
                cids = list(auth["cids"])
                q: Dict[str, List[int]] = {}
                for cid in cids:
                    qq = self._q(cid, values)
                    if qq is None:
                        self._service()
                        return _answer("refused", "the spend cannot be counted against the "
                                                  "ceiling")
                    q[cid] = qq
                ok = self._fits(cids, q, {"spender": spender, "session": session,
                                          "replica": replica})
            if self.flaw == "check_then_set":
                self._service()
            else:
                self._service()
            with self._lock:
                if not ok:
                    return _answer("refused", "over the ceiling")
                return self._issue(auth, spender, values, request_id, dig, session, replica,
                                   q=q)

    def _issue(self, auth: Dict[str, Any], spender: str, values: Dict[str, Any], rid: str,
               dig: str, session: Optional[str], replica: Optional[str], *,
               q: Optional[Dict[str, List[int]]] = None, charge: bool = True
               ) -> Dict[str, Any]:
        cids = list(auth["cids"])
        if q is None:
            q = {cid: self._q(cid, values) or [0] * len(self.ceilings[cid]["limits"])
                 for cid in cids}
        now = self._wall()
        eid = ledger.new_id("rs")
        kind = "online" if self._mech in ("online", "forwarding") else "reservation"
        na = None if kind == "online" else now + EXPIRY_S
        qty = stated_quantity(values)
        if self._mech == "forwarding":
            claims = ceiling.forward_claims(holder="toy-holder", ceiling_ids=cids,
                                            spender=spender, request_id=rid, digest=dig,
                                            issued_at=int(now * 1000), forward_id=ledger.new_id(
                                                "fw"))
            tok = standing.sign(claims, self.hidden if self.no_control else self.key,
                                ceiling.FORWARD_TYP)
        else:
            claims = ceiling.reservation_claims(
                holder="toy-holder", ceiling_ids=cids, spender=spender, quantity=qty,
                request_id=rid, not_after=None if na is None else int(na * 1000),
                issued_at=int(now * 1000), reservation_id=eid, digest=dig, kind=kind)
            tok = standing.sign(claims, self.hidden if self.no_control else self.key,
                                ceiling.RESERVATION_TYP)
        if charge:
            self.entries[eid] = {"id": eid, "cids": cids, "q": q, "spender": spender,
                                 "session": session, "replica": replica,
                                 "in_partition": replica is not None, "t_h": now,
                                 "not_after": na, "reversed": {},
                                 "state": "captured" if kind == "online" else "held",
                                 "request_id": rid, "token": tok}
        if self._mech == "forwarding":
            sp = self.spenders.get(spender)
            ans = ledger.call_spender(sp["url"], {"forward": tok, "values": values, "ref": rid}) \
                if sp else _answer("refused", "no such spender")
        else:
            ans = _answer("authorised", "reserved", issuance=tok)
        self.by_request[rid] = {"digest": dig, "spender": spender, "entry": eid,
                                "answer": json.loads(json.dumps(ans))}
        return ans

    def _share(self, auth: Dict[str, Any], spender: str) -> Dict[str, Any]:
        cid = auth["cids"][0]
        key = (cid, spender)
        sh = self.shares.get(key)
        if sh is None:
            c = self.ceilings[cid]
            n = max(1, len(self.spenders))
            lims = []
            for lim in c["limits"]:
                x = dict(lim)
                x["value"] = lim["value"] // n
                lims.append(x)
            sid = ledger.new_id("sh")
            agent = Keypair.generate("agent-share")
            cum = ledger.cumulative(cid, c["limits"], window=c["window"], rule=c["rule"],
                                    holder={"source": "toy", "kid": self.key.kid},
                                    share={"spender": spender, "share_id": sid, "limits": lims})
            claims = ledger._claims(issuer="toy-holder", subject="agent", agent=agent,
                                    principal=auth["principal"], constraints={"cumulative": cum},
                                    parent=None, now=self._wall(), source="toy")
            tok = standing.sign(claims, self.hidden if self.no_control else self.key,
                                ceiling.GRANT_TYP)
            q = {cid: [ceiling.limit_value(x) for x in lims]}
            self.entries[sid] = {"id": sid, "cids": [cid], "q": q, "spender": spender,
                                 "t_h": self._wall(), "not_after": None, "reversed": {},
                                 "state": "captured", "token": tok}
            sh = self.shares[key] = {"token": tok, "id": sid}
        self._service()
        return _answer("authorised", "your share", issuance=sh["token"])

    # what the spenders and the agent say ---------------------------------------------------

    def deliver(self, route: str, statement: str) -> Dict[str, Any]:
        peek = standing.peek(statement)
        sp = self.spenders.get(str(peek.get("spender")))
        if sp is None:
            return _answer("refused", "unknown spender")
        v = standing.verify(statement, sp["keys"], ceiling.SPEND_TYP,
                            problem_of=ceiling.spend_problem)
        if not v.ok:
            return _answer("refused", f"statement: {v.reason}")
        c = v.claims
        with self._lock:
            e = self.entries.get(c["ref"])
            if e is None:
                return _answer("refused", "no such reservation")
            if c["kind"] == "captured":
                if e.get("not_after") is not None and self.flaw == "drops_late_capture" and \
                        self._wall() > e["not_after"]:
                    e["state"] = "expired"
                    return _answer("refused", "the reservation had expired")
                if e["state"] in ("held", "expired"):
                    e["state"] = "captured"
                if self.flaw == "window_from_spender_time":
                    e["t_h"] = c["at"] / 1000.0
            elif c["kind"] == "released":
                e["state"] = "released"
            elif c["kind"] == "reversed":
                for cid in e["cids"]:
                    lims = self.ceilings[cid]["limits"]
                    add = []
                    for lim in lims:
                        x = ceiling.quantity_of_limits(c["quantity"], lim)
                        add.append(x or 0)
                    cur = e["reversed"].get(cid, [0] * len(lims))
                    e["reversed"][cid] = [a + b for a, b in zip(cur, add)]
        return _answer("accepted", c["kind"])

    def _entry_of(self, issuance: Any) -> Optional[Dict[str, Any]]:
        if isinstance(issuance, str) and issuance.count(".") == 2:
            c = standing.peek(issuance)
            rid = c.get("reservation_id") or c.get("forward_id")
            if rid in self.entries:
                return self.entries[rid]
            req = c.get("request_id")
        else:
            req = issuance
        b = self.by_request.get(str(req))
        return self.entries.get(b["entry"]) if b else None

    def cancel(self, root: str, issuance: Any) -> Dict[str, Any]:
        """The agent says a spend failed, or cancels a reservation. A correct holder frees
        nothing on the agent's word."""
        with self._lock:
            e = self._entry_of(issuance)
            if e is None:
                return {"freed": False}
            if self.flaw == "frees_on_agent_claim" or \
                    (self.flaw == "frees_on_cancel" and e["state"] == "held"):
                e["state"] = "released"
                return {"freed": True}
        return {"freed": False}

    def claim_reversal(self, root: str, effect_ref: str, values: Dict[str, Any]
                       ) -> Dict[str, Any]:
        with self._lock:
            b = self.by_request.get(effect_ref)
            e = self.entries.get(b["entry"]) if b else None
            if e is None:
                return {"freed": False}
            if self.flaw == "frees_on_agent_claim":
                e["state"] = "released"
                return {"freed": True}
            if self.flaw == "trusts_agent_reversal":
                for cid in e["cids"]:
                    lims = self.ceilings[cid]["limits"]
                    add = [toy_quantity(values, l, None) or 0 for l in lims]
                    cur = e["reversed"].get(cid, [0] * len(lims))
                    e["reversed"][cid] = [a + b for a, b in zip(cur, add)]
                return {"freed": True}
        return {"freed": False}

    def account(self, root: str) -> Dict[str, Any]:
        with self._lock:
            self._sweep()
            cid = self.auths[root]["cids"][0]
            lims = self.ceilings[cid]["limits"]
            tot = [0] * len(lims)
            for e in self.entries.values():
                if cid in e["cids"] and e["state"] not in ("released", "expired"):
                    for i in range(len(lims)):
                        tot[i] += e["q"][cid][i]
                        if self.ceilings[cid]["rule"] == "net-recorded":
                            tot[i] -= e["reversed"].get(cid, [0] * len(lims))[i]
            return {"used": tot}

    def restart(self) -> Dict[str, Any]:
        with self._lock:
            if self.flaw == "memory_counter":
                self.entries.clear()
                self.by_request.clear()
                return {"restarted": True, "kept": "nothing (memory only)"}
        return {"restarted": True, "kept": "everything (durable store)"}

    def partition_replicas(self, on: bool) -> None:
        self.partitioned = bool(on)
        self._rr = {}


# --------------------------------------------------------------------------- role B: a spender


class ToySpender:
    """A spender (role B, in process). Module docstring."""

    name = "toy-spender"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *,
                 mechanism: Optional[str] = None, clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "per_request_only"
        if flaw is not None and flaw not in FLAWS_B + INFO_B:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.flaw = flaw
        self.config = config if flaw is None else (f"bad:{flaw}" if flaw in FLAWS_B
                                                    else f"info:{flaw}")
        base = "allocation" if config in ("good-allocation", "good-strict") else "reservation"
        self._mech = mechanism or (MECH_B.get(flaw, base) if flaw else base)
        self.strict = config == "good-strict"
        self.slow = config == "slow-good"
        self.no_control = config == "no-control"
        self.clock = clock
        self._clock: Any = None
        self.key = Keypair.generate(f"toy-b-{secrets.token_hex(3)}")
        self.orgs: Dict[str, Dict[str, Any]] = {}
        self.holder_keys: Dict[str, bytes] = {}
        self.holder_url: Optional[str] = None
        self.recorder = ""
        self._lock = threading.RLock()
        self.store: Dict[str, Any] = {"used": {}, "seen": {}, "first": {}, "offsets": {}}
        """The durable store (survives `restart` unless the flaw keeps it in memory)."""
        self.mem: Dict[str, Any] = {"used": {}}
        self.effects: Dict[str, Dict[str, Any]] = {}

    # statements ------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-spender {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P22": "toy: 'never spends beyond what the holder confirmed'"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def role(self) -> str:
        return "B"

    def mechanism(self) -> str:
        return self._mech

    def ceiling_profile(self) -> Dict[str, Any]:
        return {"limit_kinds": ["amount", "count"], "currencies": ["EUR", "USD"],
                "windows": ["fixed", "rolling"], "reversals": ["gross", "net-recorded"],
                "features": ["sessions"], "min_window_s": 20, "holder_hops": True}

    def constraint_bindings(self) -> Dict[str, str]:
        return {}

    def terms(self) -> Dict[str, Any]:
        prop = PROPAGATION_S if self.flaw == "lazy_ceiling" else 0.0
        return {"tolerance_s": {"value": TOLERANCE_S, "source": "documented"},
                "commit_lag_s": {"value": 0.0, "source": "documented"},
                "propagation_s": {"value": prop, "source": "documented"}}

    def evidence_grade(self) -> str:
        return "recorder"

    def endpoints(self) -> List[str]:
        return ["e1", "e2"]

    def max_in_flight(self) -> int:
        return 16

    def exposes_times(self) -> bool:
        return True

    def reports(self) -> bool:
        return True

    def documents_hard_limit(self) -> Dict[str, Any]:
        return {"quote": "toy: 'never beyond its share'", "url": "known_bad/ceiling_toys.py"}

    def spender_identity(self) -> Dict[str, Any]:
        return {"name": B_NAME, "keys": {self.key.kid: self.key.public_bytes()}}

    def set_clock(self, clock: Any) -> None:
        self._clock = clock

    def _now(self) -> float:
        return _c(self._clock).now()

    def _wall(self) -> float:
        return _c(self._clock).wall()

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "authorised", "queued": "authorised", "refused": "refused",
                "rate-limited": "rate-limited"}.get(code, "error")

    # binding ---------------------------------------------------------------------------------

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        self.orgs[anchor["issuer"]] = {"keyset": anchor["keyset_claims"], "anchor": anchor}
        return f"pinned {anchor['issuer']}"

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        return self.bind_requester(anchor, source_url)

    def bind_holder(self, anchor: Dict[str, bytes], url: Optional[str]) -> str:
        self.holder_keys = dict(anchor)
        self.holder_url = url
        return "pinned the holder"

    def bind_recorder(self, url: str) -> str:
        self.recorder = url.rstrip("/")
        return f"effects to {self.recorder}/effect/<ref>"

    def accepts_holder_hops(self) -> bool:
        return True

    def issuers(self) -> int:
        return 4

    def restart(self) -> Dict[str, Any]:
        with self._lock:
            if self.flaw == "memory_counter":
                self.mem = {"used": {}}
                return {"restarted": True, "kept": "nothing (memory only)"}
        return {"restarted": True, "kept": "everything (durable store)"}

    # reading a presentation --------------------------------------------------------------------

    def _anchors(self) -> Dict[str, Dict[str, Any]]:
        return {iss: o["keyset"] for iss, o in self.orgs.items()}

    def _chain(self, p: Any) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]]]:
        toks = [p.headers.get("KRK-Grant") or ""] + [
            t for t in (p.headers.get("KRK-Grant-Chain") or "").split(",") if t]
        if not toks[0]:
            return "no grant", None
        hops, why = ledger.verify_chain(toks, self._anchors())
        if why:
            return f"grant chain: {why}", None
        return None, hops

    def _share(self, p: Any) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        tok = p.headers.get("KRK-Share")
        if not tok:
            return "no share", None
        v = standing.verify(tok, self.holder_keys, ceiling.GRANT_TYP,
                            problem_of=ceiling.PROBLEMS[ceiling.GRANT_TYP])
        if not v.ok:
            return f"share: {v.reason}", None
        sh = v.claims["constraints"]["cumulative"]
        if sh.get("share") is None:
            return "not a share", None
        if sh["share"]["spender"] != B_NAME and self.flaw != "ignores_spender":
            return "a share addressed to another spender", None
        return None, v.claims

    # the entry point ---------------------------------------------------------------------------

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        began = time.perf_counter()
        ans = self._present(p, session)
        ans.setdefault("body", {})
        ans["body"]["began"] = began
        ans["body"]["ended"] = time.perf_counter()
        return ans

    def _present(self, p: Any, session: Optional[str]) -> Dict[str, Any]:
        try:
            values = json.loads(p.request.decode("utf-8"))
        except ValueError:
            return _answer("refused", "unreadable request")
        ref = str(values.get("ref"))
        with self._lock:
            if ref in self.store["seen"]:
                if self.flaw == "charges_retries":
                    k = self.store["seen"][ref].get("key")
                    q = self.store["seen"][ref].get("q")
                    if k and q:
                        self._add(k, q)
                time.sleep(SERVICE_S)
                return dict(self.store["seen"][ref]["answer"])
        why, hops = self._chain(p)
        if why:
            time.sleep(SERVICE_S)
            return _answer("refused", why)
        if self._mech == "allocation":
            ans = self._allocation(p, values, hops or [], session, ref)
        else:
            ans = self._reservation(p, values, hops or [], ref)
        return ans

    # allocation ------------------------------------------------------------------------------

    def _counters(self) -> Dict[str, Any]:
        return self.mem["used"] if self.flaw == "memory_counter" else self.store["used"]

    def _add(self, key: str, q: List[int]) -> None:
        u = self._counters().setdefault(key, {"total": [0] * len(q), "spends": []})
        u["total"] = [a + b for a, b in zip(u["total"], q)]
        u["spends"].append({"t": self._wall(), "q": list(q)})

    def _window_used(self, key: str, window: Any, now: float, share_claims: Dict[str, Any],
                     n: int) -> List[int]:
        u = self._counters().get(key) or {"total": [0] * n, "spends": []}
        if not window:
            return list(u["total"])
        P = float(window["period_s"])
        off = 0.0
        if self.flaw == "window_from_issuer_time":
            sid = key
            if sid not in self.store["offsets"]:
                issued = standing.epoch_of(share_claims.get("issued_at")) or now
                self.store["offsets"][sid] = issued - now
            off = self.store["offsets"][sid]
        t = now + off
        if window["kind"] == "rolling" and self.flaw != "fixed_for_rolling":
            lo, hi = t - P, t + 1e-9
        else:
            a = window["anchor_ms"] / 1000.0 if window["kind"] == "fixed" else \
                (standing.epoch_of(share_claims.get("issued_at")) or now)
            k = (t - a) // P
            lo, hi = a + k * P, a + (k + 1) * P
        tot = [0] * n
        for s in u["spends"]:
            ts = s["t"] + off
            if lo <= ts < hi:
                tot = [x + y for x, y in zip(tot, s["q"])]
        return tot

    def _allocation(self, p: Any, values: Dict[str, Any], hops: List[Dict[str, Any]],
                    session: Optional[str], ref: str) -> Dict[str, Any]:
        why, sc = self._share(p)
        if why:
            time.sleep(SERVICE_S)
            return _answer("refused", why)
        assert sc is not None
        cum = sc["constraints"]["cumulative"]
        sh = cum["share"]
        cids = [c for c, _ in ledger.chain_ceilings(hops)]
        if cum["ceiling_id"] not in cids:
            return _answer("refused", "the share is not for this chain's ceiling")
        lims = list(sh["limits"])
        own_ceiling = False
        if self.flaw == "counter_per_grant":
            own = (hops[0].get("constraints") or {}).get("cumulative") or {}
            if own.get("ceiling_id") and own["ceiling_id"] != cum["ceiling_id"]:
                lims = [dict(x) for x in own["limits"]]
                own_ceiling = True
        key = sh["share_id"]
        if self.flaw == "per_session_counter":
            key += f"/{session}"
        if self.flaw == "per_endpoint_counter":
            key += f"/{p.endpoint}"
        if self.flaw == "counter_per_grant_id":
            key += f"/{hops[-1]['grant_id']}"
        if self.flaw == "counter_per_issuer":
            key += f"/{hops[0]['issuer']}"
        if own_ceiling:
            key += f"/{hops[0]['grant_id']}"
        q = []
        for i, lim in enumerate(lims):
            if self.flaw == "first_limit_only" and i > 0:
                q.append(0)
                continue
            x = toy_quantity(values, lim, self.flaw)
            if x is None:
                time.sleep(SERVICE_S)
                return _answer("refused", "the spend cannot be counted against the share")
            q.append(x)
        with self._lock:
            now = self._wall()
            issued = standing.epoch_of(sc.get("issued_at")) or now
            lazy = self.flaw == "lazy_ceiling" and now - issued < PROPAGATION_S
            used = self._window_used(key, cum.get("window"), now, sc, len(lims))
            if self.flaw == "counter_from_holder":
                used = self._acked(key, len(lims))
            for i, lim in enumerate(lims):
                cap = ceiling.limit_value(lim)
                if self.flaw == "off_by_one":
                    cap += ceiling.scaled(1, lim["minor_units"]) if lim["kind"] == "amount" \
                        else 1
                if self.strict:
                    cap = cap * 95 // 100
                if q[i] < 0 and self.flaw != "accepts_negative":
                    return _answer("refused", "a negative spend")
                if not lazy and used[i] + q[i] > cap:
                    time.sleep(SERVICE_S)
                    return _answer("refused", "beyond the share")
            time.sleep(SLOW_S if self.slow else SERVICE_S)
            self._add(key, q)
            ans = self._effect(values, ref)
            self.store["seen"][ref] = {"answer": ans, "key": key, "q": q, "lims": lims}
        if (ans.get("body") or {}).get("code") == "executed":
            ok = self._report("/capture", sh["share_id"], [cum["ceiling_id"]], lims, values, ref)
            if ok:
                self.store.setdefault("acked", {}).setdefault(key, []).append(q)
        return ans

    def _acked(self, key: str, n: int) -> List[int]:
        tot = [0] * n
        for q in self.store.get("acked", {}).get(key, []):
            tot = [a + b for a, b in zip(tot, q)]
        return tot

    def reverse(self, effect_ref: str, values: Dict[str, Any]) -> Dict[str, Any]:
        """Reverse part of an effect this spender performed (role B, ``restores_share``)."""
        rref = f"rv-{secrets.token_hex(6)}"
        body = {"ref": rref, "spender": B_NAME, "kind": "reversal", "reverses": effect_ref,
                "values": values}
        ledger.KEEP.post(f"{self.recorder}/effect/{rref}", json.dumps(body).encode("utf-8"))
        seen = self.store["seen"].get(effect_ref) or {}
        if self.flaw == "restores_share_on_reversal" and seen.get("key"):
            q = [toy_quantity(values, lim, None) or 0 for lim in seen.get("lims") or []]
            with self._lock:
                self._add(seen["key"], [-x for x in q])
        return {"reversal": rref}

    # reservation ----------------------------------------------------------------------------

    def _reservation(self, p: Any, values: Dict[str, Any], hops: List[Dict[str, Any]],
                     ref: str) -> Dict[str, Any]:
        cs = ledger.chain_ceilings(hops)
        if not cs:
            return _answer("refused", "the grant states no cumulative ceiling")
        cid, cm = cs[-1]
        lims = cm["limits"]
        q = ceiling.values_quantity(values, lims)
        if q is None:
            time.sleep(SERVICE_S)
            return _answer("refused", "the spend cannot be counted against the ceiling")
        chain = [p.headers.get("KRK-Grant")] + [t for t in (p.headers.get("KRK-Grant-Chain")
                                                            or "").split(",") if t]
        if self.flaw == "per_request_only":
            time.sleep(SERVICE_S)
            if all(ceiling.limit_value(a) <= ceiling.limit_value(b) for a, b in zip(q, lims)):
                return self._remember(ref, self._effect(values, ref))
            return _answer("refused", "above the per-request limit")
        if self.flaw == "own_total_against_root":
            with self._lock:
                key = cid
                used = (self._counters().get(key) or {"total": [0] * len(q)})["total"]
                qq = [ceiling.limit_value(x) for x in q]
                if any(u + x > ceiling.limit_value(l) for u, x, l in zip(used, qq, lims)):
                    return _answer("refused", "over the root's ceiling")
                self._add(key, qq)
                time.sleep(SERVICE_S)
                return self._remember(ref, self._effect(values, ref))
        if self.flaw == "commits_unconfirmed":
            ans = self._effect(values, ref)
            time.sleep(SERVICE_S * 4)
            try:
                self._reserve(chain, values, ref)
            except ledger.Unreachable:
                pass
            return self._remember(ref, ans)
        try:
            r = self._reserve(chain, values, ref)
        except ledger.Unreachable:
            if self.flaw == "fails_open_unreachable":
                return self._remember(ref, self._effect(values, ref))
            time.sleep(SERVICE_S)
            return _answer("refused", "the holder cannot be reached: nothing unconfirmed")
        body = r.get("body") or {}
        if body.get("code") != "authorised":
            time.sleep(SERVICE_S)
            return _answer("refused", f"the holder refused: {body.get('reason')}")
        v = standing.verify(body.get("issuance"), self.holder_keys, ceiling.RESERVATION_TYP,
                            problem_of=ceiling.reservation_problem)
        if not v.ok or v.claims["spender"] != B_NAME:
            return _answer("refused", "the reservation is not for this spender")
        res = v.claims
        time.sleep(SLOW_S if self.slow else SERVICE_S)
        return self._remember(ref, self._commit(res, values, ref))

    def _reserve(self, chain: List[str], values: Dict[str, Any], ref: str) -> Dict[str, Any]:
        doc = {"chain": chain, "spender": B_NAME, "values": values, "request_id": ref}
        route = "/authorise" if self._mech == "online" else "/reserve"
        return ledger.call_holder(self.holder_url or "", route, doc)

    def _remember(self, ref: str, ans: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self.store["seen"][ref] = {"answer": ans}
        return ans

    def _commit(self, res: Dict[str, Any], values: Dict[str, Any], ref: str,
                retry: bool = False) -> Dict[str, Any]:
        na = res.get("not_after")
        if na is not None and self._wall() * 1000 > na - TOLERANCE_S * 1000 and \
                self.flaw != "commits_after_expiry":
            return _answer("refused", "the reservation has expired")
        ans = self._effect(values, ref, res=res)
        if (ans.get("body") or {}).get("code") == "executed":
            self._report("/capture", res["reservation_id"], res["ceiling_ids"], None, values,
                         ref, quantity=res["quantity"])
        return ans

    def _report(self, route: str, rid: str, cids: List[str], lims: Optional[List[Dict]],
                values: Dict[str, Any], ref: str, quantity: Any = None) -> bool:
        if quantity is None:
            quantity = ceiling.values_quantity(values, lims or []) or []
        st = standing.sign(ceiling.spend_claims(
            spender=B_NAME, kind="captured", ref=rid, ceiling_ids=cids, quantity=quantity,
            effect_ref=ref, at=int(self._wall() * 1000)), self.key, ceiling.SPEND_TYP)
        for attempt in range(3):
            try:
                r = ledger.call_holder(self.holder_url or "", route, {"statement": st})
            except ledger.Unreachable:
                return False
            if r.get("status") == 503:
                if self.flaw == "releases_after_commit":
                    rel = standing.sign(ceiling.spend_claims(
                        spender=B_NAME, kind="released", ref=rid, ceiling_ids=cids,
                        quantity=quantity, effect_ref=None, at=int(self._wall() * 1000)),
                        self.key, ceiling.SPEND_TYP)
                    try:
                        ledger.call_holder(self.holder_url or "", "/release",
                                           {"statement": rel})
                    except ledger.Unreachable:
                        pass
                    return False
                continue
            return (r.get("body") or {}).get("code") == "accepted"
        return False

    def _effect(self, values: Dict[str, Any], ref: str, *, res: Optional[Dict[str, Any]] = None
                ) -> Dict[str, Any]:
        body = {"ref": ref, "spender": B_NAME, "kind": "spend", "values": values}
        url = (f"{self.recorder}/effect/{ref}" if not self.no_control
               else f"{self.recorder.rsplit('/p22/', 1)[0]}/elsewhere/{secrets.token_hex(4)}")
        try:
            code, data = ledger.KEEP.post(url, json.dumps(body).encode("utf-8"))
        except OSError as e:
            return _answer("refused", f"effect failed: {type(e).__name__}")
        if code == 503 and res is not None:
            c = _c(self._clock)
            try:
                wait = float(json.loads(data or b"{}").get("retry_after_s") or EXPIRY_S)
            except ValueError:
                wait = EXPIRY_S
            c.call_at(c.now() + wait, lambda: self._commit(res, values, ref, retry=True))
            return _answer("queued", f"held; retry in {wait:g} s")
        return _answer("executed", "performed") if code == 200 else \
            _answer("refused", f"effect failed {code}")


# --------------------------------------------------------------------------- factories


def make_a(flaw: Optional[str] = None, **kw: Any) -> ToyHolder:
    return ToyHolder("bad" if flaw else "good", flaw, **kw)


def make_b(flaw: Optional[str] = None, **kw: Any) -> ToySpender:
    return ToySpender("bad" if flaw else "good", flaw, **kw)


def make(flaw: Optional[str] = None, *, role: str = "A", **kw: Any) -> Any:
    return make_a(flaw, **kw) if role == "A" else make_b(flaw, **kw)


def toy(config: str) -> Any:
    """``a-<config>`` / ``b-<config>``, as the known-bad gate names them: ``a-good``,
    ``a-bad:<flaw>``, ``a-info:charges_retries``, ``b-no-control`` and so on."""
    role, _, rest = config.partition("-")
    cls = ToyHolder if role == "a" else ToySpender
    if rest.startswith(("bad:", "info:")):
        return cls("bad", rest.split(":", 1)[1])
    return cls(rest)


def cases() -> List[Tuple[str, str]]:
    """Every toy configuration of both roles and the outcome it must give (``pass``,
    ``fail``, ``inconclusive``)."""
    out: List[Tuple[str, str]] = []
    for g in GOOD_A:
        out.append((f"a-{g}", "pass"))
    out += [("a-bad", "fail"), ("a-no-control", "inconclusive")]
    out += [(f"a-bad:{f}", "fail") for f in FLAWS_A]
    out += [(f"a-info:{f}", "pass") for f in INFO_A]
    for g in GOOD_B:
        out.append((f"b-{g}", "pass"))
    out += [("b-bad", "fail"), ("b-no-control", "inconclusive")]
    out += [(f"b-bad:{f}", "fail") for f in FLAWS_B]
    out += [(f"b-info:{f}", "pass") for f in INFO_B]
    return out
