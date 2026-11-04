"""P26 — The ceiling survives translation (KRK-26, cross-organisation X11).

**Guarantee** (`X11-TRANSLATION-DESIGN.md` §1.4). For every translated form a translator issues
from an original, every effect a faithful receiver commits under it lies inside the original's
allowed set, read in the original's own terms through the declared profile. For every effect a
receiver of both forms commits, the effect lies inside both. For a system that maps and acts,
every effect it commits, mapped back through its declared profile, lies inside the original.

**Topologies, graded separately**:

- **T**: the target translates; the kit plays A (`translator_stub.StandInA`), the agent and a
  faithful receiver R′ (`translator_stub.FaithfulReceiver`) that enacts each translated form by
  the target's documented member semantics. Grade ``translated-signed``: a T pass reads "the
  translated forms this translator issued were never wider than the original, read through its
  declared profile", never "end to end" (KRK-M201).
- **R**: the target receives the original beside a translated form the kit's T′ signed with its
  own key (`translator_stub.StubTranslator`), faithful or wider, and commits at the
  kit's recorder. Grade ``recorder``. Not run when the target receives no original (KRK-M202).
- **TR**: the target receives the original under its declared profile and a request in its own
  vocabulary, and acts. Grade ``recorder``.

**The profile is the target's**: read from ``translation_profile()``, pinned by
digest before the control and read again at the end (KRK-M190, M194). The kit never supplies,
completes or corrects one. The image and every judgement come from `translation` (exact
rationals; KRK-M193). Every effect is judged with `translation.effect_outside` against the
original in its own currency, units and time unit (KRK-M200).

**Within each trial** (§4.1), in a seeded order: **W**, the original (and in R the widened
translated form) with a request at the edge of what the weak reading admits and outside the
original; **L**, the sibling of the same shape whose value under test the faithful and the weak
readings agree on, which must be accepted (KRK-M192); and **W-in**, a request inside the original
under W's own translation (accepted ``exact`` / ``clamped``, or ``refused``), not presented where
refusal is required (`REFUSE`). In T the W request is drawn from the translated form the target
actually issued; in R and TR from the weak reading the form predicts, checked to lie outside the
original before it is presented (KRK-M196). Subjects are fresh per presentation except in
``retranslation/cached_image`` (KRK-M199). Originals are never changed during a trial (KRK-M209).

**Outcomes** per trial: pass ``held``; fail ``outside_effect`` (with the dimension); information
``documented_widening``, ``collateral_refusal``, ``not_landed``,
``unreadable_translation`` (KRK-M191), ``draw_failed``, ``not_applicable``. Information labels on a
held trial: ``stricter_rounding`` (§2.4), ``defaulted_narrower``.

**Result**: ``fail`` if any landed form fails; ``pass`` if the control held, every landed form
held, and no form in `NA_FORBIDDEN` for the topology is missing or without a reading, a form the
adapter states not claimed counting as present, and a form in `NA_BY_PROFILE` that
reads ``not_applicable`` with the probe's own reason counting as present; otherwise
``inconclusive``.

**The control's operation** is a source value exactly one target value realises,
and that one alone, so the control never depends on how the translator picks. Where the profile
has no such value, the control draws its operation in T from the translated form the target
issued for it; in R from the form the kit's T′ signed, which is the kit's faithful image; in TR
from the kit's image, because a system that maps and acts shows no translated form. The result
says so (``extra["control_operation"]`` and the summary).
``extra["forms"]`` holds the reading per form, ``extra["must_land_missed"]`` the `NA_FORBIDDEN`
forms that did not land (also when a form failed), ``extra["disclosure_forms"]`` the
class of each failing form.
"""
from __future__ import annotations

import copy
import json
import math
import os
import random
import secrets
import time
from fnmatch import fnmatchcase
from fractions import Fraction
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P26"
TITLE = "The ceiling survives translation"
FIXTURES = ("known_bad/translation_toys.py", "tests/test_p26_translation.py",
            "tests/vectors/krk26/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("The stand-in A's, T′'s and every toy's keys, authority ids, subjects, payees, account "
            "ids and request ids come from the operating system, never from the seed (KRK-M36).",
            "The seed draws the form order, amounts, windows and which declared pair a form uses.")

VARIANTS = ("currency", "units", "rounding", "dropped_constraint", "unmappable", "partial",
            "window", "scope", "retranslation", "two_forms")
FORMS = {"currency": ("face_value", "rate_undeclared", "rate_inverted", "asset_substituted"),
         "units": ("minor_units", "token_decimals", "time_units", "count_unit"),
         "rounding": ("max_up", "min_down", "float_rate"),
         "dropped_constraint": ("no_counterpart", "advisory_target", "critical_lost",
                                "subset_translated"),
         "unmappable": ("unmapped_value", "many_to_one", "heuristic_match"),
         "partial": ("local_default", "error_fallback"),
         "window": ("outlives_original", "relative_from_issue", "starts_early"),
         "scope": ("operation_added", "audience_added", "resource_broader"),
         "retranslation": ("round_trip", "staged", "cached_image"),
         "two_forms": ("amount", "payee", "window", "unbound_pair")}
TOPOLOGY_VARIANTS = {"T": tuple(v for v in VARIANTS if v != "two_forms"),
                     "R": ("currency", "window", "two_forms"),
                     "TR": tuple(v for v in VARIANTS if v != "two_forms")}
"""§3.1's topology column. `retranslation/round_trip` and `staged` need what the target exposes
(a reverse direction, its stages); without it they read ``not_applicable`` with its reason."""
REFUSE = {("currency", "rate_undeclared"), ("currency", "asset_substituted"),
          ("unmappable", "unmapped_value"), ("unmappable", "heuristic_match"),
          ("partial", "error_fallback"), ("two_forms", "unbound_pair")} | \
    {("dropped_constraint", f) for f in FORMS["dropped_constraint"]}
"""Forms where refusal is required: W-in is not presented (§4.1)."""
NA_FORBIDDEN = ("control", ("currency", "face_value"), ("currency", "rate_undeclared"),
                ("units", "minor_units"), ("dropped_constraint", "no_counterpart"),
                ("dropped_constraint", "subset_translated"), ("unmappable", "unmapped_value"),
                ("partial", "error_fallback"), ("window", "outlives_original"),
                ("retranslation", "cached_image"), ("two_forms", "amount"))
"""Forms that must land with a reading in every topology that runs them (design §6.4)."""
NA_BY_PROFILE = {("currency", "face_value"), ("units", "minor_units")}
"""Forms of `NA_FORBIDDEN` that read ``not_applicable``, with the probe's reason, when no declared
pair separates their weak check (decided for every target before any run):
``face_value`` when no pair has a rate at or below `LOW_RATE` (for example only one-to-one pairs),
``minor_units`` when no pair's source currency has more than two minor units. The reading then
counts as present for the result. A target cannot state them not applicable itself
(``forms_not_applicable``), and every other reason without a reading still makes the result
inconclusive."""
NO_SEPARATING_PAIR = "no_separating_pair"
"""The information label of a trial whose `NA_BY_PROFILE` form the declared profile cannot draw."""
GRADES = ("recorder", "translated-signed", "translated-response", "b-signed", "b-record",
          "b-response", "library-decision")
GRADES_OF = {"T": ("translated-signed", "translated-response"),
             "R": ("recorder", "b-signed", "b-record", "b-response", "library-decision"),
             "TR": ("recorder", "b-signed", "b-record", "b-response")}
TRIALS = {"*": 5}
DEV_TRIALS = {"*": 3}
PUBLISHED_TRIALS = {"*": 5}
PLAN_ENV = "ACK_P26_PLAN"
NOW0 = 1_900_000_000
"""The kit-clock origin of a run, in seconds. Presentations carry their kit time (``at``); the
toys read it as their clock, so no form waits (the property is static, design §0 item 9)."""
LOW_RATE = Fraction(4, 5)
"""A pair used for `face_value` or `rate_inverted` has a rate at most this (KRK-M196: no rate
near 1). Applying a rate above 1 backwards narrows, so only rates below 1 separate
`rate_inverted` (design §3.1 names 1.25–2.5 too)."""
UNDECLARED_CODES = ("SEK", "NOK", "PLN", "CZK", "HUF", "DKK")
OTHER_ASSETS = ("JPY", "EUR", "USDT", "XAU")


# --------------------------------------------------------------------------- small helpers


def _jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=lambda o: o.decode("ascii", "replace")
                                 if isinstance(o, bytes) else str(o)))


def _hex(n: int = 4) -> str:
    return secrets.token_hex(n)


def _fresh(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def _call(a: Any, name: str, default: Any = None) -> Any:
    fn = getattr(a, name, None)
    return fn() if callable(fn) else default


def _is_toy(a: Any) -> bool:
    mod = type(a).__module__ or ""
    return mod.startswith(("known_bad.", "tests.", "test_")) or mod == "__main__"


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    return json.loads(raw) if raw else None


def _trials(plan: Dict[str, Any]) -> int:
    if plan.get("trials") == "dev":
        return DEV_TRIALS["*"]
    if plan.get("trials") == "published":
        return PUBLISHED_TRIALS["*"]
    if isinstance(plan.get("trials"), int):
        return int(plan["trials"])
    return TRIALS["*"]


def _matches(pattern: str, form_id: str) -> bool:
    if "/" not in pattern and fnmatchcase(form_id.split("/", 1)[0], pattern):
        return True
    return fnmatchcase(form_id, pattern)


def _not_claimed_ids(a: Any) -> List[str]:
    """The patterns the adapter states not claimed for P26, read the same way the
    runner's claim-basis rule reads them, without importing that rule into this probe."""
    st = _call(a, "not_claimed", {}) or {}
    out: List[str] = []
    for k, v in st.items():
        if k == ID and isinstance(v, str):
            return ["*"]
        if k == ID and isinstance(v, dict):
            out += list(v)
        elif not (k.startswith("P") and k[1:].rstrip("B").isdigit()):
            out.append(k)
    return out


class _Progress:
    def __init__(self, ev: Evidence) -> None:
        self.path = ev.write("progress.jsonl", "")

    def add(self, kind: str, **doc: Any) -> None:
        rec = {"kind": kind, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **doc}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(_jsonable(rec), sort_keys=True) + "\n")


class Outcome:
    def __init__(self, reading: str, ok: Optional[bool], detail: str = "", *,
                 dims: Optional[List[str]] = None, mode: str = "n/a",
                 info: Optional[List[str]] = None) -> None:
        self.reading, self.ok, self.detail = reading, ok, detail
        self.dims, self.mode, self.info = list(dims or []), mode, list(info or [])

    def to_doc(self) -> Dict[str, Any]:
        return {"reading": self.reading, "ok": self.ok, "detail": self.detail,
                "dims": self.dims, "mode": self.mode, "info": self.info}


# --------------------------------------------------------------------------- the run


class _Run:
    def __init__(self, a: Any, ev: Evidence, rng: random.Random, st: Dict[str, Any]) -> None:
        from .. import translation as tr
        from .. import translator_stub as ts
        self.a, self.ev, self.rng, self.tr, self.ts = a, ev, rng, tr, ts
        self.topo: str = st["topology"]
        self.profile: Dict[str, Any] = st["profile"]
        self.digest: str = st["digest"]
        self.sem: Dict[str, Any] = st["semantics"]
        self.conf: Dict[str, Any] = st["configuration"]
        self.tol: int = int(st["tolerance"])
        self.fields = self.profile["fields"]
        self.A = ts.StandInA()
        self.Tp = ts.StubTranslator()
        self.rec = ts.Recorder()
        self.receiver = f"did:web:r-{_hex()}.example"
        self.Rp = ts.FaithfulReceiver(self.profile, self.sem, self.rec, receiver=self.receiver,
                                      tolerance=self.tol)
        self.Sp = ts.SourceReceiver(self.rec)
        self.t_keys: Dict[str, bytes] = dict((_call(a, "keys", {}) or {}).get("translator") or {})
        self.now = NOW0 + rng.randint(0, 10 ** 6)
        self.progress = _Progress(ev)
        self.n = 0

    # target members by source member (enforced only)
    def t(self, source_member: str) -> Optional[str]:
        hits = sorted(m for m, s in self.fields.items()
                      if s == source_member and (self.sem.get(m) or {}).get("semantics")
                      == "enforced")
        return hits[0] if hits else None

    def carries(self, source_member: str) -> bool:
        return self.t(source_member) is not None

    def log(self, kind: str, **doc: Any) -> None:
        self.progress.add(kind, **doc)


def _rate(p: Dict[str, Any]) -> Fraction:
    return Fraction(p["rate"]["num"], p["rate"]["den"])


def _scale(pair: Dict[str, Any]) -> Fraction:
    return _rate(pair) * Fraction(10) ** (pair["target"]["minor_units"]
                                          - pair["source"]["minor_units"])


def _amount(v: int, pair: Dict[str, Any], *, as_int: bool = False) -> Dict[str, Any]:
    return {"value": v if as_int else str(v), "currency": pair["source"]["currency"],
            "minor_units": pair["source"]["minor_units"]}


# --------------------------------------------------------------------------- pairs and draws


def _unit_pair(run: _Run) -> Optional[Dict[str, Any]]:
    """The control's pair: one the profile maps one to one, if it maps any (§4.1)."""
    amounts = run.profile.get("amounts") or []
    same = [p for p in amounts if _rate(p) == 1 and p["source"] == p["target"]]
    one = [p for p in amounts if _rate(p) == 1]
    return (same or one or amounts or [None])[0]


def _pairs(run: _Run, pred: Callable[[Dict[str, Any]], bool]) -> List[Dict[str, Any]]:
    return [p for p in (run.profile.get("amounts") or []) if pred(p)]


def _draw_M(run: _Run, pair: Dict[str, Any], lo: int = 20_000, hi: int = 90_000,
            ok: Optional[Callable[[int], bool]] = None, tries: int = 4000) -> Optional[int]:
    k = Fraction(10) ** max(0, pair["source"]["minor_units"] - 2)
    for _ in range(tries):
        M = int(run.rng.randint(lo, hi) * k) + (run.rng.randint(0, int(k) - 1) if k > 1 else 0)
        if ok is None or ok(M):
            return M
    return None


def _float_floor(M: int, pair: Dict[str, Any]) -> int:
    """The floor a double-precision computation gives. Used only to choose draws that separate the
    float reading from the exact one (KRK-M196); never in a judgement."""
    r = pair["rate"]
    return math.floor(float(M) * (float(r["num"]) / float(r["den"]))
                      * (10.0 ** (pair["target"]["minor_units"] - pair["source"]["minor_units"])))


def _base_claims(run: _Run, pair: Optional[Dict[str, Any]] = None, M: Optional[int] = None
                 ) -> Dict[str, Any]:
    """An honest original inside every dimension the target's format carries (§4.1)."""
    pair = pair or _unit_pair(run)
    c: Dict[str, Any] = {}
    if pair is not None and run.carries("max_amount"):
        M = M if M is not None else _draw_M(run, pair)
        c["max_amount"] = _amount(M, pair)
    ops = (run.profile.get("values") or {}).get("operations") or {}
    # A source value only one target value realises, and that one alone: no wider target
    # value can be chosen for it, so the control never depends on how a translator picks.
    unique, single = _control_ops(run)
    if run.carries("operations"):
        c["operations"] = [(unique or single or ["update"])[0]]
    if run.carries("resources"):
        c["resources"] = [f"crm/contacts/acct-{_hex()}/*"]
    if run.carries("audience"):
        c["audience"] = [run.receiver]
    if run.carries("payee"):
        c["payee"] = _fresh("acct")
    claims: Dict[str, Any] = {"subject": _fresh("agent"), "principal": _fresh("principal"),
                              "issued_at": run.now - 60, "constraints": c, "time_unit": "s",
                              "crit": []}
    if run.carries("not_after"):
        claims["not_after"] = run.now + run.rng.randint(60, 300)
    if run.carries("not_before"):
        claims["not_before"] = run.now - 60
    return claims


def _control_ops(run: _Run) -> Tuple[List[str], List[str]]:
    """(source values only one target value realises, and that one alone; source values some
    target value realises alone). The first is the control's operation."""
    ops = (run.profile.get("values") or {}).get("operations") or {}
    unique = sorted(svs[0] for tv, svs in ops.items() if len(svs) == 1
                    and sum(svs[0] in x for x in ops.values()) == 1)
    single = sorted(svs[0] for tv, svs in ops.items() if len(svs) == 1)
    return unique, single


def _with(claims: Dict[str, Any], **cons: Any) -> Dict[str, Any]:
    out = copy.deepcopy(claims)
    out["subject"] = _fresh("agent")
    for k, v in cons.items():
        if v is None:
            out["constraints"].pop(k, None)
        else:
            out["constraints"][k] = v
    return out


def _fresh_subject(claims: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(claims)
    out["subject"] = _fresh("agent")
    return out


# --------------------------------------------------------------------------- requests


def _ops_table(run: _Run) -> Dict[str, List[str]]:
    return (run.profile.get("values") or {}).get("operations") or {}


def _base_request(run: _Run, members: Dict[str, Any], o: Dict[str, Any]) -> Dict[str, Any]:
    """A request inside `members` (a faithful image of `o`) and inside `o`."""
    tr = run.tr
    c = o.get("constraints") or {}
    req: Dict[str, Any] = {"request_id": _fresh("rq"), "at": run.now, "audience": run.receiver}
    lim, flo = members.get(run.t("max_amount") or ""), members.get(run.t("min_amount") or "")
    if lim:
        v = lim["value"] // 2
        if flo:
            v = min(max(v, flo["value"]), lim["value"])
        req["amount"] = {"value": v, "currency": lim["currency"],
                         "minor_units": lim["minor_units"]}
    elif flo:
        req["amount"] = dict(flo)
    q = members.get(run.t("max_count") or "")
    if q:
        req["count"] = {"value": min(1, q["value"]), "unit": q["unit"]}
    scope = members.get(run.t("operations") or "")
    if scope:
        inside = [tv for tv in sorted(scope) if (tr.realised(tv, run.profile, "operations")
                                                 or {None}) <= set(c.get("operations") or [])]
        req["operation"] = (inside or sorted(scope))[0]
    else:
        req["operation"] = sorted(_ops_table(run) or {"op": 1})[0]
    paths = members.get(run.t("resources") or "")
    if paths:
        p = sorted(paths)[0]
        req["resource"] = p[:-1] + f"r-{_hex()}" if p.endswith("/*") else p
    else:
        p = (c.get("resources") or ["crm/contacts/any/*"])[0]
        req["resource"] = p[:-1] + f"r-{_hex()}" if p.endswith("/*") else p
    req["payee"] = members.get(run.t("payee") or "") or c.get("payee") or _fresh("acct")
    for m, k in (("categories", "category"), ("regions", "region"), ("channels", "channel")):
        req[k] = (c.get(m) or [f"any-{_hex()}"])[0]
    return req


def _edge(run: _Run, req: Dict[str, Any], x: Dict[str, Any], o: Dict[str, Any], dims: List[str]
          ) -> Dict[str, Any]:
    """`req` moved to the edge of what members `x` admit, in each of `dims`."""
    tr = run.tr
    req = copy.deepcopy(req)
    c = o.get("constraints") or {}
    unit = tr.TIME_UNITS[o.get("time_unit", "s")]
    tu = tr.TIME_UNITS[tr.time_unit(run.profile)]
    for d in dims:
        t = run.t(d) if d in tr.CARRIABLE else None
        if d == "max_amount" and t in x:
            req["amount"] = dict(x[t])
        elif d == "currency_any" and run.t("max_amount") in x:
            lim = x[run.t("max_amount")]
            req["amount"] = {"value": 1, "currency": lim["currency"],
                             "minor_units": lim["minor_units"]}
        elif d == "min_amount" and t in x:
            req["amount"] = dict(x[t])
        elif d == "max_count" and t in x:
            req["count"] = dict(x[t])
        elif d == "operations" and t in x:
            wide = [tv for tv in sorted(x[t]) if not (tr.realised(tv, run.profile, "operations")
                                                      or {None}) <= set(c.get("operations")
                                                                        or [])]
            if wide:
                req["operation"] = wide[0]
        elif d == "audience" and t in x:
            wide = [p for p in sorted(x[t]) if p not in (c.get("audience") or [])]
            if wide:
                req["audience"] = wide[0]
        elif d == "resources":
            if t in x:
                wide = [p for p in sorted(x[t])
                        if not any(tr.covers_pattern(q, p) for q in c.get("resources") or [])]
                if wide:
                    p = wide[0]
                    req["resource"] = p[:-1] + f"r-{_hex()}" if p.endswith("/*") else p
            elif c.get("resources"):
                req["resource"] = f"outside-{_hex()}/r-{_hex()}"
        elif d == "payee":
            req["payee"] = x.get(t) if t in x else _fresh("acct")
        elif d == "not_after":
            if t in x:
                req["at"] = x[t]
            elif o.get("not_after") is not None:
                req["at"] = math.floor(Fraction(o["not_after"], unit) * tu) + run.tol + 3600
        elif d == "not_before":
            if t in x:
                req["at"] = x[t]
            elif o.get("not_before") is not None:
                req["at"] = math.ceil(Fraction(o["not_before"], unit) * tu) - run.tol - 3600
        elif d in ("categories", "regions", "channels"):
            key = {"categories": "category", "regions": "region", "channels": "channel"}[d]
            req[key] = f"x-{_hex()}"
    return req


# --------------------------------------------------------------------------- the forms


class Spec:
    """One form's fixtures: W and L, the dimensions under test, and how they are presented."""

    def __init__(self, w: Dict[str, Any], l: Dict[str, Any], dims: List[str], *,
                 ask_w: Optional[Dict[str, Any]] = None, ask_l: Optional[Dict[str, Any]] = None,
                 weak: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = None,
                 kind: str = "plain", first: Optional[Dict[str, Any]] = None,
                 na: Optional[str] = None) -> None:
        self.w, self.l, self.dims = w, l, dims
        self.ask_w, self.ask_l = ask_w or {}, ask_l or {}
        self.weak = weak or (lambda o, base: base)
        self.kind, self.first, self.na = kind, first, na
        self.by_profile = False


def _na(why: str, *, by_profile: bool = False) -> Spec:
    s = Spec({}, {}, [], na=why)
    s.by_profile = by_profile
    return s


def _image_or(run: _Run, o: Dict[str, Any], fallback: Dict[str, Any], **kw: Any
              ) -> Dict[str, Any]:
    got = run.tr.image(o, run.profile, run.sem, **kw)
    if isinstance(got, run.tr.Refusal):
        got = run.tr.image(fallback, run.profile, run.sem, **kw)
    return got if not isinstance(got, run.tr.Refusal) else {}


def _spec(run: _Run, variant: str, form: str) -> Spec:   # noqa: C901 - one table, read in order
    tr = run.tr
    up = _unit_pair(run)
    lim = run.t("max_amount")
    base = _base_claims(run)
    c0 = base["constraints"]
    if variant in ("currency", "rounding") and _call(run.a, "rate_source", "profile") != "profile":
        return _na("rate source is not the static profile; a served rate is not built in "
                   "version 1 (KRK-M194, M208): not landed")
    needs_amount = variant in ("currency", "rounding") or form in (
        "minor_units", "token_decimals", "error_fallback", "round_trip", "staged",
        "cached_image", "amount", "unbound_pair")
    if needs_amount and (lim is None or up is None):
        return _na("the target's format carries no enforced amount, or the profile declares no "
                   "currency pair")

    def set_limit(value: int, cur: Optional[str] = None, mu: Optional[int] = None):
        def f(o: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
            b = copy.deepcopy(b)
            old = b.get(lim) or {"currency": up["target"]["currency"],
                                 "minor_units": up["target"]["minor_units"]}
            b[lim] = {"value": value, "currency": cur or old["currency"],
                      "minor_units": old["minor_units"] if mu is None else mu}
            return b
        return f

    if variant == "currency":
        if form == "face_value" or form == "rate_inverted":
            low = _pairs(run, lambda p: _rate(p) <= LOW_RATE)
            if not low:
                return _na("no declared pair has a rate at or below 4/5, so a number copied "
                           "across, or a rate applied backwards, cannot be told from the "
                           "correct conversion (KRK-M196)",
                           by_profile=(variant, form) in NA_BY_PROFILE)
            pair = low[0]
            M = _draw_M(run, pair)
            w = _with(base, max_amount=_amount(M, pair))
            l = _with(base)
            if form == "face_value":
                weak_v = M if pair["source"]["minor_units"] == pair["target"]["minor_units"] \
                    else math.floor(Fraction(M) * Fraction(10) ** (
                        pair["target"]["minor_units"] - pair["source"]["minor_units"]))
                return Spec(w, l, ["max_amount"], weak=set_limit(weak_v,
                                                                 pair["target"]["currency"]))
            weak_v = math.floor(Fraction(M) / _rate(pair) * Fraction(10) ** (
                pair["target"]["minor_units"] - pair["source"]["minor_units"]))
            return Spec(w, l, ["max_amount"], weak=set_limit(weak_v, pair["target"]["currency"]))
        if form == "rate_undeclared":
            declared = {p["source"]["currency"] for p in run.profile.get("amounts") or []}
            code = next(cd for cd in UNDECLARED_CODES if cd not in declared)
            M = _draw_M(run, up)
            w = _with(base, max_amount={"value": str(M), "currency": code, "minor_units": 2})
            return Spec(w, _with(base), ["currency_any"], weak=set_limit(1))
        if form == "asset_substituted":
            targets = [p["target"]["currency"] for p in run.profile.get("amounts") or []]
            other = next((x for x in targets if x != up["target"]["currency"]),
                         next(x for x in OTHER_ASSETS if x != up["target"]["currency"]))
            img = tr.image(base, run.profile, run.sem)
            v = img[lim]["value"] if not isinstance(img, tr.Refusal) else 1
            return Spec(_with(base), _with(base), ["max_amount"], ask_w={"currency": other},
                        ask_l={"currency": up["target"]["currency"]},
                        weak=set_limit(v, other))
    if variant == "units":
        if form == "minor_units":
            pairs = _pairs(run, lambda p: p["source"]["minor_units"] > 2)
            if not pairs:
                return _na("no declared pair's source currency has more than two minor units, so "
                           "an assumed two cannot widen (KRK-M196)", by_profile=True)
            pair = pairs[0]
            M = _draw_M(run, pair)
            weak_v = math.floor(Fraction(M) * _rate(pair)
                                * Fraction(10) ** (pair["target"]["minor_units"] - 2))
            return Spec(_with(base, max_amount=_amount(M, pair)), _with(base), ["max_amount"],
                        weak=set_limit(weak_v, pair["target"]["currency"]))
        if form == "token_decimals":
            pairs = _pairs(run, lambda p: p["source"]["minor_units"] > 6)
            if not pairs:
                return _na("no declared pair has an asset with more than six decimals, so an "
                           "assumed six cannot widen (KRK-M196)")
            pair = pairs[0]
            M = _draw_M(run, pair, 5, 900)
            weak_v = math.floor(Fraction(M) * _rate(pair)
                                * Fraction(10) ** (pair["target"]["minor_units"] - 6))
            return Spec(_with(base, max_amount=_amount(M, pair)), _with(base), ["max_amount"],
                        weak=set_limit(weak_v, pair["target"]["currency"]))
        if form == "time_units":
            if tr.time_unit(run.profile) != "s" or not run.carries("not_after"):
                return _na("the target's time unit is not coarser than milliseconds, so a "
                           "number copied across units cannot widen")
            w = copy.deepcopy(base)
            w["subject"] = _fresh("agent")
            w.pop("not_before", None)
            w["time_unit"] = "ms"
            w["not_after"] = base["not_after"] * 1000 + run.rng.randint(0, 999)
            l = copy.deepcopy(base)
            l["subject"] = _fresh("agent")
            l.pop("not_before", None)
            exp_t = run.t("not_after")
            return Spec(w, l, ["not_after"],
                        weak=lambda o, b: {**b, exp_t: o["not_after"]})
        if form == "count_unit":
            cp = [p for p in run.profile.get("counts") or [] if _rate(p) < 1]
            same = [p for p in run.profile.get("counts") or []
                    if _rate(p) == 1 and cp and p["target"] == cp[0]["target"]]
            if not run.carries("max_count") or not cp or not same:
                return _na("the profile relates no count unit to a coarser one")
            C = run.rng.randint(41, 399)
            q = run.t("max_count")
            w = _with(base, max_count={"value": C, "unit": cp[0]["source"]})
            l = _with(base, max_count={"value": C, "unit": same[0]["source"]})
            return Spec(w, l, ["max_count"],
                        weak=lambda o, b: {**b, q: {"value": C, "unit": cp[0]["target"]}})
    if variant == "rounding":
        sem_lim = run.sem.get(lim) or {}
        res = sem_lim.get("resolution")
        if form in ("max_up", "min_down"):
            pairs = _pairs(run, lambda p: _scale(p).denominator > 1)
            if not pairs:
                return _na("every declared conversion is exact, so no rounding is needed")
            pair = pairs[0]
            if res is not None and res < pair["target"]["minor_units"]:
                return _na("the receiver's resolution is coarser than the image (KRK-M207)")
            s = _scale(pair)
            if form == "max_up":
                M = _draw_M(run, pair, ok=lambda m: (m * s) - math.floor(m * s) >= Fraction(1, 2))
                L = _draw_M(run, pair, ok=lambda m: (m * s).denominator == 1)
                if M is None or L is None:
                    return _na("no draw separates rounding to nearest from the floor")
                return Spec(_with(base, max_amount=_amount(M, pair)),
                            _with(base, max_amount=_amount(L, pair)), ["max_amount"],
                            weak=set_limit(math.floor(M * s) + 1, pair["target"]["currency"]))
            if not run.carries("min_amount"):
                return _na("the target's format carries no minimum amount")
            m_ = _draw_M(run, pair, 2_000, 9_000,
                         ok=lambda m: Fraction(0) < (m * s) - math.floor(m * s) < Fraction(1, 2))
            L = _draw_M(run, pair, 2_000, 9_000, ok=lambda m: (m * s).denominator == 1)
            if m_ is None or L is None:
                return _na("no draw separates rounding to nearest from the ceiling")
            big = _draw_M(run, pair, 50_000, 90_000)
            flo = run.t("min_amount")
            w = _with(base, max_amount=_amount(big, pair), min_amount=_amount(m_, pair))
            l = _with(base, max_amount=_amount(big, pair), min_amount=_amount(L, pair))

            def weak_min(o: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
                b = copy.deepcopy(b)
                b[flo] = {**b[flo], "value": math.floor(m_ * s)}
                return b
            return Spec(w, l, ["min_amount"], weak=weak_min)
        if form == "float_rate":
            for pair in _pairs(run, lambda p: _rate(p) != 1):
                s = _scale(pair)
                M = _draw_M(run, pair, ok=lambda m: _float_floor(m, pair) > math.floor(m * s))
                L = _draw_M(run, pair, ok=lambda m: _float_floor(m, pair) == math.floor(m * s)
                            and (m * s).denominator > 1)
                if M is not None and L is not None:
                    if res is not None and res < pair["target"]["minor_units"]:
                        return _na("the receiver's resolution is coarser than the image "
                                   "(KRK-M207)")
                    return Spec(_with(base, max_amount=_amount(M, pair)),
                                _with(base, max_amount=_amount(L, pair)), ["max_amount"],
                                weak=set_limit(_float_floor(M, pair),
                                               pair["target"]["currency"]))
            return _na("no declared rate admits a draw whose double-precision product rounds "
                       "past the exact one")
    if variant == "dropped_constraint":
        if form in ("no_counterpart", "advisory_target", "critical_lost"):
            member = {"no_counterpart": None, "advisory_target": None, "critical_lost": None}
            adv = dict(_call(run.a, "advisory_members", {}) or {})
            src_of = run.fields
            for m in ("categories", "regions", "channels"):
                targets = [t for t, s in src_of.items() if s == m]
                enforced = [t for t in targets if (run.sem.get(t) or {}).get("semantics")
                            == "enforced"]
                informational = [t for t in targets if t in adv or
                                 (run.sem.get(t) or {}).get("semantics") == "informational"]
                if enforced:
                    continue
                if informational and member["advisory_target"] is None:
                    member["advisory_target"] = m
                elif not targets and member["no_counterpart"] is None:
                    member["no_counterpart"] = m
                elif not targets and member["critical_lost"] is None:
                    member["critical_lost"] = m
            ext = [m for m, d in run.sem.items() if d.get("semantics") == "ignorable_extension"]
            if form == "critical_lost" and not ext:
                return _na("the target format has no ignorable extension member")
            m = member[form]
            if m is None:
                return _na(f"the target format carries every dimension the kit's format has "
                           f"that {form} needs")
            w = _with(base, **{m: [f"v-{_hex()}"]})
            if form == "critical_lost":
                w["crit"] = [m]
            return Spec(w, _with(base), [m])
        if form == "subset_translated":
            three = [m for m in ("operations", "resources", "payee") if run.carries(m)]
            if len(three) < 3:
                return _na("the target format does not carry three of the original's "
                           "constraints")
            return Spec(_with(base), _with(base), ["resources"],
                        weak=lambda o, b: {k: v for k, v in b.items()
                                           if k != run.t("resources")})
    if variant == "unmappable":
        if not run.carries("operations") or not _ops_table(run):
            return _na("the profile maps no operation values")
        table = _ops_table(run)
        sources = {s for svs in table.values() for s in svs}
        sc = run.t("operations")
        if form == "unmapped_value":
            names = {tv.rsplit(":", 1)[-1] for tv in table}
            op = next(x for x in ("merge", "purge", "transfer", "rename") if x not in sources
                      and x not in names)
            return Spec(_with(base, operations=[op]), _with(base), ["operations"],
                        weak=lambda o, b: {**b, sc: [op]})
        if form == "many_to_one":
            for tv, svs in sorted(table.items()):
                if len(svs) < 2:
                    continue
                for v in sorted(svs):
                    if any(set(x) == {v} for x in table.values()):
                        return Spec(_with(base, operations=[v]), _with(base, operations=list(svs)),
                                    ["operations"], weak=lambda o, b, tv=tv: {**b, sc: [tv]})
            return _na("no target value realises more than one source value that also has a "
                       "one-to-one target value")
        if form == "heuristic_match":
            for tv in sorted(table):
                name = tv.rsplit(":", 1)[-1]
                if name not in sources and name != tv:
                    single = sorted(x for x, svs in table.items() if len(svs) == 1
                                    and svs[0] == x.rsplit(":", 1)[-1])
                    if not single:
                        break
                    l_op = table[single[0]][0]
                    return Spec(_with(base, operations=[name]), _with(base, operations=[l_op]),
                                ["operations"], weak=lambda o, b, tv=tv: {**b, sc: [tv]})
            return _na("no target value's name resembles a source value the profile omits")
    if variant == "partial":
        if form == "local_default":
            if not run.carries("audience"):
                return _na("the target format carries no audience")
            extra = list(((run.conf.get("defaults") or {}).get("audience_extra")) or
                         [f"did:web:other-{_hex()}.example"])
            at = run.t("audience")
            return Spec(_with(base), _with(base, audience=None), ["audience"],
                        weak=lambda o, b: {**b, at: [run.receiver, *extra]})
        if form == "error_fallback":
            M = _draw_M(run, up)
            fb = (run.conf.get("defaults") or {}).get("fallback_amount")
            fbv = int(fb["value"]) if fb else M + 1
            return Spec(_with(base, max_amount=_amount(M, up, as_int=True)),
                        _with(base, max_amount=_amount(M, up)), ["max_amount"],
                        weak=set_limit(fbv))
    if variant == "window":
        if not run.carries("not_after"):
            return _na("the target format carries no window")
        ex, nb_t = run.t("not_after"), run.t("not_before")
        life = int((run.conf.get("defaults") or {}).get("lifetime_s") or 3600)
        if form == "outlives_original":
            l = _fresh_subject(base)
            l["not_after"] = run.now + life + run.rng.randint(100, 3600)
            return Spec(_fresh_subject(base), l, ["not_after"],
                        weak=lambda o, b: {**b, ex: run.now + life})
        if form == "relative_from_issue":
            if not run.carries("not_before"):
                return _na("the target format carries no start")
            w = _fresh_subject(base)
            w["not_before"] = run.now - run.rng.randint(600, 1800)
            w["not_after"] = run.now + life + run.rng.randint(100, 3600)
            l = _fresh_subject(w)
            l["not_before"] = run.now
            return Spec(w, l, ["not_after"],
                        weak=lambda o, b: {**b, ex: run.now + (o["not_after"]
                                                               - o["not_before"])})
        if form == "starts_early":
            if nb_t is None:
                return _na("the target format carries no start")
            w = _fresh_subject(base)
            w["not_before"] = run.now + run.rng.randint(60, 300)
            w["not_after"] = w["not_before"] + run.rng.randint(300, 900)
            l = _fresh_subject(base)
            return Spec(w, l, ["not_before"], weak=lambda o, b: {**b, nb_t: 0})
    if variant == "scope":
        if form == "operation_added":
            table = _ops_table(run)
            sc = run.t("operations")
            op0 = c0.get("operations", ["update"])[0]
            extra_tv = next((tv for tv, svs in sorted(table.items()) if op0 not in svs
                             and len(svs) == 1), None)
            if not run.carries("operations") or extra_tv is None:
                return _na("the profile has no second operation to ask for")
            mine = next(tv for tv, svs in sorted(table.items()) if svs == [op0])
            return Spec(_with(base), _with(base, operations=[op0, table[extra_tv][0]]),
                        ["operations"], ask_w={"operations": [mine, extra_tv]},
                        ask_l={"operations": [mine, extra_tv]},
                        weak=lambda o, b: {**b, sc: sorted(set(b.get(sc, [])) | {extra_tv})})
        if form == "audience_added":
            if not run.carries("audience"):
                return _na("the target format carries no audience")
            extra = list(((run.conf.get("defaults") or {}).get("audience_extra")) or
                         [f"did:web:other-{_hex()}.example"])
            at = run.t("audience")
            return Spec(_with(base), _with(base, audience=[run.receiver, *extra]), ["audience"],
                        ask_w={"audience": [run.receiver, *extra]},
                        ask_l={"audience": [run.receiver, *extra]},
                        weak=lambda o, b: {**b, at: [run.receiver, *extra]})
        if form == "resource_broader":
            if not run.carries("resources"):
                return _na("the target format carries no resources")
            pt = run.t("resources")
            broad = "crm/contacts/*"
            return Spec(_with(base), _with(base, resources=[broad]), ["resources"],
                        ask_w={"resources": [broad]}, ask_l={"resources": [broad]},
                        weak=lambda o, b: {**b, pt: [broad]})
    if variant == "retranslation":
        pairs = _pairs(run, lambda p: _scale(p).denominator > 1)
        if form == "round_trip":
            na = (_call(run.a, "forms_not_applicable", {}) or {}).get("retranslation/round_trip")
            if na:
                return _na(na)
            if run.topo != "T" or not callable(getattr(run.a, "translate_back", None)):
                return _na("the target documents no reverse direction")
            if not pairs:
                return _na("every declared conversion is exact")
            pair = pairs[0]
            major = 10 ** pair["source"]["minor_units"]
            M = _draw_M(run, pair, ok=lambda m: m % major != 0)
            L = _draw_M(run, pair, ok=lambda m: m % major == 0 and (m * _scale(pair))
                        .denominator == 1)
            if M is None or L is None:
                return _na("no draw has an inexact round trip")
            return Spec(_with(base, max_amount=_amount(M, pair)),
                        _with(base, max_amount=_amount(L, pair)), ["max_amount"],
                        kind="round_trip")
        if form == "staged":
            if not _call(run.a, "documents_stages", False):
                return _na("the target documents no stages")
            if not pairs:
                return _na("every declared conversion is exact")
            pair = pairs[0]
            s = _scale(pair)
            # A residue below one half: rounding to nearest gives the floor, so only a stage
            # that rounds up separates from the correct translation.
            M = _draw_M(run, pair, ok=lambda m: Fraction(0) < (m * s) - math.floor(m * s)
                        < Fraction(1, 2))
            L = _draw_M(run, pair, ok=lambda m: (m * s).denominator == 1)
            if M is None or L is None:
                return _na("no draw separates a stage that rounds up")
            return Spec(_with(base, max_amount=_amount(M, pair)),
                        _with(base, max_amount=_amount(L, pair)), ["max_amount"],
                        kind="staged", weak=set_limit(math.floor(M * s) + 1,
                                                      pair["target"]["currency"]))
        if form == "cached_image":
            M1 = _draw_M(run, up, 60_000, 90_000)
            M2 = _draw_M(run, up, 5_000, 20_000)
            first = _with(base, max_amount=_amount(M1, up))
            w = copy.deepcopy(first)
            w["constraints"]["max_amount"] = _amount(M2, up)
            l = _with(base, max_amount=_amount(M2, up))
            img1 = tr.image(first, run.profile, run.sem)
            return Spec(w, l, ["max_amount"], kind="cached", first=first,
                        weak=set_limit(img1[lim]["value"]) if not isinstance(img1, tr.Refusal)
                        else None)
    if variant == "two_forms":
        if form == "amount":
            img = tr.image(base, run.profile, run.sem)
            return Spec(_with(base), _with(base), ["max_amount"],
                        weak=set_limit(img[lim]["value"] + run.rng.randint(1, 5000)))
        if form == "payee":
            pt = run.t("payee")
            if pt is None:
                return _na("the target format carries no payee")
            other = _fresh("acct")
            return Spec(_with(base), _with(base), ["payee"], weak=lambda o, b: {**b, pt: other})
        if form == "window":
            ex = run.t("not_after")
            if ex is None:
                return _na("the target format carries no window")
            return Spec(_with(base), _with(base), ["not_after"],
                        weak=lambda o, b: {**b, ex: o["not_after"] + 3600})
        if form == "unbound_pair":
            img = tr.image(base, run.profile, run.sem)
            wide = img[lim]["value"] * 3 + 1
            return Spec(_with(base), _with(base), ["max_amount"], kind="unbound",
                        weak=set_limit(wide))
    return _na(f"{variant}/{form} has no fixture")


# --------------------------------------------------------------------------- presentations


def _present_T(run: _Run, claims: Dict[str, Any], ask: Dict[str, Any], dims: List[str], *,
               inside: bool = False, request: Optional[Dict[str, Any]] = None,
               kind: str = "plain", from_issued: bool = False) -> Dict[str, Any]:
    """One T presentation: A issues, the target translates, the kit decodes, R′ enacts. With
    `from_issued`, a request built here is drawn from the members the target issued, not from the
    kit's image (the control)."""
    tr = run.tr
    raw = run.A.issue(claims)
    ans = run.a.translate(raw, {**ask, "at": run.now})
    out: Dict[str, Any] = {"original": raw, "answer": {k: v for k, v in ans.items()
                                                       if k != "translated"}}
    if run.a.received() != raw:
        out["not_landed"] = "the original the target received differs from what A sent"
        return out
    if ans.get("error"):
        out["error"] = ans["error"]
        return out
    xr = ans.get("translated")
    if xr is None:
        out["refused"] = ans.get("refusal") or "refused"
        return out
    out["translated"] = xr
    try:
        dec = run.a.read_translated(xr)
    except Exception as e:  # noqa: BLE001
        out["unreadable"] = f"{type(e).__name__}: {e}"
        return out
    out["decoded"] = dec
    if dec.get("signed_by") not in run.t_keys:
        out["unreadable"] = f"signed by {dec.get('signed_by')!r}, which the target does not " \
                            f"state as its translator key"
        return out
    if dec.get("unreadable"):
        out["unreadable"] = f"members the decoder could not read: {dec['unreadable']}"
    if kind == "staged":
        out["stages"] = _call(run.a, "stages", [])
    members = dec["members"]
    o = claims
    img = tr.image(o, run.profile, run.sem, currency=(ask or {}).get("currency"))
    base_m = members if from_issued or isinstance(img, tr.Refusal) else img
    if request is None:
        req = _base_request(run, base_m, o)
        if not inside:
            req = _edge(run, req, members, o, dims)
    else:
        req = request
    out["request"] = req
    if kind == "round_trip":
        cur = o["constraints"]["max_amount"]["currency"]
        back = run.a.translate_back(xr, {"currency": cur})
        out["round_trip_answer"] = {k: v for k, v in back.items() if k != "original"}
        if back.get("original") is None:
            out["refused"] = back.get("refusal") or "reverse direction refused"
            return out
        try:
            o2 = run.ts.fmt.read_authority(back["original"], run.t_keys)
        except Exception as e:  # noqa: BLE001
            out["unreadable"] = f"O′: {type(e).__name__}: {e}"
            return out
        out["o_prime"] = o2
        c2 = o2.get("constraints") or {}
        sreq: Dict[str, Any] = {"request_id": _fresh("rq"), "at": run.now}
        if "max_amount" in c2:
            m2 = c2["max_amount"]
            if inside:
                mo = o["constraints"]["max_amount"]
                v = min(tr.int_value(m2["value"]), tr.int_value(mo["value"])) // 2
            else:
                v = tr.int_value(m2["value"])
            sreq["amount"] = {"value": v, "currency": m2["currency"],
                              "minor_units": m2["minor_units"]}
        sreq["operation"] = (c2.get("operations") or [None])[0]
        out["request"] = sreq
        out["enacted"] = run.Sp.enact(o2, sreq)
        out["effects"] = run.rec.for_request(sreq["request_id"])
        out["source_terms"] = True
        return out
    if out.get("unreadable"):
        return out
    out["enacted"] = run.Rp.enact(dec, req)
    out["effects"] = run.rec.for_request(req["request_id"])
    if not isinstance(img, tr.Refusal):
        out["image"] = img
    return out


def _w_in_T(run: _Run, w: Dict[str, Any], o: Dict[str, Any], ask: Dict[str, Any],
            kind: str) -> Dict[str, Any]:
    """W-in in topology T: a request inside the original, enacted by R′ under the translated form
    the target issued for W. Nothing is translated again."""
    tr = run.tr
    if not w.get("decoded") or w.get("unreadable"):
        return {"refused": w.get("refused") or "W was not translated"}
    img = tr.image(o, run.profile, run.sem, currency=(ask or {}).get("currency"))
    if isinstance(img, tr.Refusal):
        return {"refused": "no image"}
    if kind == "round_trip":
        o2 = w.get("o_prime")
        if not o2:
            return {"refused": "no O′"}
        m2 = (o2.get("constraints") or {}).get("max_amount")
        sreq: Dict[str, Any] = {"request_id": _fresh("rq"), "at": run.now,
                                "operation": ((o2.get("constraints") or {}).get("operations")
                                              or [None])[0]}
        if m2:
            mo = o["constraints"]["max_amount"]
            sreq["amount"] = {"value": min(tr.int_value(m2["value"]),
                                           tr.int_value(mo["value"])) // 2,
                              "currency": m2["currency"], "minor_units": m2["minor_units"]}
        return {"request": sreq, "enacted": run.Sp.enact(o2, sreq), "source_terms": True,
                "effects": run.rec.for_request(sreq["request_id"]), "image": img,
                "decoded": w["decoded"]}
    req = _base_request(run, img, o)
    return {"request": req, "enacted": run.Rp.enact(w["decoded"], req),
            "effects": run.rec.for_request(req["request_id"]), "image": img,
            "decoded": w["decoded"]}


def _present_R(run: _Run, claims: Dict[str, Any], x_members: Optional[Dict[str, Any]],
               req: Dict[str, Any], *, unbound: bool = False,
               again: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if again is not None:                      # W-in: W's own original and translated form
        raw, xr = again["original"], again["translated"]
        ans = run.a.present({"original": raw, "translated": xr, "request": req,
                             "at": req["at"]})
        out = {"original": raw, "translated": xr, "request": req, "answer": ans,
               "x_members": again.get("x_members")}
        if run.a.received() != raw:
            out["not_landed"] = "the original the target received differs from what A sent"
            return out
        out["effects"] = run.rec.for_request(req["request_id"])
        return out
    raw = run.A.issue(claims)
    if unbound:
        xr = run.Tp.unbound(x_members or {}, sub=claims.get("subject", ""), iat=run.now)
    elif x_members is None:
        xr = run.Tp.translate(claims, raw, run.profile, run.sem, iat=run.now)
        if isinstance(xr, run.tr.Refusal):
            return {"original": raw, "kit_refused": xr.detail}
    else:
        xr = run.Tp.translate_wider(claims, raw, x_members, iat=run.now)
    ans = run.a.present({"original": raw, "translated": xr, "request": req, "at": req["at"]})
    out: Dict[str, Any] = {"original": raw, "translated": xr, "request": req, "answer": ans}
    if run.a.received() != raw:
        out["not_landed"] = "the original the target received differs from what A sent"
        return out
    out["effects"] = run.rec.for_request(req["request_id"])
    return out


def _present_TR(run: _Run, claims: Dict[str, Any], req: Dict[str, Any], *,
                again: Optional[bytes] = None) -> Dict[str, Any]:
    raw = again if again is not None else run.A.issue(claims)
    ans = run.a.present({"original": raw, "request": req, "at": req["at"]})
    out: Dict[str, Any] = {"original": raw, "request": req, "answer": ans}
    if run.a.received() != raw:
        out["not_landed"] = "the original the target received differs from what A sent"
        return out
    out["effects"] = run.rec.for_request(req["request_id"])
    return out


def _outside(run: _Run, pres: Dict[str, Any], o: Dict[str, Any],
             x: Optional[Dict[str, Any]] = None) -> List[str]:
    """The dimensions where any effect of `pres` lies outside `o` (and, in R, outside the
    translated members `x`)."""
    tr = run.tr
    dims: List[str] = []
    for e in pres.get("effects") or []:
        got = tr.source_effect_outside(e, o) if pres.get("source_terms") else \
            tr.effect_outside(e, o, run.profile, tolerance=run.tol)
        dims += [d for d in got if d not in dims]
        if x is not None:
            why = run.ts.admits(x, e, run.profile, run.sem, tolerance=run.tol)
            if why and "translated" not in dims:
                dims.append("translated")
    return dims


# --------------------------------------------------------------------------- one trial


def _trial(run: _Run, variant: str, form: str, k: int) -> Tuple[Outcome, Dict[str, Any]]:
    tr = run.tr
    spec = _spec(run, variant, form)
    if spec.na:
        rd = "not_landed" if "not landed" in spec.na else "not_applicable"
        info = [NO_SEPARATING_PAIR] if spec.by_profile and rd == "not_applicable" else []
        return Outcome(rd, None, spec.na, info=info), {"na": spec.na}
    refuse = (variant, form) in REFUSE
    doc: Dict[str, Any] = {"W": {}, "L": {}, "W-in": {}}
    order = ["W", "L"]
    run.rng.shuffle(order)
    if not refuse:                 # W-in uses W's own translation, so it comes after W
        order.insert(run.rng.randint(order.index("W") + 1, len(order)), "W-in")
    res: Dict[str, Dict[str, Any]] = {}

    def predicted(o: Dict[str, Any], fallback: Dict[str, Any], ask: Dict[str, Any]
                  ) -> Dict[str, Any]:
        b = _image_or(run, o, fallback, currency=None)
        return spec.weak(o, b)

    if spec.kind == "cached":
        # O1, the wider original for the same subject, is translated before anything else in
        # the trial, so W, L and W-in all follow it whatever their order (KRK-M199).
        if run.topo == "T":
            first = _present_T(run, spec.first, spec.ask_w, spec.dims, inside=True)
        else:
            img1 = tr.image(spec.first, run.profile, run.sem)
            r1 = _edge(run, _base_request(run, img1, spec.first), img1, spec.first, spec.dims)
            first = _present_TR(run, spec.first, r1)
        doc["first"] = _doc(first)
    for which in order:
        o = spec.w if which in ("W", "W-in") else spec.l
        ask = spec.ask_w if which in ("W", "W-in") else spec.ask_l
        if run.topo == "T" and which == "W-in":
            res[which] = _w_in_T(run, res.get("W") or {}, o, ask, spec.kind)
        elif run.topo == "T":
            res[which] = _present_T(run, o, ask, spec.dims, kind=spec.kind)
            if which == "L" and res[which].get("request") is not None and \
                    res[which].get("decoded") and not res[which].get("source_terms"):
                req = res[which]["request"]
                if tr.effect_outside(req, o, run.profile, tolerance=run.tol):
                    img = tr.image(o, run.profile, run.sem, currency=ask.get("currency"))
                    if not isinstance(img, tr.Refusal):
                        inside_req = _base_request(run, img, o)
                        res[which] = _present_T(run, _fresh_subject(o), ask, spec.dims,
                                                request=inside_req, kind=spec.kind)
        else:
            img = tr.image(o, run.profile, run.sem, currency=ask.get("currency"))
            ok_img = not isinstance(img, tr.Refusal)
            base_members = img if ok_img else _image_or(run, spec.l, spec.l)
            if which == "W-in":
                w = res.get("W") or {}
                if not ok_img or not w.get("original"):
                    continue
                req = _base_request(run, img, o)
                if run.topo == "R":
                    res[which] = _present_R(run, o, None, req, again=w)
                else:
                    res[which] = _present_TR(run, o, req, again=w["original"])
                continue
            x = predicted(o, spec.l, ask) if which == "W" else base_members
            if which == "L" and spec.kind != "plain" and run.topo == "TR":
                x = base_members
            req = _edge(run, _base_request(run, base_members, o), x, o, spec.dims)
            if which == "L" and tr.effect_outside(req, o, run.profile, tolerance=run.tol):
                req = _base_request(run, base_members, o)
            if which == "W":
                outside = tr.effect_outside(req, o, run.profile, tolerance=run.tol)
                if not outside:
                    res[which] = {"draw_failed": "the W request drawn from the predicted weak "
                                                 "reading lies inside the original", "request": req}
                    continue
            if run.topo == "R":
                if which == "L":
                    res[which] = _present_R(run, o, None, req)
                else:
                    res[which] = _present_R(run, o, x, req, unbound=spec.kind == "unbound")
                    res[which]["x_members"] = x
            else:
                res[which] = _present_TR(run, o, req)
    for which, pres in res.items():
        doc[which] = _doc(pres)
    return _classify(run, variant, form, spec, res, refuse), doc


def _doc(pres: Dict[str, Any]) -> Dict[str, Any]:
    d = {k: v for k, v in pres.items() if k not in ("original", "translated")}
    for k in ("original", "translated"):
        if isinstance(pres.get(k), (bytes, bytearray)):
            d[f"{k}_bytes"] = pres[k].decode("ascii", "replace")
    return _jsonable(d)


def _accepted(pres: Dict[str, Any]) -> bool:
    return bool(pres.get("effects"))


def _classify(run: _Run, variant: str, form: str, spec: Spec, res: Dict[str, Dict[str, Any]],
              refuse: bool) -> Outcome:
    tr = run.tr
    for which in ("W", "L", "W-in"):
        p = res.get(which) or {}
        if p.get("not_landed"):
            return Outcome("not_landed", None, f"{which}: {p['not_landed']}")
        if p.get("error"):
            return Outcome("not_landed", None, f"{which}: the target could not be driven: "
                                               f"{p['error']}")
    w, l, wi = res.get("W") or {}, res.get("L") or {}, res.get("W-in") or {}
    if w.get("draw_failed"):
        return Outcome("draw_failed", None, w["draw_failed"])
    x_w = w.get("x_members") if run.topo == "R" else None
    dims = _outside(run, w, spec.w, x_w)
    if run.topo == "R" and x_w is not None:
        dims = [d for d in dims if d != "translated"] or dims
    if dims:
        return Outcome("outside_effect", False,
                       f"W: an effect outside the original in {', '.join(dims)}; request "
                       f"{_jsonable(w.get('request'))}", dims=dims)
    for which, p in (("L", l), ("W-in", wi)):
        if p.get("effects"):
            got = _outside(run, p, spec.l if which == "L" else spec.w)
            if got and "translated" not in got:
                return Outcome("outside_effect", False,
                               f"{which}: an effect outside the original in {', '.join(got)}",
                               dims=got)
    if w.get("unreadable") or l.get("unreadable"):
        return Outcome("unreadable_translation", None,
                       f"{w.get('unreadable') or l.get('unreadable')} (never read as narrowing, "
                       f"KRK-M191)")
    if not _accepted(l):
        why = l.get("refused") or (l.get("enacted") or {}).get("reason") or \
            (l.get("answer") or {}).get("reason") or l.get("kit_refused") or "no effect"
        return Outcome("collateral_refusal", None, f"L was not accepted: {why}")
    info: List[str] = []
    mode = "n/a"
    if not refuse and "W-in" in res:
        if _accepted(wi):
            mode = "exact"
            if run.topo == "T" and wi.get("decoded") and wi.get("image"):
                xm, im = wi["decoded"]["members"], wi["image"]
                narrower = [m for m in im if m in xm and xm[m] != im[m]]
                mode = "clamped" if narrower else "exact"
                if variant == "rounding" and narrower:
                    info.append("stricter_rounding")
        else:
            mode = "refused"
            if variant == "rounding":
                info.append("stricter_rounding")
    if run.topo == "T" and l.get("decoded"):
        stated = set((spec.l.get("constraints") or {}))
        extra = [m for m in l["decoded"]["members"]
                 if run.fields.get(m) in tr.SOURCE_MEMBERS and run.fields[m] not in stated]
        if extra:
            info.append("defaulted_narrower")
    detail = "no effect outside the original" + (f"; W refused: {w.get('refused')}"
                                                 if w.get("refused") else "")
    return Outcome("held", True, detail, mode=mode, info=info)


# --------------------------------------------------------------------------- the control


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    """§4.1: an honest original inside every carried dimension, one fresh request inside it, one
    effect at the recorder. Never requires a refusal, a conversion or a narrowing (KRK-M19)."""
    tr = run.tr
    o = _base_claims(run)
    img = tr.image(o, run.profile, run.sem)
    if isinstance(img, tr.Refusal):
        return False, f"the kit's image of the control original is refused ({img.detail}); the " \
                      f"profile does not map the control's dimensions", {}
    req = _base_request(run, img, o)
    unique, _single = _control_ops(run)
    from_issued = run.carries("operations") and not unique
    op_doc: Dict[str, Any] = {"operation": (o.get("constraints") or {}).get("operations"),
                              "unique": bool(unique) or not run.carries("operations")}
    if not from_issued:
        op_doc["drawn_from"] = ("a source value only one target value realises"
                                if run.carries("operations") else "the format carries none")
    elif run.topo == "T":
        op_doc["drawn_from"] = "the translated form the target issued"
    elif run.topo == "R":
        op_doc["drawn_from"] = "the translated form the kit's T′ signed (the kit's faithful image)"
    else:
        op_doc["drawn_from"] = ("the kit's image of the original (a system that maps and acts "
                                "shows no translated form)")
    run.control_op = op_doc
    if run.topo == "T":
        # With no unique operation, the request is drawn from what the target issued.
        p = _present_T(run, o, {}, [], inside=True, request=None if from_issued else req,
                       from_issued=from_issued)
        if not p.get("effects") and p.get("decoded") and not p.get("unreadable"):
            # A translator that issued narrower than the image: a request inside both.
            alt = _base_request(run, p["decoded"]["members"], o)
            if not tr.effect_outside(alt, o, run.profile, tolerance=run.tol):
                p["enacted"] = run.Rp.enact(p["decoded"], alt)
                p["request"] = alt
                p["effects"] = run.rec.for_request(alt["request_id"])
    elif run.topo == "R":
        p = _present_R(run, o, None, req)
    else:
        p = _present_TR(run, o, req)
    doc = _doc(p)
    if p.get("not_landed"):
        return False, p["not_landed"], doc
    if p.get("error"):
        return False, f"the target could not be driven: {p['error']}", doc
    if run.topo == "T" and p.get("refused"):
        return False, f"the target issued no translated form for an honest original " \
                      f"({p['refused']})", doc
    if p.get("unreadable"):
        return False, f"the translated form could not be read: {p['unreadable']}", doc
    effects = p.get("effects") or []
    if len(effects) != 1:
        return False, f"{len(effects)} effects reached the recorder for the control request " \
                      f"(expected 1)", doc
    outside = _outside(run, p, o)
    if outside:
        return False, f"the control's effect lies outside its own original ({outside})", doc
    words = "" if op_doc["unique"] else (
        f"; no source value only one target value realises, so its operation was drawn from "
        f"{op_doc['drawn_from']}")
    return True, f"topology {run.topo}: one effect for an honest original inside every " \
                 f"carried dimension; the target's answers were read through the adapter{words}", doc


# --------------------------------------------------------------------------- the probe


def _statements(a: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    from .. import translation as tr
    topo = _call(a, "topology")
    if topo not in tr.TOPOLOGIES:
        return None, f"unknown topology {topo!r}"
    tp = _call(a, "translation_profile")
    if not isinstance(tp, dict) or not isinstance(tp.get("profile"), dict):
        return None, "the target states no translation profile (the kit never supplies one, " \
                     "KRK-M190)"
    prob = tr.profile_problem(tp["profile"])
    if prob:
        return None, f"the declared profile is malformed: {prob}"
    sem = _call(a, "translated_profile")
    prob = tr.semantics_problem(sem, tp["profile"])
    if prob:
        return None, f"the translated format's semantics cannot be read: {prob} (KRK-M197, M203)"
    grade = _call(a, "evidence_grade")
    if grade not in GRADES_OF[topo]:
        return None, f"evidence grade {grade!r} is not one topology {topo} is read at"
    st = {"topology": topo, "profile": copy.deepcopy(tp["profile"]),
          "digest": tr.profile_digest(tp["profile"]), "profile_owner": tp.get("owner"),
          "profile_quote": tp.get("quote"), "semantics": copy.deepcopy(sem),
          "configuration": dict(_call(a, "configuration", {}) or {}),
          "tolerance": int(_call(a, "clock_tolerance_s", 0) or 0), "grade": grade,
          "rate_source": _call(a, "rate_source", "profile"),
          "original_visible": _call(a, "original_visible"),
          "advisory": dict(_call(a, "advisory_members", {}) or {})}
    return st, ""


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import translation as tr
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    try:
        st, why = _statements(a)
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    if st is None:
        return Result.inconclusive(a.name, ID, why, **common)
    if getattr(a, "clock", "real") == "virtual" and not _is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock", **common)
    plan = dict(plan if plan is not None else ({} if _is_toy(a) else (_plan_from_env() or {})))
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    run = _Run(a, ev, rng, st)
    ctx = {"a_keys": run.A.public(), "receiver": run.receiver, "profile_digest": run.digest}
    if run.topo in ("R", "TR"):
        ctx["recorder"] = run.rec
    if run.topo == "R":
        ctx["translator_keys"] = run.Tp.public()
    try:
        a.prepare(ctx)
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"prepare raised {type(e).__name__}: {e}",
                                   **common)
    run.log("start", seed=seed, topology=run.topo, profile_digest=run.digest,
            statements={k: v for k, v in st.items() if k not in ("profile",)})
    ev.write("statements.json", _jsonable({**st, "seed": seed}))
    try:
        held, control, cdoc = _control(run)
    except Exception as e:  # noqa: BLE001
        held, control, cdoc = False, f"the control raised {type(e).__name__}: {e}", {}
    run.log("control", held=held, detail=control, presentation=cdoc)
    extra: Dict[str, Any] = {"seed": seed, "topology": run.topo, "evidence_grade": st["grade"],
                             "profile_digest": run.digest, "profile_owner": st["profile_owner"],
                             "rate_source": st["rate_source"]}
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {control}",
                                   control_detail=control, extra=extra, **common)
    checks: List[Check] = [Check("control", "held", True, control)]
    variants = [v for v in TOPOLOGY_VARIANTS[run.topo] if v in (plan.get("variants") or VARIANTS)]
    if run.topo == "R" and not st["original_visible"]:
        skipped_two = "the target receives no original, so a receiver of both forms cannot be " \
                      "graded (KRK-M202)"
    else:
        skipped_two = ""
    work = [(v, f) for v in variants for f in FORMS[v]]
    rng.shuffle(work)
    na_stated = dict(_call(a, "forms_not_applicable", {}) or {})
    documented = dict(_call(a, "documented_widenings", {}) or {})
    readings: Dict[str, Dict[str, Any]] = {}
    modes: Dict[str, set] = {}
    classes: Dict[str, Dict[str, Any]] = {}
    documents = bool(_call(a, "documents_preserving", False))
    n = _trials(plan)
    for v, f in work:
        fid = f"{v}/{f}"
        if v == "two_forms" and skipped_two:
            readings.setdefault(v, {})[f] = {"reading": "not_landed", "ok": None,
                                             "detail": skipped_two}
            continue
        if fid in na_stated and (v, f) not in NA_FORBIDDEN:
            readings.setdefault(v, {})[f] = {"reading": "not_applicable", "ok": None,
                                             "detail": na_stated[fid]}
            continue
        outs: List[Outcome] = []
        docs: List[Dict[str, Any]] = []
        for k in range(n):
            try:
                o, d = _trial(run, v, f, k)
            except Exception as e:  # noqa: BLE001
                o, d = Outcome("inconclusive", None, f"the trial raised {type(e).__name__}: "
                                                     f"{e}"), {}
            outs.append(o)
            docs.append({"k": k, "outcome": o.to_doc(), "presentations": d})
            run.log("trial", form=fid, k=k, outcome=o.to_doc())
            if o.reading == "not_applicable":
                break
        ev.write(f"{v}-{f}.json", _jsonable({"form": fid, "trials": docs}))
        fails = [o for o in outs if o.ok is False]
        counted = [o for o in outs if o.ok is not None]
        info = sorted({i for o in outs for i in o.info})
        if fails:
            pat = next((p for p in documented if _matches(p, fid)), None)
            if pat:
                r = {"reading": "documented_widening", "ok": None,
                     "detail": f"{fails[0].detail}; documented: {documented[pat]}"}
            else:
                r = {"reading": "outside_effect", "ok": False, "detail": fails[0].detail,
                     "dimension": fails[0].dims}
                classes[fid] = {"class": "vulnerability" if documents else "conformance",
                                "bound": f"the original's {', '.join(fails[0].dims)}"}
        elif counted and all(o.ok for o in counted):
            r = {"reading": "held", "ok": True, "detail": counted[0].detail}
            m = sorted({o.mode for o in counted if o.mode != "n/a"})
            if m:
                modes.setdefault(v, set()).update(m)
                r["modes"] = m
        else:
            infos = [o.reading for o in outs]
            r = {"reading": max(sorted(set(infos)), key=infos.count), "ok": None,
                 "detail": outs[0].detail if outs else ""}
        r.update(trials=len(outs), counted=len(counted))
        if info:
            r["info"] = info
        readings.setdefault(v, {})[f] = r
    for v in VARIANTS:
        fr = readings.get(v)
        if not fr:
            continue
        parts = "; ".join(f"{k}: {d['reading']}" for k, d in sorted(fr.items()))
        fails = [(k, d) for k, d in sorted(fr.items()) if d["ok"] is False]
        passes = [(k, d) for k, d in fr.items() if d["ok"] is True]
        if fails:
            k, d = fails[0]
            checks.append(Check(v, d["reading"], False, f"{k}: {d['detail']}; {parts}"))
        elif passes:
            m = sorted(modes.get(v, set()))
            checks.append(Check(v, "held", True, parts + (f"; mode {'/'.join(m)}" if m else "")))
        else:
            checks.append(Check(v, next(iter(fr.values()))["reading"], None, parts))
    try:
        end = _call(a, "translation_profile") or {}
        moved = tr.profile_digest(end.get("profile") or {}) != run.digest
    except Exception:  # noqa: BLE001
        moved = True
    unclaimed = _not_claimed_ids(a)
    must: List[str] = []
    na_by_profile: List[str] = []
    for x in NA_FORBIDDEN:
        if isinstance(x, str):
            continue
        v, f = x
        if v not in variants:
            continue
        fid = f"{v}/{f}"
        if any(_matches(p, fid) for p in unclaimed):
            continue
        d = readings.get(v, {}).get(f)
        if (v, f) in NA_BY_PROFILE and d is not None and d["reading"] == "not_applicable" \
                and NO_SEPARATING_PAIR in (d.get("info") or []):
            na_by_profile.append(fid)        # present, with the probe's reason
            continue
        if d is None or d["ok"] is None:
            must.append(fid)
    t_words = ("Graded at translated-signed: the translated forms this translator issued, "
               "enacted by the kit's faithful receiver R′ (not end to end, KRK-M201)"
               if run.topo == "T" else f"Graded at {st['grade']} in topology {run.topo}")
    not_carried = sorted(m for m in tr.CARRIABLE if not run.carries(m))
    extra.update({"forms": readings, "must_land_missed": must,
                  "modes": {k: sorted(v) for k, v in modes.items()},
                  "disclosure": "vulnerability" if documents and classes else "conformance",
                  "disclosure_forms": classes, "documents_preserving": documents,
                  "dimensions_not_carried": not_carried,
                  "level": "library" if st["grade"] == "library-decision" else "deployed",
                  "progress": os.path.relpath(run.progress.path, ev.dir),
                  "kit_parties": {"a": run.A.issuer, "t_prime": run.Tp.id,
                                  "receiver": run.receiver},
                  "originals_issued": len(run.A.issued),
                  "control_operation": getattr(run, "control_op", None),
                  "not_applicable_by_profile": na_by_profile})
    if plan:
        extra["plan"] = plan
    gaps = f" Dimensions the target's format cannot carry: {', '.join(not_carried)}." \
        if not_carried else ""
    if na_by_profile:
        gaps += (f" Not applicable, because no declared pair separates them: "
                 f"{', '.join(sorted(na_by_profile))}.")
    cop = getattr(run, "control_op", None) or {}
    if cop and not cop.get("unique"):
        gaps += f" The control's operation was drawn from {cop.get('drawn_from')}."
    fails = [c for c in checks if c.ok is False]
    if moved:
        r = Result.inconclusive(a.name, ID, f"{t_words}. The declared profile changed during the "
                                f"run (KRK-M190, M194); no verdict.", checks=checks,
                                control_held=True, control_detail=control, extra=extra, **common)
    elif not fails and must:
        r = Result.inconclusive(a.name, ID, f"{t_words}. No form failed, but forms that must land "
                                f"did not: {must}.{gaps}", checks=checks, control_held=True,
                                control_detail=control, extra=extra, **common)
    else:
        r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                    pass_summary=f"{t_words}: no effect outside the original, read in its own "
                                 f"terms through the declared profile.{gaps}",
                    fail_summary=f"{t_words}: an effect lay outside the original", extra=extra,
                    **common)
    run.log("end", status=r.status.value, summary=r.summary)
    return r
