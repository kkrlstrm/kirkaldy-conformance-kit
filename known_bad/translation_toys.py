"""Known-bad toys for P26 (KRK-26, the ceiling survives translation).

`X11-TRANSLATION-DESIGN.md` §4.5. One toy translator and receiver, `ToyTranslation`, run in any of
the three topologies (T, R, TR) with a real recorder path (the kit's recorder in R and TR; the
kit's faithful receiver R′ in T):

- ``good``: computes the image from the declared profile in exact rational arithmetic; refuses an
  unmapped value, a missing rate, a constraint its format cannot carry and a member it cannot
  parse; never reads its own defaults where the original states a member; keys its cache by the
  original's digest; as R, enforces both forms and the binding between them.
- ``good-strict``: as ``good``, but refuses any translation that needs a rate other than 1 or any
  rounding (mode ``refused``).
- one ``bad:<flaw>`` per flaw in `FLAWS`, each a behaviour of the toy's own translator or receiver,
  never a member deleted from what the toy was sent (KRK-M47);
- ``no-control``: in T its translation endpoint never answers; in R and TR it answers but its
  executor never reaches the recorder.

A configuration names its topology after ``@``: ``good@T``, ``bad:face_value@TR``. The toys'
correct path uses `fractions.Fraction` only; the one floating-point computation is the
``float_convert`` flaw itself.

The toy's target format is the kit's ``kirkaldy.translated/0.1`` (`translation_formats`), with the
member semantics in `TOY_SEMANTICS` and the profile in `TOY_PROFILE`; the toy states both before
a run, as a target would. Its configuration (`TOY_CONFIGURATION`) states the defaults a flawed
toy reads: an extra audience, a lifetime and a fallback amount.
"""
from __future__ import annotations

import copy
import json
import math
import secrets
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

from conformance import translation_formats as fmt
from conformance.receipts import Keypair
from conformance.result import Status

TOPOLOGIES = ("T", "R", "TR")
FLAWS = {
    "face_value": "currency", "built_in_rate": "currency", "rate_backwards": "currency",
    "asset_unchecked": "currency",
    "two_minor_units": "units", "six_decimals": "units", "seconds_as_ms": "units",
    "unit_name_ignored": "units",
    "round_nearest": "rounding", "float_convert": "rounding",
    "translate_what_maps": "dropped_constraint", "advisory_ok": "dropped_constraint",
    "crit_ignored": "dropped_constraint", "skips_member": "dropped_constraint",
    "copy_unmapped": "unmappable", "widest_image": "unmappable", "lexical_match": "unmappable",
    "default_fill": "partial", "fallback_on_error": "partial",
    "default_lifetime": "window", "ttl_from_issue": "window", "valid_from_zero": "window",
    "grants_requested": "scope", "audience_from_config": "scope", "prefix_widened": "scope",
    "round_trip_drift": "retranslation", "stage_rounds_up": "retranslation",
    "cache_by_subject": "retranslation",
    "translated_only": "two_forms", "binding_only": "two_forms",
}
"""Each flaw and the variant it is built to fail (design §3.1's last column)."""
VARIANT_TOPOLOGIES = {"currency": ("T", "R", "TR"), "units": ("T", "TR"),
                      "rounding": ("T", "TR"), "dropped_constraint": ("T", "TR"),
                      "unmappable": ("T", "TR"), "partial": ("T", "TR"),
                      "window": ("T", "R", "TR"), "scope": ("T", "TR"),
                      "retranslation": ("T", "TR"), "two_forms": ("R",)}
NOT_IN = {("round_trip_drift", "TR"): "a system that maps and acts exposes no reverse direction"}
PARTNER = "did:web:partner.example"
LIFETIME_S = 3600
FALLBACK = {"value": 1_000_000_000, "currency": "USD", "minor_units": 2}
BUILTIN = {"SEK": Fraction(1, 10), "NOK": Fraction(1, 10)}
"""The rates the ``built_in_rate`` toy carries in its own code, never declared in the profile."""
INTERNAL_DECIMALS = 6
"""The precision of the toy's internal stage (``retranslation/staged``)."""


def _pair(sc: str, sm: int, tc: str, tm: int, num: int, den: int) -> Dict[str, Any]:
    return {"source": {"currency": sc, "minor_units": sm},
            "target": {"currency": tc, "minor_units": tm}, "rate": {"num": num, "den": den}}


TOY_PROFILE: Dict[str, Any] = {
    "schema": "kirkaldy.translation-profile/0.1",
    "source": fmt.SOURCE, "target": fmt.TARGET,
    "fields": {"limit": "max_amount", "floor": "min_amount", "quota": "max_count",
               "scope": "operations", "paths": "resources", "aud": "audience",
               "pay_to": "payee", "nbf": "not_before", "exp": "not_after",
               "regions_hint": "regions"},
    "values": {"operations": {"contacts:read": ["read"], "contacts:update": ["update"],
                              "contacts:delete": ["delete"],
                              "contacts:write": ["update", "delete"],
                              "contacts:export": ["export"], "contacts:archive": ["delete"]}},
    "amounts": [_pair("USD", 2, "USD", 2, 1, 1), _pair("EUR", 2, "USD", 2, 108, 100),
                _pair("CHF", 2, "USD", 2, 7, 10), _pair("KWD", 3, "USD", 2, 33, 10),
                _pair("GBP", 2, "JPY", 0, 190, 1), _pair("DAI", 18, "USD", 2, 1, 1),
                _pair("SGD", 2, "USD", 2, 6305039478318693, 9007199254740991)],
    "counts": [{"source": "message", "target": "batch", "rate": {"num": 1, "den": 10}},
               {"source": "batch", "target": "batch", "rate": {"num": 1, "den": 1}}],
    "time": {"target_unit": "s", "basis": "absolute"},
    "unmapped": "refuse",
}
_DOC = "kirkaldy.translated/0.1, toy documentation"
TOY_SEMANTICS: Dict[str, Dict[str, Any]] = {
    **{m: {"semantics": "enforced", "absent": "unbounded",
           "quote": f"{m}: enforced by every receiver; when absent, the form does not constrain "
                    f"that dimension"}
       for m in ("limit", "floor", "quota", "scope", "paths", "aud", "pay_to", "nbf", "exp")},
    "regions_hint": {"semantics": "informational",
                     "quote": "regions_hint: informational; receivers do not enforce it"},
    "ext": {"semantics": "ignorable_extension",
            "quote": "ext: extensions; a receiver ignores members it does not understand"},
}
TOY_CONFIGURATION = {"name": "toy-default",
                     "defaults": {"audience_extra": [PARTNER], "lifetime_s": LIFETIME_S,
                                  "fallback_amount": FALLBACK}}


class Refused(Exception):
    """The toy refuses to translate, or to commit."""


def topologies_of(flaw: str) -> Tuple[str, ...]:
    return tuple(t for t in VARIANT_TOPOLOGIES[FLAWS[flaw]] if (flaw, t) not in NOT_IN)


def cases() -> List[Tuple[str, str]]:
    """Every toy configuration of P26 and its required outcome (`knownbad.cases`)."""
    out: List[Tuple[str, str]] = []
    for t in TOPOLOGIES:
        out += [(f"good@{t}", Status.PASS.value), (f"good-strict@{t}", Status.PASS.value),
                (f"no-control@{t}", Status.INCONCLUSIVE.value)]
        out += [(f"bad:{f}@{t}", Status.FAIL.value) for f in FLAWS if t in topologies_of(f)]
    return out


def toy(config: str) -> "ToyTranslation":
    body, _, topo = config.partition("@")
    topo = topo or "T"
    if body.startswith("bad:"):
        return ToyTranslation("bad", body.split(":", 1)[1], topo)
    return ToyTranslation(body, None, topo)


def _parse(v: Any) -> Optional[int]:
    """The toy's amount parser: a string of decimal digits only (the source format also allows a
    JSON integer, which this parser does not take)."""
    if isinstance(v, str) and v.isdigit() and (v == "0" or v[0] != "0"):
        return int(v)
    return None


def _up(p: str) -> str:
    """A resource pattern one level up: ``a/b/c/*`` -> ``a/b/*``; an id ``a/b/c`` -> ``a/b/*``."""
    stem = p[:-2] if p.endswith("/*") else p
    parent = stem.rsplit("/", 1)[0]
    return f"{parent}/*"


def _covers(p: str, rid: str) -> bool:
    return rid.startswith(p[:-1]) and rid != p[:-1] if p.endswith("/*") else p == rid


class ToyTranslation:
    """A toy translator and receiver of `TOY_PROFILE`, in one topology."""

    clock = "virtual"

    def __init__(self, base: str, flaw: Optional[str] = None, topology: str = "T") -> None:
        if topology not in TOPOLOGIES:
            raise ValueError(f"unknown topology {topology!r}")
        if flaw is not None and flaw not in FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.base, self.flaw, self.topo = base, flaw, topology
        self.name = "toy-translation"
        self.config = f"{base}{':' + flaw if flaw else ''}@{topology}"
        self.strict = base == "good-strict"
        self.id = "did:web:toy-translator.example"
        self.key = Keypair.generate(f"toy-{secrets.token_hex(4)}")
        self.ctx: Dict[str, Any] = {}
        self._received: Optional[bytes] = None
        self._stages: List[Dict[str, Any]] = []
        self._cache: Dict[Any, Any] = {}

    # ------------------------------------------------------------------ statements

    def version(self) -> str:
        return "toy"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P26": "toy: a translated form admits only what the original admits"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def topology(self) -> str:
        return self.topo

    def evidence_grade(self) -> str:
        return "translated-signed" if self.topo == "T" else "recorder"

    def translation_profile(self) -> Dict[str, Any]:
        return {"profile": copy.deepcopy(TOY_PROFILE), "owner": self.id,
                "quote": "the toy's declared profile", "url": "known_bad/translation_toys.py"}

    def translated_profile(self) -> Dict[str, Any]:
        return copy.deepcopy(TOY_SEMANTICS)

    def advisory_members(self) -> Dict[str, str]:
        return {"regions_hint": TOY_SEMANTICS["regions_hint"]["quote"]}

    def rate_source(self) -> str:
        return "profile"

    def original_visible(self) -> Optional[str]:
        return "original" if self.topo == "R" else None

    def configuration(self) -> Dict[str, Any]:
        return copy.deepcopy(TOY_CONFIGURATION)

    def clock_tolerance_s(self) -> int:
        return 0

    def keys(self) -> Dict[str, Any]:
        return {"translator": {self.key.kid: self.key.public_bytes()}}

    def documents_preserving(self) -> bool:
        return False

    def documents_stages(self) -> bool:
        return True

    def forms_not_applicable(self) -> Dict[str, str]:
        return {"retranslation/round_trip": NOT_IN[("round_trip_drift", "TR")]} \
            if self.topo == "TR" else {}

    def prepare(self, ctx: Dict[str, Any]) -> None:
        self.ctx = dict(ctx)

    def received(self) -> Optional[bytes]:
        return self._received

    def stages(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self._stages)

    def read_translated(self, raw: bytes) -> Dict[str, Any]:
        return fmt.read_translated(raw, {self.key.kid: self.key.public_bytes(),
                                         **(self.ctx.get("translator_keys") or {})})

    # ------------------------------------------------------------------ the translator

    def _amount(self, a: Dict[str, Any], bound: str, ask: Dict[str, Any]) -> Dict[str, Any]:
        f = self.flaw
        v = _parse(a.get("value"))
        if v is None:
            if f == "fallback_on_error" and bound == "max":
                return dict(FALLBACK)
            raise Refused(f"amount value {a.get('value')!r} does not parse")
        cur, mu = a["currency"], a["minor_units"]
        pair = next((p for p in TOY_PROFILE["amounts"] if p["source"]["currency"] == cur), None)
        if pair is None:
            if f == "built_in_rate" and cur in BUILTIN:
                rate, smu, tcur, tmu = BUILTIN[cur], mu, "USD", 2
            else:
                raise Refused(f"no declared rate from {cur}")
        else:
            rate = Fraction(pair["rate"]["num"], pair["rate"]["den"])
            smu, tcur, tmu = pair["source"]["minor_units"], pair["target"]["currency"], \
                pair["target"]["minor_units"]
            if f == "two_minor_units":
                smu = 2                                  # assumes every currency has two
            elif f == "six_decimals" and mu > 4:
                smu = 6                                  # assumes every token has six
            elif mu != smu:
                raise Refused(f"{cur} with {mu} minor units is not the profile's {smu}")
        if f == "rate_backwards":
            rate = 1 / rate
        if ask.get("currency") and ask["currency"] != tcur:
            if f != "asset_unchecked":
                raise Refused(f"asked for {ask['currency']}; the profile maps {cur} to {tcur}")
            tcur = ask["currency"]
        if f == "face_value":
            value = v
            self._stages = [{"stage": "outward", "value": value}]
            return {"value": value, "currency": tcur, "minor_units": tmu}
        exact = Fraction(v) * rate * Fraction(10) ** (tmu - smu)
        if self.strict and (rate != 1 or exact.denominator != 1):
            raise Refused("strict: refuses a translation that needs a rate or rounding")
        if f == "round_nearest":
            value = math.floor(exact + Fraction(1, 2))
        elif f == "float_convert" and bound == "max":
            r = pair["rate"] if pair else {"num": rate.numerator, "den": rate.denominator}
            value = math.floor(float(v) * (float(r["num"]) / float(r["den"]))
                               * (10.0 ** (tmu - smu)))
        else:
            scale = Fraction(10) ** INTERNAL_DECIMALS
            internal = math.floor(exact * scale) if bound == "max" else math.ceil(exact * scale)
            outward = Fraction(internal) / scale
            if bound == "max":
                value = math.ceil(outward) if f == "stage_rounds_up" else math.floor(outward)
            else:
                value = math.ceil(outward)
            self._stages = [{"stage": "internal", "value": internal,
                             "decimals": tmu + INTERNAL_DECIMALS, "currency": tcur},
                            {"stage": "outward", "value": value, "decimals": tmu,
                             "currency": tcur}]
        return {"value": value, "currency": tcur, "minor_units": tmu}

    def _translate(self, o: Dict[str, Any], ask: Dict[str, Any], now: int) -> Dict[str, Any]:
        """The toy's translated members for original claims `o`; raises `Refused`."""
        f = self.flaw
        c = o.get("constraints") or {}
        known = {"max_amount", "min_amount", "max_count", "operations", "resources", "audience",
                 "payee", "categories", "regions", "channels"}
        if set(c) - known:
            raise Refused(f"unknown constraint members {sorted(set(c) - known)}")
        out: Dict[str, Any] = {}
        ext: Dict[str, Any] = {}
        if "max_amount" in c:
            out["limit"] = self._amount(c["max_amount"], "max", ask)
        if "min_amount" in c:
            out["floor"] = self._amount(c["min_amount"], "min", ask)
        if "max_count" in c:
            mc = c["max_count"]
            if f == "unit_name_ignored":
                out["quota"] = {"value": mc["value"], "unit": "batch"}
            else:
                pair = next((p for p in TOY_PROFILE["counts"] if p["source"] == mc["unit"]),
                            None)
                if pair is None:
                    raise Refused(f"no declared relation from unit {mc['unit']!r}")
                rate = Fraction(pair["rate"]["num"], pair["rate"]["den"])
                if self.strict and rate != 1:
                    raise Refused("strict: refuses a count conversion")
                out["quota"] = {"value": math.floor(mc["value"] * rate), "unit": pair["target"]}
        if "operations" in c:
            table = TOY_PROFILE["values"]["operations"]
            ops = set(c["operations"])
            chosen = set()
            for op in sorted(ops):
                cands = sorted(tv for tv, svs in table.items() if op in svs)
                if not cands:
                    if f == "copy_unmapped":
                        chosen.add(op)
                        continue
                    if f == "lexical_match":
                        near = [tv for tv in table if tv.rsplit(":", 1)[-1] == op]
                        if near:
                            chosen.add(near[0])
                            continue
                    raise Refused(f"operation {op!r} has no entry in the profile")
                if f == "widest_image":
                    chosen.add(max(cands, key=lambda tv: (len(table[tv]), tv)))
                    continue
                ok = [tv for tv in cands if set(table[tv]) <= ops]
                if not ok:
                    raise Refused(f"no target value realises {op!r} within the original")
                chosen.update(ok)
            if f == "grants_requested":
                chosen.update(ask.get("operations") or [])
            out["scope"] = sorted(chosen)
        if "resources" in c and f != "skips_member":
            out["paths"] = [_up(p) if f == "prefix_widened" else p for p in c["resources"]]
        aud = list(c["audience"]) if "audience" in c else None
        if f == "default_fill":
            aud = [self.ctx.get("receiver", ""), *TOY_CONFIGURATION["defaults"]["audience_extra"]]
        elif f == "audience_from_config" and aud is not None:
            aud = sorted(set(aud) | set(TOY_CONFIGURATION["defaults"]["audience_extra"]))
        if aud is not None:
            out["aud"] = aud
        if "payee" in c:
            out["pay_to"] = c["payee"]
        k = 1000 if o.get("time_unit", "s") == "ms" else 1
        na, nb = o.get("not_after"), o.get("not_before")
        if na is not None:
            if f == "seconds_as_ms":
                exp = na                                 # the number copied across units
            else:
                if self.strict and na % k:
                    raise Refused("strict: refuses a time that needs rounding")
                exp = na // k
            nbf = None
            if nb is not None:
                nbf = nb if f == "seconds_as_ms" else -((-nb) // k)
            if f == "default_lifetime":
                exp = max(exp, now + LIFETIME_S)
            elif f == "ttl_from_issue":
                exp = now + (exp - nbf) if nbf is not None else now + LIFETIME_S
            if f == "valid_from_zero":
                nbf = 0
            out["exp"] = exp
            if nbf is not None:
                out["nbf"] = nbf
        for m, has_info in (("categories", False), ("regions", True), ("channels", False)):
            if m not in c:
                continue
            if f == "translate_what_maps":
                continue
            if f == "advisory_ok" and has_info:
                out["regions_hint"] = list(c[m])
                continue
            if f == "crit_ignored":
                ext[m] = list(c[m])
                continue
            raise Refused(f"{m}: the target format has no enforced member for it")
        if ext:
            out["ext"] = ext
        return out

    def _members(self, o: Dict[str, Any], raw: bytes, ask: Dict[str, Any], now: int
                 ) -> Dict[str, Any]:
        if self.flaw == "cache_by_subject":
            key: Any = ("subject", o.get("subject"))
        else:
            key = (fmt.digest(raw), json.dumps(ask, sort_keys=True), now)
        if key in self._cache:
            return copy.deepcopy(self._cache[key])
        got = self._translate(o, ask, now)
        self._cache[key] = copy.deepcopy(got)
        return got

    def _original(self, raw: bytes) -> Dict[str, Any]:
        try:
            return fmt.read_authority(raw, self.ctx.get("a_keys") or {})
        except fmt.BadToken as e:
            raise Refused(f"original does not verify: {e}")

    def translate(self, raw: bytes, ask: Dict[str, Any]) -> Dict[str, Any]:
        """Topology T: translate `raw` for the agent's `ask`."""
        self._received = raw
        if self.base == "no-control":
            return {"translated": None, "refusal": None,
                    "error": "the translation endpoint did not answer"}
        self._stages = []
        try:
            o = self._original(raw)
            members = self._members(o, raw, ask, int(ask.get("at", 0)))
        except Refused as e:
            return {"translated": None, "refusal": str(e)}
        token = fmt.write_translated(members, self.key, issuer=self.id,
                                     sub=o.get("subject", ""), orig=fmt.digest(raw),
                                     iat=int(ask.get("at", 0)), token_id=f"tx-{secrets.token_hex(8)}")
        return {"translated": token, "refusal": None}

    def translate_back(self, raw: bytes, ask: Dict[str, Any]) -> Dict[str, Any]:
        """Topology T: the reverse direction, a translated form back to the source format."""
        try:
            d = self.read_translated(raw)
        except fmt.BadToken as e:
            return {"original": None, "refusal": f"does not verify: {e}"}
        m = d["members"]
        cons: Dict[str, Any] = {}
        if "limit" in m:
            cur = ask.get("currency")
            pair = next((p for p in TOY_PROFILE["amounts"] if p["source"]["currency"] == cur
                         and p["target"]["currency"] == m["limit"]["currency"]), None)
            if pair is None:
                return {"original": None, "refusal": "no declared pair for the reverse direction"}
            smu, tmu = pair["source"]["minor_units"], pair["target"]["minor_units"]
            exact = Fraction(m["limit"]["value"]) / Fraction(pair["rate"]["num"],
                                                             pair["rate"]["den"]) \
                * Fraction(10) ** (smu - tmu)
            if self.flaw == "round_trip_drift":
                major = Fraction(10) ** smu
                value = math.ceil(exact / major) * int(major)   # up, to a whole major unit
            else:
                value = math.floor(exact)
            cons["max_amount"] = {"value": str(value), "currency": cur, "minor_units": smu}
        if "scope" in m:
            table = TOY_PROFILE["values"]["operations"]
            cons["operations"] = sorted({s for tv in m["scope"] for s in table.get(tv, [])})
        if "paths" in m:
            cons["resources"] = list(m["paths"])
        if "aud" in m:
            cons["audience"] = list(m["aud"])
        if "pay_to" in m:
            cons["payee"] = m["pay_to"]
        claims: Dict[str, Any] = {"issuer": self.id, "subject": d.get("sub"),
                                  "authority_id": f"au-{secrets.token_hex(8)}",
                                  "constraints": cons, "time_unit": "s"}
        if "exp" in m:
            claims["not_after"] = m["exp"]
        if "nbf" in m:
            claims["not_before"] = m["nbf"]
        return {"original": fmt.write_round_trip(claims, self.key), "refusal": None}

    # ------------------------------------------------------------------ the receiver

    def _admits(self, members: Dict[str, Any], req: Dict[str, Any]) -> Optional[str]:
        """The toy's own reading of its format (`TOY_SEMANTICS`)."""
        a = req.get("amount")
        for m, cmp in (("limit", lambda x, y: x <= y), ("floor", lambda x, y: x >= y)):
            if m in members:
                lim = members[m]
                if a is None or (self.flaw != "asset_unchecked" and
                                 (a["currency"] != lim["currency"]
                                  or a["minor_units"] != lim["minor_units"])):
                    return f"{m}: amount in another currency"
                if not cmp(int(a["value"]), lim["value"]):
                    return f"{m}: amount outside"
        if "quota" in members:
            q, c = members["quota"], req.get("count")
            if c is None or c["unit"] != q["unit"] or c["value"] > q["value"]:
                return "quota"
        if "scope" in members and req.get("operation") not in members["scope"]:
            return "scope"
        if "paths" in members and not any(_covers(p, str(req.get("resource")))
                                          for p in members["paths"]):
            return "paths"
        if "aud" in members and req.get("audience") not in members["aud"]:
            return "aud"
        if "pay_to" in members and req.get("payee") != members["pay_to"]:
            return "pay_to"
        if "exp" in members and req["at"] > members["exp"]:
            return "exp"
        if "nbf" in members and req["at"] < members["nbf"]:
            return "nbf"
        return None

    def _ask_of(self, req: Dict[str, Any]) -> Dict[str, Any]:
        ask: Dict[str, Any] = {}
        if req.get("amount"):
            ask["currency"] = req["amount"]["currency"]
        if req.get("operation"):
            ask["operations"] = [req["operation"]]
        return ask

    def present(self, p: Dict[str, Any]) -> Dict[str, Any]:
        """Topologies R and TR: one presentation; commits at the kit's recorder on acceptance."""
        self._received = p.get("original")
        req, at = p["request"], int(p["at"])
        try:
            o = self._original(p["original"])
            if self.topo == "R":
                try:
                    x = fmt.read_translated(p["translated"],
                                            self.ctx.get("translator_keys") or {})
                except fmt.BadToken as e:
                    raise Refused(f"translated form does not verify: {e}")
                if self.flaw != "translated_only" and x["orig"] != fmt.digest(p["original"]):
                    raise Refused("the translated form does not name the original presented")
                why = self._admits(x["members"], req)
                if why:
                    raise Refused(f"translated form: {why}")
                if self.flaw not in ("translated_only", "binding_only"):
                    why = self._admits(self._members(o, p["original"], self._ask_of(req), at),
                                       req)
                    if why:
                        raise Refused(f"original: {why}")
            else:
                why = self._admits(self._members(o, p["original"], self._ask_of(req), at), req)
                if why:
                    raise Refused(why)
        except Refused as e:
            return {"accepted": False, "reason": str(e)}
        if self.base != "no-control":
            self.ctx["recorder"].commit(req, by=self.config)
        return {"accepted": True, "reason": ""}
