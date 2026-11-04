"""KRK-M150 to KRK-M169: P24's measurement errors (docs/FAILURE-MODES.md), one
regression test each, showing the wrong reading and the check that prevents it. All anticipated;
none observed against a product."""
import ast
import base64
import dataclasses
import hashlib
import json
import random
import unicodedata
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import mandator, requester, standing, terms as tm  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p24_mandate_bound as p24  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.mandate_toys import ToyMandate, make, toy  # noqa: E402
from known_bad.withdrawal_toys import _answer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, variants, *, trials=1, seed=5, tag="f"):
    ev = Evidence("p24f", t.name, "P24", t.config.replace(":", "-") + tag)
    t.start()
    try:
        r = p24.probe(t, ev, run_tag=tag, seed=seed,
                      plan={"trials": trials, "variants": list(variants)})
    finally:
        t.stop()
    return r, ev


def _form(r, v, f):
    return r.extra["forms"][v][f]


def _trials(ev, variant):
    (path,) = ev.dir.glob(f"*-{variant}.json")
    return json.loads(path.read_text())["trials"]


# ------------------------------------------------------------------------------- the toys


class _PurposeNoMap(ToyMandate):
    def purpose_map(self):
        return None


class _ShapeRefuser(ToyMandate):
    """Refuses every mandate whose terms list two slots or more, whatever their values: a B that
    cannot parse multi-slot terms (KRK-M155)."""

    def _terms(self, p, chain, values, linked, basis):
        if any(len(g["terms"].get("slots") or []) > 1 for g in chain
               if isinstance(g["terms"].get("slots"), list)):
            return "refuse", "cannot read multi-slot terms", None
        return super()._terms(p, chain, values, linked, basis)


class _StripsPurpose(ToyMandate):
    """``request_purpose`` behind a proxy that drops the agent's purpose header (KRK-M156)."""

    def __init__(self):
        super().__init__("bad", "request_purpose")

    def present(self, p, *, session=None):
        h = {k: v for k, v in p.headers.items() if k != mandator.PURPOSE_HEADER}
        return super().present(dataclasses.replace(p, headers=h), session=session)


class _KnownGoalOnly(ToyMandate):
    """Checks only that the payment authority names some goal it has seen (KRK-M159)."""

    def __init__(self):
        super().__init__("bad", "goal_unchecked")
        self.known = set()

    def _decide(self, p):
        claims = standing.peek(p.headers.get(requester.GRANT_HEADER) or "")
        self.known.add((claims.get("terms") or {}).get("goal_id"))
        ans, values, later = super()._decide(p)
        ltok = p.headers.get(mandator.LINKED_HEADER)
        if ltok and values is not None:
            serves = (standing.peek(ltok).get("terms") or {}).get("serves")
            if serves not in self.known:
                return _answer("refused", "a goal this B has never seen"), None, False
        return ans, values, later


class _NoDigest(ToyMandate):
    def confirmation_binds_action(self):
        return False


class _Normalising(ToyMandate):
    """The correct B behind a proxy that NFC-normalises the request body (KRK-M162)."""

    def present(self, p, *, session=None):
        body = unicodedata.normalize("NFC", p.request.decode("utf-8")).encode("utf-8")
        return super().present(dataclasses.replace(p, request=body), session=session)


class _SkuKeyed(ToyMandate):
    def item_key(self):
        return "sku"


class _ReadsSkuDeclaresId(ToyMandate):
    """Declares the item key ``id`` and reads ``sku`` (a statement that does not match B)."""

    def _slots_ok(self, items, slots, key):
        return super()._slots_ok(items, slots, "sku")


class _ByResponse(ToyMandate):
    def evidence_grade(self):
        return "b-response"


class _Library(ToyMandate):
    def evidence_grade(self):
        return "library-decision"


class _Changing(ToyMandate):
    """Its purpose map changes after the run starts (KRK-M167)."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def purpose_map(self):
        self.reads += 1
        m = super().purpose_map()
        if self.reads > 1:
            m["research"]["operations"].append("data.record.delete")
        return m


class _SingleUse(ToyMandate):
    """Treats each mandate as single use: a second accepted use is refused as a repeat."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.used = set()

    def is_repeat_refusal(self, answer):
        return "repeat" in str(((answer or {}).get("body") or {}).get("reason", ""))

    def _decide(self, p):
        gid = standing.peek(p.headers.get(requester.GRANT_HEADER) or "").get("grant_id")
        if gid in self.used:
            return _answer("refused", "repeat: this mandate was used"), None, False
        ans, values, later = super()._decide(p)
        if values is not None:
            self.used.add(gid)
        return ans, values, later


# ------------------------------------------------------------------------------- KRK-M150..M169


def test_KRK_M150_purpose_forms_land_only_with_bs_own_map():
    """KRK-M150: with no declared map the kit reads no purpose form, and never supplies one."""
    r, _ = _run(_PurposeNoMap(), ["purpose", "outside_ceiling", "unknown_term"])
    for f in p24.FORMS["purpose"]:
        d = _form(r, "purpose", f)
        assert d["reading"] == "format_gap" and "KRK-M150" in d["detail"], (f, d)
    assert r.status is Status.INCONCLUSIVE        # purpose declared, its core forms cannot land
    assert tm.purpose_covers(None, "research", "data.record.read", []) is False


def test_KRK_M151_a_w_action_outside_a_limit_is_refused_as_a_fixture(monkeypatch):
    """KRK-M151: a W that is also outside a limit would let a limits-only B pass a term form;
    `truth` raises instead."""
    real = p24.fixture

    def over(v, f, rng, ctx):
        fx = real(v, f, rng, ctx)
        if (v, f) == ("goal_items", "partial"):
            fx.W.values["amount"] = {"value": 10 ** 9, "currency": "EUR", "minor_units": 2}
        return fx
    monkeypatch.setattr(p24, "fixture", over)
    r, _ = _run(toy("bad"), ["goal_items"])
    assert r.status is Status.INCONCLUSIVE and "KRK-M151" in r.summary, r.summary
    monkeypatch.setattr(p24, "fixture", real)
    r, _ = _run(toy("bad"), ["goal_items"])
    assert _form(r, "goal_items", "partial")["ok"] is False


def test_KRK_M152_the_kits_goal_check_shares_no_target_reading():
    """KRK-M152: partial is less, an empty list admits nothing, and terms.py imports no target."""
    s = [{"slot": "s1", "acceptable": ["a"], "quantity": 1},
         {"slot": "s2", "acceptable": ["b"], "quantity": 1}]
    assert tm.reason_of(tm.fill([{"id": "a", "quantity": 1}], s)) == tm.LESS
    e = [{"slot": "e", "acceptable": [], "quantity": 1}]
    assert tm.reason_of(tm.fill([{"id": "z", "quantity": 1}], e)) == tm.OTHER
    assert p24.is_wildcard_reading(e[0]) is False
    tree = ast.parse((ROOT / "conformance" / "terms.py").read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level}
    assert mods <= {None, "receipts"}, mods      # `from . import attenuation`, `.receipts`
    assert {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level
            and n.module is None for a in n.names} == {"attenuation"}


def test_KRK_M153_not_acceptable_keeps_the_counts_so_a_count_check_fails_it():
    """KRK-M153: the substitution changes only which item fills which slot."""
    r, ev = _run(make("count_only"), ["goal_items"])
    assert _form(r, "goal_items", "not_acceptable")["ok"] is False
    assert _form(r, "goal_items", "partial")["ok"] is True
    trials = _trials(ev, "goal_items")
    t = next(x for x in trials if x["form"] == "not_acceptable")
    assert t["extra"]["truth"]["W"]["terms_kit"].startswith("other:")


def test_KRK_M154_a_hidden_term_whose_disclosure_reached_b_is_not_landed(monkeypatch):
    real = p24.fixture

    def leak(v, f, rng, ctx):
        fx = real(v, f, rng, ctx)
        if (v, f) == ("hidden_terms", "fixed_hidden"):
            fx.W = dataclasses.replace(fx.W, withhold=())
        return fx
    monkeypatch.setattr(p24, "fixture", leak)
    r, _ = _run(make("hidden_as_absent"), ["hidden_terms"])
    d = _form(r, "hidden_terms", "fixed_hidden")
    assert d["reading"] == "not_landed" and "KRK-M154" in d["detail"], d
    assert _form(r, "hidden_terms", "slot_hidden")["ok"] is False


def test_KRK_M155_a_parse_refusal_is_not_read_as_a_term_check():
    """KRK-M155: L carries the same members with values that admit the action; L refused gives
    no reading."""
    r, _ = _run(_ShapeRefuser(), ["goal_items"])
    for f in ("partial", "extra_item", "over_quantity"):
        assert _form(r, "goal_items", f)["reading"] == "collateral_refusal", f
        assert _form(r, "goal_items", f)["ok"] is None


def test_KRK_M156_the_agents_claim_that_never_reached_b_is_not_landed():
    r, _ = _run(_StripsPurpose(), ["purpose"])
    d = _form(r, "purpose", "asserted_by_agent")
    assert d["reading"] == "not_landed" and "KRK-M156" in d["detail"], d
    r, _ = _run(make("request_purpose"), ["purpose"])
    assert _form(r, "purpose", "asserted_by_agent")["ok"] is False


def test_KRK_M157_held_forever_is_not_read_as_enforced():
    r, _ = _run(toy("info:hold_forever"), ["condition", "outside_ceiling", "unknown_term"])
    assert r.status is Status.INCONCLUSIVE
    for f in p24.FORMS["condition"]:
        d = _form(r, "condition", f)
        assert d["reading"] == "shape_refused" and "KRK-M157" in d["detail"], d


def test_KRK_M158_held_at_the_answer_and_performed_later_fails(monkeypatch):
    """KRK-M158: classified at B's answer, the late executor would pass."""
    r, _ = _run(make("late_executor"), ["condition"])
    assert _form(r, "condition", "unconfirmed")["ok"] is False
    monkeypatch.setattr(p24, "stability_window", lambda stated: 0.1)
    r, _ = _run(make("late_executor"), ["condition"])
    assert _form(r, "condition", "unconfirmed")["ok"] is True       # the wrong reading


class _RefusesThenPerforms(ToyMandate):
    """Answers *refused* for an action it holds, then performs it 5 s later."""

    def present(self, p, *, session=None):
        from conformance.mandator import headers_digest
        ref = str(json.loads(p.request.decode("utf-8")).get("ref"))
        self.seen[ref] = {"digest": headers_digest(p.headers, p.request)}
        ans, values, later = self._decide(p)
        if later:
            c = self._c()
            c.call_at(c.now() + 5.0, lambda: self._effect(values))
            return _answer("refused", "terms: not confirmed")
        if values is None:
            return ans
        res = self._effect(values)
        return res if res is not None else ans


def test_KRK_M158_refused_at_the_answer_and_performed_before_S_fails_when_published():
    """A refusal followed by the effect between 2 s and S. A development run
    settles for 2 s and misses it; a published run watches every ``condition`` trial for S."""
    dev, ev = _run(_RefusesThenPerforms("bad", "late_executor"), ["condition"], tag="dev")
    assert _form(dev, "condition", "unconfirmed")["ok"] is True          # the wrong reading
    assert {t["extra"]["settle_s"] for t in _trials(ev, "condition")} == {p24.SETTLE_S}
    assert dev.extra["stability_every_trial"] == []
    t = _RefusesThenPerforms("bad", "late_executor")
    evp = Evidence("p24f", t.name, "P24", "late-refused-pub")
    t.start()
    try:
        pub = p24.probe(t, evp, run_tag="pub", seed=5,
                        plan={"trials": "published", "variants": ["condition"]})
    finally:
        t.stop()
    assert _form(pub, "condition", "unconfirmed")["ok"] is False
    assert _form(pub, "condition", "unconfirmed")["reading"] == "outside_effect"
    assert {t["extra"]["settle_s"] for t in _trials(evp, "condition")} == {pub.extra["stability_s"]}
    assert pub.extra["stability_every_trial"] == ["condition", "hidden_terms"]


def test_KRK_M159_the_other_goal_is_one_b_knows(monkeypatch):
    """KRK-M159: G1 is completed at B first, so only a check against the action's own goal
    refuses."""
    r, _ = _run(_KnownGoalOnly(), ["cross_goal"])
    assert _form(r, "cross_goal", "other_goal")["ok"] is False
    real = p24.fixture

    def stranger(v, f, rng, ctx):
        fx = real(v, f, rng, ctx)
        if v == "cross_goal":
            fx.prior = None
        return fx
    monkeypatch.setattr(p24, "fixture", stranger)
    r, _ = _run(_KnownGoalOnly(), ["cross_goal"])
    assert _form(r, "cross_goal", "other_goal")["ok"] is True       # the wrong reading


def test_KRK_M160_a_confirmation_that_cannot_bind_an_action_is_a_format_gap():
    r, _ = _run(_NoDigest(), ["condition"])
    d = _form(r, "condition", "confirmed_sibling")
    assert d["reading"] == "format_gap" and "KRK-M160" in d["detail"], d
    assert _form(r, "condition", "unconfirmed")["ok"] is True


def test_KRK_M161_free_text_is_never_judged_by_the_tester():
    for t in (toy("good"), make("reads_text")):
        r, _ = _run(t, ["free_text"])
        d = _form(r, "free_text", "text_narrower")
        assert d["ok"] is None and d["reading"] in ("text_ignored", "text_applied"), d
    assert ("free_text", "text_narrower") in p24.INFORMATION_ONLY
    r, _ = _run(make("reads_text"), ["free_text"])
    assert _form(r, "free_text", "text_wider")["ok"] is False     # graded on the structure


def test_KRK_M162_a_value_normalised_before_b_saw_it_is_not_landed(monkeypatch):
    from conformance.timing import VirtualClock
    A = mandator.StubMandator(requester.new_issuer(), clock=VirtualClock())
    try:
        A.serve_local()
        nfd = unicodedata.normalize("NFD", "Café 1")
        m = A.issue_v4("a1", {}, {"goal_id": tm.new_goal_id()}, principal="p")
        p = A.present([m], {"operation": "op", "ref": "r-1", "payee": nfd},
                      audience={"counterparty": "did:web:b.example", "endpoint": "e1"})
        assert nfd.encode("utf-8") in p.request
        assert unicodedata.normalize("NFC", nfd).encode("utf-8") not in p.request
    finally:
        A.close()
    real = p24.fixture

    def nfd(v, f, rng, ctx):
        fx = real(v, f, rng, ctx)
        if (v, f) == ("fixed", "normalised"):
            alt = unicodedata.normalize("NFD", fx.notes["fixed"])
            fx.W.values["payee"] = fx.L.values["payee"] = alt
            fx.mandates["L"].hops[0][1]["fixed"]["payee"] = alt
        return fx
    monkeypatch.setattr(p24, "fixture", nfd)
    r, _ = _run(_Normalising(), ["fixed"])
    d = _form(r, "fixed", "normalised")
    assert d["reading"] == "not_landed" and "KRK-M162" in d["detail"], d


def test_KRK_M163_items_are_identified_by_bs_declared_key():
    r, _ = _run(_SkuKeyed(), ["goal_items"])
    assert all(d["ok"] is True for d in r.extra["forms"]["goal_items"].values())
    # A statement that does not match B is caught by the control, which carries a slot keyed
    # as B declared: no verdict, never a false one.
    r, _ = _run(_ReadsSkuDeclaresId(), ["goal_items"])
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary, r.summary


def test_KRK_M164_a_clamp_is_credited_only_where_the_effect_is_seen():
    r, _ = _run(toy("good-clamp"), ["goal_items"])
    assert "clamped" in _form(r, "goal_items", "extra_item")["detail"]

    class _ClampByResponse(_ByResponse):
        def __init__(self):
            super().__init__("good-clamp")
    r, _ = _run(_ClampByResponse(), ["goal_items"])
    assert _form(r, "goal_items", "extra_item")["ok"] is False
    assert _form(r, "goal_items", "over_quantity")["ok"] is False
    assert p24.clamp_credited("b-response") is False and p24.clamp_credited("recorder")


def test_KRK_M165_ws_action_is_inside_the_linked_authoritys_limits():
    r, ev = _run(toy("good"), ["cross_goal"])
    trials = _trials(ev, "cross_goal")
    for t in trials:
        w = t["extra"]["truth"]["W"]
        assert w["limits"] is None, t["form"]
        if t["form"] != "unbound":
            assert w["terms_kit"].startswith("other-goal:"), t["form"]


def _seal2(value, salt):
    """A second implementation of the seal, written from design §2.4 only (KRK-M166)."""
    b = json.dumps([salt, value], sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")
    return {"_sealed": base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip("=")}


def test_KRK_M166_the_kits_seal_matches_a_second_implementation():
    rng = random.Random(9)
    for _ in range(50):
        v = rng.choice([{"code": f"c-{rng.random()}".replace(".", "")},
                        [f"sku-{rng.randrange(10**6)}"], f"m-{rng.randrange(10**6)}",
                        {"value": rng.randrange(10**6), "currency": "EUR", "minor_units": 2}])
        salt = f"s{rng.randrange(10**9)}"
        assert tm.seal(v, salt) == _seal2(v, salt)
        t = {"fixed": {"payee": _seal2(v, salt)}}
        assert tm.open_sealed(t, [[salt, "fixed/payee", v]]) == {"fixed": {"payee": v}}
    r, _ = _run(toy("good"), ["hidden_terms"])
    assert all(d["ok"] is True for d in r.extra["forms"]["hidden_terms"].values())


def test_KRK_M167_a_meaning_changed_under_the_run_gives_no_verdict():
    r, _ = _run(_Changing(), ["purpose"])
    assert r.status is Status.INCONCLUSIVE and "KRK-M167" in r.summary, r.summary


def test_KRK_M168_a_pending_verdict_at_library_level_reads_pending():
    class _HoldLibrary(_Library):
        def __init__(self):
            super().__init__("good-hold")
    r, _ = _run(_HoldLibrary(), ["condition"])
    assert r.extra["modes"]["condition"] == ["pending"], r.extra["modes"]
    assert r.extra["level"] == "library"


def test_KRK_M169_w_is_presented_before_w_in():
    r, ev = _run(_SingleUse(), ["goal_items", "fixed"])
    assert all(d["ok"] is True for v in ("goal_items", "fixed")
               for d in r.extra["forms"][v].values()), r.extra["forms"]
    for v in ("goal_items", "fixed"):
        for t in _trials(ev, v):
            order = t["extra"]["order"]
            if "W-in" in order:
                assert order.index("W") < order.index("W-in") == len(order) - 1, order
    r, _ = _run(_SingleUse("bad", "limits_only"), ["goal_items"])
    assert _form(r, "goal_items", "partial")["ok"] is False
