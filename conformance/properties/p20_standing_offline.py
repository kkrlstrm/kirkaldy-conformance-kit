"""P20 — Standing verifiable offline (KRK-20, cross-organisation X1).

**Guarantee.** For every effect B commits for organisation A's agent, B held at commit time
evidence that a principal at A holds standing for this class of action, that passes every link
(the key is A's now for standing, by A's own key statement; the evidence is A's, about the root
principal of the agent's grant chain, for this operation, addressed to B or to any) and whose
newest part A issued no more than T before the commit; with A unreachable, B refuses once that is
so, and accepts again within its recovery bound when A returns.

**Question.** When B commits an effect for another organisation's agent, does it rest on evidence
B checked itself that a principal at that organisation holds standing for this action, signed by a
key the organisation still names, no older than the bound B states, including when the
organisation cannot be reached, through a delegation chain and a hop into a third organisation?

**Who is graded.** B. The kit plays A with `issuer.StubIssuer` (X4's stub, extended
in a new module so P16 to P19 do not change), plus A′ (another issuer B pins), A2 (an
organisation whose sources stay up, for the offline sibling) and C (a third organisation whose
agents re-delegate), each with its own anchor, keys and source. Effects are counted at the kit's
recorder downstream of B. Nothing is withdrawn in any variant: every failure is B acting on
evidence that aged, or that was never sufficient. Withdrawal stays X4's.

**T** is X4's: `withdrawal_bound()`, read once, with its source; X1 does not read a T of its own. An adapter's `standing_bound()` is used only if smaller; a larger one is a finding.
A ``carried`` T never decides the verdict. B's clock tolerance is not added to
T.

**Two standing profiles** (`role_b.STANDING_PROFILES`). ``kirkaldy`` (the kit's formats): a key
statement under a pinned anchor, standing assertions with an action class, grant 0.2 with
holder-signed hops; every link can be expressed, and the evidence under test is the root
principal's assertion, served on A's ``/standing/<principal>`` and stapled where B reads staples.
``x4-status``: B reads standing only from X4's status snapshot (per principal, no class), its
keys pinned once at bind; the evidence under test is A's status source, so a fixture that changes
the evidence changes the whole source and is timed from the moment it does (KRK-M73: the sibling
is then A2's). A link a profile cannot express is a format gap: the form does not land and the gap
is a finding, never a pass (KRK-M76).

**Waiting for B's fetch** (KRK-M95). In the kit's profile, a B that obtains standing
evidence only by fetching it is presented with a static trial's requests, and with
``stale_signed``'s ``served`` and ``aged_at_fetch`` evidence, only once it has fetched what they
rest on: W's and L's root principals' assertions (or A's answer that it has none), and for a chain
through C the leaf principals' assertions and C's key statement listing its agents.
``served`` with no such fetch is ``fixture_not_landed``, as in the X4-status profile.

**Before B's first fetch** (KRK-M95b). The wait hides a B that acts before it has
fetched anything. ``agent_not_principal/before_first_fetch`` presents to a pull-only B at once:
A publishes an assertion for W's root principal covering another operation only, and W is
presented, twice, before B has fetched anything for that principal (``presented_before_fetch``;
a B that had already fetched leaves the form ``fixture_not_landed``). It is graded on W's effect
alone: an effect fails, since the standing A publishes does not cover the operation; a refusal,
for any reason, is safe. L is not presented. For a B that is not pull-only the other static
forms already present before its first fetch, so the form is not applicable.

**Times** (design §2.5), all on the kit's monotonic clock. ``t_f`` is the newest signing time, by
the stub's signing log, of valid evidence for the trial's principal that reached B by a fetch
(the fetch log, joined by serial or snapshot version) or a staple (the staple log) (KRK-M67,
M68, M74). ``t_o`` is when A's sources stop answering B; ``t_k`` when A's key source first serves
a revocation. Timed variants are judged with X4's harness unchanged (`timing.schedule`,
`classify_trial`, `aggregate`, `statistics`, `crosses`, `judge_recovery`) and P19's dispatcher
(presentations sent at their slots), with the reference instant (``t_f`` or ``t_k``)
in place of X4's ``t_w``: an acceptance of a presentation sent after it plus T, or an effect
committed after it, is late whatever B's clock says.

**Control** (design §4.1). On a fresh principal: A publishes its key statement, issues a one-hop
grant and asserts standing; a fresh request under W (A's agent) and under L (A2's agent where B
pins A2, else A's agent for another principal) is accepted at every endpoint, one effect each; the
kit's baseline reads A's key statement and the principal's evidence, and `standing.standing_state`
reads it as current. The control never requires that B fetches anything, reads keys, refuses,
works offline, reads staples, takes holder hops, pins a second issuer or states a T (KRK-M19).

**Variants** (`VARIANTS`, design §3.1), each with the toy that fails it
(`known_bad/standing_toys.py`); see `docs/KRK20-INTERFACE.md` for the table, the forms and what
each profile can express.

**Outcomes.** Static trials: ``refused`` (pass), ``accepted`` (an effect on evidence that breaks a
link, naming it; fail). Timed: ``within`` (pass), ``late`` (``accepted_beyond_T``), ``not_within_W``,
``flapped``, ``online_only`` (``a_unreachable``: B accepted nothing offline while its evidence was
younger than T) (fail). Information: ``fixture_not_landed``, ``collateral_refusal``,
``inconclusive``, ``not_landed``, ``not_ready``, ``depth_refused``,
``issuer_not_supported`` (KRK-M70), ``false_refusal`` (``issuer_behind``), ``format_gap``.
Per variant: ``refused`` / ``refused_within_T`` (pass); ``accepted``, ``refused_late``,
``not_refused_within_W``, ``flapped``, ``online_only`` (fail); recovery as X4.

**A development plan** (`plan=`, or `PLAN_ENV` holding JSON or a path; real targets only) may
set ``trials`` (a mapping with keys ``a_unreachable``, ``a_unreachable/worst``, ``static`` and
``*``, or ``"dev"``), ``window_s``, ``stability_s``, ``variants`` and ``forms`` (``{variant: [form,
...]}``). It is recorded in ``extra.plan`` and the summary starts "Development plan". ``{"trials":
"published"}`` alone is not one: it sets `PUBLISHED_TRIALS`.

**Result.** ``fail`` if any landed variant fails; ``pass`` only if the control held, every landed
variant passed and no variant in `NA_FORBIDDEN` that applies is missing or inconclusive;
otherwise ``inconclusive``. Format gaps are listed in ``extra.format_gaps``.
"""
from __future__ import annotations

import json
import os
import random
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict
from . import p19_withdrawal_within_t as p19

ID = "P20"
TITLE = "Standing verifiable offline"
FIXTURES = ("known_bad/standing_toys.py", "tests/test_p20_standing_offline.py",
            "tests/vectors/krk20/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = (
    "The stub organisations' keys, agents' keys, grant ids, principals and each request's ref "
    "come from the operating system, never from the seed (KRK-M36).",
    "Times are B's and the clock's; the seed draws the variant order, the jitter, the phase and "
    "the requests' values.",
)

VARIANTS = ("stale_signed", "a_unreachable", "aged_in_queue", "retired_key", "key_of_other_org",
            "other_organisation", "agent_not_principal", "deep_chain", "clock_skew",
            "restart_offline")
FORMS = {"stale_signed": ("served", "stapled", "aged_at_fetch"),
         "a_unreachable": ("down", "hang", "error", "partition"),
         "retired_key": ("retired_before_bind", "revoked_key"),
         "other_organisation": ("other_issuer", "other_audience", "c_standing"),
         "agent_not_principal": ("omitted", "other_principal", "other_action_class",
                                 "self_attested", "undesignated_key", "before_first_fetch"),
         "deep_chain": ("three_hops", "root_source_down", "root_missing"),
         "clock_skew": ("issuer_ahead", "issuer_behind")}
CONTROL = "control"
STATIC_KIT = {("retired_key", "retired_before_bind"), ("key_of_other_org", ""),
              ("other_organisation", "other_issuer"), ("other_organisation", "other_audience"),
              ("other_organisation", "c_standing"), ("deep_chain", "three_hops"),
              ("deep_chain", "root_missing")} | {("agent_not_principal", f) for f in
                                                 FORMS["agent_not_principal"]}
"""Forms judged without timing in the kit's profile (design §4.3)."""
STATIC_X4 = {("other_organisation", "other_issuer"), ("agent_not_principal", "omitted"),
             ("agent_not_principal", "other_principal")}
"""Forms judged without timing in the X4-status profile; there a key fixture changes A's whole
source, so ``retired_before_bind`` and ``key_of_other_org`` are timed from the change."""
X4_GAPS = {
    ("stale_signed", "stapled"): "B reads no stapled evidence",
    ("a_unreachable", "partition"): "B reads no stapled evidence, so no agent can carry fresh "
                                    "evidence past a partition",
    ("other_organisation", "other_audience"): "a status snapshot addresses no relying party",
    ("agent_not_principal", "other_action_class"): "a status snapshot states standing per "
                                                    "principal, not for an action class "
                                                    "",
    ("agent_not_principal", "self_attested"): "B takes standing only from A's source; an agent "
                                              "has no channel to present a statement of its own",
    ("agent_not_principal", "undesignated_key"): "B's pinned keys carry no purposes, so no key "
                                                 "can be outside its purpose",
    ("agent_not_principal", "before_first_fetch"): "a status snapshot states standing per "
                                                   "principal, not for an action class "
                                                   ", and one that predates the "
                                                   "grant reads it as in force, so "
                                                   "nothing B could hold before its first fetch "
                                                   "puts the request outside the standing",
}
TRIALS = {"a_unreachable": 30, "a_unreachable/worst": 5, "*": 5, "static": 5}
DEV_TRIALS = {"a_unreachable": 5, "a_unreachable/worst": 2, "*": 1, "static": 3}
PUBLISHED_TRIALS = {"a_unreachable": 100, "a_unreachable/worst": 5, "*": 5, "static": 5}
NA_FORBIDDEN = (CONTROL, "stale_signed", "a_unreachable", "agent_not_principal", "retired_key")
"""Variants an adapter may not declare not applicable (design §6.4). Of their forms the ones
that must land with a verdict are `MUST_LAND`."""
MUST_LAND = (("stale_signed", "served"), ("stale_signed", "stapled"), ("a_unreachable", "down"),
             ("agent_not_principal", "omitted"), ("agent_not_principal", "other_principal"),
             ("retired_key", "retired_before_bind"))
"""``served`` only for a pull B, ``stapled`` only for a B that reads staples."""
VULNERABLE_VARIANTS = ("retired_key", "key_of_other_org", "other_organisation",
                       "agent_not_principal")
PLAN_ENV = "ACK_P20_PLAN"
SETTLE_S = 2.0
READY_S = 30.0
OPERATION = "crm.record.push"
OTHER_OPERATION = "crm.record.delete"
OTHER_PARTY = "did:web:b-prime.example"
STATIC_ROUNDS = 2
"""Static trials present W and L this many times each, fresh requests, in a seeded order."""


def _amount(v: int) -> Dict[str, Any]:
    from ..issuer import amount
    return amount(v)


ROOT_CONSTRAINTS = {"operations": [OPERATION], "max_amount": {"value": 9_999_900,
                                                              "currency": "EUR",
                                                              "minor_units": 2}}
"""The root's constraints in the kit's profile, less the audience, which is B's own id
(`_Run.root_constraints`: P20's grants name B, as P21's do)."""


# --------------------------------------------------------------------------- one run


class _Run(p19._Run):
    """P19's run (clock, dispatcher, recorder, progress), with X1's organisations and profile."""

    def __init__(self, *a: Any, profile: str, std_channels: List[str], issuers: int,
                 keys_from: str, holder_hops: bool, max_depth: Optional[int], **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.profile = profile
        self.std_channels = std_channels
        self.n_issuers = issuers
        self.keys_from = keys_from
        self.holder_hops = holder_hops
        self.max_depth = max_depth
        self.org_of: Dict[str, Any] = {}
        self.aprime: Any = None
        self.a2: Any = None
        self.c: Any = None
        self.kit = profile == "kirkaldy"
        self.retired_kid: Optional[str] = None
        self.revocable: List[str] = []
        self.delta = 0.0

    @property
    def pull(self) -> bool:
        return "pull" in self.std_channels

    @property
    def staples(self) -> bool:
        return "stapled" in self.std_channels

    @property
    def pull_only(self) -> bool:
        """B obtains standing evidence only by fetching it (KRK-M95)."""
        return self.pull and not self.staples

    def root_constraints(self) -> Dict[str, Any]:
        """A root grant's constraints in the kit's profile: `ROOT_CONSTRAINTS`, addressed to B, so a B that requires a 0.2 chain to name it runs at its default."""
        return {**ROOT_CONSTRAINTS, "audience": [self.counterparty]}

    def values(self, *, lo: int = 100, hi: int = 99_999) -> Dict[str, Any]:
        v = super().values(lo=lo, hi=hi)
        v["operation"] = OPERATION
        if self.kit:
            v["amount"] = _amount(v["amount"])
            v.pop("items", None)
        return v

    def grant(self, org: Any, subject: str, principal: str) -> Any:
        if self.kit:
            g = org.issue_v2(subject, self.root_constraints(), principal=principal)
        else:
            g = org.issue(subject, principal=principal)
        self.org_of[g.id] = org
        return g

    def evidence(self, org: Any, principal: str, **kw: Any) -> Any:
        """Valid standing evidence for `principal` at `org` (kit: an assertion; X4-status: the
        principal is in every snapshot already)."""
        if self.kit:
            return org.assert_standing(principal, {OPERATION: None}, **kw)
        return None

    def presentation(self, grant: Any, endpoint: str, *, values: Optional[Dict[str, Any]] = None,
                     signer: Optional[str] = None, staple: Any = None) -> Any:
        vals = values or self.values()
        aud = self.audience(endpoint)
        if self.kit:
            return self.stub.under_v2(grant, vals, audience=aud,
                                      staple=staple if self.staples else None,
                                      window_s=self.req_window)
        org = self.org_of.get(grant.id, self.stub)
        return org.under(grant, vals, audience=aud, signer=signer or self.signer,
                         window_s=self.req_window)

    def principal_path(self, org: Any, principal: str) -> str:
        if self.kit:
            from ..issuer import STANDING_PATH
            import urllib.parse
            return STANDING_PATH + urllib.parse.quote(principal, safe="")
        return "/status/list"

    def t_f(self, org: Any, principal: str, before: float) -> Optional[float]:
        if self.kit:
            return org.latest_delivered(principal, before)
        return org.latest_snapshot_delivered(principal, before)

    def b_fetches(self, org: Any, since: float, path: Optional[str] = None) -> List[Dict[str, Any]]:
        out = [e for e in org.fetch_log(since) if e.get("t_end") is not None]
        if path:
            out = [e for e in out if e.get("path") == path]
        return out

    def wait_fetch(self, org: Any, after: float, path: str, limit_s: float) -> Optional[float]:
        """A fetch by B of `path` at `org` that started after `after` and succeeded."""
        deadline = self.clock.now() + limit_s
        while self.clock.now() <= deadline:
            done = [e["t_end"] for e in self.b_fetches(org, after, path)
                    if e["t_start"] > after and e.get("outcome") in ("ok", "stale")]
            if done:
                return min(done)
            self.clock.sleep(0.05)
        return None


# --------------------------------------------------------------------------- a trial


class _Trial(p19._Trial):
    def __init__(self, run: _Run, variant: str, form: str, k: int) -> None:
        super().__init__(run, variant, form, k)
        self.t_ref: Optional[float] = None
        self.t_o: Optional[float] = None
        """When the fixture began: presentations sent before it (set-up) are not judged, though
        their effects are (KRK-M63's shape: on a virtual clock a set-up presentation can share
        the instant of the evidence B fetched for it)."""
        self.extra: Dict[str, Any] = {}
        self.failsafe = False
        self.static = False
        self.held_ref: Optional[str] = None


def _ready(run: _Run, grant: Any, under: str, ep: str, *, deadline: float, log: List[Any],
           staple: Any = None) -> bool:
    from ..timing import delta_s
    while True:
        p = run.send(run.presentation(grant, ep, staple=staple() if callable(staple) else staple),
                     under, tag="ready")
        log.append(p)
        if p.accepted:
            return True
        if run.clock.now() >= deadline:
            return False
        run.clock.sleep(max(0.2, delta_s(run.T)))


def _new_principal(tag: str, org: Any) -> str:
    dom = org.issuer.split(":")[-1]
    return f"{tag}-{secrets.token_hex(3)}@{dom}"


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    from .. import standing as st
    A = run.stub
    subject = f"agent-{secrets.token_hex(4)}"
    pw = _new_principal("pw", A)
    W = run.grant(A, subject, pw)
    sw = run.evidence(A, pw)
    if run.a2 is not None:
        pl = _new_principal("pl", run.a2)
        L = run.grant(run.a2, f"agent-{secrets.token_hex(4)}", pl)
        lorg = run.a2
    else:
        pl = _new_principal("pl", A)
        L = run.grant(A, subject, pl)
        lorg = A
    sl = run.evidence(lorg, pl)
    log: List[Any] = []
    deadline = run.clock.now() + READY_S
    for ep in run.endpoints:
        for g, u, org, p in ((W, "W", A, pw), (L, "L", lorg, pl)):
            stap = (lambda o=org, q=p: o.current_standing(q)) if run.kit else None
            if not _ready(run, g, u, ep, deadline=deadline, log=log, staple=stap):
                return False, (f"a fresh request under {u} at endpoint {ep!r} was not accepted "
                               f"within {READY_S:g} s"), {"presentations": log}
    run.settle(run.clock.now() + 0.5)
    for p in log:
        run.fill(p)
        if run.grade != "recorder":
            continue
        n = len(run.effect_times(p.ref))
        if p.accepted and n != 1:
            return False, f"an accepted presentation ({p.ref}) has {n} effects", \
                {"presentations": log}
        if not p.accepted and n:
            return False, f"a presentation B did not accept ({p.ref}) has an effect", \
                {"presentations": log}
    obs: Dict[str, Any] = {"presentations": log}
    ok, tok, detail = A.baseline_get("/keys")
    if not ok:
        return False, f"the kit's baseline could not read A's key statement ({detail})", obs
    v = st.verify(tok, {A.anchor.kid: A.anchor.public_bytes()}, st.KEYSET_TYP)
    if not v.ok:
        return False, f"A's key statement does not verify under its anchor ({v.reason})", obs
    obs["keyset_version"] = v.claims["version"]
    if run.kit:
        import urllib.parse
        ok, tok, detail = A.baseline_get("/standing/" + urllib.parse.quote(pw, safe=""))
        cur = A.current_standing(pw)
        sv = st.verify(tok, st.keys_of(v.claims), st.STANDING_TYP) if ok else None
        state = st.standing_state(sv.claims if sv and sv.ok else None,
                                  kid=sv.kid if sv else None, keyset=v.claims, issuer=A.issuer,
                                  principal=pw, operation=OPERATION,
                                  audience=run.counterparty, at=A.now(),
                                  T=float(run.T or 60.0),
                                  signed_at=A.now() - (run.clock.now() - cur.t_signed)
                                  if cur else None)
        obs["standing_state"] = state
        if state["state"] != "current":
            return False, f"the kit's own reading of A's evidence is {state['state']} " \
                          f"({state['why']})", obs
    else:
        okb, _t, detail = A.baseline_read()
        if not okb:
            return False, f"the kit's baseline could not read A's status source ({detail})", obs
        got = A.read_back({f"principal:{pw}": "standing"})
        if not all(got.values()):
            return False, f"A's snapshot does not list {pw} as standing", obs
    if run.pull:
        limit = max(10.0, 2.0 * (run.T or 30.0))
        end = run.clock.now() + limit
        path = run.principal_path(A, pw)
        while run.clock.now() < end and len(run.b_fetches(A, float("-inf"), path)) < 3:
            run.clock.sleep(0.25)
        from ..timing import fetch_intervals
        iv = fetch_intervals(run.b_fetches(A, float("-inf"), path))
        if iv:
            run.max_interval = max(iv)
        obs["fetch_intervals_s"] = [round(x, 3) for x in iv]
    return True, "", obs


# --------------------------------------------------------------------------- the guards
# One function each, so a test can show the reading each one prevents (KRK-M67 to KRK-M79).


def t_f_of(run: _Run, org: Any, principal: str, before: float) -> Optional[float]:
    """KRK-M67, M68, M74: from the signing log joined to every delivery path, never from the
    evidence's own claims or from when B fetched it."""
    return run.t_f(org, principal, before)


def needs_second_issuer(run: _Run, variant: str, form: str) -> Optional[str]:
    """KRK-M70: another organisation's evidence lands only with that organisation pinned."""
    if (variant, form) in (("key_of_other_org", ""), ("other_organisation", "other_issuer")) \
            and run.aprime is None:
        return "B pins one issuer, so another organisation's key or evidence would be refused " \
               "as unpinned whatever B checks (KRK-M70)"
    return None


def key_reading_is_adapters(run: _Run, variant: str, form: str) -> bool:
    """KRK-M71: a key-change reading that rests on the adapter's translation is information."""
    return variant == "retired_key" and form == "revoked_key" and run.keys_from == "adapter"


def depth_supported(run: _Run) -> Optional[str]:
    """KRK-M75: deep chains and hops into C are run only on a B that states it
    takes them; ``three_hops`` must then be accepted before the other forms count."""
    if not run.holder_hops:
        return "B states it accepts no hop signed by another organisation's agent"
    if run.max_depth is not None and run.max_depth < 4:
        return f"B states a maximum chain of {run.max_depth} grants"
    if run.c is None:
        return "B cannot pin the third organisation C"
    return None


def stale_enough(age_s: float, T: float, eps: float) -> bool:
    """KRK-M77: a stale fixture counts only once its age passes T plus 2 ε."""
    return age_s > T + 2 * eps


def not_after_far(s: Any) -> bool:
    """KRK-M78: every fixture's own expiry lies at least twelve hours after its signing."""
    from .. import standing as st
    a, b = st.epoch_of(s.claims.get("issued_at")), st.epoch_of(s.claims.get("not_after"))
    return a is not None and b is not None and b - a >= 12 * 3600 - 1


def online_only(run: _Run, pres: List[Any], t_f: float, t_o: float, up: bool) -> bool:
    """KRK-M72: B accepted nothing under W after `t_o` while its evidence was
    younger than T - 2Δ, with three or more presentations in that interval, the evidence no
    older than T/2 at `t_o`, and B shown up (L accepted, or a recovery)."""
    T = run.T or run.window
    if t_o - t_f > T / 2.0:
        return False
    end = t_f + T - 2 * run.delta
    ws = [p for p in pres if p.under == "W" and t_o <= p.t_sent <= end and p19._settled(p)]
    return len(ws) >= 3 and not any(p.accepted for p in ws) and up


def chain_signers(grants: List[Any]) -> List[str]:
    """KRK-M79: who signed each hop, for the evidence."""
    return [getattr(g, "signer", "org") for g in grants]


def waits_for_fetch(run: _Run) -> bool:
    """KRK-M95: in the kit's profile, a B that obtains standing evidence only by
    fetching it is not presented with a request until it has fetched the evidence the request
    rests on (the principal's assertion, and for a hop C's agent signed, C's key statement), as
    the X4-status profile waits for B's fetch of a snapshot (KRK-M94). Presented at once, its
    refusals are about evidence it could not yet hold."""
    return run.kit and run.pull_only


def await_fetches(run: _Run, waits: List[Tuple[str, Any, str, float, Tuple[str, ...]]]
                  ) -> Dict[str, bool]:
    """KRK-M95: wait, up to the fetch limit for each, for B's fetch of each `(label, org, path,
    after, outcomes)`; returns which were seen. The limit is X4's (`max(2 P, 5 s) + 1 s`)."""
    limit = max(2 * run.max_interval, 5.0) + 1
    return {label: org.wait_fetched(path, after, limit, outcomes=outcomes) is not None
            for label, org, path, after, outcomes in waits}


BEFORE_FETCH = ("agent_not_principal", "before_first_fetch")
"""KRK-M95b: the form that presents to a pull-only B before its first fetch."""
ANSWERED = ("ok", "stale", "not-found")
"""Fetch outcomes after which B holds an answer from A for the principal."""


def b_fetched(org: Any, path: str, after: float) -> List[float]:
    """The end times of B's fetches of `path` that started after kit time `after` and brought
    an answer from A (`ANSWERED`). The stub's fetch log holds B's fetches only; the kit's own
    reads go through its baseline path, which is not logged (KRK-M95b)."""
    with org._slock:
        return sorted(e["t_end"] for e in org._fetch_log if e.get("path") == path
                      and e.get("t_end") is not None and e["t_start"] > after
                      and e.get("outcome") in ANSWERED)


def _before_fetch_trial(run: _Run, tr: _Trial, W: Any, pw: str, t_fix: float) -> None:
    """KRK-M95b: present W at once, `STATIC_ROUNDS` times, before B has fetched anything for
    `pw`; record what B had fetched when each presentation was sent."""
    A = run.stub
    path = run.principal_path(A, pw)
    seen = b_fetched(A, path, t_fix)
    tr.extra["presented_before_fetch"] = not seen
    if seen:
        tr.stop_info("fixture_not_landed", "B had already fetched the principal's evidence when "
                                           "the request could be presented (KRK-M95b)")
        return
    sent_after: List[bool] = []
    for i in range(STATIC_ROUNDS):
        ep = run.endpoints[i % len(run.endpoints)]
        sent_after.append(bool(b_fetched(A, path, t_fix)))
        p = run.send(run.presentation(W, ep, staple=None), "W", tag="static:W:before_fetch")
        tr.pres.append(p)
        tr.w_refs.append(p.ref)
    tr.extra["fetched_when_sent"] = sent_after
    first = b_fetched(A, path, t_fix)
    tr.extra["first_fetch_after_s"] = round(first[0] - t_fix, 3) if first else None


def _judge_before_fetch(run: _Run, tr: _Trial) -> Any:
    """KRK-M95b: W's effect alone. An effect fails: the only standing A publishes for the root
    principal covers another operation. Any refusal is safe, whatever check gave it."""
    from ..timing import TrialOutcome
    W = [p for p in tr.pres if p.under == "W"]
    n = sum(1 for p in W if p.accepted)
    if n:
        return TrialOutcome("accepted", False, form=tr.form,
                            detail=f"{n} of {len(W)} presentations under W had an effect, sent "
                                   f"before B had fetched any evidence for the root principal, "
                                   f"whose only standing covers {OTHER_OPERATION} "
                                   f"({tr.extra.get('fixture')})")
    if W and all(p.refused for p in W):
        return TrialOutcome("refused", True, form=tr.form,
                            detail="every presentation under W, sent before B's first fetch "
                                   "for the root principal, was refused; graded on W alone "
                                   "")
    return TrialOutcome("not_answered", None, form=tr.form,
                        detail="a presentation under W had no readable answer")


# --------------------------------------------------------------------------- static trials


def _static_trial(run: _Run, variant: str, form: str, k: int) -> Tuple[_Trial, Dict[str, Any]]:
    """W carries the evidence under test, L the same chain shape with valid evidence (KRK-M69);
    each is presented `STATIC_ROUNDS` times on fresh requests."""
    A, clock = run.stub, run.clock
    tr = _Trial(run, variant, form, k)
    tr.static = True
    run.variant = variant
    run.disp.begin_trial()
    ex = tr.extra
    subject = f"agent-{secrets.token_hex(4)}"
    pw, pl = _new_principal("pw", A), _new_principal("pl", A)
    staple_w: Any = None
    deep = (variant, form) in (("deep_chain", "three_hops"), ("deep_chain", "root_missing"),
                               ("other_organisation", "c_standing"))
    if deep:
        W, ex_w, pc = _deep_chain(run, subject, pw)
        L, ex_l, pcl = _deep_chain(run, f"agent-{secrets.token_hex(4)}", pl)
        ex["W_signers"], ex["L_signers"], ex["W_leaf_principal"] = ex_w, ex_l, pc
        ex["L_leaf_principal"] = pcl
        run._w_pc = pc
    else:
        W = run.grant(A, subject, pw)
        L = run.grant(A, subject, pl)
    sl = run.evidence(A, pl)
    staple_l = sl
    t_fix = clock.now()
    if run.kit:
        staple_w, why = _kit_static_fixture(run, variant, form, W, pw)
    else:
        staple_w, why = _x4_static_fixture(run, variant, form, W, pw)
    ex["fixture"] = why
    if tr.info:
        return tr, ex
    landed = _static_landed(run, variant, form, pw, staple_w)
    if landed:
        tr.stop_info("fixture_not_landed", landed)
        return tr, ex
    if (variant, form) == BEFORE_FETCH:
        _before_fetch_trial(run, tr, W, pw, t_fix)
        return tr, ex
    if waits_for_fetch(run):
        # KRK-M95: B holds W's evidence under test (or has been told there is none) and L's
        # valid evidence before either is judged; for a chain through C, also C's leaf
        # principals' assertions and the key statement listing C's agents.
        anyans = ("ok", "stale", "not-found")
        waits = [("W", A, run.principal_path(A, pw), t_fix, anyans),
                 ("L", A, run.principal_path(A, pl), t_fix, ("ok",))]
        if deep:
            C = run.c
            waits += [(f"{u}_leaf", C, run.principal_path(C, ex[f"{u}_leaf_principal"]),
                       t_fix, ("ok",)) for u in ("W", "L")]
            waits.append(("C_keys", C, "/keys", C.keyset()["t_signed"], ("ok",)))
        got = await_fetches(run, waits)
        ex["fetched_before_present"] = got
    elif run.pull and not run.kit and "pull-list" in run.channels:
        # A B that reads status lists must hold a snapshot listing W and L before W is judged:
        # one signed before them reads as not yet listed, in force.
        got = run.wait_fetch(A, t_fix, "/status/list", max(2 * run.max_interval, 5.0) + 1)
        if run.a2 is not None and variant == "other_organisation":
            run.wait_fetch(run.aprime, t_fix, "/status/list", max(2 * run.max_interval, 5.0) + 1)
        ex["fetched_after_fixture"] = got is not None
    order = (["W", "L"] * STATIC_ROUNDS)
    run.rng.shuffle(order)
    for i, u in enumerate(order):
        ep = run.endpoints[i % len(run.endpoints)]
        g = W if u == "W" else L
        stp = staple_w if u == "W" else staple_l
        if run.kit and u == "L" and deep:
            stp = A.current_standing(pl)
        p = run.send(run.presentation(g, ep, staple=stp), u, tag=f"static:{u}")
        tr.pres.append(p)
        if u == "W":
            tr.w_refs.append(p.ref)
    return tr, ex


def _deep_chain(run: _Run, subject: str, principal: str) -> Tuple[Any, List[str], str]:
    """A → a1 (signed by A) → c1 (signed by a1, C's agent) → c2 (signed by c1): the leaf (c2's
    grant) is presented (KRK-M79)."""
    A, C = run.stub, run.c
    root = A.issue_v2(subject, run.root_constraints(), principal=principal)
    pc = _new_principal("pc", C)
    h1 = A.delegate_holder(root, f"c1-{secrets.token_hex(3)}", org=C, principal=principal)
    h2 = C.delegate_holder(h1, f"c2-{secrets.token_hex(3)}", principal=pc)
    C.assert_standing(pc, {OPERATION: None})
    for g in (root, h1, h2):
        run.org_of[g.id] = A
    return h2, chain_signers(A.chain_v2(h2)), pc


def _kit_static_fixture(run: _Run, variant: str, form: str, W: Any, pw: str
                        ) -> Tuple[Any, str]:
    """The evidence under test for W's root principal `pw`, in the kit's formats: served as the
    principal's current assertion on A's source and returned to staple. Returns (staple, what)."""
    A = run.stub
    if variant == "agent_not_principal":
        if form == "omitted":
            A.withhold_standing(pw)
            return None, "no assertion for the root principal on any channel"
        if form == "other_principal":
            p2 = _new_principal("p2", A)
            s = A.assert_standing(p2, {OPERATION: None}, publish=False)
            A.relay_standing(pw, s)
            return s, f"A's genuine assertion for {p2}, not for {pw}"
        if form == "other_action_class":
            s = A.assert_standing(pw, {OTHER_OPERATION: None}, broken="class")
            return s, f"A's genuine assertion for {pw}, covering {OTHER_OPERATION} only"
        if form == "before_first_fetch":
            s = A.assert_standing(pw, {OTHER_OPERATION: None}, broken="class")
            return None, f"A publishes an assertion for {pw} covering {OTHER_OPERATION} only; " \
                         f"W is presented before B's first fetch for {pw}, with no staple"
        if form == "self_attested":
            A.withhold_standing(pw)
            agent = (W.holder or A).agent(W.subject)
            s = A.assert_standing(pw, {OPERATION: None}, signer=agent, broken="key",
                                  publish=False)
            return s, "an assertion for the root principal signed by the agent's own key, " \
                      "stapled only"
        if form == "undesignated_key":
            s = A.assert_standing(pw, {OPERATION: None}, kid=A.key.kid, broken="key")
            return s, "A's assertion signed by A's grant key, which A's statement does not " \
                      "designate for standing"
    if variant == "retired_key" and form == "retired_before_bind":
        s = A.assert_standing(pw, {OPERATION: None}, kid=run.retired_kid, broken="key")
        return s, f"signed with {run.retired_kid}, retired in A's statement before bind " \
                  f""
    if variant == "key_of_other_org":
        s = run.aprime.assert_standing(pw, {OPERATION: None}, issuer_claim=A.issuer,
                                       publish=False, broken="key")
        A.relay_standing(pw, s)
        return s, "A′'s genuine standing key signed an assertion naming A and the root " \
                  "principal; A's source relays its bytes"
    if variant == "other_organisation":
        if form == "other_issuer":
            A.withhold_standing(pw)
            s = run.aprime.assert_standing(pw, {OPERATION: None})
            return s, f"A′ genuinely asserts standing for a principal named {pw} at A′"
        if form == "other_audience":
            s = A.assert_standing(pw, {OPERATION: None}, audience=[OTHER_PARTY],
                                  broken="audience")
            return s, f"A's genuine assertion addressed to {OTHER_PARTY}"
        if form == "c_standing":
            A.withhold_standing(pw)
            s = run.c.current_standing(run._w_pc)
            return s, "the root principal has no assertion at A; the leaf's organisation C " \
                      "asserts its own principal, stapled"
    if variant == "deep_chain":
        if form == "three_hops":
            s = run.evidence(A, pw)
            return s, "fresh evidence for the root principal: must be accepted"
        if form == "root_missing":
            A.withhold_standing(pw)
            return None, "no evidence for A's root principal; C's principal's is fresh"
    raise ValueError(f"no static fixture for {variant}/{form}")


def _x4_static_fixture(run: _Run, variant: str, form: str, W: Any, pw: str
                       ) -> Tuple[Any, str]:
    A = run.stub
    if variant == "agent_not_principal" and form == "omitted":
        A.omit_from_snapshots(pw)
        A.reissue()
        return None, "the root principal is left out of A's snapshots' standing"
    if variant == "agent_not_principal" and form == "other_principal":
        A.omit_from_snapshots(pw)
        p2 = _new_principal("p2", A)
        run.grant(A, f"agent-{secrets.token_hex(4)}", p2)
        return None, f"A's snapshots list {p2} as standing, not {pw}"
    if variant == "other_organisation" and form == "other_issuer":
        A.omit_from_snapshots(pw)
        A.reissue()
        run.grant(run.aprime, f"agent-{secrets.token_hex(4)}", pw)
        return None, f"A′'s snapshots list a principal named {pw}; A's leave it out"
    raise ValueError(f"no static fixture for {variant}/{form} in the X4-status profile")


def _static_landed(run: _Run, variant: str, form: str, pw: str, staple: Any) -> str:
    """KRK-M26: the published evidence reads back as built; '' when it did."""
    A = run.stub
    if run.kit:
        if form == "self_attested":
            return "" if run.staples else "B reads no staples, the agent's only channel"
        if variant == "other_organisation" and form in ("other_issuer", "c_standing"):
            got = A.read_back_x1({f"standing:{pw}": None})
            return "" if all(got.values()) else f"A still serves evidence for {pw}"
        want = None if form in ("omitted", "root_missing") else A.current_standing(pw)
        got = A.read_back_x1({f"standing:{pw}": want})
        if not all(got.values()):
            return f"A's source does not serve the fixture's bytes for {pw}"
        if want is not None and not not_after_far(want):
            return "the fixture's own expiry is under twelve hours (KRK-M78)"
        return ""
    if variant == "other_organisation":
        a = A.read_back({f"principal:{pw}": "absent"})
        b = run.aprime.read_back({f"principal:{pw}": "standing"})
        return "" if all(a.values()) and all(b.values()) else f"read back {a} {b}"
    got = A.read_back({f"principal:{pw}": "absent"})
    return "" if all(got.values()) else f"A's snapshot still lists {pw}: {got}"


def _judge_static(run: _Run, tr: _Trial) -> Any:
    from ..timing import TrialOutcome
    run.settle(run.clock.now() + 2.0)
    for p in tr.pres:
        run.fill(p)
    if tr.info:
        return TrialOutcome(tr.info, None, detail=tr.info_detail, form=tr.form)
    if (tr.variant, tr.form) == BEFORE_FETCH:
        return _judge_before_fetch(run, tr)
    W = [p for p in tr.pres if p.under == "W"]
    L = [p for p in tr.pres if p.under == "L"]
    unreached = [p for p in W if p.refused and not p.reached]
    if unreached:
        return TrialOutcome("stopped_before_guarantee", None, form=tr.form,
                            detail="the adapter attributes a refusal to something else")
    if tr.variant == "deep_chain" and tr.form == "three_hops":
        if all(p.accepted for p in W):
            return TrialOutcome("accepted_as_required", True, form=tr.form,
                                detail="a three-hop chain with fresh root evidence was accepted")
        return TrialOutcome("depth_refused", None, form=tr.form,
                            detail="B refused a three-hop chain with fresh root evidence "
                                   "(KRK-M75)")
    if any(p.accepted for p in W):
        link = {"retired_key": "key", "key_of_other_org": "key",
                "other_organisation": "organisation" if tr.form != "other_audience"
                else "audience", "deep_chain": "principal"}.get(tr.variant)
        if tr.variant == "agent_not_principal":
            link = {"other_action_class": "class", "self_attested": "key",
                    "undesignated_key": "key"}.get(tr.form, "principal")
        n = sum(1 for p in W if p.accepted)
        return TrialOutcome("accepted", False, form=tr.form,
                            detail=f"{n} of {len(W)} presentations under W had an effect on "
                                   f"evidence that breaks the {link} link ({tr.extra.get('fixture')})")
    if any(p.refused for p in L) or not any(p.accepted for p in L):
        return TrialOutcome("collateral_refusal", None, form=tr.form,
                            detail="the sibling with valid evidence was refused too, so the "
                                   "refusal is not shown to be about the evidence (KRK-M69)")
    if not all(p.refused for p in W):
        return TrialOutcome("not_answered", None, form=tr.form,
                            detail="a presentation under W had no readable answer")
    return TrialOutcome("refused", True, form=tr.form,
                        detail=f"every presentation under W refused; L accepted "
                               f"({tr.extra.get('fixture')})")


# --------------------------------------------------------------------------- timed trials


def _timed_trial(run: _Run, variant: str, form: str, k: int, phase: str
                 ) -> Tuple[_Trial, Dict[str, Any]]:
    from .. import timing
    A, clock, T = run.stub, run.clock, run.T
    tr = _Trial(run, variant, form, k)
    run.variant = variant
    run.disp.begin_trial()
    run.sample_network(1)
    ex = tr.extra
    ex["phase"] = phase
    subject = f"agent-{secrets.token_hex(4)}"
    pw = _new_principal("pw", A)
    org = A
    skew = 0.0
    key_kid = None
    stale_s = None
    deep = variant == "deep_chain"
    W = None
    try:
        t_issue = clock.now()
        if deep:
            W, ex["W_signers"], _pc = _deep_chain(run, subject, pw)
        else:
            W = run.grant(A, subject, pw)
        if variant == "retired_key" and form == "revoked_key":
            key_kid = run.revocable.pop(0) if run.revocable else None
            if key_kid is None:
                tr.stop_info("not_landed", "no key prepared at bind is left to revoke")
                return tr, ex
            ex["revoked_kid"] = key_kid
            if run.kit:
                A.assert_standing(pw, {OPERATION: None}, kid=key_kid)
            else:
                A.status_signing_with(key_kid)
                A.reissue()
        elif variant == "stale_signed":
            pass
        else:
            run.evidence(A, pw)
        L, lorg, lp = None, None, None
        if run.a2 is not None:
            lp = _new_principal("pl", run.a2)
            L = run.grant(run.a2, f"agent-{secrets.token_hex(4)}", lp)
            run.evidence(run.a2, lp)
            lorg = run.a2
        elif variant == "retired_key" and form == "revoked_key" and run.kit:
            lp = _new_principal("pl", A)
            L = run.grant(A, subject, lp)
            run.evidence(A, lp)
            lorg = A
        tr.failsafe = L is None
        ex["sibling"] = "A2" if lorg is run.a2 and L is not None else ("A" if L else None)
        if variant == "clock_skew":
            tol = float(run.bound.get("clock_tolerance_s") or 0.0)
            skew = max(2 * T, tol + T) if T else tol + 120.0
            skew = skew if form == "issuer_ahead" else -skew
            A.set_clock_offset(skew)
            ex["clock_offset_s"] = skew
            if run.kit:
                run.evidence(A, pw)
            else:
                A.reissue()
        deadline = clock.now() + READY_S
        pre: List[Any] = []

        def staple_w() -> Any:
            return A.current_standing(pw) if run.kit else None

        # stale_signed starts from its fixture: W is never accepted on fresh evidence first.
        if variant != "stale_signed":
            okw = _ready(run, W, "W", run.endpoints[0], deadline=deadline, log=pre,
                         staple=staple_w)
            if variant == "clock_skew" and form == "issuer_behind" and not okw:
                tr.pres.extend(pre)
                tr.stop_info("false_refusal", "B refused on evidence A dated in the past by "
                                              "the offset, before the outage (information)")
                return tr, ex
        else:
            okw = True
        okl = True
        if L is not None:
            okl = _ready(run, L, "L", run.endpoints[0], deadline=deadline, log=pre,
                         staple=(lambda: lorg.current_standing(lp)) if run.kit else None)
        tr.pres.extend(pre)
        tr.w_refs.extend(p.ref for p in pre if p.under == "W")
        if not (okw and okl):
            tr.stop_info("not_ready", f"before the fixture W accepted: {okw}, L accepted: {okl}")
            return tr, ex
        clock.sleep(SETTLE_S)
        path = run.principal_path(A, pw)
        if not run.kit and "pull-list" in run.channels and variant != "stale_signed":
            # A B that reads status lists may accept W on a snapshot signed before W's grant (not
            # yet listed) without holding any evidence that names W's principal.
            # Judge from evidence B holds: wait for its next fetch of a snapshot listing them.
            got = run.wait_fetch(A, t_issue, path, max(2 * run.max_interval, 5.0) + 1)
            ex["fetched_listing_principal"] = got is not None
        # Phase (pull B): the outage drawn across B's fetch interval, or just before B's next
        # fetch is due (worst: B's newest evidence is a whole interval old at the outage).
        if run.pull and variant == "a_unreachable" and form != "partition":
            P = run.max_interval
            f = run.wait_fetch(A, clock.now(), path, max(2 * P, 5.0) + 1) if P else None
            if f is None and phase == "worst":
                tr.stop_info("not_landed", "no fetch by B was observed, so its worst phase "
                                           "cannot be targeted")
                return tr, ex
            if f is not None:
                if phase == "worst":
                    target = f + max(0.0, P - timing.WORST_PHASE_S)
                else:
                    target = timing.phase_target(f, P, run.rng, "random")
                clock.sleep_until(target)
                tr.phase_s = clock.now() - f
        if variant == "clock_skew" and run.pull:
            got = run.wait_fetch(A, clock.now(), path, max(2 * run.max_interval, 5.0) + 1)
            ex["fetched_offset_evidence"] = got is not None
        held_ref = None
        if variant == "aged_in_queue":
            retry = (T if T else 30.0) + p19.IN_FLIGHT_MARGIN_S
            p = run.presentation(W, run.endpoints[0], staple=staple_w())
            held_ref = json.loads(p.request.decode("utf-8"))["ref"]
            run.recorder.hold(held_ref, retry)
            hp = run.send(p, "W", tag="in-flight")
            tr.pres.append(hp)
            tr.w_refs.append(hp.ref)
            ex.update(held_ref=held_ref, retry_after_s=retry, held_answer=hp.cls)
            tr.held_ref = held_ref
            tr.settle_until = clock.now() + retry + 2.0

        # The fixture --------------------------------------------------------------------
        moving = False
        start_s = 0.0
        if variant == "stale_signed":
            tr.t_o = clock.now()
            stale_s, start_s = _stale_fixture(run, tr, form, W, pw)
            if tr.info:
                return tr, ex
            t_o = clock.now()
            tr.t_ref = stale_s.t_signed if stale_s is not None else t_o
        elif variant == "retired_key" and form == "revoked_key":
            ch = A.revoke_key(key_kid)
            got = A.read_back_x1({f"key:{key_kid}": "revoked"})
            if not all(got.values()):
                tr.stop_info("fixture_not_landed", f"A's key statement does not read back with "
                                                   f"{key_kid} revoked (KRK-M26)")
                return tr, ex
            ch.t_landed = clock.now()
            t_o = tr.t_ref = ch.t_commit
            ex["t_k_version"] = ch.version
            if run.kit:
                A.assert_standing(pw, {OPERATION: None}, kid=key_kid, broken="key")
            else:
                A.reissue()
            if key_reading_is_adapters(run, variant, form):
                ex["adapter_translates_keys"] = True
        elif not run.kit and variant == "retired_key":
            t_o = clock.now()
            A.status_signing_with(run.retired_kid, broken="key")
            A.reissue()
            tr.t_ref = run.t_f(A, pw, t_o) or t_o
        elif not run.kit and variant == "key_of_other_org":
            # A's source serves snapshots of A's own state genuinely signed by A′'s key: wrong
            # content, genuinely signed; A's statement never lists the key.
            t_o = clock.now()
            A.status_signing_with(run.aprime.key, broken="key")
            A.reissue()
            tr.t_ref = run.t_f(A, pw, t_o) or t_o
        else:
            mode = {"down": "down", "hang": "hang", "error": "error"}.get(form, "down")
            if variant == "a_unreachable" and form == "partition":
                A.set_partition(True)
                moving = True
            elif deep:
                A.set_source("down")
            else:
                A.set_source(mode)
            t_o = clock.now()
            tr.t_ref = run.t_f(A, pw, t_o)
            if tr.t_ref is None:
                tr.stop_info("not_landed", "no valid evidence for W reached B before the outage")
                return tr, ex
            reached, _tok, detail = A.baseline_get("/keys")
            ex["baseline_during_outage"] = detail
            if reached and not moving:
                tr.stop_info("fixture_not_landed", f"the kit's baseline still reached A "
                                                   f"({detail}) (KRK-M59)")
                return tr, ex
            start_s = max(0.0, t_o - tr.t_ref)
        if variant not in ("stale_signed",) and start_s == 0.0:
            start_s = max(0.0, t_o - tr.t_ref)
        ex["t_o_minus_t_ref_s"] = round(t_o - tr.t_ref, 4)
        tr.t_w = tr.t_ref
        if tr.t_o is None:
            tr.t_o = t_o
        _loop(run, tr, W, L, lorg, lp, pw, t_o=t_o, start_s=start_s, moving=moving,
              restart=variant == "restart_offline")
        if variant in ("a_unreachable", "aged_in_queue", "restart_offline", "clock_skew") \
                and not moving:
            ok_fetch = [e for e in run.b_fetches(A, t_o) if e.get("outcome") == "ok"
                        and e["t_start"] >= t_o]
            ex["fetches_during_outage"] = len(run.b_fetches(A, t_o))
            if ok_fetch:
                tr.stop_info("fixture_not_landed", f"B fetched A's source successfully during "
                                                   f"the outage ({len(ok_fetch)}) (KRK-M59)")
        if moving:
            fails = [e for e in run.b_fetches(A, t_o) if e.get("outcome") == "ok"]
            if fails:
                tr.stop_info("fixture_not_landed", "B reached A's source during the partition")
        if variant == "aged_in_queue":
            held = [e for e in run.recorder.held(run.prefix)
                    if (e.get("effect") or {}).get("ref") == held_ref]
            ex["held_attempts"] = len(held)
            if not held:
                tr.stop_info("not_landed", "B made no effect call for the request presented "
                                           "just before the outage, so nothing was held")
        if variant == "restart_offline" and "restart" in ex and \
                not p19.restart_happened(ex["restart"]):
            tr.stop_info("not_landed", f"the restart hook reported no new boot ({ex['restart']})")
        if variant == "clock_skew":
            ex["t_f_from_log"] = True
        return tr, ex
    finally:
        if skew:
            A.set_clock_offset(0.0)
        A.set_source("up")
        A.set_partition(False)
        if not run.kit:
            A.status_signing_with(None)
            A.reissue()
        if stale_s is not None:
            A.serve_standing_to_b(pw, None)
        if variant == "a_unreachable" and tr.t_ref is not None and tr.info is None \
                and W is not None:
            ex["recovery"] = _recovery(run, tr, W, pw)


def _stale_fixture(run: _Run, tr: _Trial, form: str, W: Any, pw: str) -> Tuple[Any, float]:
    """``served``: B's fetches get the evidence signed at s0 from the start, the baseline the
    current; ``stapled``: A's paths fail for B and the agent staples s0's evidence;
    ``aged_at_fetch``: B first gets evidence already 0.8 T old, then A goes down. Returns the
    stale evidence and the first slot's offset from it."""
    A, clock = run.stub, run.clock
    T = run.T or 60.0
    if form == "stapled" and not run.staples:
        tr.stop_info("not_landed", "B reads no staples")
        return None, 0.0
    if form == "served" and not run.pull:
        tr.stop_info("not_landed", "B fetches no evidence")
        return None, 0.0
    if run.kit:
        s0 = A.assert_standing(pw, {OPERATION: None}, publish=form != "aged_at_fetch")
        path = run.principal_path(A, pw)
        if form == "served":
            t_fix = clock.now()
            A.serve_standing_to_b(pw, s0)
            if waits_for_fetch(run):
                # KRK-M95: present once B holds the evidence under test, as the X4-status
                # profile does below; until then B holds nothing for this principal.
                got = await_fetches(run, [("W", A, path, t_fix, ("stale",))])
                tr.extra["fetched_stale"] = got["W"]
                if not got["W"]:
                    A.serve_standing_to_b(pw, None)
                    tr.stop_info("fixture_not_landed", "B fetched nothing for the principal "
                                                       "after the stale assertion was set "
                                                       "(KRK-M95)")
                    return None, 0.0
        elif form == "stapled":
            A.set_partition(True)
            tr.extra["staple_serial"] = s0.serial
        else:
            clock.sleep(0.8 * T)
            t_fix = clock.now()
            A.relay_standing(pw, s0)
            if waits_for_fetch(run):
                # KRK-M95: B first gets the evidence already aged, then A goes down.
                got = await_fetches(run, [("W", A, path, t_fix, ("ok",))])
                tr.extra["fetched_aged"] = got["W"]
        if not not_after_far(s0):
            tr.stop_info("fixture_not_landed", "the fixture's own expiry is too near (KRK-M78)")
        if form == "aged_at_fetch":
            p = run.send(run.presentation(W, run.endpoints[0], staple=s0), "W", tag="aged-first")
            tr.pres.append(p)
            tr.w_refs.append(p.ref)
            A.set_source("down")
        tr.extra["stale_serial"] = s0.serial
        tr._staple = s0
        return s0, max(0.0, clock.now() - s0.t_signed)
    # X4-status: the snapshot signed when W's grant was published.
    v = A.current()
    if form == "served":
        t_fix = clock.now()
        A.set_source("stale", version=v["version"])
        # Present only once B holds the evidence under test: until its next fetch it may still
        # hold older evidence from before (a refusal then is not about this fixture).
        got = run.wait_fetch(A, t_fix, "/status/list", max(2 * run.max_interval, 5.0) + 1)
        tr.extra["fetched_stale"] = got is not None
        if got is None:
            tr.stop_info("fixture_not_landed", "B fetched nothing after the stale snapshot was "
                                               "set (KRK-M59's shape)")
    else:
        A.set_source("stale", version=v["version"])
        clock.sleep(0.8 * T)
        A.set_source("down")
    rec = A.snapshot(v["version"])
    tr.extra["stale_version"] = v["version"]

    class _S:
        t_signed = rec["t_signed"]
        serial = v["version"]
    return _S, max(0.0, clock.now() - rec["t_signed"])


def _loop(run: _Run, tr: _Trial, W: Any, L: Any, lorg: Any, lp: Optional[str], pw: str, *,
          t_o: float, start_s: float, moving: bool, restart: bool) -> None:
    """Presentations on X4's schedule from the reference instant: W at every slot,
    L as a companion, until the refusal has held S or the window ends."""
    from .. import timing
    A, clock, T, disp = run.stub, run.clock, run.T, run.disp
    t_ref = tr.t_ref
    slots = timing.schedule(T, run.rng, window=run.window, resolution_s=run.resolution,
                            start_s=start_s)
    skipped: List[Dict[str, Any]] = []
    tr.notes["skipped"] = skipped
    restarted = None
    staple0 = getattr(tr, "_staple", None)
    for i, slot in enumerate(slots):
        clock.sleep_until(t_ref + slot.offset_s)
        disp.poll()
        ep = run.endpoints[i % len(run.endpoints)]
        # The agent staples only what the fixture says: the stale evidence (stale_signed), fresh
        # evidence it fetched past a partition, or nothing (A is unreachable for it too).
        stp = staple0
        if moving and run.kit:
            stp = A.assert_standing(pw, {OPERATION: None})
        pw_ = disp.submit(run.presentation(W, ep, staple=stp), "W", tag=slot.kind)
        if pw_ is None:
            skipped.append({"offset_s": round(slot.offset_s, 4), "under": "W"})
        else:
            tr.pres.append(pw_)
            tr.w_refs.append(pw_.ref)
            pw_.t_f_at_send = run.t_f(A, pw, clock.now() + 1e-6) if moving else t_ref  # type: ignore[attr-defined]
        if L is not None:
            q = run.presentation(L, ep, staple=lorg.current_standing(lp) if run.kit else None)
            got = disp.submit(q, "L", tag="regular", companion=True)
            if got is not None:
                tr.pres.append(got)
        now = clock.now()
        if restart and restarted is None and now >= t_o + (T or 30.0) / 2.0:
            disp.drain()
            try:
                restarted = dict(run.a.restart() or {})
            except Exception as e:  # noqa: BLE001
                restarted = {"raised": f"{type(e).__name__}: {e}"[:200]}
            tr.extra["restart"] = restarted
            tr.extra["t_restart_s"] = round(clock.now() - t_o, 3)
        streak = p19._streak(tr.pres)
        if streak is not None and now - streak >= run.stability and now >= tr.settle_until \
                and (not restart or restarted is not None) and not moving:
            break
    disp.drain()
    tr.notes["slots_used"] = i + 1 if slots else 0


def _recovery(run: _Run, tr: _Trial, W: Any, pw: str) -> Dict[str, Any]:
    """After an ``a_unreachable`` trial, A is back: is W accepted again within B's stated
    recovery bound? (P19's `judge_recovery`; here the authority was never
    withdrawn, so W itself is the one that must recover.)"""
    from .. import timing
    clock, T, disp, A = run.clock, run.T, run.disp, run.stub
    t_r = clock.now()
    bound = run.bound.get("recovery_s")
    bound = float(bound) if bound else None
    pres: List[Any] = []
    first = None
    slots = timing.schedule(T, run.rng, window=run.window, resolution_s=run.resolution,
                            boundary_at=bound)
    for i, slot in enumerate(slots):
        clock.sleep_until(t_r + slot.offset_s)
        disp.poll()
        ep = run.endpoints[i % len(run.endpoints)]
        q = disp.submit(run.presentation(W, ep, staple=A.current_standing(pw) if run.kit
                                         else None), "W", tag="recovery")
        if q is not None:
            pres.append(q)
        if first is None:
            for x in pres:
                if not p19._settled(x):
                    break
                if x.accepted:
                    first = x.t_sent - t_r
                    break
        if first is not None and clock.now() - t_r >= max(T or 0.0, first + 3 * timing.delta_s(T)):
            break
    disp.drain()
    run.settle(clock.now() + 2.0)
    for p in pres:
        run.fill(p)
    j = timing.judge_recovery([(p.t_sent - t_r, p.accepted, p.refused) for p in pres], None,
                              bound, run.window, run.resolution)
    return {"limit_s": run.window, "recovery_bound_s": bound, **j,
            "presentations": [p19._pres_doc(p, t_r) for p in pres]}


def _finish(run: _Run, tr: _Trial) -> Any:
    from ..timing import TrialLog
    run.settle(max(tr.settle_until, run.clock.now() + 2.0))
    for p in tr.pres:
        run.fill(p)
    if run.grade == "recorder":
        w_eff = [t for r in set(tr.w_refs) for t in run.effect_times(r)]
    else:
        w_eff = [p.effect_t for p in tr.pres if p.under == "W" and p.effect_t is not None]
    t_ref = tr.t_ref if tr.t_ref is not None else run.clock.now()
    judged = [p for p in tr.pres if tr.t_o is None or p.t_sent >= tr.t_o]
    if tr.held_ref:
        judged = [p for p in judged if p.ref != tr.held_ref]
    return TrialLog(tr.variant, tr.form, t_ref, run.T, run.window, run.stability,
                    presentations=judged, w_effects=w_eff, failsafe=tr.failsafe,
                    info=tr.info, info_detail=tr.info_detail, ended_at=run.clock.now(),
                    phase_s=tr.phase_s, resolution_s=run.resolution)


def _judge_timed(run: _Run, tr: _Trial, log: Any) -> Any:
    from .. import timing
    from ..timing import TrialOutcome
    if log.info is None and tr.form == "partition":
        T = run.T or run.window
        late = [p for p in log.presentations if p.under == "W" and p.accepted
                and p.t_sent > getattr(p, "t_f_at_send", log.t_w) + T]
        acc = sum(1 for p in log.presentations if p.under == "W" and p.accepted)
        if late:
            return TrialOutcome("late", False, form=tr.form, detail=f"accepted a presentation "
                                f"sent more than T after the newest evidence it carried")
        return TrialOutcome("within", True, form=tr.form,
                            detail=f"{acc} presentations accepted on fresh stapled evidence, "
                                   f"none more than T after the evidence it carried")
    o = timing.classify_trial(log)
    # X4's words name a withdrawal; nothing is withdrawn in X1, and times run from the reference
    # instant (t_f, or t_k for a key revocation).
    ref = "t_k" if (tr.variant, tr.form) == ("retired_key", "revoked_key") else "t_f"
    o = TrialOutcome(o.outcome, o.ok, time_s=o.time_s, bracket=o.bracket,
                     last_effect_s=o.last_effect_s, onset_endpoint=o.onset_endpoint,
                     detail=o.detail.replace("after the withdrawal", f"after {ref}")
                     .replace("under the withdrawn authority", "under W"),
                     phase_s=o.phase_s, form=o.form)
    if o.outcome == "late":
        o = TrialOutcome("late", False, time_s=o.time_s, bracket=o.bracket,
                         last_effect_s=o.last_effect_s, onset_endpoint=o.onset_endpoint,
                         detail="accepted_beyond_T: " + o.detail, phase_s=o.phase_s, form=o.form)
    if o.ok is True and tr.variant == "a_unreachable" and tr.form != "partition":
        rec = tr.extra.get("recovery") or {}
        up = bool(rec.get("ok")) or any(p.under == "L" and p.accepted and p.t_sent >= log.t_w
                                        for p in log.presentations)
        t_o = log.t_w + float(tr.extra.get("t_o_minus_t_ref_s") or 0.0)
        if online_only(run, log.presentations, log.t_w, t_o, up):
            return TrialOutcome("online_only", False, time_s=o.time_s, bracket=o.bracket,
                                form=o.form, detail="B accepted nothing under W after A became "
                                "unreachable while its evidence was younger than T: it fails "
                                "safe, with an offline window of zero")
    if o.ok is True and tr.extra.get("adapter_translates_keys"):
        return TrialOutcome("adapter_reading", None, form=o.form,
                            detail="the key change reached B through the adapter (KRK-M71)")
    return o


def _offline_window(log: Any, tr: _Trial) -> Optional[Dict[str, float]]:
    t_o = log.t_w + float(tr.extra.get("t_o_minus_t_ref_s") or 0.0)
    acc = [p.t_sent for p in log.presentations if p.under == "W" and p.accepted
           and p.t_sent >= t_o]
    ref = [p.t_sent for p in log.presentations if p.under == "W" and p.refused
           and p.t_sent >= t_o]
    return {"O_s": round(max(acc) - log.t_w, 3) if acc else 0.0,
            "first_refusal_s": round(min(ref) - log.t_w, 3) if ref else None,
            "t_o_s": round(t_o - log.t_w, 3)}


# --------------------------------------------------------------------------- the probe


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    if raw.strip().startswith("{"):
        return json.loads(raw)
    with open(raw, encoding="utf-8") as f:
        return json.load(f)


def _trials_for(plan: Dict[str, Any], key: str, static: bool) -> int:
    t = plan.get("trials") or TRIALS
    if t == "dev":
        t = DEV_TRIALS
    elif t == "published":
        t = PUBLISHED_TRIALS
    if static:
        return int(t.get("static", t.get("*", 1)))
    return int(t.get(key, t.get("*", 1)))


def _forms(variant: str) -> Tuple[str, ...]:
    return FORMS.get(variant, ("",))


def _is_static(run: _Run, variant: str, form: str) -> bool:
    return (variant, form) in (STATIC_KIT if run.kit else STATIC_X4)


def _gap(run: _Run, variant: str, form: str, a: Any) -> Optional[Tuple[str, str]]:
    """(outcome, why) when a form cannot run on this B, before anything is built."""
    if not run.kit and (variant, form) in X4_GAPS:
        return "format_gap", X4_GAPS[(variant, form)]
    if (variant, form) == ("stale_signed", "stapled") and not run.staples:
        return "not_applicable", "B reads no stapled evidence"
    if (variant, form) == ("stale_signed", "served") and not run.pull:
        return "not_applicable", "B fetches no evidence"
    if run.kit and (variant, form) == BEFORE_FETCH and not run.pull_only:
        return "not_applicable", ("B does not obtain standing only by fetching it, so the other "
                                  "static forms already present before its first fetch "
                                  "(KRK-M95b)")
    if (variant, form) == ("a_unreachable", "partition") and not run.staples:
        return "not_applicable", "B reads no stapled evidence, so a partition changes nothing " \
                                 "but an outage would"
    if variant == "restart_offline" and not callable(getattr(a, "restart", None)):
        return "not_applicable", "no restart hook: a hosted B is never restarted"
    if variant == "deep_chain" or (variant, form) == ("other_organisation", "c_standing"):
        why = depth_supported(run)
        if why:
            return "depth_refused", why
    why = needs_second_issuer(run, variant, form)
    if why:
        return "issuer_not_supported", why
    if variant == "key_of_other_org" and not run.kit and run.aprime is None:
        return "issuer_not_supported", "B pins one issuer (KRK-M70)"
    return None


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import role_b
    from ..issuer import StubIssuer
    from ..mockserver import MockServer
    from ..requester import new_issuer
    from ..timing import make_clock, stability_s, window_s

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if getattr(a, "role", lambda: "B")() != "B":
        return Result.inconclusive(a.name, ID, "P20 grades B in version 1; role A is version 2 "
                                   "(design §6.6)", **common)
    base = role_b.RoleB()

    def opt(name: str) -> Any:
        f = getattr(a, name, None)
        return f() if callable(f) else getattr(base, name)()
    try:
        bound = dict(a.withdrawal_bound() or {})
        agreement = dict(a.agreement() or {})
        grade = a.evidence_grade()
        profile = opt("standing_profile") or "kirkaldy"
        std_channels = list(opt("standing_channels") or [])
        n_iss = int(opt("issuers") or 1)
        keys_from = opt("keys_from") or "statement"
        holder_hops = bool(opt("accepts_holder_hops"))
        max_depth = opt("max_depth")
        sbound = opt("standing_bound")
        channels = list(getattr(a, "channels", lambda: [])() or [])
        forms = list(getattr(a, "presentation_forms", lambda: ["agent"])() or ["agent"])
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    if profile not in role_b.STANDING_PROFILES:
        return Result.inconclusive(a.name, ID, f"unknown standing profile {profile!r}", **common)
    if any(c not in role_b.STANDING_CHANNELS for c in std_channels) or \
            keys_from not in role_b.KEYS_FROM:
        return Result.inconclusive(a.name, ID, f"standing channels {std_channels} / keys_from "
                                   f"{keys_from!r} are not the kit's", **common)
    T = bound.get("T_s")
    if T is not None and (not isinstance(T, (int, float)) or T <= 0):
        return Result.inconclusive(a.name, ID, f"T_s must be a positive number or None", **common)
    if bound.get("source") not in p19.BOUND_SOURCES:
        return Result.inconclusive(a.name, ID, "the bound's source is not one of "
                                   f"{p19.BOUND_SOURCES}", **common)
    findings: List[str] = []
    if T is not None and bound["source"] == "carried":
        bound = {**bound, "carried_T_s": T, "T_s": None}
        T = None
    if sbound and isinstance(sbound.get("T_s"), (int, float)):
        if T is None or sbound["T_s"] < T:
            bound = {**bound, "withdrawal_T_s": T, "T_s": float(sbound["T_s"]),
                     "source": sbound.get("source", bound.get("source")),
                     "standing_bound": sbound}
            T = float(sbound["T_s"])
        elif sbound["T_s"] > T:
            findings.append(f"states standing evidence may be {sbound['T_s']:g} s old, more than "
                            f"its withdrawal bound of {T:g} s")
    if not agreement.get("counterparty") or grade not in p19.GRADES:
        return Result.inconclusive(a.name, ID, "no counterparty id, or an unknown evidence grade",
                                   **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not p19._is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock (KRK-M56)",
                                   **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    bad = sorted(v for v in na if v in NA_FORBIDDEN or v not in VARIANTS)
    if bad:
        return Result.inconclusive(a.name, ID, f"the adapter declares {bad} not applicable; "
                                   f"{list(NA_FORBIDDEN)} may not be", **common)
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    plan = dict(plan if plan is not None else ({} if p19._is_toy(a) else (_plan_from_env() or {})))
    published = plan == {"trials": "published"}
    development = bool(plan) and not published
    win = float(plan.get("window_s") or window_s(T))
    stab = float(plan.get("stability_s") or stability_s(T))
    only = list(plan.get("variants") or VARIANTS)
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    clock = make_clock(kind)
    if kind == "virtual":
        a.set_clock(clock)
    recorder = MockServer(clock=clock.now)
    status_profile = "kirkaldy"
    A = StubIssuer(new_issuer(), clock=clock, status_profile=status_profile,
                   ttl_s=int(T) if T else 60, audience=agreement["counterparty"],
                   standing_purpose="standing" if profile == "kirkaldy" else "status")
    A.hang_s = (T or 30.0) + 5.0
    url = A.serve()
    progress = p19._Progress(ev)
    run = None
    try:
        # Keys prepared before bind: one retired from a minute ago (``retired_before_bind``),
        # and one active key per ``revoked_key`` trial, so a B that reads A's keys once at bind
        # has seen each before it is revoked.
        purpose = "standing" if profile == "kirkaldy" else "status"
        rk, _ = A.add_key([purpose], state="retired", since_offset_s=-60.0)
        n_rev = _trials_for(plan, "*", False) * (1 if "retired_key" in only else 0) + 2
        revocable = [A.add_key([purpose])[0].kid for _ in range(n_rev)]
        bind_how = a.bind_requester(A.trust_anchor_x1(), url)
        peers: Dict[str, Any] = {}
        for role in ("A′", "A2", "C")[:max(0, n_iss - 1)]:
            o = A.peer()
            how = a.bind_peer(o.trust_anchor_x1(), o.source_url)
            peers[role] = (o, how)
        prefix = f"/p20/{run_tag}{secrets.token_hex(4)}"
        rec_how = a.bind_recorder(recorder.url + prefix)
        run = _Run(a, ev, clock=clock, stub=A, recorder=recorder, prefix=prefix,
                   agreement=agreement, bound=bound, channels=channels, forms=forms,
                   grade=grade, rng=rng, window=win, stability=stab, profile=profile,
                   std_channels=std_channels, issuers=n_iss, keys_from=keys_from,
                   holder_hops=holder_hops, max_depth=max_depth)
        run.progress = progress
        run.retired_kid = rk.kid
        run.revocable = revocable
        run.aprime = peers.get("A′", (None,))[0]
        run.a2 = peers.get("A2", (None,))[0]
        run.c = peers.get("C", (None,))[0]
        from ..timing import delta_s
        run.delta = delta_s(T)
        statements = {"T_s": T, "bound": bound, "standing_profile": profile,
                      "standing_channels": std_channels, "issuers": n_iss,
                      "keys_from": keys_from, "accepts_holder_hops": holder_hops,
                      "max_depth": max_depth, "standing_bound": sbound}
        ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order,
                              "statements": p19._jsonable(statements), "plan": plan,
                              "window_s": win, "stability_s": stab, "clock": kind,
                              "evidence_grade": grade, "variants_not_applicable": na,
                              "bind_requester": bind_how,
                              "bind_peer": {k: v[1] for k, v in peers.items()},
                              "bind_recorder": rec_how})
        run.log("run", seed=seed, statements=statements, plan=plan, window_s=win,
                stability_s=stab, variant_order=[CONTROL] + order)
        return _probe(run, a, ev, common, bound, na, notes, plan, development, only, order, seed,
                      findings)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        if run is not None:
            run.disp.close()
        recorder.close()
        A.close()
        clock.close()


def _aggregate(outcomes: List[Any], T: Optional[float], need: int, static: bool
               ) -> Tuple[str, Optional[bool]]:
    from .. import timing
    counted = [o for o in outcomes if o.ok is not None]
    if static:
        if any(o.ok is False for o in counted):
            return next(o.outcome for o in counted if o.ok is False), False
        if counted and all(o.ok for o in counted):
            return ("accepted_as_required" if counted[0].outcome == "accepted_as_required"
                    else "refused"), True
        infos = [o.outcome for o in outcomes]
        return (max(sorted(set(infos)), key=infos.count) if infos else "not_run"), None
    if any(o.outcome == "online_only" for o in counted):
        return "online_only", False
    other = next((o for o in counted if o.ok is False and o.outcome not in
                  ("late", "not_within_W", "flapped")), None)
    if other is not None:
        return other.outcome, False
    return timing.aggregate(outcomes, T, need=need)


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], bound: Dict[str, Any],
           na: Dict[str, str], notes: Dict[str, str], plan: Dict[str, Any], development: bool,
           only: List[str], order: List[str], seed: int, findings: List[str]) -> Result:
    from .. import timing
    T = run.T
    held, why, obs = _control(run)
    ev.write("control.json", {"held": held, "why": why,
                              **{k: v for k, v in p19._jsonable(obs).items()
                                 if k != "presentations"},
                              "presentations": [p19._pres_doc(p, None)
                                                for p in obs.get("presentations", [])]})
    run.log("control", held=held, why=why)
    if not held:
        run.log("end", status="inconclusive", summary=f"control did not hold: {why}")
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    control = ("a fresh request under W and under L accepted at every endpoint, one effect each "
               "at the recorder; the kit's baseline read A's key statement and the principal's "
               "evidence as current")
    by_form: Dict[Tuple[str, str], List[Any]] = {}
    gaps: Dict[Tuple[str, str], Tuple[str, str]] = {}
    docs: Dict[str, List[Dict[str, Any]]] = {}
    windows: List[Dict[str, Any]] = []
    recovery: List[Any] = []
    depth_ok: Optional[bool] = None
    for variant in order:
        if variant in na or variant not in only:
            continue
        for form in _forms(variant):
            if form and variant in (plan.get("forms") or {}) and \
                    form not in plan["forms"][variant]:
                continue
            g = _gap(run, variant, form, a)
            if g is not None:
                gaps[(variant, form)] = g
                continue
            if (variant, form) in (("deep_chain", "root_source_down"),
                                   ("deep_chain", "root_missing"),
                                   ("other_organisation", "c_standing")):
                if depth_ok is None:
                    depth_ok = _three_hops_first(run)
                if not depth_ok:
                    gaps[(variant, form)] = ("depth_refused", "B refused a three-hop chain with "
                                             "fresh root evidence (KRK-M75)")
                    continue
            static = _is_static(run, variant, form)
            phases = ["random"]
            if variant == "a_unreachable" and form != "partition" and run.pull:
                phases.append("worst")
            for phase in phases:
                key = variant + ("/worst" if phase == "worst" else "")
                for k in range(_trials_for(plan, key, static)):
                    if static:
                        tr, ex = _static_trial(run, variant, form, k)
                        o = _judge_static(run, tr)
                        log = None
                    else:
                        tr, ex = _timed_trial(run, variant, form, k, phase)
                        log = _finish(run, tr)
                        o = _judge_timed(run, tr, log)
                        if variant == "a_unreachable" and tr.info is None:
                            windows.append({"form": form, "phase": phase, **(
                                _offline_window(log, tr) or {})})
                        if "recovery" in ex:
                            r = ex["recovery"]
                            br = r.get("bracket")
                            recovery.append(timing.TrialOutcome(
                                r["outcome"], r["ok"], detail=r["detail"], form=form,
                                time_s=r.get("first_L_accepted_s"),
                                bracket=tuple(br) if br else None))
                    if form == "three_hops":
                        depth_ok = o.ok is True
                    by_form.setdefault((variant, form), []).append(o)
                    doc = {"form": form, "k": k, "phase": phase, "outcome": o.to_doc(),
                           "extra": p19._jsonable(ex),
                           "t_ref_kit": tr.t_ref, "presentations": [
                               p19._pres_doc(p, tr.t_ref) for p in tr.pres]}
                    docs.setdefault(variant, []).append(doc)
                    run.log("trial", variant=variant, **doc)
        if variant in docs:
            ev.write(f"{variant}.json", {"variant": variant, "trials": docs[variant]})
    checks: List[Check] = []
    stats: Dict[str, Any] = {}
    format_gaps: List[Dict[str, str]] = []
    form_readings: Dict[str, Dict[str, Any]] = {}
    for variant in VARIANTS:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        if variant not in only:
            continue
        outs: List[Any] = []
        parts: List[str] = []
        fr: Dict[str, Any] = {}
        for form in _forms(variant):
            key = (variant, form)
            if form and variant in (plan.get("forms") or {}) and \
                    form not in plan["forms"][variant]:
                continue
            if key in gaps:
                outcome, why = gaps[key]
                fr[form or "-"] = {"reading": outcome, "ok": None, "detail": why}
                if outcome == "format_gap":
                    format_gaps.append({"variant": variant, "form": form, "why": why})
                parts.append(f"{form or variant}: {outcome} ({why})")
                continue
            os_ = by_form.get(key, [])
            outs += os_
            static = _is_static(run, variant, form)
            need = sum(_trials_for(plan, variant + s, static) for s in
                       ([""] + (["/worst"] if variant == "a_unreachable" and form != "partition"
                                and run.pull else [])))
            lab, ok = _aggregate(os_, T, need, static)
            fr[form or "-"] = {"reading": lab, "ok": ok,
                               "detail": next((o.detail for o in os_ if o.ok is False),
                                              os_[0].detail if os_ else "")}
            parts.append(f"{form or variant}: {lab}")
        form_readings[variant] = fr
        if outs and any(not _is_static(run, variant, f) for f in _forms(variant)):
            stats[variant] = timing.statistics([o for o in outs if o.outcome != "accepted"], T)
        fails = [(f, d) for f, d in fr.items() if d["ok"] is False]
        passes = [(f, d) for f, d in fr.items() if d["ok"] is True]
        incon = [(f, d) for f, d in fr.items() if d["reading"] == timing.INCONCLUSIVE]
        if fails:
            f, d = fails[0]
            c = Check(variant, d["reading"], False, f"{f}: {d['detail']}; " + "; ".join(parts))
        elif incon:
            c = Check(variant, timing.INCONCLUSIVE, None, "; ".join(parts))
        elif passes:
            labs = sorted({d["reading"] for _f, d in passes})
            c = Check(variant, labs[0] if len(labs) == 1 else "+".join(labs), True,
                      "; ".join(parts))
        else:
            c = Check(variant, next(iter(fr.values()))["reading"] if fr else "not_run", None,
                      "; ".join(parts))
        if variant in notes:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (adapter note: {notes[variant]})")
        checks.append(c)
    if recovery:
        rf = [o for o in recovery if o.ok is False]
        if rf:
            checks.append(Check("recovery", rf[0].outcome, False, rf[0].detail))
        elif any(o.outcome == timing.INCONCLUSIVE for o in recovery):
            checks.append(Check("recovery", timing.INCONCLUSIVE, None, "a recovery bracket "
                                "crossed the stated recovery bound"))
        else:
            checks.append(Check("recovery", "recovered", True, f"W accepted again after each of "
                                f"{len(recovery)} outages"))
        stats["recovery"] = timing.statistics(recovery, None)
    must = []
    for v, f in MUST_LAND:
        if v not in only or v in na:
            continue
        if (v, f) == ("stale_signed", "served") and not run.pull:
            continue
        if (v, f) == ("stale_signed", "stapled") and not run.staples:
            continue
        if (v, f) in gaps and gaps[(v, f)][0] in ("format_gap", "not_applicable",
                                                  "issuer_not_supported"):
            continue
        d = form_readings.get(v, {}).get(f)
        if d is None or d["ok"] is None:
            must.append(f"{v}/{f}")
    fails = [c for c in checks if c.ok is False]
    unresolved = [c.name for c in checks if c.outcome == timing.INCONCLUSIVE]
    documents = bool(getattr(a, "documents_standing", lambda: False)())
    vuln = documents and any(
        c.name in VULNERABLE_VARIANTS and not (c.name == "retired_key"
                                               and run.keys_from != "statement")
        or (c.name in ("a_unreachable", "stale_signed") and c.outcome == "not_refused_within_W")
        for c in fails)
    worst = max((s.get("max_s") or 0.0 for v, s in stats.items() if v != "recovery"
                 and isinstance(s.get("max_s"), (int, float))), default=None)
    extra: Dict[str, Any] = {
        "seed": seed, "bound": p19._jsonable(bound), "T_source": bound.get("source"),
        "standing_profile": run.profile, "standing_channels": run.std_channels,
        "issuers": run.n_issuers, "keys_from": run.keys_from,
        "accepts_holder_hops": run.holder_hops, "max_depth": run.max_depth,
        "evidence_grade": run.grade, "clock": getattr(a, "clock", "real"),
        "window_s": run.window, "stability_s": run.stability, "statistics": stats,
        "forms": form_readings, "format_gaps": format_gaps, "offline_windows": windows,
        "findings": findings, "worst_case_s": worst,
        "disclosure": "vulnerability" if vuln else "conformance",
        "scheduler": {**run.disp.totals, "limit": run.disp.limit},
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if windows:
        Os = sorted(w["O_s"] for w in windows)
        extra["offline_window_s"] = {"min": Os[0], "median": Os[len(Os) // 2], "max": Os[-1],
                                     "n": len(Os), "note": "the latest acceptance under W after "
                                     "A became unreachable, less t_f (reported, no minimum)"}
    if plan:
        extra["plan"] = plan
    if T is None:
        extra["finding"] = "no stated bound on the age of the evidence B acts on"
        extra["effective_bound_s"] = worst
    head = (f"no stated bound; measured worst case "
            f"{'%.2f s' % worst if worst is not None else 'none'}. " if T is None else "")
    dev = "Development plan (smaller counts; not a published run). " if development else ""
    gap_txt = (f" Format gaps (findings, never a pass): "
               f"{', '.join(g['variant'] + '/' + g['form'] for g in format_gaps)}."
               if format_gaps else "")
    if not fails and (must or unresolved):
        why_txt = []
        if must:
            why_txt.append(f"forms that must land did not: {must}")
        if unresolved:
            why_txt.append(f"brackets crossed the bound: {unresolved}")
        r = Result.inconclusive(a.name, ID, f"{dev}{head}no variant failed, but "
                                f"{'; and '.join(why_txt)}.{gap_txt}", checks=checks,
                                control_held=True, control_detail=control, extra=extra, **common)
    elif not [c for c in checks if c.ok is not None]:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant landed with a verdict.{gap_txt}",
                                checks=checks, control_held=True, control_detail=control,
                                extra=extra, **common)
    else:
        bt = f"T = {T:g} s ({bound.get('source')})" if T else f"the {run.window:g} s window"
        r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                    pass_summary=f"{dev}{head}every effect rested on standing evidence B could "
                                 f"check, within {bt}, offline included.{gap_txt}",
                    fail_summary=f"{dev}{head}an effect rested on evidence that broke a link "
                                 f"or was older than {bt}, or B could not act offline"
                                 f"{'.' + gap_txt if gap_txt else ''}",
                    extra=extra, **common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r


def _three_hops_first(run: _Run) -> bool:
    """KRK-M75: one ``three_hops`` trial before the forms that depend on it, if none ran."""
    tr, _ex = _static_trial(run, "deep_chain", "three_hops", -1)
    return _judge_static(run, tr).ok is True
