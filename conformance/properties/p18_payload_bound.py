"""P18 — Payload bound, single use (KRK-18, cross-organisation X3).

**Guarantee.** When organisation B receives a request presented under an authorisation from
organisation A, B performs an effect only if the authorisation covers this exact request: every
member B acts on, under the binding basis the agreement declares, addressed to the B, endpoint
and tenant that received it, inside its validity window, and for the specific request rather
than a class of requests unless the agreement allows a class for that operation. Across every
presentation of one authorisation (repeated, concurrent, after a restart or failover, at another
endpoint or tenant, split into parts), B performs the effect at most as often as the
authorisation allows, which is once unless it says otherwise. A retry of the same request is
answered without a second effect, and B's answer to it never states that the request was not
executed when it was.

**Question.** Does the receiving organisation perform an effect only for the exact request the
requesting organisation authorised, addressed to it and still valid, and at most as often as that
authorisation allows across every presentation, restart, endpoint and tenant; and does it answer a
repeated presentation truthfully, without a second effect?

**Who is graded.** The target, in role B. The kit plays A with a stub
(`conformance/requester.py`): its own Ed25519 key, per-request authorisations it signs, raw
request bytes, and a transport that presents each request once, can drop B's answer after B
acted, and can release several presentations together. Effects are counted at the kit's recorder
(`conformance/mockserver.py`), downstream of B's executor, never from B's answers (spec §2,
"Recorder"; §5.1 rule 4). A secondary family of six checks grades a target in role A against
the stub B in its strict mode (`counterparty.StubCounterparty(single_use=True)`); an adapter
whose `role()` is ``"A"`` gets that family instead (`probe_role_a`, "The role-A family" below).

**Decisions that bind the probe:**

- "the same request" is the authorisation's own id together with the request digest. The
  same id and digest again is a repeat: no second effect. A client idempotency key outside the
  authorisation is not a replay defence (``replay_new_key``);
- a ``refused`` or ``not-executed`` answer to a repeat of an executed request is the fail
  ``denied_done``;
- use is remembered at least until expiry plus the stated tolerance, or forever; the memory
  survives restart and failover and is shared across endpoints and tenants;
- a refusal that uses up the authorisation is the fail ``consumed_by_refusal``;
- a false refusal of an equivalent serialisation is information (``false_refusal``); checking
  one reading and acting on another is a fail;
- exact binding is the default for every operation the agreement does not mark ``class``;
  P18 does not apply to an operation the agreement allows a class for;
- evidence grades run ``recorder`` > ``B-store-read`` > ``B-answer``, and B's answer alone gives
  no verdict on a variant that counts effects;
- parts only when the authorisation lists them;
- a B with only an API key runs like any other and fails what it cannot answer;
- targets are self-hosted only in version 1.

**Probe.**

1. Draw the seed. Read the target's stated agreement before anything runs (spec §3.4):
   endpoints, aliases, tenants, operations with their binding kind, the binding basis, mapping
   profiles, the longest validity, the memory horizon, the clock tolerance, the answer codes and
   whether it claims replay protection. Start the kit's recorder.
2. Each pair (the control, then each variant in a seeded shuffled order) gets a fresh stub A: a
   new issuer id, a new key from the operating system, pinned at B (`pin_requester_key`, with the
   mapping the pair's agreement declares, if any), and its own recorder namespace
   (`bind_recorder`).
3. Control (below). Then each variant: its capability control, the variant, the landed check.
4. After every step the recorder is read; effects are attributed to requests by the request's
   ``ref`` member, which the stub draws per request from the operating system.
5. B's answers are classified by the adapter (`classify`) from codes quoted from the product.

**Control** (design §5.1; spec §3.1). It proves only that the probe reached the real path and
never demands the guarantee (KRK-M19). On a fresh pair, M honest requests (M drawn from
`SERIES`), each with its own genuine authorisation addressed to the first endpoint and tenant,
each presented once. It holds when the recorder was empty for the pair before the first
presentation and shows exactly one effect per request afterwards, with that request's values;
the wire log shows each presentation leaving the kit once and, where B keeps a record of what it
received (`received`), the same bytes; every answer was readable; and a fresh authorisation
presented after the series still runs. It does not require that B verifies a signature, compares
a digest, keeps a use record, refuses anything or answers in any particular shape. A B that runs
whatever arrives passes the control and fails the variants (the ``no_check`` toy).

**Variants** (`requester.VARIANTS`; design §3.1), each with the toy B that fails it:

| Variant | Planted | Pass | Toy that fails it |
|---|---|---|---|
| `body_changed` | R′ (one member changed) beside R's authorisation | refused | `signature_only` |
| `unbound_member` | R; every header outside the binding changed | refused, or ran with R's values | `header_recipient` |
| `noncanonical_equivalent` | R re-serialised | ran with R's values, or refused (`false_refusal`, information) | none (honest half) |
| `duplicate_key` | bytes with a member twice, genuinely signed by a lenient A | refused | `last_key_wins` |
| `number_precision` | 2^53+1 beside an authorisation for 2^53 | refused, or ran with 2^53 | `float_amounts` |
| `unicode_fold` | a fullwidth recipient NFKC folds to the authorised one | refused, or ran with the authorised value | `nfkc_before_check` |
| `class_for_exact` | a class authorisation for an exact operation | refused | `accepts_scope` |
| `replay_after_answer` | the same bytes and authorisation again | one effect; second answer not refused | `no_memory` |
| `retry_after_lost_answer` | B's answer dropped, identical retry | one effect; second answer not refused | `duplicate_as_refusal` |
| `replay_new_key` | the same with a fresh client idempotency key | one effect | `dedupes_on_client_key` |
| `replay_after_restart` | a restart of B's process between | one effect | `memory_only` |
| `replay_after_failover` | the second to another instance | one effect | `per_replica_memory` |
| `replay_other_endpoint` | presented at E2 first, addressed to E1 | refused at E2 (or E2 an alias), once in total | `per_endpoint_memory` |
| `replay_other_tenant` | presented at T2 first, addressed to T1 | refused at T2, once in total | `ignores_tenant` |
| `replay_other_counterparty` | an authorisation addressed to another organisation | refused | `ignores_audience` |
| `race_same` | N identical presentations released together, overlap shown inside B | one effect per round | `check_then_set` |
| `split_undeclared` | two parts, each beside the whole's authorisation | refused | `accepts_subset` |
| `split_declared` | declared parts, then the whole | each part once, the whole refused | `parts_and_whole` |
| `expired` | `not_after` past by more than the tolerance | refused | `ignores_not_after` |
| `validity_beyond_memory` | `not_after` beyond a shortened memory horizon | refused at first, or once in total after the horizon | `forgets_before_expiry` |
| `refused_then_retry` | a dependency off, then back; identical retry | the retry runs, once | `consumes_on_refusal` |
| `crash_between_use_and_effect` | B dies between its use record and its effect | at most one effect; never "done" without one | `effect_before_mark`, `mark_before_effect_says_done` |
| `translated_declared` | R in B's vocabulary under the declared mapping | ran with R's values through the mapping, or `false_refusal` | none (honest half) |
| `mapping_undeclared` | the same with no mapping declared | refused | `matches_by_shape` |

`body_changed`, `class_for_exact`, `replay_other_endpoint`, `replay_other_tenant`, `expired`,
`refused_then_retry`, `retry_after_lost_answer`, `race_same`, the restart variants and the crash
variant each run a capability control first (design §5.1 table), and count only if it holds;
otherwise the outcome is ``capability_not_held`` (information).

**Outcomes per variant.** Pass: ``refused``, ``ran_once``, ``ran_as_authorised``. Fail:
``ran_changed``, ``ran_twice`` / ``ran_<N>x``, ``ran_wrong_audience``, ``ran_expired``,
``denied_done``, ``claims_done``, ``consumed_by_refusal``, and three added in the build:
``ran_ambiguous`` (an effect for bytes with no single reading), ``ran_under_class`` (an effect for
an exact-bound operation under a class authorisation) and ``ran_without_basis`` (an effect for a
request in another vocabulary with no declared mapping). Information: ``stuck``,
``false_refusal``, ``no_overlap``, ``capability_not_held``, ``fixture_not_landed``,
``not_applicable``, ``not_driven``, and ``answer_only`` (at the ``B-answer`` grade, an executed
answer on a variant where only the values would tell; `judge_answers`).

**Result.** ``fail`` if any landed variant fails. ``pass`` only if the control held, every variant
in `NA_FORBIDDEN` was driven and landed with a verdict, ``replay_after_restart`` was driven (it
may not be declared not applicable, and an adapter with no ``restart`` hook leaves it
``not_driven``), and every landed variant passed. ``inconclusive`` if the control did not hold,
or if nothing failed but a variant that must land did not. The result carries the evidence grade,
the agreement as read, and the disclosure class: ``vulnerability`` where the agreement claims
replay protection or request binding and a variant shows a second effect, an effect under a
changed request, or one under an authorisation addressed to someone else;
``conformance`` otherwise.

**Measurement errors guarded** (`docs/FAILURE-MODES.md`). KRK-M36 authorisation ids, keys and
request refs from the operating system; the seed draws only choices. KRK-M37 fixtures are bytes
from construction to the wire; the wire log and `received` are compared with the fixture.
KRK-M38 the transport has no retry and adds no header; it counts presentations. KRK-M39 a race
round counts only if every presentation began inside B within half an uncontended
presentation's duration, both measured inside B. KRK-M40 the capability control of each
endpoint, tenant and instance variant needs an effect there to reach the recorder. KRK-M41
replays are presented well inside the window; ``expired`` has a control on the valid side by the
same margin. KRK-M42 every header outside the binding is changed, and the values B used are read
at the recorder, whatever the adapter declared. KRK-M43 answer classes come from the adapter's
quoted product codes; an unmapped code is ``error``, information. KRK-M44 a restart counts only if
the process holding B's state reports a new boot id and a fresh authorisation runs after it.

**The role-A family** (design §6.8), for an adapter whose `role()` is ``"A"``. The
target sends requests to the stub B in its strict single-use mode, through a path the kit gives
it (`bind_counterparty`); B keeps the raw bytes and any authorisation it receives. Control: an
approved request reaches B once, B executes it, and the target's status is readable. Checks:

| Check | Fails when |
|---|---|
| `authorisation_present` | B receives no authorisation, an unsigned one, one that does not verify under the key the target publishes, or one that does not name the digest of the bytes B received, B as audience, and a window |
| `retry_same` | after a lost answer the target's retry carries different bytes or another authorisation id |
| `fresh_per_decision` | a second decision on an identical request reaches B under the first decision's use key (authorisation id, or the correlation id when there is no authorisation) |
| `one_audience` | an authorisation (or, with none, a correlation id) presented to one counterparty is presented to a second |
| `honours_duplicate` | on B's ``duplicate`` answer to its retry the target records the action as not executed or refused |
| `record_matches_effect` | after the honest retry, the target's own reading of the outcome (`outcome`) contradicts what B did, counted in B's store: not done while B performed it, or done while B did not |

These checks are not the property; they say whether A makes it reachable for any B.
`record_matches_effect` grades the `retry_same` round. ``disputed`` passes only where B's answers
to the target conflict with B's store; ``open``, a reading outside `OUTCOME_READINGS` and a
target with no `outcome` method are information, never a pass (`record_check`). The control
requires none of it (KRK-M19). KRK-M45: B's effect is counted from B's store (`b_effect`), never
from B's answer to the repeat.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import time
from typing import Any, Dict, List, Optional, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P18"
TITLE = "Payload bound, single use"

FIXTURES = ("known_bad/binding_toys.py", "tests/test_p18_payload_bound.py",
            "tests/vectors/krk18/*.json", "tests/vectors/krk18/requests/*")
"""The known-bad toys (both roles), their required outcomes, and the KRK-18 vectors. The stub A
(`requester.py`), `authz.py`, the recorder and the stub B are imported by the probe, so they are
hashed into `probe_version`."""
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = (
    "The stub A's keys come from the operating system (Ed25519PrivateKey.generate), never from "
    "the seed: the seed is written into result.json.",
    "Authorisation ids and each request's ref come from the operating system (secrets), so a "
    "re-run with one seed never presents an id or a request a target with durable memory saw "
    "before (KRK-M36). Issuer ids per pair, client idempotency keys and request ids likewise.",
    "Times (validity windows, began_at) are read from the clock; which presentation of a race "
    "wins is decided by the target's scheduling.",
)

SERIES = (2, 5)
CONTROL = "control"
VARIANTS = ("body_changed", "unbound_member", "noncanonical_equivalent", "duplicate_key",
            "number_precision", "unicode_fold", "class_for_exact", "replay_after_answer",
            "retry_after_lost_answer", "replay_new_key", "replay_after_restart",
            "replay_after_failover", "replay_other_endpoint", "replay_other_tenant",
            "replay_other_counterparty", "race_same", "split_undeclared", "split_declared",
            "expired", "validity_beyond_memory", "refused_then_retry",
            "crash_between_use_and_effect", "translated_declared", "mapping_undeclared")
"""The same list as `requester.VARIANTS`, the stub A's plans (a test checks they agree). Kept
here as a literal so the catalogue loads without `cryptography`, which only the probe needs."""

NA_FORBIDDEN = (CONTROL, "body_changed", "unbound_member", "duplicate_key", "number_precision",
                "class_for_exact", "replay_after_answer", "retry_after_lost_answer",
                "replay_new_key", "replay_other_counterparty", "race_same", "split_undeclared",
                "expired", "replay_after_restart")
"""Variants an adapter may not declare not applicable. Every B that acts on another
organisation's requests has these questions. ``replay_after_restart`` is here too: an adapter
with no restart hook leaves it ``not_driven``, which is never a pass (design §6.5)."""
MUST_LAND = tuple(v for v in NA_FORBIDDEN if v != CONTROL)
HOOKS = {"replay_after_restart": "restart", "replay_after_failover": "restart",
         "validity_beyond_memory": "set_memory_horizon", "refused_then_retry": "dependency",
         "crash_between_use_and_effect": "crash_between"}
COUNTING = ("replay_after_answer", "retry_after_lost_answer", "replay_new_key",
            "replay_after_restart", "replay_after_failover", "race_same", "split_declared",
            "validity_beyond_memory", "refused_then_retry", "crash_between_use_and_effect",
            "replay_other_endpoint", "replay_other_tenant")
"""Variants that count effects (B4, B5, B6). At the `B-answer` grade they are `not_driven`."""
CLASSES = ("executed", "original", "duplicate", "in-progress", "refused", "not-executed",
           "error")
DENYING = ("refused", "not-executed")
CLAIMING = ("executed", "original", "duplicate")
GRADES = ("recorder", "B-store-read", "B-answer")
VALUE_MEMBERS = ("ref", "operation", "recipient", "amount", "items")
VULNERABLE = ("ran_twice", "ran_changed", "ran_wrong_audience", "ran_ambiguous")


class Adapter(Protocol):
    """Role B. Every method is the product's own path; the adapter adds no check of its own."""

    name: str
    config: str

    def role(self) -> str:
        """``"B"``. (``"A"`` selects the role-A family, `RoleAAdapter`.)"""
        ...

    def agreement(self) -> Dict[str, Any]:
        """What the product states before the run (spec §3.4): ``counterparty`` (its own id),
        ``endpoints``, ``aliases`` ({endpoint: the endpoint it is an alias of}), ``tenants``,
        ``operations`` ({operation: "exact" | "class"}), ``binding_basis``, ``mappings``
        ({profile name: mapping}), ``max_validity_s``, ``memory_horizon_s`` (seconds or
        "permanent"), ``clock_tolerance_s``, ``answer_codes``, ``claims_replay_protection``,
        and ``quotes`` ({field: quote or "not-found"})."""
        ...

    def pin_requester_key(self, issuer: str, kid: str, public_key: bytes,
                          mapping: Optional[Dict[str, Any]] = None) -> None:
        """Pin A's key for `issuer`, with the mapping this pair's agreement declares (None when
        it declares none), in whatever form the product takes them."""
        ...

    def bind_recorder(self, recorder_url: str) -> str:
        """Route B's executor's effects to `recorder_url`, one POST per effect with the values it
        used and ``began_at``. Returns how, for the evidence."""
        ...

    def present(self, p: Any) -> Dict[str, Any]:
        """Send one `authz.Presentation` through the product's real entry point, raw bytes and
        headers unchanged, with no client retry. Returns B's answer: ``status``, ``body``, and,
        where B's own log has them, ``began_at`` and ``ended_at`` (epoch seconds, read inside
        B)."""
        ...

    def classify(self, answer: Dict[str, Any]) -> str:
        """One of `CLASSES`, by the product's documented codes (quoted in the agreement). An
        unknown code is ``error``."""
        ...

    def evidence_grade(self) -> str:
        """One of `GRADES`."""
        ...

    # optional
    def received(self, pid: str) -> Optional[bytes]: ...
    def effects(self, since: float) -> List[Dict[str, Any]]: ...
    def restart(self, kind: str) -> Dict[str, str]: ...
    def instances(self) -> List[str]: ...
    def dependency(self, available: bool) -> str: ...
    def crash_between(self, step: str) -> str: ...
    def crashed(self) -> bool: ...
    def set_memory_horizon(self, seconds: Optional[int]) -> str: ...
    def elapse(self, seconds: float) -> None: ...
    def authorisation_profile(self) -> Optional[str]: ...
    def variants_not_applicable(self) -> Dict[str, str]: ...
    def variant_notes(self) -> Dict[str, str]: ...


# --------------------------------------------------------------------------- running a plan


class Pair:
    """One fresh pair: a new stub A pinned at B, a recorder namespace, a transport."""

    def __init__(self, a: Adapter, recorder: Any, grade: str, profile: Optional[str],
                 tag: str, mapping: Optional[Dict[str, Any]] = None) -> None:
        from .. import requester
        self.a, self.recorder, self.grade = a, recorder, grade
        self.stub = requester.StubRequester(requester.new_issuer(), profile=profile)
        kid, pub = self.stub.public_key()
        a.pin_requester_key(self.stub.issuer, kid, pub, mapping)
        self.prefix = f"/p18/{tag}-{secrets.token_hex(4)}"
        self.binding = a.bind_recorder(recorder.url + self.prefix)
        self.since = time.time()
        self.transport = requester.Transport(a.present)
        self.log: List[Dict[str, Any]] = []
        self.hook_missing: Optional[str] = None
        self.empty_before = not self.effects()

    def effects(self) -> List[Dict[str, Any]]:
        if self.grade == "recorder":
            return [e for e in self.recorder.effects(self.prefix)]
        if self.grade == "B-store-read":
            got = getattr(self.a, "effects", lambda since: [])(self.since) or []
            return [{"effect": e, "began_at": e.get("began_at") if isinstance(e, dict) else None}
                    for e in got]
        return []

    def by_ref(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        for e in self.effects():
            v = e.get("effect") or {}
            out.setdefault(str(v.get("ref")), []).append(v)
        return out

    def classify(self, ans: Optional[Dict[str, Any]]) -> str:
        if ans is None:
            return "dropped"
        if ans.get("raised"):
            return "error"
        try:
            c = self.a.classify(ans)
        except Exception:  # noqa: BLE001
            return "error"
        return c if c in CLASSES else "error"

    def run(self, plan: Any) -> None:
        """Run every step of `plan`, reading the recorder after each."""
        for i, st in enumerate(plan.steps):
            rec: Dict[str, Any] = {"i": i, "op": st.op, "role": st.role, "label": st.label}
            if st.op == "present":
                p = st.presentation
                ans = self.transport.send(p, drop_answer=st.drop_answer)
                kept = self.transport.answers.get(p.pid)
                rec.update(pid=p.pid, endpoint=p.endpoint, tenant=p.tenant,
                           dropped=st.drop_answer, answer=_short(kept),
                           cls=self.classify(kept), seen_by_a=ans is not None,
                           request_sha256=_sha(p.request))
                got = getattr(self.a, "received", None)
                if got is not None:
                    try:
                        b = got(p.pid)
                    except Exception as e:  # noqa: BLE001
                        b = None
                        rec["received_error"] = f"{type(e).__name__}: {e}"
                    rec["received_sha256"] = _sha(b) if isinstance(b, (bytes, bytearray)) else None
            elif st.op == "race":
                answers = self.transport.release_together(st.presentations)
                rec.update(pids=[p.pid for p in st.presentations],
                           classes=[self.classify(x) for x in answers],
                           began=[x.get("began_at") for x in answers],
                           ended=[x.get("ended_at") for x in answers],
                           answers=[_short(x) for x in answers])
            elif st.op == "hook":
                fn = getattr(self.a, st.hook, None)
                if fn is None:
                    self.hook_missing = st.hook
                    rec["missing"] = True
                    self.log.append(rec)
                    return
                try:
                    rec["returned"] = fn(*st.args)
                except Exception as e:  # noqa: BLE001
                    rec["raised"] = f"{type(e).__name__}: {e}"[:300]
            elif st.op == "elapse":
                getattr(self.a, "elapse", time.sleep)(st.seconds)
                rec["seconds"] = st.seconds
            rec["effects"] = {k: len(v) for k, v in self.by_ref().items()}
            self.log.append(rec)


def _sha(b: Any) -> Optional[str]:
    from .. import receipts
    return receipts.sha256_ref(bytes(b)) if isinstance(b, (bytes, bytearray)) else None


def _short(ans: Any) -> Any:
    if not isinstance(ans, dict):
        return ans
    out = {k: ans[k] for k in ("status", "raised", "began_at", "ended_at") if k in ans}
    body = ans.get("body")
    out["body"] = body if not isinstance(body, (str, bytes)) else str(body)[:300]
    return out


# --------------------------------------------------------------------------- judging


def matches(effect: Dict[str, Any], authorised: Optional[Dict[str, Any]]
            ) -> Tuple[bool, List[str]]:
    """Do the values B's executor used equal the authorised request's? Every member of the
    authorised values the effect carries is compared (KRK-M42: whatever the adapter declared)."""
    if authorised is None:
        return False, []
    differs = [k for k in VALUE_MEMBERS if k in effect and k in authorised
               and effect[k] != authorised[k]]
    compared = [k for k in VALUE_MEMBERS if k in effect and k in authorised]
    return (not differs and len(compared) >= 2), differs


def capability_ran(effects: Dict[str, List[Dict[str, Any]]], req: Any) -> bool:
    """A capability control's request ran once, with its values, where the recorder sees it
    (KRK-M40, KRK-M41)."""
    got = effects.get(str(req.ref), [])
    return len(got) == 1 and matches(got[0], req.values)[0]


def restart_happened(ret: Any) -> bool:
    """The restart hook reported a new boot or instance id for the process holding B's state
    (KRK-M44)."""
    return isinstance(ret, dict) and bool(ret.get("before")) and ret.get("before") != ret.get(
        "after")


def overlapped(spread_s: float, yardstick_s: float) -> bool:
    """A race round counts only if every presentation began inside B within half of one
    uncontended presentation's duration (KRK-M39)."""
    return spread_s < yardstick_s / 2


def _steps(log: List[Dict[str, Any]], role: str = "variant") -> List[Dict[str, Any]]:
    return [s for s in log if s.get("role") == role]


def _count(effects: Dict[str, List[Dict[str, Any]]], ref: Optional[str]) -> int:
    return len(effects.get(str(ref), []))


def _times(n: int) -> str:
    return "ran_twice" if n == 2 else f"ran_{n}x"


def _landed_bytes(pair: Pair, plan: Any) -> Optional[str]:
    """KRK-M37: did the fixture's bytes reach B unchanged? None if they did."""
    want = plan.meta.get("fixture")
    if want is None:
        return None
    for s in pair.log:
        if s.get("op") != "present" or s.get("role") != "variant":
            continue
        if s.get("request_sha256") != _sha(want):
            return "the bytes that left the kit are not the fixture's"
        if "received_sha256" in s and s["received_sha256"] not in (None, s["request_sha256"]):
            return "B's own record of the bytes it received differs from what the kit sent"
    return None


def judge(variant: str, plan: Any, pair: Pair) -> Check:
    """One variant's outcome, from the recorder (or B's store at the lower grade) and B's
    answers, after its capability control (module docstring)."""
    log = pair.log
    eff = pair.by_ref()
    ref = plan.meta.get("ref")
    auth = (plan.meta.get("authorised") or {}).get(ref)
    n = _count(eff, ref)
    mine = eff.get(str(ref), [])
    var = _steps(log)
    cap = _steps(log, "capability")
    note = ""

    def ck(outcome: str, ok: Optional[bool], detail: str) -> Check:
        return Check(variant, outcome, ok, detail + note)

    def cap_ran(label: str) -> bool:
        return capability_ran(eff, plan.requests[label])

    def values_outcome(honest: bool = False) -> Check:
        if n == 0:
            if honest:
                return ck("false_refusal", None, "an honest equivalent was refused (safe)")
            return ck("refused", True, "refused; no effect under it at the recorder")
        if n > 1:
            return ck(_times(n), False, f"{n} effects under one authorisation")
        ok, differs = matches(mine[0], auth)
        if ok:
            return ck("ran_as_authorised", True, "one effect, with the authorised values")
        return ck("ran_changed", False, f"the effect's {differs or 'values'} differ from the "
                  f"authorised request's: {_diff(mine[0], auth)}")

    def repeat_outcome() -> Check:
        if n == 0:
            first = var[0] if var else {}
            return ck("fixture_not_landed", None, f"B ran nothing under a genuine authorisation "
                      f"(first answer {first.get('cls')!r}); single use was never exercised")
        if n > 1:
            return ck(_times(n), False, f"{n} effects under one authorisation; answers "
                      f"{[s.get('cls') for s in var]}")
        ok, differs = matches(mine[0], auth)
        if not ok:
            return ck("ran_changed", False, f"the one effect's {differs} differ")
        later = [s for s in var if s.get("op") == "present"][1:]
        denied = [s for s in later if s.get("cls") in DENYING]
        if denied:
            return ck("denied_done", False, f"B answered {denied[0]['cls']!r} to a repeat of a "
                      f"request whose effect the recorder shows")
        errs = [s for s in later if s.get("cls") == "error"]
        tail = f"; {len(errs)} later answer(s) gave no statement" if errs else ""
        return ck("ran_once", True, f"one effect in total; later answers "
                  f"{[s.get('cls') for s in later]}{tail}")

    if variant in ("body_changed",):
        if not cap_ran("R'-own"):
            return ck("capability_not_held", None, "R′ with its own genuine authorisation did "
                      "not run once with its values, so a refusal of R′ under R's would say "
                      "nothing about binding")
        if n == 0:
            return ck("refused", True, f"refused R′ ({plan.meta['change']}) beside R's "
                      f"authorisation; no effect")
        return values_outcome()
    if variant in ("unbound_member",):
        return values_outcome()
    if variant in ("noncanonical_equivalent", "translated_declared"):
        gap = _landed_bytes(pair, plan)
        if gap:
            return ck("fixture_not_landed", None, gap)
        return values_outcome(honest=True)
    if variant == "duplicate_key":
        gap = _landed_bytes(pair, plan)
        if gap:
            return ck("fixture_not_landed", None, gap)
        if n == 0:
            return ck("refused", True, "refused bytes with a member twice")
        r = plan.meta["readings"]
        return ck("ran_ambiguous", False, f"{n} effect(s) for bytes with two readings (amount "
                  f"{r['first']} or {r['last']}); it ran with {mine[0].get('amount')}")
    if variant in ("number_precision", "unicode_fold"):
        gap = _landed_bytes(pair, plan)
        if gap:
            return ck("fixture_not_landed", None, gap)
        return values_outcome()
    if variant == "class_for_exact":
        if plan.meta.get("class_operation"):
            if not cap_ran("class-allowed"):
                return ck("capability_not_held", None, "a genuine class authorisation for the "
                          f"operation the agreement allows a class for "
                          f"({plan.meta['class_operation']}) did not run")
        if n == 0:
            return ck("refused", True, f"refused a class authorisation for exact-bound "
                      f"{plan.meta['operation']}")
        return ck("ran_under_class", False, f"{n} effect(s) for exact-bound "
                  f"{plan.meta['operation']} under a class authorisation")
    if variant in ("replay_after_answer", "replay_new_key"):
        return repeat_outcome()
    if variant == "retry_after_lost_answer":
        before = next((s for s in log if s.get("op") == "read"), {})
        if before.get("effects", {}).get(str(ref), 0) != 1:
            return ck("capability_not_held", None, "the recorder showed no effect before the "
                      "retry, so B had not committed when the answer was dropped")
        return repeat_outcome()
    if variant in ("replay_after_restart", "replay_after_failover"):
        h = next((s for s in cap if s.get("op") == "hook"), {})
        ret = h.get("returned") if isinstance(h.get("returned"), dict) else {}
        if h.get("raised") or not restart_happened(ret):
            return ck("capability_not_held", None, f"the restart hook did not report a new boot "
                      f"or instance id for the process holding B's state ({h.get('raised') or ret}) "
                      f"(KRK-M44)")
        if not cap_ran("fresh-after-restart"):
            return ck("capability_not_held", None, "a fresh authorisation did not run after the "
                      "restart, so B was not serving")
        note = f" ({plan.meta['restart']}: {ret.get('before')} -> {ret.get('after')}" + (
            f"; {ret['how']}" if ret.get("how") else "") + ")"
        return repeat_outcome()
    if variant in ("replay_other_endpoint", "replay_other_tenant"):
        capl = "addressed-to-E2" if variant == "replay_other_endpoint" else "addressed-to-T2"
        if not cap_ran(capl):
            return ck("capability_not_held", None, f"an authorisation addressed to "
                      f"{plan.meta['second']} did not run there and reach the recorder, so the "
                      f"recorder may not see that {('endpoint' if 'endpoint' in variant else 'tenant')} (KRK-M40)")
        mid = next((s for s in log if s.get("op") == "read"), {})
        k = mid.get("effects", {}).get(str(ref), 0)
        if k and not plan.meta.get("alias"):
            return ck("ran_wrong_audience", False, f"{k} effect(s) at {plan.meta['second']} under "
                      f"an authorisation addressed elsewhere")
        if n > 1:
            return ck(_times(n), False, f"{n} effects in total across the two audiences")
        if n == 0:
            return ck("consumed_by_refusal", False, "refused at the wrong audience, then refused "
                      "at its own: the refusal used the authorisation up")
        if plan.meta.get("alias"):
            return repeat_outcome()
        return ck("refused", True, f"refused at {plan.meta['second']}; ran once where it was "
                  f"addressed")
    if variant == "replay_other_counterparty":
        if n == 0:
            return ck("refused", True, f"refused an authorisation addressed to "
                      f"{plan.meta['audience']}")
        return ck("ran_wrong_audience", False, f"{n} effect(s) under an authorisation addressed "
                  f"to {plan.meta['audience']}")
    if variant == "race_same":
        return _judge_race(plan, pair, eff)
    if variant == "split_undeclared":
        if n == 0:
            return ck("refused", True, "refused each undeclared part")
        return ck("ran_changed", False, f"{n} effect(s) for parts the authorisation does not "
                  f"declare (items {[e.get('items') for e in mine]})")
    if variant == "split_declared":
        parts = plan.meta["parts"]
        by = {lbl: sum(1 for e in mine if e.get("items") == v["items"]) for lbl, v in parts.items()}
        whole = sum(1 for e in mine if e.get("items") == auth["items"])
        if by["R1"] > 1 or by["R2"] > 1 or whole:
            return ck("ran_Nx", False, f"declared parts ran {by}, the whole {whole} time(s): more "
                      f"uses than the authorisation allows")
        if by["R1"] == 1 and by["R2"] == 1:
            return ck("ran_once", True, "each declared part ran once; the whole was refused")
        return ck("false_refusal", None, f"declared parts ran {by} (an honest part refused); the "
                  f"whole was refused")
    if variant == "expired":
        if not cap_ran("valid-by-the-margin"):
            return ck("capability_not_held", None, f"an authorisation valid by the same margin "
                      f"({plan.meta['margin_s']} s) did not run (KRK-M41)")
        if n == 0:
            return ck("refused", True, "refused an authorisation expired by more than the "
                      "tolerance")
        return ck("ran_expired", False, f"{n} effect(s) under an expired authorisation")
    if variant == "validity_beyond_memory":
        h = next((s for s in cap if s.get("op") == "hook"), {})
        if h.get("raised"):
            return ck("capability_not_held", None, f"set_memory_horizon raised: {h['raised']}")
        if n == 0:
            return ck("refused", True, f"refused an authorisation valid beyond its memory "
                      f"horizon ({plan.meta['horizon_s']} s)")
        return repeat_outcome() if n > 1 else ck(
            "ran_once", True, "one effect in total after the horizon passed")
    if variant == "refused_then_retry":
        c = plan.meta["capability"]
        if _count(eff, c["down"]) != 0 or _count(eff, c["up"]) != 1:
            return ck("capability_not_held", None, "with the dependency off a fresh "
                      "authorisation was not refused, or with it back another did not run")
        first = next((s for s in var if s.get("op") == "present"), {})
        if first.get("effects", {}).get(str(ref), 0):
            return ck("fixture_not_landed", None, "B ran the request with its dependency off")
        if n == 0:
            return ck("consumed_by_refusal", False, "the identical retry after the dependency "
                      "came back was refused: the earlier refusal used the authorisation up "
                      "")
        if n > 1:
            return ck(_times(n), False, f"{n} effects")
        return ck("ran_once", True, "refused while the dependency was down; the retry ran once")
    if variant == "crash_between_use_and_effect":
        h = [s for s in cap if s.get("op") == "hook"]
        crashed = len(h) > 1 and h[1].get("returned") is True
        if not crashed:
            return ck("capability_not_held", None, f"the crash was not reported at the named "
                      f"step ({[x.get('returned') or x.get('raised') for x in h]})")
        how = h[0].get("returned")
        note = f" (crash: {how})" if how else ""
        if n > 1:
            return ck(_times(n), False, f"{n} effects: the retry after the crash ran again")
        if n == 1:
            return repeat_outcome()
        claimed = [s for s in var if s.get("cls") in CLAIMING]
        if claimed:
            return ck("claims_done", False, f"answered {claimed[0]['cls']!r} with no effect at "
                      f"the recorder")
        return ck("stuck", None, f"no effect, and B never said done (answers "
                  f"{[s.get('cls') for s in var]}): liveness, not safety")
    if variant == "mapping_undeclared":
        gap = _landed_bytes(pair, plan)
        if gap:
            return ck("fixture_not_landed", None, gap)
        if n == 0:
            return ck("refused", True, "refused a request in another vocabulary with no "
                      "declared mapping")
        return ck("ran_without_basis", False, f"{n} effect(s) for a request in B's vocabulary "
                  f"with no mapping declared for this pair")
    raise AssertionError(variant)


ANSWER_FAIL = {"body_changed": "ran_changed", "duplicate_key": "ran_ambiguous",
               "class_for_exact": "ran_under_class", "replay_other_counterparty":
               "ran_wrong_audience", "expired": "ran_expired", "split_undeclared": "ran_changed",
               "mapping_undeclared": "ran_without_basis"}
"""At the `B-answer` grade: the variants where B's own ``executed`` answer is a fail by itself,
whatever values it used. For the others (`unbound_member`, `number_precision`, `unicode_fold`,
the honest halves) an ``executed`` answer says nothing about the values, so it is information."""


def judge_answers(variant: str, plan: Any, pair: Pair) -> Check:
    """The `B-answer` grade: no effect is seen, so a refusal variant is read from
    B's answers alone, and only where a refusal, or B's own statement that it executed, is all
    there is to see. Capability controls must be answered ``executed``."""
    cap = [s for s in pair.log if s.get("role") == "capability" and s.get("op") == "present"]
    if any(s.get("cls") != "executed" for s in cap):
        return Check(variant, "capability_not_held", None, f"B did not answer executed to the "
                     f"capability control ({[s.get('cls') for s in cap]})")
    var = [s for s in pair.log if s.get("role") == "variant" and s.get("op") == "present"]
    classes = [s.get("cls") for s in var]
    if all(c in DENYING for c in classes):
        return Check(variant, "refused", True, f"B answered {classes} (grade B-answer: no effect "
                     f"was observed, only B's answers)")
    if "executed" in classes and variant in ANSWER_FAIL:
        return Check(variant, ANSWER_FAIL[variant], False, f"B answered executed ({classes}), "
                     f"by its own statement (grade B-answer)")
    return Check(variant, "answer_only", None, f"B answered {classes}; at the B-answer grade the "
                 f"values B used are not observed")


def _diff(effect: Dict[str, Any], auth: Optional[Dict[str, Any]]) -> str:
    if not auth:
        return "no single authorised reading"
    return "; ".join(f"{k}: {effect.get(k)!r} for {auth.get(k)!r}" for k in VALUE_MEMBERS
                     if k in effect and k in auth and effect[k] != auth[k])


def _judge_race(plan: Any, pair: Pair, eff: Dict[str, List[Dict[str, Any]]]) -> Check:
    """KRK-M39: a round counts only if every presentation began inside B within half of one
    uncontended presentation's duration, both measured inside B."""
    alone = next((s for s in pair.log if s.get("label") == "alone"), {})
    a = alone.get("answer") or {}
    if not (isinstance(a.get("began_at"), (int, float)) and isinstance(a.get("ended_at"),
                                                                       (int, float))):
        return Check("race_same", "no_overlap", None, "B's answers carry no start and end time "
                     "measured inside B, so no round can be shown to overlap (KRK-M39)")
    if _count(eff, plan.requests["alone"].ref) != 1:
        return Check("race_same", "capability_not_held", None, "the uncontended presentation did "
                     "not run once")
    yard = max(0.0, a["ended_at"] - a["began_at"])
    rounds, worst = [], None
    for meta, s in zip(plan.meta["rounds"], [x for x in pair.log if x.get("op") == "race"]):
        began = [b for b in s["began"] if isinstance(b, (int, float))]
        spread = (max(began) - min(began)) if len(began) == meta["n"] else float("inf")
        k = _count(eff, meta["ref"])
        denied = [c for c in s["classes"] if c in DENYING]
        ok_vals = all(matches(e, plan.requests[meta["label"]].values)[0]
                      for e in eff.get(meta["ref"], []))
        r = {"n": meta["n"], "effects": k, "spread_s": round(spread, 4), "classes": s["classes"],
             "overlapped": overlapped(spread, yard)}
        rounds.append(r)
        if not r["overlapped"]:
            continue
        if k != 1:
            worst = worst or Check("race_same", _times(k) if k > 1 else "fixture_not_landed",
                                   False if k > 1 else None,
                                   f"{k} effects from {meta['n']} presentations released "
                                   f"together")
        elif denied:
            worst = worst or Check("race_same", "denied_done", False, f"one effect, and "
                                   f"{len(denied)} presentation(s) answered {denied[0]!r} "
                                   f"")
        elif not ok_vals:
            worst = worst or Check("race_same", "ran_changed", False, "the effect's values differ")
    detail = f"yardstick {yard:.3f} s; rounds {rounds}"
    if worst is not None:
        return Check("race_same", worst.outcome, worst.ok, f"{worst.detail}; {detail}")
    if not any(r["overlapped"] for r in rounds):
        return Check("race_same", "no_overlap", None, f"no round overlapped inside B; {detail}")
    return Check("race_same", "ran_once", True, f"one effect in every overlapping round; {detail}")


# --------------------------------------------------------------------------- the probe


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None) -> Result:
    role = getattr(a, "role", lambda: "B")()
    if role == "A":
        return probe_role_a(a, ev, run_tag=run_tag, seed=seed)
    return probe_role_b(a, ev, run_tag=run_tag, seed=seed)


def probe_role_b(a: Adapter, ev: Evidence, *, run_tag: str = "",
                 seed: Optional[int] = None) -> Result:
    from .. import requester
    from ..mockserver import MockServer

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    try:
        agreement = dict(a.agreement() or {})
        grade = a.evidence_grade()
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the agreement raised "
                                   f"{type(e).__name__}: {e}", **common)
    if not agreement.get("counterparty"):
        return Result.inconclusive(a.name, ID, "the agreement names no counterparty id for B",
                                   **common)
    if grade not in GRADES:
        return Result.inconclusive(a.name, ID, f"unknown evidence grade {grade!r}", **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    bad = sorted(v for v in na if v in NA_FORBIDDEN or v not in VARIANTS)
    if bad:
        return Result.inconclusive(a.name, ID, f"the adapter declares {bad} not applicable; "
                                   f"{list(NA_FORBIDDEN)} may not be, and only P18's variants can "
                                   f"be", **common)
    if any(not isinstance(w, str) or not w.strip() for w in na.values()):
        return Result.inconclusive(a.name, ID, "a variant is declared not applicable without a "
                                   "reason", **common)
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    profile = getattr(a, "authorisation_profile", lambda: None)()
    if profile is not None and profile not in requester.PROFILES:
        return Result.inconclusive(a.name, ID, f"unknown authorisation profile {profile!r}",
                                   **common)

    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    m = rng.randint(*SERIES)
    ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order, "series": m,
                          "agreement": _jsonable(agreement), "evidence_grade": grade,
                          "variants_not_applicable": na, "variant_notes": notes,
                          "authorisation_profile": profile})
    recorder = MockServer()
    try:
        return _run_b(a, ev, agreement, grade, na, notes, profile, rng, order, m, seed,
                      recorder, run_tag, common)
    finally:
        recorder.close()


def _declared_mapping(agreement: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The mapping a ``translated_declared`` pair's agreement declares: the first profile the
    product supports, by name. Every other pair declares none."""
    maps = agreement.get("mappings") or {}
    return maps[sorted(maps)[0]] if maps else None


def _jsonable(x: Any) -> Any:
    import json
    return json.loads(json.dumps(x, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))


def _run_b(a, ev, agreement, grade, na, notes, profile, rng, order, m, seed, recorder,
           run_tag, common) -> Result:
    def record(name: str, plan: Any, pair: Optional["Pair"], **more: Any) -> None:
        doc = {"variant": name, "meta": _jsonable(plan.meta) if plan else None, **more}
        if pair is not None:
            doc.update(recorder_binding=pair.binding, issuer=pair.stub.issuer,
                       recorder_prefix=pair.prefix, steps=_jsonable(pair.log),
                       wire_log=_jsonable(pair.transport.wire_log),
                       effects=_jsonable([e.get("effect") for e in pair.effects()]),
                       authorisations=[{k: v for k, v in i.items() if k != "token"}
                                       for i in pair.stub.issued])
        ev.write(f"{name}.json", doc)

    # ------------------------------------------------------------------ control
    try:
        ctl_pair = Pair(a, recorder, grade, profile, f"{run_tag}control")
        ctl = ctl_pair.stub.control_plan(agreement, rng=rng, m=m)
        ctl_pair.run(ctl)
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"control raised {type(e).__name__}: {e}",
                                   **common)
    held, why = _control_held(ctl, ctl_pair, grade)
    record(CONTROL, ctl, ctl_pair, held=held, why=why)
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    control = (f"{m} honest requests, each with its own authorisation, presented once: one "
               f"effect each with its values at the {grade} grade, each presentation once on the "
               f"wire, every answer readable, and a fresh authorisation after the series ran")

    checks: List[Check] = []
    extra: Dict[str, Any] = {"seed": seed, "evidence_grade": grade, "series": m,
                             "agreement": _jsonable(agreement),
                             "claims_replay_protection": bool(
                                 agreement.get("claims_replay_protection"))}
    if na:
        extra["variants_not_applicable"] = na
    for variant in order:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            record(variant, None, None, not_applicable=na[variant])
            continue
        if variant == "validity_beyond_memory" and not hasattr(a, "set_memory_horizon"):
            horizon = agreement.get("memory_horizon_s")
            if horizon == "permanent":
                q = (agreement.get("quotes") or {}).get("memory_horizon_s", "not-found")
                checks.append(Check(variant, "not_applicable", None, f"memory is permanent, as "
                                    f"the product states ({q}); the horizon was not measured"))
            else:
                checks.append(Check(variant, "not_driven", None, f"the adapter cannot shorten "
                                    f"the memory horizon (stated {horizon!r}); not measured"))
            continue
        if grade == "B-answer" and variant in COUNTING:
            checks.append(Check(variant, "not_driven", None, "at the B-answer grade the kit would "
                                "count effects by asking B, which the recorder rule forbids "
                                ""))
            continue
        try:
            mapping = _declared_mapping(agreement) if variant == "translated_declared" else None
            pair = Pair(a, recorder, grade, profile, f"{run_tag}{variant}", mapping=mapping)
            plan = pair.stub.plan(variant, agreement, rng=random.Random(rng.getrandbits(64)))
        except Exception as e:  # noqa: BLE001
            checks.append(Check(variant, "not_driven", None, f"building the pair raised "
                                f"{type(e).__name__}: {e}"))
            continue
        if plan.gap:
            checks.append(Check(variant, "not_applicable", None, f"{plan.gap} (agreement as "
                                f"stated)"))
            record(variant, plan, None, gap=plan.gap)
            continue
        if pair.stub.format_gaps:
            checks.append(Check(variant, "fixture_not_landed", None, f"the authorisation format "
                                f"{profile!r} cannot express this variant (KRK-M21)"))
            continue
        try:
            pair.run(plan)
            if pair.hook_missing:
                c = Check(variant, "not_driven", None, f"the adapter has no {pair.hook_missing!r} "
                          f"hook")
            elif grade == "B-answer":
                c = judge_answers(variant, plan, pair)
            else:
                c = judge(variant, plan, pair)
        except Exception as e:  # noqa: BLE001
            c = Check(variant, "not_driven", None, f"the probe raised {type(e).__name__}: {e}")
        finally:
            if variant == "validity_beyond_memory" and hasattr(a, "set_memory_horizon"):
                try:
                    a.set_memory_horizon(None)
                except Exception:  # noqa: BLE001
                    pass
        if grade != "recorder" and c.ok is not None:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (grade {grade})")
        if variant in notes:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (adapter note: {notes[variant]})")
        checks.append(c)
        record(variant, plan, pair, outcome=c.outcome, ok=c.ok, detail=c.detail)

    fails = [c for c in checks if c.ok is False]
    unlanded = [c.name for c in checks if c.name in MUST_LAND and c.ok is None]
    extra["disclosure"] = ("vulnerability" if fails and agreement.get("claims_replay_protection")
                           and any(c.outcome.startswith("ran_") and (c.outcome in VULNERABLE or
                                   c.outcome.endswith("x")) for c in fails) else "conformance")
    if not fails and unlanded:
        return Result.inconclusive(a.name, ID, f"no variant failed, but variants that must land "
                                   f"did not: {unlanded}", checks=checks, control_held=True,
                                   control_detail=control, extra=extra, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="every effect was the authorised request, addressed and valid, "
                                "at most once, with truthful answers to repeats",
                   fail_summary="B performed an effect the authorisation does not cover, or "
                                "more often than it allows, or answered a repeat untruthfully",
                   extra=extra, **common)


def _control_held(plan: Any, pair: Pair, grade: str) -> Tuple[bool, str]:
    if not pair.empty_before:
        return False, "the recorder already held effects for this pair before it started"
    steps = [s for s in pair.log if s.get("op") == "present"]
    if any(s.get("cls") == "error" and (s.get("answer") or {}).get("raised") for s in steps):
        bad = next(s for s in steps if (s.get("answer") or {}).get("raised"))
        return False, f"an honest presentation got no readable answer ({bad['answer']['raised']})"
    for s in steps:
        if pair.transport.sent(s["pid"]) != 1:
            return False, f"presentation {s['pid']} left the kit {pair.transport.sent(s['pid'])} times"
        if "received_sha256" in s and s["received_sha256"] not in (None, s["request_sha256"]):
            return False, "B's record of the bytes it received differs from what the kit sent"
    if grade == "B-answer":
        not_exec = [s["label"] for s in steps if s.get("cls") != "executed"]
        if not_exec:
            return False, f"at the B-answer grade B did not answer executed to {not_exec}"
        return True, ""
    eff = pair.by_ref()
    for label, r in plan.requests.items():
        got = eff.get(str(r.ref), [])
        if len(got) != 1:
            return False, f"{label}: {len(got)} effects at the {grade} grade (expected one)"
        ok, differs = matches(got[0], r.values)
        if not ok:
            return False, f"{label}: the effect's values differ from the request's ({differs})"
    return True, ""


# =========================================================================== role A


class RoleAAdapter(Protocol):
    """Role A (the secondary family). The KRK-16 driving methods, plus the path to B."""

    name: str
    config: str

    def role(self) -> str:
        """``"A"``."""
        ...

    def pin_counterparty_key(self, kid: str, public_key: bytes) -> None: ...

    def bind_counterparty(self, peer: str, send: Any) -> str:
        """Give the target the path its executor uses to reach `peer`:
        ``send(request: bytes, authorisation: str | None, headers: dict) -> answer``, where the
        answer is ``{"receipt": token or None, "answer": class, "code": ...}``, or raises
        `requester.AnswerLost` when the transport dropped B's answer after B acted. Several
        peers may be bound. Returns how, for the evidence."""
        ...

    def authorisation_key(self) -> Optional[Tuple[str, bytes]]:
        """The key the target signs per-request authorisations with, if it publishes one."""
        ...

    def submit(self, envelope: Dict[str, Any], expected: Any) -> str: ...

    def send(self, case_id: str) -> str:
        """Run the target's execute path once; its executor calls the bound `send`."""
        ...

    def retry(self, case_id: str) -> str:
        """Make the target send its request again, the way it would after a lost answer, by its
        own documented path. Returns what was done."""
        ...

    def status(self, case_id: str) -> str: ...

    def outcome(self, case_ref: str) -> Any:
        """Optional. The target's own reading of the action's outcome, translated and nothing
        more (KRK-M24, KRK-M25): one of `OUTCOME_READINGS`, or ``{"outcome": <one of them>,
        "product": {...}}`` with the product's own words for the evidence. A target without it
        reads ``not_readable`` on `record_matches_effect`, information, never a pass."""
        ...


A_CHECKS = ("authorisation_present", "retry_same", "fresh_per_decision", "one_audience",
            "honours_duplicate", "record_matches_effect")
OUTCOME_READINGS = ("done", "not-done", "open", "disputed")
"""What a role-A target's `outcome` may say: the action was performed, it was not, nothing is
settled yet (still waiting on B, or held), or the target holds a disagreement about it."""
A_REQUESTER = "did:web:a.example"
A_OPERATION = "crm.record.push"
A_CONTAINER = "people"
A_VERBS = ("upsert",)
A_COUNT = (3, 40)
CLOSES = ("not-executed", "refused")


def probe_role_a(a: Any, ev: Evidence, *, run_tag: str = "",
                 seed: Optional[int] = None) -> Result:
    """The role-A family (module docstring). Not the property: it says whether the target, as
    the requesting organisation, gives B what X3 needs."""
    from .. import authz, counterparty, receipts, requester

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    salt = rng.getrandbits(128).to_bytes(16, "big")
    bkey = receipts.Keypair.generate("b-receipts-p18")
    try:
        akey = getattr(a, "authorisation_key", lambda: None)()
    except Exception:  # noqa: BLE001
        akey = None
    req_keys = {akey[0]: bytes(akey[1])} if akey else {}
    drops: set = set()
    bound: Dict[str, Any] = {}
    ev.write("run.json", {"seed": seed, "role": "A", "checks": A_CHECKS,
                          "authorisation_key": akey[0] if akey else None})

    def new_b(tag: str, repeat: str = "original"):
        peer = f"did:web:b-{tag}-{secrets.token_hex(3)}.example"
        b = counterparty.StubCounterparty(str(ev.dir / f"b-{tag}.sqlite"), bkey, salt,
                                          counterparty_id=peer, single_use=True,
                                          repeat_answer=repeat, requester_keys=req_keys)

        def send(request: bytes, authorisation: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
            out = b.receive(request, authorisation, headers, rng=rng)
            cid = b.received_requests[-1].get("correlation_id")
            if cid in drops:
                drops.discard(cid)
                raise requester.AnswerLost("the transport dropped B's answer after B acted")
            return out
        bound[tag] = {"peer": peer, "how": a.bind_counterparty(peer, send,
                                                                (bkey.kid, bkey.public_bytes()))}
        return peer, b

    def case(tag: str, peer: str, *, cid: Optional[str] = None,
             items: Optional[List[str]] = None):
        n = rng.randint(*A_COUNT)
        its = items or sorted({f"person-{rng.getrandbits(48):012x}@example.test"
                               for _ in range(n)})
        exp = receipts.ExpectedEffect(operation=A_OPERATION, counterparty=peer,
                                      container=A_CONTAINER, verbs=A_VERBS, count=len(its),
                                      items_digest=receipts.items_digest(salt, its))
        env = {"schema": "kirkaldy.effect-request/0.1",
               "correlation_id": cid or f"p18a-{tag}-{run_tag}-{secrets.token_hex(6)}",
               "operation": A_OPERATION, "requester": A_REQUESTER, "counterparty": peer,
               "container": A_CONTAINER, "items": its, "expected_effect_digest": exp.digest()}
        return env, exp

    def got(b, cid: str) -> List[Dict[str, Any]]:
        return [r for r in b.received_requests if r.get("correlation_id") == cid]

    def evid(name: str, doc: Dict[str, Any]) -> None:
        ev.write(f"{name}.json", _jsonable({k: (v.hex() if isinstance(v, bytes) else v)
                                            for k, v in doc.items()}))

    # ------------------------------------------------------------------ control
    try:
        peer, b0 = new_b("control")
        env, exp = case("control", peer)
        b0.expect(env["correlation_id"], exp)
        cid0 = a.submit(env, exp)
        said = a.send(cid0)
        status0 = a.status(cid0)
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"control raised {type(e).__name__}: {e}",
                                   **common)
    seen = got(b0, env["correlation_id"])
    written = b0.store_counts(env["correlation_id"])["written"]
    evid(CONTROL, {"envelope": env, "said": said, "status": status0, "received":
                   [_rx(r) for r in seen], "written": written, "bound": bound})
    if len(seen) != 1 or written != exp.count or not isinstance(status0, str):
        return Result.inconclusive(a.name, ID, f"control did not hold: B received "
                                   f"{len(seen)} presentation(s) of the approved request and "
                                   f"wrote {written} of {exp.count}; status {status0!r}",
                                   **common)
    differs = _envelope_differs(seen[0]["raw"], env)
    # The envelope's own format version is the requester's to set (a requester on schema 0.2 does);
    # every other approved member must reach B unchanged.
    if differs is None or any(k in env and k != "schema" for k in differs):
        return Result.inconclusive(a.name, ID, f"control did not hold: what B received is not "
                                   f"the approved request ({differs})", **common)
    control = (f"an approved request reached B once and B wrote all {exp.count} items; the "
               f"target's status reads {status0!r}"
               + (f"; the bytes B received differ from the approved envelope in "
                  f"{sorted(differs)}" if differs else ""))
    checks: List[Check] = []

    # ------------------------------------------------------------------ authorisation_present
    r0 = seen[0]
    tok = r0.get("authorisation")
    if not tok:
        checks.append(Check("authorisation_present", "absent", False, "B received the request "
                            "bytes and nothing it could bind them to: no authorisation"))
    elif not akey:
        checks.append(Check("authorisation_present", "unverifiable", False, "B received an "
                            "authorisation but the target publishes no key to verify it with"))
    else:
        v = authz.verify_authorisation(tok, req_keys)
        if not v.ok:
            checks.append(Check("authorisation_present", "unsigned" if v.reason == "unsigned"
                                else "unverifiable", False, f"the authorisation does not verify "
                                f"under the key the target publishes ({v.reason}: {v.detail})"))
        else:
            c = v.claims
            bnd = c["binding"]
            try:
                want = authz.binding_digest(r0["raw"], bnd["basis"])
            except authz.NotBindable as e:
                want = f"unbindable ({e.reason})"
            gaps = [g for g, ok in (
                ("an exact binding", bnd["kind"] == "exact"),
                ("the digest of the bytes B received", bnd.get("request_digest") == want),
                ("B as audience", c["audience"]["counterparty"] == peer),
                ("a window", bool(c.get("not_after")))) if not ok]
            if gaps:
                checks.append(Check("authorisation_present", "unbindable", False,
                                    f"the authorisation does not name {', '.join(gaps)}"))
            else:
                checks.append(Check("authorisation_present", "present", True, f"a signed "
                                    f"authorisation ({c['authorisation_id']}) naming the digest "
                                    f"of the bytes B received, B as audience, and a window"))

    # ------------------------------------------------------------------ retry_same
    def retry_round(tag: str, repeat: str):
        peer, b = new_b(tag, repeat)
        env, exp = case(tag, peer)
        cid = env["correlation_id"]
        b.expect(cid, exp)
        obs: Dict[str, Any] = {"envelope": env}
        try:
            k = a.submit(env, exp)
            drops.add(cid)
            obs["first_send"] = a.send(k)
        except Exception as e:  # noqa: BLE001
            obs["error"] = f"the first send raised {type(e).__name__}: {e}"
            return obs, b, None
        drops.discard(cid)
        obs["status_after_lost_answer"] = _status(a, k)
        if len(got(b, cid)) != 1 or b.store_counts(cid)["written"] != exp.count:
            obs["error"] = (f"B did not act once on the first send ({len(got(b, cid))} "
                            f"presentations)")
            return obs, b, k
        try:
            obs["retry"] = a.retry(k)
        except Exception as e:  # noqa: BLE001
            obs["retry_raised"] = f"{type(e).__name__}: {e}"
        obs["status"] = _status(a, k)
        obs["outcome"] = _outcome(a, k)
        obs["b_effect"] = b_effect(b, cid)
        obs["received"] = [_rx(r) for r in got(b, cid)]
        obs["written"] = b.store_counts(cid)["written"]
        return obs, b, k

    obs, b, _ = retry_round("retry", "original")
    retried = obs
    evid("retry_same", obs)
    if "error" in obs:
        checks.append(Check("retry_same", "not_driven", None, obs["error"]))
    elif len(obs["received"]) < 2:
        checks.append(Check("retry_same", "no_retry", None, f"the target did not send again "
                            f"({obs.get('retry_raised') or obs.get('retry')}); status "
                            f"{obs['status']!r}"))
    else:
        f, s2 = obs["received"][0], obs["received"][1]
        dif = _envelope_differs(bytes.fromhex(s2["raw"]), json.loads(bytes.fromhex(f["raw"])))
        tail = (f"; B answered the retry {s2.get('answer')!r}, wrote {obs['written']} items in "
                f"all, and the target's status is {obs['status']!r} (retry: {obs.get('retry')})")
        if f["raw_sha256"] != s2["raw_sha256"]:
            checks.append(Check("retry_same", "changed_bytes", False, f"the retry's bytes "
                                f"differ from the first send's (members {sorted(dif or [])}), so "
                                f"B sees the same request id with another body{tail}"))
        elif f.get("authorisation_id") != s2.get("authorisation_id"):
            checks.append(Check("retry_same", "changed_authorisation", False,
                                f"the retry carries another authorisation id{tail}"))
        else:
            what = ("and the same authorisation" if f.get("authorisation_id")
                    else "(and no authorisation, either time)")
            checks.append(Check("retry_same", "same", True, f"the retry carries the same bytes "
                                f"{what}{tail}"))

    # ------------------------------------------------------------------ fresh_per_decision
    peer, b = new_b("decisions")
    env, exp = case("decisions", peer)
    cid = env["correlation_id"]
    b.expect(cid, exp)
    fo: Dict[str, Any] = {"envelope": env}
    try:
        k1 = a.submit(env, exp)
        a.send(k1)
        fo["first"] = [_rx(r) for r in got(b, cid)]
        try:
            k2 = a.submit(dict(env), exp)
            fo["second_submit"] = k2
            try:
                fo["second_send"] = a.send(k2)
            except Exception as e:  # noqa: BLE001
                fo["second_send_raised"] = f"{type(e).__name__}: {e}"
            fo["status_2"] = _status(a, k2)
        except Exception as e:  # noqa: BLE001
            fo["second_submit_raised"] = f"{type(e).__name__}: {e}"
        fo["all"] = [_rx(r) for r in got(b, cid)]
    except Exception as e:  # noqa: BLE001
        fo["error"] = f"{type(e).__name__}: {e}"
    evid("fresh_per_decision", fo)
    if "error" in fo or len(fo.get("first") or []) != 1:
        checks.append(Check("fresh_per_decision", "not_driven", None,
                            fo.get("error") or "the first decision did not reach B once"))
    elif len(fo["all"]) == 1:
        checks.append(Check("fresh_per_decision", "refused_by_a", True, f"the target refused a "
                            f"second decision on the same request "
                            f"({fo.get('second_submit_raised') or fo.get('second_send_raised') or fo.get('second_send')})"))
    else:
        k_1, k_2 = fo["all"][0]["use_key"], fo["all"][1]["use_key"]
        if k_1 == k_2:
            checks.append(Check("fresh_per_decision", "shared", False, f"two decisions reached B "
                                f"under one use key ({k_1}); B answered the second "
                                f"{fo['all'][1].get('answer')!r} and the target's second "
                                f"decision reads {fo.get('status_2')!r}"))
        else:
            checks.append(Check("fresh_per_decision", "fresh", True, "each decision reached B "
                                "under its own use key"))

    # ------------------------------------------------------------------ one_audience
    p1, b1 = new_b("aud1")
    p2, b2 = new_b("aud2")
    env1, exp1 = case("aud", p1)
    cid = env1["correlation_id"]
    b1.expect(cid, exp1)
    exp2 = receipts.ExpectedEffect(operation=exp1.operation, counterparty=p2,
                                   container=exp1.container, verbs=exp1.verbs, count=exp1.count,
                                   items_digest=exp1.items_digest)
    env2 = dict(env1, counterparty=p2, expected_effect_digest=exp2.digest())
    b2.expect(cid, exp2)
    oo: Dict[str, Any] = {"envelope_1": env1, "envelope_2": env2}
    try:
        a.send(a.submit(env1, exp1))
        try:
            k2 = a.submit(env2, exp2)
            try:
                oo["second_send"] = a.send(k2)
            except Exception as e:  # noqa: BLE001
                oo["second_send_raised"] = f"{type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001
            oo["second_submit_raised"] = f"{type(e).__name__}: {e}"
        oo["at_1"] = [_rx(r) for r in got(b1, cid)]
        oo["at_2"] = [_rx(r) for r in got(b2, cid)]
    except Exception as e:  # noqa: BLE001
        oo["error"] = f"{type(e).__name__}: {e}"
    evid("one_audience", oo)
    if "error" in oo or len(oo.get("at_1") or []) != 1:
        checks.append(Check("one_audience", "not_driven", None,
                            oo.get("error") or "the first counterparty did not receive it once"))
    elif not oo["at_2"]:
        checks.append(Check("one_audience", "refused_by_a", True, f"the target refused to send "
                            f"the same request id to a second counterparty "
                            f"({oo.get('second_submit_raised') or oo.get('second_send_raised')})"))
    else:
        r1, r2 = oo["at_1"][0], oo["at_2"][0]
        aud2 = (authz.claims_of(r2.get("authorisation_token")) or {}).get("audience", {})
        if r1["use_key"] == r2["use_key"] or aud2.get("counterparty") == p1:
            what = ("the same authorisation" if r1.get("authorisation_id") else
                    "the same correlation id, with no authorisation (the only use key B sees)")
            checks.append(Check("one_audience", "presented_twice", False, f"{what} reached a "
                                f"second counterparty ({r2['use_key']})"))
        else:
            checks.append(Check("one_audience", "fresh", True, "the second counterparty received "
                                "its own use key"))

    # ------------------------------------------------------------------ honours_duplicate
    obs, b, _ = retry_round("duplicate", "duplicate")
    evid("honours_duplicate", obs)
    if "error" in obs:
        checks.append(Check("honours_duplicate", "not_driven", None, obs["error"]))
    elif len(obs["received"]) < 2:
        checks.append(Check("honours_duplicate", "not_reached", None, "the target did not send "
                            "again, so B never gave a duplicate answer"))
    elif obs["received"][1].get("answer") != "duplicate":
        checks.append(Check("honours_duplicate", "not_reached", None, f"the retry was not the "
                            f"same request, so B answered {obs['received'][1].get('answer')!r}, "
                            f"not duplicate; the target's status after it is "
                            f"{obs['status']!r}"))
    elif obs["status"] in CLOSES:
        checks.append(Check("honours_duplicate", "recorded_not_executed", False, f"B answered "
                            f"that the request was already performed and the target recorded "
                            f"{obs['status']!r}"))
    else:
        checks.append(Check("honours_duplicate", "honoured", True, f"on B's duplicate answer "
                            f"the target reads {obs['status']!r}"))

    # ------------------------------------------------------------------ record_matches_effect
    # Graded on the retry_same round, where B answers a repeat with its original receipt. The
    # duplicate round belongs to honours_duplicate; its reading is kept as information.
    if "error" in retried:
        checks.append(Check("record_matches_effect", "not_driven", None, retried["error"]))
    elif len(retried["received"]) < 2:
        checks.append(Check("record_matches_effect", "no_retry", None, "the target did not "
                            "send again, so there is no honest retry to read the record after"))
    else:
        c = record_check(retried["outcome"], retried["b_effect"],
                         [r.get("answer") for r in retried["received"][1:]])
        if "error" not in obs and len(obs.get("received") or []) >= 2:
            dup = record_check(obs.get("outcome"), obs.get("b_effect") or {},
                               [r.get("answer") for r in obs["received"][1:]])
            c = Check(c.name, c.outcome, c.ok, f"{c.detail}. After B's duplicate answer "
                      f"(not graded here; honours_duplicate grades it): {dup.outcome}")
        checks.append(c)

    extra = {"seed": seed, "role": "A", "family": "role-A checks (secondary; not the property)",
             "role_b": "not run in this configuration",
             "authorisation_key": akey[0] if akey else None, "bound": bound,
             # Every role-A failure is a conformance finding, record_matches_effect
             # included; the vulnerability class is about B's effects.
             "disclosure": "conformance"}
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="role A: the target gives B a binding, retries with the same "
                                "bytes, and keeps each authorisation to one decision and one "
                                "counterparty",
                   fail_summary="role A: the target does not give B what X3 needs",
                   extra=extra, **common)


def b_effect(b: Any, correlation_id: str) -> Dict[str, Any]:
    """What B did for one request, counted from the rows of B's store: the requests it logged
    as executed and the item rows it wrote. Never from B's answers: an answer to a repeat says
    what B did with that presentation, not whether the request was performed (KRK-M45)."""
    counts = b.store_counts(correlation_id)
    executed = sum(1 for r in b.issued()
                   if r["correlation_id"] == correlation_id and r["verdict"] == "executed")
    return {"performed": executed > 0, "executed_requests": executed,
            "written": counts["written"], "by": "B's store"}


def record_check(said: Any, eff: Dict[str, Any], answers: List[Any]) -> Check:
    """`record_matches_effect` for one round: the target's own reading of the outcome (`said`,
    from `outcome`) against what B did (`eff`, from `b_effect`), given the answers B gave the
    target after the lost one (`answers`).

    Fail (``contradicts_effect``): the target reads not done where B performed the effect, or
    done where B did not. Pass (``agrees``): the reading is what B did. ``disputed`` is a pass
    (``disputed_held``) when what B told the target conflicts with what B did (a denial while
    the effect stands, or a claim while it does not): the target then holds a disagreement it
    really has, which is the honest record, and it contradicts nothing. With no such conflict
    it is information (``disputed_without_conflict``), so a target that reads every outcome as
    disputed cannot pass by it. ``open`` is information (``left_open``): it says nothing either
    way, and a target that never settles anything must not pass (as KRK-M66's open reading).
    No `outcome` method, or a reading outside `OUTCOME_READINGS`, is information."""
    name = "record_matches_effect"
    if isinstance(said, dict) and "error" in said:
        return Check(name, "not_readable", None, said["error"])
    reading = said.get("outcome") if isinstance(said, dict) else said
    if reading is None:
        return Check(name, "not_readable", None, "the target gives no reading of the outcome "
                     "(no outcome method), so its record cannot be compared with what B did")
    if reading not in OUTCOME_READINGS:
        return Check(name, "unreadable", None, f"the target's reading {reading!r} is not one of "
                     f"{OUTCOME_READINGS}")
    did = bool(eff.get("performed"))
    b_said = ", ".join(repr(x) for x in answers) or "nothing"
    n = eff.get("executed_requests")
    what = (f"B's store holds the effect ({eff.get('written')} items, {n} executed "
            f"request{'' if n == 1 else 's'})" if did
            else "B's store holds no effect for the request")
    tail = f"; B answered the retry {b_said}"
    if reading in ("done", "not-done"):
        if (reading == "done") == did:
            return Check(name, "agrees", True, f"the target reads {reading!r} and {what}{tail}")
        denial = did and any(x in DENYING for x in answers)
        return Check(name, "contradicts_effect", False, f"the target reads {reading!r} while "
                     f"{what}{tail}" + ("; B's refusal of a repeat was read as the outcome of "
                                        "the request" if denial else ""))
    if reading == "disputed":
        conflict = (did and any(x in DENYING for x in answers)) or             (not did and any(x in CLAIMING for x in answers))
        if conflict:
            return Check(name, "disputed_held", True, f"the target holds the outcome as "
                         f"disputed, and B's answers do conflict with its store: {what}{tail}")
        return Check(name, "disputed_without_conflict", None, f"the target reads 'disputed' "
                     f"though nothing B told it conflicts with B's store: {what}{tail}")
    return Check(name, "left_open", None, f"the target leaves the outcome open: no reading to "
                 f"compare; {what}{tail}")


def _outcome(a: Any, case_id: str) -> Any:
    fn = getattr(a, "outcome", None)
    if not callable(fn):
        return None
    try:
        return fn(case_id)
    except Exception as e:  # noqa: BLE001
        return {"error": f"outcome raised {type(e).__name__}: {e}"}


def _status(a: Any, case_id: str) -> Any:
    try:
        return a.status(case_id)
    except Exception as e:  # noqa: BLE001
        return f"status raised {type(e).__name__}: {e}"


def _rx(r: Dict[str, Any]) -> Dict[str, Any]:
    """One presentation as the stub B received it, for evidence and comparison."""
    from .. import authz
    claims = authz.claims_of(r.get("authorisation")) if r.get("authorisation") else None
    return {"n": r.get("n"), "raw": bytes(r["raw"]).hex(), "raw_sha256": r.get("raw_sha256"),
            "authorisation_id": (claims or {}).get("authorisation_id"),
            "authorisation_token": r.get("authorisation"),
            "authorisation_verified": r.get("authorisation_verified"),
            "use_key": r.get("use_key"), "answer": r.get("answer"),
            "request_digest": r.get("request_digest")}


def _envelope_differs(raw: bytes, approved: Dict[str, Any]) -> Optional[List[str]]:
    """The members in which `raw` (as received) differs from `approved`; None if unreadable."""
    try:
        got = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(got, dict):
        return None
    return sorted(k for k in set(got) | set(approved) if got.get(k) != approved.get(k))
