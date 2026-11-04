"""P18B — Payload bound, single use, with the authority held at B (KRK-18 (authority at B)).

**Profile.** `b-issuer/0.1` (`conformance/bissuer.py`; design
B issues the
credential and the exact object the property judges, holds the consent, and the kit holds none of
B's keys. The kit plays A with a stand-in agent (`conformance/stand_in.py`) that obtains every
object through B's own flow, and plays the person at B's page through a declared hook. Results
are labelled (§5.3) and are never set beside P18's: P18 judges a B that honours authority another
organisation issued; P18B judges a B against the authority it issued itself.

**Guarantee.** B performs an effect only for an exact object B itself issued, to this agent
identity, at this B and tenant, inside the object's validity, and only after an acceptance of
that object as its current version; the effect's values equal the terms B signed for the object
accepted; across every presentation of one acceptance B performs the effect at most once; B's
answer to a repeat agrees with its store; and a refusal for a passing reason does not use up the
object (design §3.1; X3's B1 to B6 read with "A's authorisation" as "B's exact object and its
acceptance").

**What is graded, from which evidence** (design §2.4). Effect counts and values from B's store,
read through B's own read path (`store`), at the ``B-store-read`` grade; whether an object is B's,
current, superseded, expired or another's from B's signed objects, verified by the kit's own
verifier against B's published keys (`bissuer.verify_b_object`, KRK-M140); B5 from B's classified
answers against the store. B's own account of an effect (a proof, an "executed" answer) is never
counted (KRK-M143). The ``recorder`` grade (B's executor pointed at the kit's recorder) is not built
in phase 1a; an adapter that reports it reads inconclusive.

**The judge is P18's** (design decision 3). This module imports `p18_payload_bound` and uses its
outcome names, its answer classes and, for the variants whose question carries unchanged, its
`judge` itself: the steps are logged in P18's shape (``present``, ``race``, ``hook``, ``read``,
with roles ``capability`` and ``variant``), and ``plan.meta["authorised"]`` holds **B's signed
terms of the object accepted**, which is what an effect must equal under rule 3. A later fix to
P18's judge therefore lapses P18B results too, which is correct. The variants whose question
changes under the profile (§3.1 "changes") are judged here, with P18's helpers and outcome names.

**Binding rules** (design §1.6, binding for every target under the profile):

1. the class layer is the credential B issues on the pair's consent; KRK-18 does not grade what a
   class allows;
2. the exact layer is B's exact object (its id, and B's digest of its terms where B states one)
   with the acceptance as presented;
3. what is executed is the terms of the object accepted;
4. a key the requester chooses (an ``Idempotency-Key``) is outside the exact layer;
5. audience is B, the tenant and the agent identity the object was issued to; validity is the
   object's own stated expiry;
6. where B keeps objects and use records in one store, neither outlives the other;
7. every object presented is one B issued, as B sent it; nothing is altered, re-signed or
   invented;
8. **restatement**: B's first signed terms for a request must equal the request, or be labelled
   by B as a counter-proposal; the stand-in accepts only terms it asked for. For ambiguous input
   (V2: a duplicated member, an integer beyond 2^53, text NFKC folds) it accepts B's one signed
   reading and the effect is judged against it. A silent restatement is information
   (``restated_changed``) and a finding, never a fail of KRK-18: the stand-in
   did not accept it, so no effect happened under it;
9. **resource reconciliation**: every change B's store shows on the kit's declared test
   resources must match an acceptance the kit made; one that does not is the fail
   ``effect_without_acceptance``. Changes before the run (the baseline) and by
   declared background writers are not counted (KRK-M147).

**Forms per shape** (`revision`, `consent-id`, `rar-token`; design §3.1 table). The stand-in builds
each shape's bytes; the kit decides what changes:

| Variant | `revision` | `consent-id` | `rar-token` | Pass |
|---|---|---|---|---|
| `body_changed` | accept r after B issued r+1 on the kit's counter-proposal | submission naming C with one term changed | request differing from the token's details in one member | refused; for the other two shapes also "ran with C's terms" |
| `unbound_member` | every header outside the terms changed, and an ``instruction`` member naming other terms added | the same | the same | refused, or ran with B's terms |
| `noncanonical_equivalent` | the request re-serialised before B restates it | the same | the same | ran with the request's values, or refused (``false_refusal``, information) |
| `duplicate_key` | (a) a request with ``amount`` twice: refused, or B signed one reading and the effect equals it; (b) the acceptance with ``approved_by`` twice | (b) ``consent_id`` twice | (b) ``amount`` twice in the request | (a) as stated; (b) refused |
| `number_precision` | amount 2^53+1 in the request | the same | the same | refused, or ran with B's signed terms |
| `unicode_fold` | fullwidth recipient in the request | the same | the same | refused, or ran with B's signed terms (and so on the resource they name) |
| `class_for_exact` | ``standing_permission`` on a revision B marked for the person's approval | a submission with no consent id for an exact-bound operation | the pair's class token for an exact-bound operation | refused (capability: the class route for a class operation runs) |
| `other_holder` (new) | a second identity accepts the first's revision under its own credential | the second identity submits the first's consent id | the second identity presents the first's token with its own proof | refused, and the first identity's acceptance then runs once |
| `replay_other_counterparty` | a revision issued by a second instance of the product (its own keys, KRK-M142) accepted at the target, then at its own instance | the same with a consent | the same with a token | refused at the target |
| `split_undeclared` | not applicable (structural: the requester never sends the payload that is executed) | two submissions, each with part of the items, naming the whole consent | two requests, each with part of the token's items | refused |
| others | P18's question with B's objects: one acceptance of one object, presented as P18 presents one authorisation | | | as P18 |

`split_declared` is not applicable where the agreement states B's object lists no parts;
`translated_declared` and `mapping_undeclared` are not applicable unless B declares a mapping
profile (structural: B restates the request in its own vocabulary, so the restatement is the
mapping and rule 8 checks it). With a mapping declared they are `not_driven`: no form is built.

**Control** (never the guarantee, KRK-M19). On a fresh pair: one consent through the hook; M
honest requests (M from P18's `SERIES`), each restated faithfully by B and accepted once (or the
shape's equivalent); B's store shows exactly one effect per acceptance with B's signed terms; every
presentation left the kit once; B's answers were readable; every object verified; the hook's log
holds only the decisions the probe asked for; and one more request after the series still runs.
The control does not require that B refuses anything, checks any digest, keeps a use record or
restates faithfully beyond the control's own requests. A B that executes every acceptance passes
the control and fails the variants (the ``no_check`` toy). A B that restates every request
silently gives no verdict: the stand-in accepts nothing, so nothing is measured.

**Once per run** (never part of a control): the **decline check** (design §2.3): a
fresh identity's consent is declined through the same hook, and whether B still issued a
credential is recorded (``consent_not_enforced``, information here; P20B grades it).

**Result.** ``fail`` if any landed variant fails or resource reconciliation fails. ``pass`` only if
the control held, every variant in this shape's `na_forbidden` landed with a verdict,
reconciliation ran and found every change accepted, and nothing failed. ``inconclusive`` if the
control did not hold, if nothing failed but a variant that must land did not, if reconciliation
could not run, or if the adapter called B's reset aid during the run (KRK-M145). Every result
carries ``extra.authority`` (`bissuer.label`) and opens with `bissuer.SUMMARY_SENTENCE`.

**Measurement errors guarded** (`docs/FAILURE-MODES.md`): KRK-M130 (the runner refuses an A-issued
property for an adapter whose authority is at B, and this probe refuses one at A); KRK-M131 (the
summary names the hook kind and never the person's consent); KRK-M132 (restatement); KRK-M133 (the
hook kinds, the decline check); KRK-M134 (effects counted as the union of every store read, so a
store a restart rebuilt does not hide the first effect); KRK-M139 (one consent per pair, the
hook's log compared with the decisions asked for); KRK-M140 (the kit's own verifier, B's keys
from `published_keys`); KRK-M141 (the superseding revision read from B's own signed object);
KRK-M142 (the second instance's key thumbprints must differ); KRK-M143 (effects from the store
only); KRK-M145 (a reset during the run is inconclusive); KRK-M147 (baseline and declared
background writers). P18's KRK-M36 to KRK-M44 hold through `requester.Transport` and P18's judge.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import time
from typing import Any, Dict, List, Optional, Protocol, Tuple

from .. import bissuer, stand_in
from ..evidence import Evidence
from ..result import Check, Result, verdict
from . import p18_payload_bound as p18

ID = "P18B"
TITLE = "Payload bound, single use (authority at B)"
OUTSIDE_NAME = "KRK-18 (authority at B)"
PROFILE = bissuer.PROFILE

FIXTURES = ("known_bad/bissuer_core.py", "known_bad/bissuer_binding_toys.py",
            "tests/test_p18b_payload_bound_b.py", "tests/vectors/bissuer/*.json")
"""The B-issuer toy core, P18B's toy file, the test that states their required outcomes, and the
JCS vectors (design §4.6). P18's own fixtures are not here: P18B does not run P18's toys."""
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = (
    "Agent identities (client ids and Ed25519 keys) come from the operating system, never from "
    "the seed: the seed is written into result.json (KRK-M36).",
    "Each request's ref, the client idempotency keys and request ids come from the operating "
    "system (secrets), so a re-run with one seed never asks B for a request it saw before.",
    "B's object ids, its terms' expiry and its clock are B's; which presentation of a race wins "
    "is decided by B's scheduling.",
)

SERIES = p18.SERIES
CONTROL = p18.CONTROL
VARIANTS = ("body_changed", "unbound_member", "noncanonical_equivalent", "duplicate_key",
            "number_precision", "unicode_fold", "class_for_exact", "replay_after_answer",
            "retry_after_lost_answer", "replay_new_key", "replay_after_restart",
            "replay_after_failover", "replay_other_endpoint", "replay_other_tenant",
            "replay_other_counterparty", "other_holder", "race_same", "split_undeclared",
            "split_declared", "expired", "validity_beyond_memory", "refused_then_retry",
            "crash_between_use_and_effect", "translated_declared", "mapping_undeclared")
"""P18's variants (`p18.VARIANTS`) in P18's order, with ``other_holder`` added (design §3.1)."""
assert set(VARIANTS) == set(p18.VARIANTS) | {"other_holder"}

NA_FORBIDDEN_ALL = (CONTROL, "body_changed", "unbound_member", "duplicate_key",
                    "number_precision", "class_for_exact", "replay_after_answer",
                    "retry_after_lost_answer", "replay_new_key", "replay_other_counterparty",
                    "other_holder", "race_same", "expired", "replay_after_restart")
"""Variants an adapter may not declare not applicable, in every shape (design §3.1). As in P18,
``replay_after_restart`` is here: an adapter with no restart hook leaves it ``not_driven``."""
SPLIT_SHAPES = ("consent-id", "rar-token")
STRUCTURAL_NA = {
    ("revision", "split_undeclared"):
        "structural: in the revision shape the requester never sends the "
        "payload that is executed; B executes the terms it signed, whole, so there are no parts "
        "for A to send",
}


def na_forbidden(shape: Optional[str]) -> Tuple[str, ...]:
    """`NA_FORBIDDEN_ALL`, plus ``split_undeclared`` for the consent-id and rar-token shapes."""
    return NA_FORBIDDEN_ALL + (("split_undeclared",) if shape in SPLIT_SHAPES else ())


def must_land(shape: Optional[str]) -> Tuple[str, ...]:
    return tuple(v for v in na_forbidden(shape) if v != CONTROL)


GRADES = ("B-store-read", "B-answer")
"""The grades built in phase 1a. ``recorder`` (P18's top grade) needs B's executor pointed at
the kit's recorder; no B-issuer adapter offers that yet."""
COUNTING = p18.COUNTING + ("other_holder",)
CLASSES = p18.CLASSES
DENYING = p18.DENYING
CLAIMING = p18.CLAIMING
VALUE_MEMBERS = p18.VALUE_MEMBERS
VULNERABLE = p18.VULNERABLE
EFFECT_WITHOUT_ACCEPTANCE = "effect_without_acceptance"
RESTATED_CHANGED = "restated_changed"
CONSENT_NOT_ENFORCED = "consent_not_enforced"
ROUTED_TO_P18 = ("unbound_member", "replay_after_answer", "retry_after_lost_answer",
                 "replay_new_key", "replay_after_restart", "replay_after_failover",
                 "replay_other_endpoint", "replay_other_tenant", "race_same", "split_declared",
                 "expired", "validity_beyond_memory", "refused_then_retry",
                 "crash_between_use_and_effect", "class_for_exact")
"""Variants judged by `p18.judge` itself, unchanged (module docstring)."""
ROUTED_TO_P18_SPLIT = ("body_changed", "split_undeclared")
"""Judged by `p18.judge` in the consent-id and rar-token shapes."""
TWO53 = 2 ** 53


class Adapter(Protocol):
    """Role B under the B-issuer profile (design §6.5). The adapter decides nothing: it starts
    and reads B, and the stand-in builds B's protocol bytes."""

    name: str
    config: str

    def authority(self) -> Dict[str, Any]:
        """The agreement's ``authority`` block (design §6.8); ``issuer`` must be ``"B"``."""
        ...

    def agreement(self) -> Dict[str, Any]:
        """P18's keys (``counterparty``, ``endpoints``, ``aliases``, ``tenants``, ``operations``,
        ``max_validity_s``, ``memory_horizon_s``, ``clock_tolerance_s``, ``answer_codes``,
        ``claims_replay_protection``, ``quotes``), plus ``binding_basis`` (one of
        `bissuer.BASES`), ``test_resources``, ``background_writers``, ``instances``,
        ``store_survives_restart`` and ``stated_choices``."""
        ...

    def agent(self, n: int, identities: Optional[List[Any]] = None) -> List[Any]:
        """`n` stand-in agents (`stand_in.StandInAgent`) for one pair, each a fresh identity,
        or one per given identity (the same agent at a second instance of the product)."""
        ...

    def hook(self) -> Any:
        """The `stand_in.PersonHook`."""
        ...

    def present(self, p: Any) -> Dict[str, Any]:
        """One `authz.Presentation` through B's real entry point, raw, no client retry; the
        answer with ``began_at``/``ended_at`` from B's own timing where it has it."""
        ...

    def classify(self, answer: Dict[str, Any]) -> str:
        """One of P18's `CLASSES`, from quoted product codes."""
        ...

    def store(self, since: float) -> List[Dict[str, Any]]:
        """B's store through its read path and serializer: effects with B's operation id
        (``op_id``) and the values B used (`VALUE_MEMBERS`)."""
        ...

    def resource_history(self, resources: List[str]) -> List[Dict[str, Any]]:
        """Every change B's store shows on the declared test resources: ``resource``,
        ``op_id``, ``ref`` (the request it served, where B records one) and ``writer``."""
        ...

    def published_keys(self) -> Dict[str, Any]:
        """B's JWKS, read through the kit's baseline path, never through a verifier of B's."""
        ...

    def evidence_grade(self) -> str: ...

    # optional
    def peer(self) -> Any: ...
    def restart(self, kind: str) -> Dict[str, str]: ...
    def instances(self) -> List[str]: ...
    def dependency(self, available: bool) -> str: ...
    def crash_between(self, step: str) -> str: ...
    def crashed(self) -> bool: ...
    def set_memory_horizon(self, seconds: Optional[int]) -> str: ...
    def elapse(self, seconds: float) -> None: ...
    def resets(self) -> List[Dict[str, Any]]: ...
    def variants_not_applicable(self) -> Dict[str, str]: ...
    def variant_notes(self) -> Dict[str, str]: ...


# --------------------------------------------------------------------------- one run's state


class Run:
    """What the kit holds for one run: its own record of objects, consents and acceptances."""

    def __init__(self, a: Any, ev: Evidence, agreement: Dict[str, Any],
                 authority: bissuer.Authority, grade: str, hook: Any, keys: Any) -> None:
        self.a, self.ev, self.ag, self.auth, self.grade = a, ev, agreement, authority, grade
        self.shape = authority.shape
        self.hook, self.keys = hook, keys
        self.objects = bissuer.BObjectLog()
        self.accepted_refs: set = set()
        """The ref of every object the kit sent an acceptance for (rule 9)."""
        self.restated: List[Dict[str, Any]] = []
        self.unverified: List[Dict[str, Any]] = []
        self.asked: int = 0
        """Decisions the probe asked the hook for; compared with the hook's log (KRK-M139)."""
        self.n = 0
        exact = dict(authority.objects.get("exact_object") or {})
        self.members = {"id": exact.get("id_member", "id"),
                        "terms": exact.get("terms_member", "terms"),
                        "expiry": exact.get("expiry_member", "exp"),
                        "issued_at": exact.get("issued_at_member", "iat"),
                        "issued_to": exact.get("issued_to_member", "issued_to"),
                        "tenant": exact.get("tenant_member", "tenant"),
                        "supersedes": exact.get("supersedes_member", "supersedes"),
                        "counter": exact.get("counter_member", "counter_proposal"),
                        "digest": (exact.get("terms_digest") or {}).get("member")}
        self.signed = exact.get("signed", "jws") == "jws"
        self.parts = bool(exact.get("parts", False))
        basis = agreement.get("binding_basis") or "jcs"
        self.basis = basis if basis in bissuer.BASES else "jcs"

    def pid(self) -> str:
        self.n += 1
        return f"b{self.n:03d}-{secrets.token_hex(4)}"

    def hook_log_len(self) -> int:
        return len(getattr(self.hook, "log", []) or [])


def _short(ans: Any) -> Any:
    return p18._short(ans)


def _sha(b: Any) -> Optional[str]:
    return p18._sha(b)


def sdk_headers(values: Dict[str, Any]) -> Dict[str, str]:
    """What a client SDK sends beside a request: the recipient and amount repeated, a client
    idempotency key and a request id, all outside the terms (rule 4; P18's `requester.HEADERS`)."""
    return {"X-Recipient": str(values.get("recipient")), "X-Amount": str(values.get("amount")),
            "Idempotency-Key": secrets.token_hex(8), "X-Request-Id": secrets.token_hex(8)}


class PairB:
    """One fresh pair: fresh agent identities with one consent each, a transport, and a log of
    steps in P18's shape so P18's judge reads it."""

    def __init__(self, run: Run, variant: str, tag: str, *, identities: int = 1) -> None:
        from .. import requester
        self.run, self.a, self.variant = run, run.a, variant
        self.tag = f"{tag}-{secrets.token_hex(3)}"
        self.plan = requester.Plan(variant, meta={"authorised": {}})
        self.log: List[Dict[str, Any]] = []
        self.transport = requester.Transport(self.a.present)
        self.since = time.time()
        self.seen: Dict[str, Dict[str, Any]] = {}
        """Every effect ever read for this pair, by B's op id: the union of every store read
        (KRK-M134), so a store a restart rebuilt cannot hide an earlier effect."""
        self.hook_missing: Optional[str] = None
        self.gap: Optional[str] = None
        """Why the variant's fixture could not be built (B refused to issue, restated, an
        object did not verify): the variant reads ``fixture_not_landed``."""
        self.gap_kind: Optional[str] = None
        """``refused`` (B issued no object), ``restated``, ``unverified`` or ``other``."""
        self.consents: List[Any] = []
        self.hook_at_start = run.hook_log_len()
        self.agents = list(self.a.agent(identities))
        self.tenants: Dict[int, set] = {i: set() for i in range(len(self.agents))}
        t1 = (run.ag.get("tenants") or [None])[0]
        for i in range(len(self.agents)):
            self.consent(i, t1)

    # ------------------------------------------------------------------ store

    def effects(self) -> List[Dict[str, Any]]:
        if self.run.grade != "B-store-read":
            return []
        got = self.a.store(self.since) or []
        for e in got:
            if not isinstance(e, dict):
                continue
            key = str(e.get("op_id") or json.dumps(e, sort_keys=True, default=str))
            self.seen.setdefault(key, e)
        return [{"effect": e, "began_at": e.get("began_at")} for e in self.seen.values()]

    def by_ref(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        for e in self.effects():
            v = e.get("effect") or {}
            out.setdefault(str(v.get("ref")), []).append(v)
        return out

    def _counts(self) -> Dict[str, int]:
        return {k: len(v) for k, v in self.by_ref().items()}

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

    # ------------------------------------------------------------------ steps

    def _send(self, p: Any, *, op: str, role: str, label: str, drop: bool = False
              ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        ans = self.transport.send(p, drop_answer=drop)
        kept = self.transport.answers.get(p.pid)
        rec = {"i": len(self.log), "op": op, "role": role, "label": label, "pid": p.pid,
               "endpoint": p.endpoint, "tenant": p.tenant, "dropped": drop,
               "answer": _short(kept), "cls": self.classify(kept), "seen_by_a": ans is not None,
               "request_sha256": _sha(p.request)}
        rec["effects"] = self._counts()
        self.log.append(rec)
        return kept, rec

    def consent(self, i: int, tenant: Optional[str], decision: str = "approve") -> Any:
        """The pair's consent for identity `i` at `tenant`, through the hook: one per identity
        and tenant, each a step the probe asked for (KRK-M139)."""
        self.run.asked += 1
        rec = self.agents[i].consent(self.run.hook, tenant=tenant, pair=self.tag,
                                     decision=decision)
        self.consents.append(rec)
        self.tenants[i].add(tenant)
        self.log.append({"i": len(self.log), "op": "consent", "role": "setup", "identity": i,
                         "tenant": tenant, "decision": getattr(rec, "decision", None),
                         "credential": bool(getattr(rec, "credential", None))})
        return rec

    def _gap(self, kind: str, why: str) -> None:
        if self.gap is None:
            self.gap, self.gap_kind = why, kind

    def _objects(self, ans: Optional[Dict[str, Any]], endpoint: str, agent: Any
                 ) -> List[bissuer.BObject]:
        if ans is None or ans.get("raised"):
            return []
        try:
            objs = agent.read(ans, endpoint=endpoint) or []
        except Exception:  # noqa: BLE001
            return []
        out = []
        for o in objs:
            o.received_at = time.time()
            o.pair = self.tag
            self._verify(o)
            self.run.objects.add(o)
            out.append(o)
        return out

    def _verify(self, o: bissuer.BObject) -> None:
        """The kit's own verifier, B's keys from `published_keys`, and the kit's own reading of
        the members the agreement names (KRK-M140): the stand-in's parse is not trusted."""
        if o.kind not in ("exact",):
            return
        if not self.run.signed:
            o.verified = None
            o.why = "the agreement states B's exact objects are not signed"
            return
        v = bissuer.verify_b_object(o.raw, self.run.keys)
        o.verified = v.ok
        if not v.ok:
            o.why = f"{v.reason}: {v.detail}"
            self.run.unverified.append({"id": o.id, "why": o.why, "pair": self.tag})
            return
        c, m = v.claims or {}, self.run.members
        o.claims = dict(c)
        o.kid, o.alg = v.kid, v.alg
        mine = {"id": c.get(m["id"]), "terms": c.get(m["terms"]),
                "expires_at": c.get(m["expiry"]), "issued_at": c.get(m["issued_at"]),
                "issued_to": c.get(m["issued_to"]), "tenant": c.get(m["tenant"]),
                "supersedes": c.get(m["supersedes"]),
                "counter_proposal": bool(c.get(m["counter"]))}
        theirs = {k: getattr(o, k) for k in mine}
        if mine != theirs:
            o.verified = False
            o.why = (f"the stand-in's reading of B's object differs from the kit's reading of the "
                     f"signed members: {sorted(k for k in mine if mine[k] != theirs[k])}")
            self.run.unverified.append({"id": o.id, "why": o.why, "pair": self.tag})
            return
        if m["digest"]:
            o.terms_digest = c.get(m["digest"])

    def obtain(self, label: str, values: Optional[Dict[str, Any]], *, raw: Optional[bytes] = None,
               agent: int = 0, tenant: Any = "_", endpoint: Optional[str] = None,
               person: bool = True, ambiguous: bool = False, role: str = "setup",
               readings: Optional[List[Dict[str, Any]]] = None) -> Optional[Any]:
        """Ask B for its exact object for `values` (or the bytes `raw`), check B's restatement
        (rule 8), have the person approve it at B's page where B waits for that, and redeem it
        where the shape needs that. Returns a `requester.Req` whose values are **B's signed
        terms**, registered in the plan; or None, with `self.gap` saying why."""
        from .. import requester
        ag = self.agents[agent]
        tenant = self.t1 if tenant == "_" else tenant
        endpoint = endpoint or self.e1
        body = raw if raw is not None else requester.request_bytes(values)
        p = ag.request(body, pid=self.run.pid(), tenant=tenant, endpoint=endpoint)
        ans, rec = self._send(p, op="request", role=role, label=f"request {label}")
        objs = [o for o in self._objects(ans, endpoint, ag) if o.kind in ("exact", "pending")]
        if not objs:
            self._gap("refused", f"B issued no object for {label} (answer {rec['cls']!r})")
            return None
        obj = objs[-1]
        if obj.kind == "exact" and not self._acceptable(label, values, obj, ambiguous, readings):
            return None
        handle = ag.person_needed(obj) if person else None
        if handle:
            self.run.asked += 1
            crec = self.run.hook.approve(handle, pair=self.tag)
            self.log.append({"i": len(self.log), "op": "approve", "role": "setup",
                             "label": f"approve {label}", "handle": handle,
                             "decision": getattr(crec, "decision", None)})
        nxt = ag.complete(obj, pid=self.run.pid(), tenant=tenant, endpoint=endpoint)
        if nxt is not None:
            ans2, rec2 = self._send(nxt, op="complete", role=role, label=f"complete {label}")
            objs2 = [o for o in self._objects(ans2, endpoint, ag) if o.kind == "exact"]
            if not objs2:
                self._gap("refused", f"B issued no object on redeeming {label} (answer "
                                     f"{rec2['cls']!r})")
                return None
            obj = objs2[-1]
            if not self._acceptable(label, values, obj, ambiguous, readings):
                return None
        if obj.kind != "exact":
            self._gap("other", f"{label}: B's object is {obj.kind!r}, not an exact object")
            return None
        if obj.verified is False:
            self._gap("unverified", f"{label}: B's object {obj.id} did not verify ({obj.why})")
            return None
        r = requester.Req(label, dict(obj.terms or {}), body, None,
                          sdk_headers(dict(obj.terms or {})), endpoint, tenant)
        r.obj, r.agent, r.requested = obj, agent, values  # type: ignore[attr-defined]
        self.plan.requests[label] = r
        if r.ref is not None:
            self.plan.meta["authorised"][r.ref] = dict(obj.terms or {})
        return r

    def _acceptable(self, label: str, values: Optional[Dict[str, Any]], obj: bissuer.BObject,
                    ambiguous: bool, readings: Optional[List[Dict[str, Any]]]) -> bool:
        """Rule 8. The stand-in accepts only terms it asked for, a counter-proposal B labelled,
        or, for ambiguous input, B's one signed reading if it is one of the readings."""
        if obj.verified is False:
            self._gap("unverified", f"{label}: B's object {obj.id} did not verify ({obj.why})")
            return False
        asked = [values] if values is not None else []
        if ambiguous and readings:
            asked = readings
        if not asked:
            return True
        diffs = [bissuer.restatement(v, obj.terms, basis=self.run.basis) for v in asked]
        if any(d is None for d in diffs):
            return True
        entry = {"pair": self.tag, "variant": self.variant, "label": label, "object": obj.id,
                 "differs": diffs[0], "labelled_counter": obj.counter_proposal,
                 "ambiguous": ambiguous}
        self.run.restated.append(entry)
        if ambiguous and readings is None:
            return True             # V2: B's one signed reading, judged against what it signed
        self._gap("restated", f"{label}: B's signed terms differ from the request "
                              f"({sorted(diffs[0])}) and B did not label them a "
                              f"counter-proposal; the stand-in did not accept them (rule 8)")
        return False

    @property
    def t1(self) -> Optional[str]:
        return (self.run.ag.get("tenants") or [None])[0]

    @property
    def e1(self) -> str:
        return (self.run.ag.get("endpoints") or ["default"])[0]

    def body(self, r: Any, *, approval: str = "person", **change: Any) -> bytes:
        """The honest acceptance body for `r`, with members replaced by `change`."""
        from .. import requester
        d = dict(self.agents[r.agent].acceptance_body(r.obj, approval=approval))
        d.update(change)
        return requester.request_bytes_loose(d)

    def accept(self, r: Any, label: str, *, role: str = "variant", agent: Optional[int] = None,
               body: Optional[bytes] = None, endpoint: Optional[str] = None, tenant: Any = "_",
               headers: Optional[Dict[str, str]] = None, credential_tenant: Any = "_",
               drop: bool = False, approval: str = "person") -> Dict[str, Any]:
        i = r.agent if agent is None else agent
        if body is None:
            body = self.body(r, approval=approval)
        tenant = r.tenant if tenant == "_" else tenant
        ct = r.tenant if credential_tenant == "_" else credential_tenant
        p = self.agents[i].accept(r.obj, body, pid=self.run.pid(), tenant=tenant,
                                  endpoint=endpoint or r.endpoint,
                                  headers=dict(headers if headers is not None else r.headers),
                                  credential_tenant=ct)
        if r.ref is not None:
            self.run.accepted_refs.add(str(r.ref))
        _, rec = self._send(p, op="present", role=role, label=label, drop=drop)
        return rec

    def class_use(self, label: str, values: Dict[str, Any], *, role: str = "variant",
                  agent: int = 0) -> Dict[str, Any]:
        from .. import requester
        ag = self.agents[agent]
        body = requester.request_bytes(ag.class_body(values))
        p = ag.class_use(body, pid=self.run.pid(), tenant=self.t1, endpoint=self.e1,
                         headers=sdk_headers(values))
        self.run.accepted_refs.add(str(values.get("ref")))
        r = requester.Req(label, dict(values), body, None, {}, self.e1, self.t1)
        self.plan.requests[label] = r
        _, rec = self._send(p, op="present", role=role, label=label)
        return rec

    def race(self, r: Any, n: int, label: str) -> Dict[str, Any]:
        ag = self.agents[r.agent]
        body = self.body(r)
        hdr = r.headers
        ps = tuple(ag.accept(r.obj, body, pid=self.run.pid(), tenant=r.tenant,
                             endpoint=r.endpoint, headers=dict(hdr), credential_tenant=r.tenant)
                   for _ in range(n))
        self.run.accepted_refs.add(str(r.ref))
        answers = self.transport.release_together(ps)
        rec = {"i": len(self.log), "op": "race", "role": "variant", "label": label,
               "pids": [p.pid for p in ps], "classes": [self.classify(x) for x in answers],
               "began": [x.get("began_at") for x in answers],
               "ended": [x.get("ended_at") for x in answers],
               "answers": [_short(x) for x in answers]}
        rec["effects"] = self._counts()
        self.log.append(rec)
        return rec

    def hook(self, name: str, *args: Any, role: str = "capability", label: str = "") -> Any:
        rec: Dict[str, Any] = {"i": len(self.log), "op": "hook", "role": role,
                               "label": label or name, "hook": name}
        fn = getattr(self.a, name, None)
        if fn is None:
            self.hook_missing = self.hook_missing or name
            rec["missing"] = True
            self.log.append(rec)
            return None
        try:
            rec["returned"] = fn(*args)
        except Exception as e:  # noqa: BLE001
            rec["raised"] = f"{type(e).__name__}: {e}"[:300]
        rec["effects"] = self._counts()
        self.log.append(rec)
        return rec.get("returned")

    def read(self, label: str, role: str = "capability") -> None:
        self.log.append({"i": len(self.log), "op": "read", "role": role, "label": label,
                         "effects": self._counts()})

    def elapse(self, seconds: float, label: str) -> None:
        getattr(self.a, "elapse", time.sleep)(seconds)
        self.log.append({"i": len(self.log), "op": "elapse", "role": "variant", "label": label,
                         "seconds": seconds, "effects": self._counts()})

    def unplanned_consents(self) -> int:
        """Hook decisions this pair did not ask for (KRK-M139)."""
        return self.run.hook_log_len() - self.hook_at_start - self._asked_here()

    def _asked_here(self) -> int:
        return sum(1 for s in self.log if s.get("op") in ("consent", "approve"))

    def doc(self) -> Dict[str, Any]:
        return {"pair": self.tag, "steps": _jsonable(self.log),
                "wire_log": _jsonable(self.transport.wire_log),
                "effects": _jsonable([e.get("effect") for e in self.effects()]),
                "consents": [c.doc() if hasattr(c, "doc") else str(c) for c in self.consents],
                "gap": self.gap}


def _jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))


# --------------------------------------------------------------------------- values


def draw(rng: random.Random, operation: str, n_items: Tuple[int, int] = (2, 6)) -> Dict[str, Any]:
    from .. import requester
    return requester.draw_values(rng, operation=operation, n_items=n_items)


def _fresh_ref(v: Dict[str, Any]) -> Dict[str, Any]:
    return {**v, "ref": f"r-{secrets.token_hex(8)}"}


# --------------------------------------------------------------------------- variant plans


class Planner:
    """Runs one variant's steps live: B's objects come from B's answers, so the plan is built as
    it runs (unlike P18's static plans)."""

    def __init__(self, run: Run, rng: random.Random) -> None:
        self.run, self.rng = run, rng
        ag = run.ag
        ops = ag.get("operations") or {}
        self.op_exact = next((o for o, k in ops.items() if k == "exact"), "crm.record.push")
        self.op_class = next((o for o, k in ops.items() if k == "class"), None)
        self.endpoints = list(ag.get("endpoints") or ["default"])
        self.tenants = list(ag.get("tenants") or [])
        tol = float(ag.get("clock_tolerance_s") or 0)
        self.margin = max(120.0, 2 * tol + 60)

    def v(self, **kw: Any) -> Dict[str, Any]:
        return draw(self.rng, self.op_exact, **kw)

    def pair(self, variant: str, tag: str, identities: int = 1) -> PairB:
        return PairB(self.run, variant, tag, identities=identities)

    # ------------------------------------------------------------------ the control

    def control(self, tag: str, m: int) -> PairB:
        p = self.pair(CONTROL, tag)
        for i in range(m):
            r = p.obtain(f"c{i + 1}", self.v())
            if r is None:
                return p
            p.accept(r, r.label, role="control")
        r = p.obtain("fresh-after", self.v())
        if r is not None:
            p.accept(r, r.label, role="control")
        return p

    # ------------------------------------------------------------------ B1: exact

    def body_changed(self, tag: str) -> PairB:
        p = self.pair("body_changed", tag)
        change = self.rng.choice(("amount_raised", "recipient_replaced", "item_appended"))
        r = p.obtain("R", self.v())
        if r is None:
            return p
        v2 = dict(r.values)
        if change == "amount_raised":
            v2["amount"] = r.values["amount"] * 10 + self.rng.randint(1, 99)
        elif change == "recipient_replaced":
            v2["recipient"] = f"acct-{self.rng.getrandbits(32):08x}@attacker.test"
        else:
            v2["items"] = sorted(list(r.values["items"]) + [f"sku-{self.rng.getrandbits(32):08x}"])
        p.plan.meta.update(change=change, ref=r.ref)
        cap = p.obtain("R'-own", _fresh_ref(v2))
        if cap is None:
            return p
        p.accept(cap, cap.label, role="capability")
        if self.run.shape == "revision":
            from .. import requester
            ag = p.agents[0]
            cp = ag.counter(r.obj, requester.request_bytes(v2), pid=self.run.pid(),
                            tenant=r.tenant, endpoint=r.endpoint)
            ans, rec = p._send(cp, op="request", role="setup", label="counter-proposal on R")
            new = [o for o in p._objects(ans, r.endpoint, ag) if o.kind == "exact"]
            r1 = new[-1] if new else None
            if r1 is not None and not p._acceptable("R+1", v2, r1, False, None):
                r1 = None
            p.plan.meta.update(superseding=r1.id if r1 else None, revision=r.obj.id)
            p.accept(r, "R after B issued R+1")
        else:
            body = p.body(r, **{k: v2[k] for k in ("amount", "recipient", "items")})
            p.accept(r, "R with one term changed", body=body)
        return p

    def unbound_member(self, tag: str) -> PairB:
        p = self.pair("unbound_member", tag)
        r = p.obtain("R", self.v())
        if r is None:
            return p
        other = {"recipient": f"acct-{self.rng.getrandbits(32):08x}@attacker.test",
                 "amount": r.values["amount"] * 10 + 7}
        hdr = {"X-Recipient": other["recipient"], "X-Amount": str(other["amount"]),
               "Idempotency-Key": secrets.token_hex(8), "X-Request-Id": secrets.token_hex(8)}
        p.plan.meta.update(ref=r.ref, changed=sorted(hdr) + ["instruction"])
        p.accept(r, "R, every member outside the terms changed",
                 body=p.body(r, instruction=other), headers=hdr)
        return p

    def noncanonical_equivalent(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("noncanonical_equivalent", tag)
        v = self.v()
        raw = requester.reserialise(v)
        p.plan.meta.update(ref=v["ref"], fixture=raw, honest_half=True, asked=v)
        r = p.obtain("R re-serialised", v, raw=raw)
        if r is not None:
            p.accept(r, "R re-serialised, accepted")
        return p

    def duplicate_key(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("duplicate_key", tag)
        v = self.v()
        second = v["amount"] * 99
        raw = requester.with_duplicate(v, "amount", second)
        readings = [v, {**v, "amount": second}]
        p.plan.meta.update(ref_a=v["ref"], readings={"first": v["amount"], "last": second})
        ra = p.obtain("R-ambiguous", None, raw=raw, ambiguous=True, readings=readings)
        p.plan.meta.update(a_issued=ra is not None, a_gap=p.gap)
        p.gap = p.gap_kind = None                      # (a) may be refused at issuance
        if ra is not None:
            p.accept(ra, "(a) B's one signed reading, accepted")
        rb = p.obtain("R-b", self.v())
        if rb is None:
            return p
        p.plan.meta["ref_b"] = rb.ref
        d = dict(p.agents[0].acceptance_body(rb.obj))
        shape = self.run.shape
        if shape == "revision":
            member, first, last = "approved_by", "standing_permission", d.get("approved_by")
        elif shape == "consent-id":
            other = p.obtain("R-b2", self.v())
            if other is None:
                return p
            p.plan.meta["ref_b2"] = other.ref
            member, first, last = "consent_id", other.obj.id, d.get("consent_id")
        else:
            member, first, last = "amount", rb.values["amount"] * 99, d.get("amount")
        d[member] = first
        dup = requester.with_duplicate(d, member, last) if isinstance(first, str) or \
            isinstance(first, int) else None
        p.plan.meta.update(member=member, first=first, last=last)
        p.accept(rb, f"(b) the acceptance with {member} twice", body=dup)
        return p

    def number_precision(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("number_precision", tag)
        v = {**self.v(), "amount": TWO53 + 1}
        raw = requester.request_bytes_loose(v)
        p.plan.meta.update(ref=v["ref"], presented_amount=TWO53 + 1, asked=v)
        r = p.obtain("R-2^53+1", v, raw=raw, ambiguous=True)
        if r is not None:
            p.accept(r, "B's signed reading of 2^53+1, accepted")
        return p

    def unicode_fold(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("unicode_fold", tag)
        v = self.v()
        local, _, domain = v["recipient"].partition("@")
        v = {**v, "recipient": f"{requester.fullwidth(local)}@{domain}"}
        p.plan.meta.update(ref=v["ref"], presented_recipient=v["recipient"], asked=v)
        r = p.obtain("R-fullwidth", v, ambiguous=True)
        if r is not None:
            p.accept(r, "B's signed reading of a fullwidth recipient, accepted")
        return p

    def class_for_exact(self, tag: str) -> PairB:
        p = self.pair("class_for_exact", tag)
        p.plan.meta.update(operation=self.op_exact, class_operation=self.op_class,
                           authorised={})
        if self.op_class:
            cv = draw(self.rng, self.op_class)
            if self.run.shape == "revision":
                c = p.obtain("class-allowed", cv, person=False)
                if c is None:
                    return p
                p.accept(c, "class-allowed", role="capability", approval="standing")
            else:
                p.class_use("class-allowed", cv, role="capability")
        v = self.v()
        p.plan.meta["ref"] = v["ref"]
        p.plan.meta["authorised"][v["ref"]] = None
        if self.run.shape == "revision":
            r = p.obtain("R-under-class", v, person=False)
            if r is None:
                return p
            p.plan.meta["authorised"][v["ref"]] = None
            p.accept(r, "exact revision accepted on a standing permission", approval="standing")
        else:
            p.class_use("R-under-class", v)
        return p

    # ------------------------------------------------------------------ B4/B5

    def replay_after_answer(self, tag: str) -> PairB:
        p = self.pair("replay_after_answer", tag)
        r = p.obtain("R", self.v())
        if r is not None:
            p.plan.meta["ref"] = r.ref
            p.accept(r, "first")
            p.accept(r, "replay")
        return p

    def retry_after_lost_answer(self, tag: str) -> PairB:
        p = self.pair("retry_after_lost_answer", tag)
        r = p.obtain("R", self.v())
        if r is not None:
            p.plan.meta["ref"] = r.ref
            p.accept(r, "first", drop=True)
            p.read("effect before the retry")
            p.accept(r, "retry")
        return p

    def replay_new_key(self, tag: str) -> PairB:
        p = self.pair("replay_new_key", tag)
        r = p.obtain("R", self.v())
        if r is not None:
            p.plan.meta["ref"] = r.ref
            p.accept(r, "first")
            fresh = {**r.headers, "Idempotency-Key": secrets.token_hex(8),
                     "X-Request-Id": secrets.token_hex(8)}
            p.accept(r, "replay with a fresh client key", headers=fresh)
        return p

    def _across(self, variant: str, tag: str, kind: str) -> PairB:
        p = self.pair(variant, tag)
        r = p.obtain("R", self.v())
        if r is None:
            return p
        p.plan.meta.update(ref=r.ref, restart=kind)
        p.accept(r, "first")
        p.read("before the restart", role="setup")
        p.hook("restart", kind)
        if p.hook_missing:
            return p
        fresh = p.obtain("fresh-after-restart", self.v())
        if fresh is None:
            return p
        p.accept(fresh, fresh.label, role="capability")
        p.accept(r, "replay")
        return p

    def replay_after_restart(self, tag: str) -> PairB:
        return self._across("replay_after_restart", tag, "process")

    def replay_after_failover(self, tag: str) -> PairB:
        return self._across("replay_after_failover", tag, "failover")

    def replay_other_endpoint(self, tag: str) -> PairB:
        p = self.pair("replay_other_endpoint", tag)
        if len(self.endpoints) < 2:
            p.plan.gap = "the agreement names one endpoint"
            return p
        e1, e2 = self.endpoints[0], self.endpoints[1]
        alias = (self.run.ag.get("aliases") or {}).get(e2) == e1
        cap = p.obtain("addressed-to-E2", self.v(), endpoint=e2)
        r = p.obtain("R", self.v(), endpoint=e1)
        if cap is None or r is None:
            return p
        p.plan.meta.update(ref=r.ref, second=e2, alias=alias)
        p.accept(cap, cap.label, role="capability")
        p.accept(r, "at E2, issued at E1", endpoint=e2)
        p.read("after the other endpoint", role="variant")
        p.accept(r, "at E1")
        return p

    def replay_other_tenant(self, tag: str) -> PairB:
        p = self.pair("replay_other_tenant", tag)
        if len(self.tenants) < 2:
            p.plan.gap = "the agreement names fewer than two tenants"
            return p
        t1, t2 = self.tenants[0], self.tenants[1]
        p.consent(0, t2)
        cap = p.obtain("addressed-to-T2", self.v(), tenant=t2)
        r = p.obtain("R", self.v(), tenant=t1)
        if cap is None or r is None:
            return p
        p.plan.meta.update(ref=r.ref, second=t2, alias=False)
        p.accept(cap, cap.label, role="capability")
        p.accept(r, "at T2 with T1's credential, issued at T1", tenant=t2, credential_tenant=t1)
        p.read("after the other tenant", role="variant")
        p.accept(r, "at T1")
        return p

    def replay_other_counterparty(self, tag: str) -> PairB:
        """V6: an object a second instance of the product issued (another organisation, its own
        keys) is accepted at the target first, then at its own instance (the capability
        control). Presented at its own instance second, so a shared use record cannot answer
        "duplicate" at the target and hide the audience check (P18's endpoint lesson)."""
        from .. import requester
        p = self.pair("replay_other_counterparty", tag)
        peer = getattr(self.run.a, "peer", None)
        if peer is None:
            p.hook_missing = "peer"
            return p
        try:
            other = peer()
        except Exception as e:  # noqa: BLE001
            p.gap = f"the adapter's peer() raised {type(e).__name__}: {e}"
            return p
        mine, theirs = bissuer.thumbprints(self.run.keys), \
            bissuer.thumbprints(other.published_keys())
        p.plan.meta.update(audience=getattr(other, "org", None) or
                           (other.agreement() or {}).get("counterparty"),
                           thumbprints={"target": mine, "peer": theirs})
        if not theirs or set(mine) & set(theirs):
            p.gap = ("the second instance publishes a key with the same RFC 7638 thumbprint as "
                     "the target's, so an object it signs is not another organisation's "
                     "(KRK-M142)") if theirs else "the second instance publishes no key"
            return p
        ident = p.agents[0].identity()
        (pa,) = other.agent(1, identities=[ident])
        phook = other.hook()
        pt = (other.agreement().get("tenants") or [None])[0]
        prec = pa.consent(phook, tenant=pt, pair=p.tag)
        p.log.append({"i": len(p.log), "op": "peer-consent", "role": "setup",
                      "decision": getattr(prec, "decision", None)})
        ptr = requester.Transport(other.present)
        pe = (other.agreement().get("endpoints") or ["default"])[0]
        v = self.v()
        preq = pa.request(requester.request_bytes(v), pid=self.run.pid(), tenant=pt, endpoint=pe)
        ans = ptr.send(preq)
        objs = pa.read(ans or {}, endpoint=pe) or []
        obj = objs[-1] if objs else None
        handle = pa.person_needed(obj) if obj else None
        if handle:
            phook.approve(handle, pair=p.tag)
        nxt = pa.complete(obj, pid=self.run.pid(), tenant=pt, endpoint=pe) if obj else None
        if nxt is not None:
            objs = pa.read(ptr.send(nxt) or {}, endpoint=pe) or []
            obj = objs[-1] if objs else None
        if obj is None or obj.kind != "exact":
            p.gap = "the second instance issued no exact object"
            return p
        vv = bissuer.verify_b_object(obj.raw, other.published_keys())
        if not vv.ok or bissuer.verify_b_object(obj.raw, self.run.keys).ok:
            p.gap = ("the second instance's object does not verify under its own keys, or "
                     "verifies under the target's (KRK-M142)")
            return p
        obj.verified = True
        r = requester.Req("R-from-the-other-instance", dict(obj.terms or {}), b"", None,
                          sdk_headers(dict(obj.terms or {})), p.e1, p.t1)
        r.obj, r.agent, r.requested = obj, 0, v  # type: ignore[attr-defined]
        p.plan.requests[r.label] = r
        p.plan.meta["ref"] = r.ref
        p.plan.meta["authorised"][r.ref] = dict(obj.terms or {})
        p.accept(r, "at the target, issued by the other instance")
        cap = pa.accept(obj, p.body(r), pid=self.run.pid(), tenant=pt, endpoint=pe,
                        headers=dict(r.headers), credential_tenant=pt)
        cans = ptr.send(cap)
        peff = [e for e in (other.store(p.since) or []) if str(e.get("ref")) == str(r.ref)]
        p.plan.meta["peer_capability"] = {"answer": _short(cans), "effects": len(peff)}
        return p

    def other_holder(self, tag: str) -> PairB:
        p = self.pair("other_holder", tag, identities=2)
        own = p.obtain("holder-own", self.v(), agent=1)
        r = p.obtain("R", self.v(), agent=0)
        if own is None or r is None:
            return p
        p.plan.meta.update(ref=r.ref)
        p.accept(own, own.label, role="capability")
        p.accept(r, "by the second identity, under its own credential", agent=1)
        p.read("after the other holder", role="variant")
        p.accept(r, "by the identity it was issued to")
        return p

    def race_same(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("race_same", tag)
        alone = p.obtain("alone", self.v())
        if alone is None:
            return p
        p.plan.meta.update(rounds=[])
        p.accept(alone, "alone", role="capability")
        for i in range(requester.RACE_ROUNDS):
            r = p.obtain(f"R{i + 1}", self.v())
            if r is None:
                return p
            n = self.rng.randint(*requester.RACE_N)
            p.plan.meta["rounds"].append({"ref": r.ref, "n": n, "label": r.label})
            p.race(r, n, r.label)
        return p

    def _split_items(self, items: List[str]) -> Tuple[List[str], List[str]]:
        k = self.rng.randint(1, len(items) - 1)
        return list(items[:k]), list(items[k:])

    def split_undeclared(self, tag: str) -> PairB:
        p = self.pair("split_undeclared", tag)
        r = p.obtain("R", self.v(n_items=(2, 6)))
        if r is None:
            return p
        a, b = self._split_items(r.values["items"])
        p.plan.meta.update(ref=r.ref, parts=[a, b])
        p.accept(r, "part 1, naming the whole", body=p.body(r, items=a))
        p.accept(r, "part 2, naming the whole", body=p.body(r, items=b))
        return p

    def split_declared(self, tag: str) -> PairB:
        p = self.pair("split_declared", tag)
        v = self.v(n_items=(2, 6))
        a, b = self._split_items(v["items"])
        v = {**v, "parts": [a, b]}
        r = p.obtain("R-whole", v)
        if r is None:
            return p
        if not (r.obj.terms or {}).get("parts"):
            p.gap = "B's object lists no parts, although the agreement says it can"
            return p
        whole = {k: x for k, x in r.values.items() if k != "parts"}
        p.plan.meta.update(ref=r.ref, parts={"R1": {**whole, "items": a},
                                             "R2": {**whole, "items": b}},
                           honest_half=True)
        p.plan.meta["authorised"][r.ref] = whole
        p.accept(r, "part 1", body=p.body(r, items=a, part=0))
        p.accept(r, "part 2", body=p.body(r, items=b, part=1))
        p.read("after the parts", role="variant")
        p.accept(r, "the whole after its parts")
        return p

    # ------------------------------------------------------------------ B3

    def expired(self, tag: str) -> PairB:
        """Accept after the object's own stated expiry by more than the stated tolerance; the
        capability control is a fresh object accepted on the valid side by the same margin
        (KRK-M41). Time passes through the adapter's ``elapse`` (sleeping by default)."""
        p = self.pair("expired", tag)
        r = p.obtain("R-expired", self.v())
        if r is None:
            return p
        life = _lifetime(r.obj)
        if life is None:
            p.gap = "B's object states no expiry and issue time, so it cannot be presented " \
                    "expired by a known margin"
            return p
        m = self.margin
        p.plan.meta.update(ref=r.ref, margin_s=m, lifetime_s=life)
        if life <= m:
            p.gap = f"B's objects live {life:.0f} s, not longer than the margin {m:.0f} s"
            return p
        p.elapse(life + m, "past the object's expiry by the margin")
        cap = p.obtain("valid-by-the-margin", self.v())
        if cap is None:
            return p
        cl = _lifetime(cap.obj) or life
        p.elapse(max(0.0, cl - m), "to the margin before the fresh object's expiry")
        p.accept(cap, cap.label, role="capability")
        p.accept(r, "expired by more than the tolerance")
        return p

    def validity_beyond_memory(self, tag: str) -> PairB:
        from .. import requester
        p = self.pair("validity_beyond_memory", tag)
        h = requester.HORIZON_S
        p.plan.meta.update(horizon_s=h)
        p.hook("set_memory_horizon", h)
        r = p.obtain("R", self.v())
        if r is None:
            return p
        p.plan.meta["ref"] = r.ref
        p.accept(r, "first")
        p.elapse(h + 1.5, "past the horizon")
        p.accept(r, "after the horizon")
        return p

    # ------------------------------------------------------------------ B6

    def refused_then_retry(self, tag: str) -> PairB:
        p = self.pair("refused_then_retry", tag)
        f1 = p.obtain("fresh-while-down", self.v())
        f2 = p.obtain("fresh-after-restore", self.v())
        r = p.obtain("R", self.v())
        if None in (f1, f2, r):
            return p
        p.plan.meta.update(ref=r.ref, capability={"down": f1.ref, "up": f2.ref})
        p.hook("dependency", False, label="dependency off")
        p.accept(f1, f1.label, role="capability")
        p.hook("dependency", True, label="dependency on")
        p.accept(f2, f2.label, role="capability")
        p.hook("dependency", False, role="variant", label="dependency off")
        p.accept(r, "first, refused for the dependency")
        p.hook("dependency", True, role="variant", label="dependency on")
        p.accept(r, "identical retry")
        return p

    def crash_between_use_and_effect(self, tag: str) -> PairB:
        p = self.pair("crash_between_use_and_effect", tag)
        r = p.obtain("R", self.v())
        if r is None:
            return p
        p.plan.meta["ref"] = r.ref
        p.hook("crash_between", "use-and-effect")
        p.accept(r, "first, crashing")
        p.hook("crashed")
        p.accept(r, "identical retry")
        return p


def _lifetime(obj: bissuer.BObject) -> Optional[float]:
    if isinstance(obj.expires_at, (int, float)) and isinstance(obj.issued_at, (int, float)):
        return float(obj.expires_at) - float(obj.issued_at)
    return None


# --------------------------------------------------------------------------- judging


def judge(variant: str, pair: PairB, shape: str) -> Check:
    """One variant's outcome. Variants whose question carries are judged by `p18.judge`; the
    rest here, with P18's helpers and outcome names."""
    plan = pair.plan
    if variant in ("number_precision", "unicode_fold") and pair.gap_kind == "refused":
        return Check(variant, "refused", True, f"B issued no object for the ambiguous request "
                     f"({pair.gap})")
    if variant == "noncanonical_equivalent" and pair.gap_kind == "refused":
        return Check(variant, "false_refusal", None, f"B refused to issue an object for an "
                     f"equivalent serialisation (information): {pair.gap}")
    if pair.gap and variant != "duplicate_key":
        return Check(variant, "fixture_not_landed", None, pair.gap)
    if variant in ROUTED_TO_P18 or (variant in ROUTED_TO_P18_SPLIT and shape != "revision"):
        return p18.judge(variant, plan, pair)
    eff = pair.by_ref()
    ref = plan.meta.get("ref")
    auth = (plan.meta.get("authorised") or {}).get(ref)
    mine = eff.get(str(ref), [])
    n = len(mine)

    def values(honest: bool = False) -> Check:
        if n == 0:
            if honest:
                return Check(variant, "false_refusal", None, "an honest equivalent was refused "
                             "(safe)")
            return Check(variant, "refused", True, "refused; no effect in B's store")
        if n > 1:
            return Check(variant, p18._times(n), False, f"{n} effects under one acceptance")
        ok, differs = p18.matches(mine[0], auth)
        if ok:
            return Check(variant, "ran_as_authorised", True, "one effect, with B's signed terms")
        return Check(variant, "ran_changed", False, f"the effect's {differs or 'values'} differ "
                     f"from B's signed terms: {p18._diff(mine[0], auth)}")

    if variant == "body_changed":                         # revision shape
        if not p18.capability_ran(eff, plan.requests["R'-own"]):
            return Check(variant, "capability_not_held", None, "the changed terms with their own "
                         "revision did not run once with their values")
        sup = plan.meta.get("superseding")
        if not sup or pair.run.objects.superseded(plan.meta.get("revision")) is None:
            return Check(variant, "fixture_not_landed", None, "B's own signed objects show no "
                         "revision superseding R, so R was still current (KRK-M141)")
        if n == 0:
            return Check(variant, "refused", True, f"refused revision {plan.meta['revision']} "
                         f"after B issued {sup} ({plan.meta['change']}); no effect")
        r1 = pair.run.objects.get(sup)
        what = ("R+1's terms, which were never accepted" if r1 and p18.matches(mine[0], r1.terms)[0]
                else "the superseded revision's terms" if p18.matches(mine[0], auth)[0]
                else "values neither revision states")
        return Check(variant, "ran_changed", False, f"{n} effect(s) on accepting a revision B "
                     f"had superseded, with {what}")
    if variant == "noncanonical_equivalent":
        return values(honest=True)
    if variant in ("number_precision", "unicode_fold"):
        return values()
    if variant == "duplicate_key":
        return _judge_duplicate(plan, pair, eff)
    if variant == "replay_other_counterparty":
        capd = plan.meta.get("peer_capability") or {}
        if capd.get("effects") != 1:
            return Check(variant, "capability_not_held", None, f"the object did not run once at "
                         f"the instance that issued it ({capd}), so a refusal at the target "
                         f"would say nothing")
        return p18.judge(variant, plan, pair)
    if variant == "other_holder":
        if not p18.capability_ran(eff, plan.requests["holder-own"]):
            return Check(variant, "capability_not_held", None, "the second identity's own "
                         "object did not run for it")
        mid = next((s for s in pair.log if s.get("op") == "read"), {})
        k = mid.get("effects", {}).get(str(ref), 0)
        if k:
            return Check(variant, "ran_wrong_audience", False, f"{k} effect(s) when an identity "
                         f"the object was not issued to accepted it under its own credential")
        if n > 1:
            return Check(variant, p18._times(n), False, f"{n} effects in total")
        if n == 0:
            return Check(variant, "consumed_by_refusal", False, "refused for the other holder, "
                         "then refused for its own: the refusal used the object up")
        return Check(variant, "refused", True, "refused for the other identity; ran once for "
                     "the identity it was issued to")
    raise AssertionError(variant)


def _judge_duplicate(plan: Any, pair: PairB, eff: Dict[str, List[Dict[str, Any]]]) -> Check:
    """V2. (a) A request with a member twice: refused at issuance, or B signed one of the two
    readings and the effect equals it. (b) An acceptance with a member twice: refused."""
    meta = plan.meta
    notes = []
    ra = plan.requests.get("R-ambiguous")
    if ra is not None:
        got = eff.get(str(ra.ref), [])
        if len(got) > 1:
            return Check("duplicate_key", p18._times(len(got)), False, "(a) more than one effect")
        if got and not p18.matches(got[0], ra.values)[0]:
            return Check("duplicate_key", "ran_changed", False, f"(a) B signed amount "
                         f"{ra.values.get('amount')} and executed {got[0].get('amount')}")
        notes.append(f"(a) B signed one reading (amount {ra.values.get('amount')}) and "
                     f"{'executed it' if got else 'the acceptance was refused'}")
    else:
        notes.append("(a) B issued no object for bytes with a member twice")
    rb = plan.requests.get("R-b")
    if rb is None or not meta.get("member"):
        return Check("duplicate_key", "fixture_not_landed", None,
                     f"(b) not built: {pair.gap or 'no object for the acceptance'}")
    refs = [str(rb.ref)] + ([str(plan.requests["R-b2"].ref)] if "R-b2" in plan.requests else [])
    k = sum(len(eff.get(x, [])) for x in refs)
    if k:
        return Check("duplicate_key", "ran_ambiguous", False, f"(b) {k} effect(s) for an "
                     f"acceptance with {meta['member']} twice ({meta['first']!r}, then "
                     f"{meta['last']!r}); " + "; ".join(notes))
    return Check("duplicate_key", "refused", True, f"(b) refused an acceptance with "
                 f"{meta['member']} twice; " + "; ".join(notes))


# --------------------------------------------------------------------------- the probe


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None) -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    auth = bissuer.authority_of(a)
    extra0 = {"authority": bissuer.label(auth), "profile": PROFILE}

    def inconclusive(why: str, **kw: Any) -> Result:
        kw.setdefault("extra", extra0)
        return _labelled(Result.inconclusive(a.name, ID, why, **kw, **common), auth)

    if auth.issuer != "B":
        return inconclusive("the adapter states no authority held at B (authority.issuer is "
                            f"{auth.issuer!r}); run P18 (KRK-M130)")
    prob = auth.problem()
    if prob:
        return inconclusive(prob)
    try:
        agreement = dict(a.agreement() or {})
        grade = a.evidence_grade()
        hook = a.hook()
        keys = a.published_keys()
    except Exception as e:  # noqa: BLE001
        return inconclusive(f"reading the agreement, the hook or B's keys raised "
                            f"{type(e).__name__}: {e}")
    if not agreement.get("counterparty"):
        return inconclusive("the agreement names no counterparty id for B")
    if grade not in GRADES:
        return inconclusive(f"evidence grade {grade!r} is not one of {GRADES} (the recorder "
                            f"grade is not built in phase 1a)")
    hp = stand_in.hook_problem(hook, (auth.hook or {}).get("kind"))
    if hp:
        return inconclusive(f"{hp} (KRK-M133)")
    if not bissuer.key_set(keys):
        return inconclusive("B publishes no key the kit can read through its baseline path")
    shape = auth.shape
    forbidden = na_forbidden(shape)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    bad = sorted(v for v in na if v in forbidden or v not in VARIANTS)
    if bad:
        return inconclusive(f"the adapter declares {bad} not applicable; {list(forbidden)} may "
                            f"not be in the {shape} shape, and only P18B's variants can be")
    if any(not isinstance(w, str) or not w.strip() for w in na.values()):
        return inconclusive("a variant is declared not applicable without a reason")
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    m = rng.randint(*SERIES)
    ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order, "series": m,
                          "agreement": _jsonable(agreement), "evidence_grade": grade,
                          "authority": _jsonable(auth.__dict__), "published_keys": keys,
                          "variants_not_applicable": na, "variant_notes": notes})
    run = Run(a, ev, agreement, auth, grade, hook, keys)
    resources = list(agreement.get("test_resources") or [])
    writers = set(agreement.get("background_writers") or [])
    baseline = None
    if resources and hasattr(a, "resource_history"):
        try:
            baseline = list(a.resource_history(resources) or [])
        except Exception as e:  # noqa: BLE001
            baseline = None
            ev.write("baseline-error.txt", f"{type(e).__name__}: {e}")
    resets_before = len(getattr(a, "resets", lambda: [])() or [])
    planner = Planner(run, rng)
    common_extra = dict(extra0, seed=seed, evidence_grade=grade,
                        grade_label=bissuer.grade_label(grade), series=m, shape=shape,
                        hook=(auth.hook or {}).get("kind"), agreement=_jsonable(agreement),
                        claims_replay_protection=bool(agreement.get("claims_replay_protection")))
    if na:
        common_extra["variants_not_applicable"] = na

    # ------------------------------------------------------------------ control
    try:
        ctl = planner.control(f"{run_tag}control", m)
    except Exception as e:  # noqa: BLE001
        return inconclusive(f"control raised {type(e).__name__}: {e}", extra=common_extra)
    held, why = _control_held(ctl, m, grade)
    ev.write("control.json", dict(ctl.doc(), held=held, why=why, m=m))
    if not held:
        findings = _findings(run)
        ex = dict(common_extra, findings=findings) if findings else common_extra
        return inconclusive(f"control did not hold: {why}", extra=ex)
    control = (f"{m} honest requests, each restated faithfully by B, approved through the "
               f"{(auth.hook or {}).get('kind')} hook where B asked, and accepted once: one effect "
               f"each with B's signed terms in B's store ({bissuer.grade_label(grade)}), each "
               f"presentation once on the wire, every answer readable, every object verified "
               f"under B's published keys, and one more request after the series ran")

    checks: List[Check] = []
    for variant in order:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            ev.write(f"{variant}.json", {"variant": variant, "not_applicable": na[variant]})
            continue
        sna = STRUCTURAL_NA.get((shape, variant))
        if sna:
            checks.append(Check(variant, "not_applicable", None, sna))
            continue
        if variant == "split_declared" and not run.parts:
            checks.append(Check(variant, "not_applicable", None, "the agreement states B's "
                                "objects list no parts (authority.exact_object.parts)"))
            continue
        if variant in ("translated_declared", "mapping_undeclared"):
            if agreement.get("mappings"):
                checks.append(Check(variant, "not_driven", None, "B declares a mapping profile; "
                                    "no form for it is built in phase 1a"))
            else:
                checks.append(Check(variant, "not_applicable", None, "structural: B restates the "
                                    "request in its own vocabulary, so the restatement is the "
                                    "mapping, and rule 8 checks it"))
            continue
        if variant == "validity_beyond_memory" and not hasattr(a, "set_memory_horizon"):
            horizon = agreement.get("memory_horizon_s")
            if horizon == "permanent":
                q = (agreement.get("quotes") or {}).get("memory_horizon_s", "not-found")
                checks.append(Check(variant, "not_applicable", None, f"use records are kept for "
                                    f"good, as the product states ({q})"))
            else:
                checks.append(Check(variant, "not_driven", None, f"the adapter cannot shorten "
                                    f"the use-record retention (stated {horizon!r})"))
            continue
        if grade == "B-answer" and variant in COUNTING:
            checks.append(Check(variant, "not_driven", None, "at the B-answer grade the kit would "
                                "count effects by asking B"))
            continue
        try:
            pair = getattr(planner, variant)(f"{run_tag}{variant}")
        except Exception as e:  # noqa: BLE001
            checks.append(Check(variant, "not_driven", None, f"the probe raised "
                                f"{type(e).__name__}: {e}"))
            continue
        try:
            if pair.plan.gap:
                c = Check(variant, "not_applicable", None, f"{pair.plan.gap} (agreement as "
                          f"stated)")
            elif pair.hook_missing:
                c = Check(variant, "not_driven", None, f"the adapter has no "
                          f"{pair.hook_missing!r} hook")
            elif pair.unplanned_consents() > 0:
                c = Check(variant, "fixture_not_landed", None, f"the hook made "
                          f"{pair.unplanned_consents()} decision(s) the probe did not ask for: "
                          f"the driver consented on its own (KRK-M139)")
            elif grade == "B-answer":
                c = p18.judge_answers(variant, pair.plan, pair)
            else:
                c = judge(variant, pair, shape)
        except Exception as e:  # noqa: BLE001
            c = Check(variant, "not_driven", None, f"judging raised {type(e).__name__}: {e}")
        finally:
            if variant == "validity_beyond_memory" and hasattr(a, "set_memory_horizon"):
                try:
                    a.set_memory_horizon(None)
                except Exception:  # noqa: BLE001
                    pass
            if variant == "refused_then_retry" and hasattr(a, "dependency"):
                try:
                    a.dependency(True)
                except Exception:  # noqa: BLE001
                    pass
        if c.ok is not None:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (grade {bissuer.grade_label(grade)})")
        if variant in notes:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (adapter note: {notes[variant]})")
        checks.append(c)
        ev.write(f"{variant}.json", dict(pair.doc(), variant=variant,
                                         meta=_jsonable(pair.plan.meta), outcome=c.outcome,
                                         ok=c.ok, detail=c.detail))

    # ------------------------------------------------------------------ once per run
    checks.append(_decline_check(planner, f"{run_tag}decline"))
    checks.append(_restatement_check(run))
    rec_check = _reconciliation(a, run, resources, writers, baseline, grade)
    checks.append(rec_check)
    ev.write("objects.json", run.objects.docs())
    ev.write("reconciliation.json", {"resources": resources, "background_writers": sorted(writers),
                                     "baseline": baseline, "accepted_refs": sorted(run.accepted_refs),
                                     "outcome": rec_check.outcome, "detail": rec_check.detail})
    findings = _findings(run)
    extra = dict(common_extra)
    if findings:
        extra["findings"] = findings
    fails = [c for c in checks if c.ok is False]
    unlanded = [c.name for c in checks if c.name in must_land(shape) and c.ok is None]
    extra["disclosure"] = ("vulnerability" if fails and agreement.get("claims_replay_protection")
                           and any(c.outcome in VULNERABLE or (c.outcome.startswith("ran_") and
                                   c.outcome.endswith("x")) for c in fails) else "conformance")
    resets = (getattr(a, "resets", lambda: [])() or [])[resets_before:]
    if resets:
        extra["resets"] = _jsonable(resets)
        return inconclusive(f"the adapter called B's reset aid {len(resets)} time(s) during the "
                            f"run, so a later effect count may read a forgotten store (KRK-M145)",
                            checks=checks, control_held=True, control_detail=control, extra=extra)
    if not fails and rec_check.ok is None:
        return inconclusive(f"no variant failed, but resource reconciliation did not run: "
                            f"{rec_check.detail}", checks=checks, control_held=True,
                            control_detail=control, extra=extra)
    if not fails and unlanded:
        return inconclusive(f"no variant failed, but variants that must land did not: "
                            f"{unlanded}", checks=checks, control_held=True,
                            control_detail=control, extra=extra)
    r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                pass_summary="every effect was the terms B signed for an object it issued to "
                             "this identity at this tenant, accepted while current and valid, "
                             "at most once, with truthful answers to repeats, and every change "
                             "on the test resources matched an acceptance",
                fail_summary="B performed an effect its own object does not cover, or more "
                             "often than once, or answered a repeat untruthfully, or changed a "
                             "test resource with no acceptance",
                extra=extra, **common)
    return _labelled(r, auth)


def _labelled(r: Result, auth: bissuer.Authority) -> Result:
    """The §5.3 label: the fixed first sentence, then the hook kind (KRK-M131)."""
    r.summary = f"{bissuer.SUMMARY_SENTENCE} {bissuer.hook_sentence((auth.hook or {}).get('kind'))} " \
                f"{r.summary}"
    r.extra.setdefault("authority", bissuer.label(auth))
    return r


def _control_held(p: PairB, m: int, grade: str) -> Tuple[bool, str]:
    if p.gap:
        return False, p.gap
    if p.hook_missing:
        return False, f"the adapter has no {p.hook_missing!r} hook"
    if p.unplanned_consents() > 0:
        return False, (f"the hook made {p.unplanned_consents()} decision(s) the probe did not ask "
                       f"for: the driver consented on its own (KRK-M139)")
    for c in p.consents:
        if getattr(c, "decision", None) != "approved" or getattr(c, "credential", None) is None:
            return False, "the pair's consent did not yield a credential"
    steps = [s for s in p.log if s.get("op") in ("present", "request", "complete")]
    for s in steps:
        if (s.get("answer") or {}).get("raised"):
            return False, f"an honest presentation got no readable answer " \
                          f"({s['answer']['raised']})"
        if p.transport.sent(s["pid"]) != 1:
            return False, f"presentation {s['pid']} left the kit {p.transport.sent(s['pid'])} times"
    labels = [f"c{i + 1}" for i in range(m)] + ["fresh-after"]
    missing = [x for x in labels if x not in p.plan.requests]
    if missing:
        return False, f"no object for {missing}"
    acc = [s for s in p.log if s.get("op") == "present"]
    if len(acc) != len(labels):
        return False, f"{len(acc)} acceptances for {len(labels)} objects"
    if grade == "B-answer":
        not_exec = [s["label"] for s in acc if s.get("cls") != "executed"]
        if not_exec:
            return False, f"at the B-answer grade B did not answer executed to {not_exec}"
        return True, ""
    eff = p.by_ref()
    for label in labels:
        r = p.plan.requests[label]
        got = eff.get(str(r.ref), [])
        if len(got) != 1:
            return False, f"{label}: {len(got)} effects in B's store (expected one)"
        ok, differs = p18.matches(got[0], r.values)
        if not ok:
            return False, f"{label}: the effect's values differ from B's signed terms ({differs})"
    return True, ""


def _decline_check(planner: Planner, tag: str) -> Check:
    """Once per run (design §2.3): the same hook declines a fresh identity's
    consent. Information here; never part of a control."""
    run = planner.run
    try:
        (ag,) = run.a.agent(1)
        t1 = (run.ag.get("tenants") or [None])[0]
        run.asked += 1
        rec = ag.consent(run.hook, tenant=t1, pair=tag, decision="decline")
    except Exception as e:  # noqa: BLE001
        return Check("decline_check", "not_driven", None, f"the decline raised "
                     f"{type(e).__name__}: {e}")
    if getattr(rec, "credential", None) is not None:
        return Check("decline_check", CONSENT_NOT_ENFORCED, None, "B issued a credential after "
                     "the tester declined the consent at B's page through the same hook "
                     "(information here; graded in P20B)")
    return Check("decline_check", "consent_enforced", None, "B issued no credential after the "
                 "tester declined, so the hook was not the deciding step (KRK-M133)")


def _restatement_check(run: Run) -> Check:
    silent = [x for x in run.restated if not x["labelled_counter"] and not x["ambiguous"]]
    if silent:
        return Check("restatement", RESTATED_CHANGED, None, f"B signed terms that differ from "
                     f"the request without labelling them a counter-proposal, {len(silent)} "
                     f"time(s), first {silent[0]['label']} ({sorted(silent[0]['differs'])}); the "
                     f"stand-in accepted none of them (rule 8: information and a "
                     f"finding)")
    amb = [x for x in run.restated if x["ambiguous"]]
    return Check("restatement", "restated_faithfully", None, "every unambiguous request was "
                 "signed as asked" + (f"; for {len(amb)} ambiguous request(s) B signed one "
                                      f"reading (V2)" if amb else ""))


def _reconciliation(a: Any, run: Run, resources: List[str], writers: set,
                    baseline: Optional[List[Dict[str, Any]]], grade: str) -> Check:
    """Rule 9 (KRK-M147)."""
    if grade != "B-store-read":
        return Check("resource_reconciliation", "not_driven", None, "no store read at this grade")
    if not resources:
        return Check("resource_reconciliation", "not_driven", None, "the agreement declares no "
                     "test resources (rule 9)")
    if baseline is None or not hasattr(a, "resource_history"):
        return Check("resource_reconciliation", "not_driven", None, "B's resource history could "
                     "not be read before the first pair")
    try:
        after = list(a.resource_history(resources) or [])
    except Exception as e:  # noqa: BLE001
        return Check("resource_reconciliation", "not_driven", None, f"reading B's resource "
                     f"history raised {type(e).__name__}: {e}")
    key = (lambda c: json.dumps(c, sort_keys=True, default=str))
    seen = {key(c) for c in baseline}
    new = [c for c in after if key(c) not in seen]
    background = [c for c in new if c.get("writer") in writers]
    ours = [c for c in new if c.get("writer") not in writers]
    stray = [c for c in ours if str(c.get("ref")) not in run.accepted_refs]
    if stray:
        return Check("resource_reconciliation", EFFECT_WITHOUT_ACCEPTANCE, False,
                     f"{len(stray)} change(s) on the test resources match no acceptance the kit "
                     f"made, first {_jsonable(stray[0])} (rule 9)")
    return Check("resource_reconciliation", "reconciled", True, f"{len(ours)} change(s) on "
                 f"{resources}, each matching an acceptance the kit made; {len(background)} by "
                 f"declared background writers, {len(baseline)} before the run")


def _findings(run: Run) -> List[Dict[str, Any]]:
    out = []
    silent = [x for x in run.restated if not x["labelled_counter"] and not x["ambiguous"]]
    if silent:
        out.append({"finding": RESTATED_CHANGED, "class": "conformance", "count": len(silent),
                    "first": _jsonable(silent[0])})
    if run.unverified:
        out.append({"finding": "object_not_verified", "class": "information",
                    "count": len(run.unverified), "first": run.unverified[0]})
    return out

