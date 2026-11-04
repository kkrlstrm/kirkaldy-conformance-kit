"""P17 — Reconcilable two-sided record (KRK-17, cross-organisation X8).

**Guarantee.** When an agent at organisation A asks organisation B to perform an effect, A's
record of its part and B's record of its part can be joined action by action on a key both sides
recorded, and every difference between them is found: an entry one side has and the other lacks,
entries that disagree, an entry changed or removed after the other side acknowledged it, and a
repeat, gap or reordering in either side's numbering of its entries for that counterparty. A
change or removal on A's own side after B acknowledged it is refused, or is detectable from what
B holds. Where A reconciles, each difference ends in a stated state, both original entries are
kept, the settlement is a new entry that names them, and no disagreement about whether or how
much of an effect happened closes without a person.

**Question.** Can an independent reader, holding only A's export and what A holds of B, and B's
record and what B holds of A, find every difference the kit plants? And where A says it
reconciles: does A's own reconciliation find it, put it in front of a person, settle it only by
its stated rule, and keep both originals?

It does not ask whether either side is honest. A B that lies the same way in its receipt, its log
and its state agrees with itself everywhere; only an observation outside B's records shows that.

**Who is graded.** The target, in role A, as for KRK-16. Two families of check:

- **record checks**, which every target gets: the kit's own reconciler (`books.Reconciler`), as
  an independent third party, run over the target's export (`export`), what the target holds of
  B (`holdings`), B's record for this pair and what B holds of A. A record alone is enough to
  pass;
- **reconciliation checks**, only for a target that reconciles or says it does (`reconciles()`).
  A target that does not reads "records reconcilable; target does not reconcile" beside its
  result, and these checks are recorded as not applicable.

**Probe.** The kit plays B (`counterparty.StubCounterparty`), which now keeps an append-only
log numbered per requester (KRK-M35, KRK-M28), signs checkpoints with a key of its own, keeps
what A sends it, and serves a read API. Each variant runs on a fresh pair: a new peer id, new
receipt and checkpoint keys, a new agreement salt, a fresh B store.

1. Take the run's seed. For each pair, generate B's keys from the operating system, pin B's
   receipt key (`pin_counterparty_key`) and give the target the agreement
   (`bind_counterparty_record`): B's keys, the declared vocabulary mapping (none, except in
   `translated_declared`), and the paths to B's record, checkpoints, holdings and read API. Read
   the target's stated rule (`settlement_rule`) before anything runs (spec §3.4).
2. Control: a series of M honest actions (M drawn from `SERIES`). Each is submitted, B executes
   it, B's answer is delivered `ATTEMPTS` times and B's checkpoint once; then the target's
   deadline plus `MARGIN_S` passes and the target reconciles (if it does).
3. Each variant, in a seeded shuffled order, on a fresh pair: the same series, with the fixture
   applied to one action at a position drawn at random, or after the series for the
   ``*_after_ack`` variants (with a reconciliation pass first).
4. Landed check before reading the target: B's ground truth (`log_truth`, `tamper_log`, the
   store) shows the fixture; for a fixture on the target's side, the target's own export read
   back shows the change, or the hook reports it refused (KRK-M32).
5. The target reconciles `ATTEMPTS` times; its breaks, states and flags are read; its record is
   exported, raw and in the kit's terms.
6. The kit's reconciler runs over both sides (record checks).
7. A scripted person settles each break the target reported (`settle_as_person`) with a decision
   that names no outcome (``keep-both``); the target is exported again and every original entry
   must still be there, byte for byte (KRK-M34).
8. For each of the probe's own cases that a break about an effect names (`HOLDS_EFFECT`, keyed
   to the case's action), the target's reading of that effect is read (`effect_state`): after
   the no-outcome settlement it must still be held open, neither done nor not done, and the case
   not closed (KRK-M66). Then the scripted person gives an outcome in a second
   settlement (`OUTCOMES`; the one the target's own record already holds for the attempt, else
   what B's store shows), and the effect must now read as that outcome.

**Control** (§4.1 of the design; spec §3.1). It proves only that the probe reached the real path,
and never requires the guarantee (KRK-M19): B's store shows every effect and B's log an entry for
every request; the kit's wire copy holds every request and answer; the kit's reconciler, run over
the kit's own wire copy of A's side and B's log, reports every action matched (this checks the
kit's instrument, not the target); the target's export and holdings calls returned; every
action's status is readable. It does not require that the export joins, is complete, is ordered,
carries commitments, or that the target reconciles: those are the guarantee, judged as the
control's record checks `join`, `complete` and `order`.

Two guards on the reconciliation checks only (they never touch the record checks): the target
reconciles once after the first submit and before B executes, and an action read as matched then
means it matches A against itself (KRK-M30); and a break the target reports on the honest series
means its detection cannot be told from noise. Either way the reconciliation checks give no
verdict, and the reading is kept.

The control also reads the target's effect state for each honest action, as evidence, and never
requires anything of it (KRK-M19). One guard on the effect checks only: a target that reads an
honest action B completed as held open cannot be told apart from one that holds an effect after a
no-outcome settlement, so its effect checks give no verdict.

**Variants** (`VARIANTS`), with the break kinds the kit's reconciler must report (`EXPECT`):

| Variant | Planted by | Expected |
|---|---|---|
| `receipt_contradicts_log` | B signs N; B's log and store say N-k | `statement-vs-log` |
| `receipt_contradicts_state` | B's receipt and log say N; B's read API shows N-k | `statement-vs-state` |
| `unbacked_on_b` | B records an effect for A under a correlation id A never used | `missing-on-a` |
| `unbacked_on_a` | B drops the request; a scripted person settles A's attempt as executed | `missing-on-b` |
| `compensating_pair` | one of A's requests missing at B, one extra at B, same count | `missing-on-a` and `missing-on-b` |
| `join_collision` | B's record for A shows another requester's entries under the same correlation id | `join-ambiguous` |
| `b_edit_after_ack` | an insider at B changes an effect entry and re-chains the rest | `changed-after-ack` or `statement-vs-log` |
| `b_delete_after_ack` | an insider at B deletes a receipt-issued entry | `removed-after-ack` or `gap` |
| `void_over_receipt` | B voids an effect A holds a signed receipt for | `removed-after-ack` |
| `seq_reorder` | an insider at B swaps two entries' numbers | `renumbered` |
| `seq_duplicate` | B executes one request twice | `repeated` |
| `late_entry` | B acts after the window; a person meanwhile settled the action as not executed | `settlement-contradicted` |
| `basis_undeclared` | B records the action in its own vocabulary; no mapping declared | state `no-basis` |
| `a_edit_after_ack` | an insider at A changes an A-only member of an A entry (`operator_write`) | `changed-after-ack`, or `prevented` |
| `a_delete_after_ack` | the same insider removes an A entry | `removed-after-ack` or `gap`, or `prevented` |
| `torn_write` | A's process dies between two writes of one settlement (`crash_between`) | A's record still holds the settling entry |
| `clock_skew` (honest) | B's clock is off on one action, by 60-3600 s and beyond the target's stated tolerance | no break |
| `translated_declared` (honest) | B's vocabulary, under the mapping the agreement declares | no break |
| `declared_void` (honest) | B aborts a request and says so in a `void` entry | no break (`explained`) |

Not built in this version: `forked_log` (B shows A and the third party different histories). It
needs a target that claims the `witnessed` grade and a witness both sides trust; the kit runs no
witness and no target claims that grade, so it would be `not_applicable` for every target.

Tamper fixtures on the target's side (`operator_write`) run only on self-hosted targets, change
plain data only, and never sign anything. B's tamper fixtures go through the
stub's kit-only path, which an honest run never touches (KRK-M35). A target with no
`operator_write` must declare why its own operators have no such path; "the adapter did not
write one" is not a reason, and the variant is then not driven (no verdict on it, never a pass).

**Outcomes.** Record checks per variant: `found` (pass), `prevented` (pass, target-side tamper
refused), `intact` (pass, `torn_write`), `reconcilable` (pass, honest variants), `hidden` (fail),
`torn` (fail), `export_disagrees` (fail), and information: `fixture_not_landed`,
`not_applicable`, `not_driven`. Control record checks: `join`, `complete`, `order`.

Reconciliation checks (`c:<variant>`): `found_flagged` (pass), `explained` (pass), `missed`,
`found_silent`, `closed_without_person`, `overwrote`, `joined_by_clock` (a break on
`clock_skew`, whose skew is drawn beyond the stated tolerance), `matched_while_torn` (fail), and
information: `false_break` (on `translated_declared` or `declared_void`),
`own_check_found` / `own_check_missed` (target-side tamper), `no_verdict`, `not_applicable`.

Effect checks (`e:<variant>`, step 8), only for a target that reconciles and only on a variant
where a break about an effect named one of the probe's cases: `held_then_followed` (pass),
`closed_without_outcome` (fail: after a settlement that names no outcome, the effect reads done
or not done, or the case is closed; KRK-M66), `outcome_not_followed` (fail: after the person's
outcome, the effect does not read as it), and information, never a pass: `effect_unread` (the
target reports no effect state, its call raised, or it answered outside `EFFECT_READINGS`),
`no_outcome_path` (the effect was held, and the target took no outcome from a person), and
`no_verdict` (a guard above).

The result is `fail` if a landed variant fails a record, reconciliation or effect check or a
control record check fails; `pass` only if the control held, `join`, `complete` and `order`
passed, every landed variant passed its record checks and, where the target reconciles, its
reconciliation checks and no effect check failed; `inconclusive` if the control did not hold. A
pass whose effect checks gave no verdict says so in its summary (`extra.effect_checks`). It carries both sides' grades as the kit
computed them on the control (`grade_a`, `grade_b`), the grade the target claims, and whether it
reconciles.

**Measurement errors guarded** (`docs/FAILURE-MODES.md`): KRK-M27 B's log read only through
`record()`, never built from receipts; KRK-M28 B numbers per requester, so a gap is a removal;
KRK-M29 the kit's reconciler compares contents and fails its own self-test under every weakened
copy; KRK-M30 the pre-execution reconciliation read; KRK-M31 no order or join by wall clock;
KRK-M32 a target-side tamper counts only if the target's own export shows it, or the hook says
refused; KRK-M33 only the mapping the agreement declares; KRK-M34 originals compared byte for
byte after settlement; KRK-M35 B's log is append-only outside the tamper path; KRK-M66 the
effect read after a settlement that names no outcome, not only the record.
"""
from __future__ import annotations

import json
import os
import random
import time
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P17"
TITLE = "Reconcilable two-sided record"

FIXTURES = ("known_bad/records_toys.py", "tests/test_p17_reconcilable_record.py",
            "tests/test_books.py", "tests/vectors/krk17/*.json")
"""The known-bad toys and their required outcomes, the kit reconciler's self-test and the record
vectors, hashed into `fixture_version`. The stub B (`counterparty.py`) and the kit's reconciler
(`books.py`) are imported by the probe, so they are part of `probe_version`."""
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = (
    "B's receipt and checkpoint keys come from the operating system's secure source, not from the "
    "seed, so a published seed cannot be used to sign as B.",
    "Entry and checkpoint times (recorded_at, issued_at) are read from the clock.",
    "Correlation ids and peer ids carry the run id before their seeded part.",
)

ATTEMPTS = 2
MARGIN_S = 2.0
SERIES = (3, 8)
COUNT_RANGE = (20, 120)
K_MAX = 15
SKEW_S = (60, 3600)
TOLERANCE_S = 300.0
"""The kit's own clock tolerance: beyond it, a clock difference is recorded as `explained`
(information); it never orders or joins anything (KRK-M31)."""

REQUESTER = "did:web:a.example"
OTHER_REQUESTER = "did:web:other-requester.example"
OPERATION, CONTAINER, VERBS = "crm.record.push", "people", ("upsert",)
VOCABULARY = {"operation": {OPERATION: "people.upsert"}, "container": {CONTAINER: "contacts"}}
"""B's own terms for the action, in `translated_declared` and `basis_undeclared`."""
MAPPING = {"operation": {"people.upsert": OPERATION}, "container": {"contacts": CONTAINER}}
"""The mapping the agreement declares in `translated_declared` (B's term -> A's term)."""
PERSON = "person:kit-scripted-approver"

CONTROL = "honest"
B_SIDE = ("receipt_contradicts_log", "receipt_contradicts_state", "unbacked_on_b",
          "unbacked_on_a", "compensating_pair", "join_collision", "b_edit_after_ack",
          "b_delete_after_ack", "void_over_receipt", "seq_reorder", "seq_duplicate",
          "late_entry", "basis_undeclared")
A_SIDE = ("a_edit_after_ack", "a_delete_after_ack", "torn_write")
HONEST = ("clock_skew", "translated_declared", "declared_void")
VARIANTS = B_SIDE + A_SIDE + HONEST
AFTER_ACK = ("b_edit_after_ack", "b_delete_after_ack", "void_over_receipt", "seq_reorder",
             "a_edit_after_ack", "a_delete_after_ack")
"""Variants planted after the series, once A holds B's receipts and checkpoints, with one
reconciliation pass by the target before the change."""
TAMPER_A = ("a_edit_after_ack", "a_delete_after_ack")
NOT_BUILT = {"forked_log": "needs a target claiming the witnessed grade and a witness both sides "
                           "trust; the kit runs no witness (module docstring)"}
NA_FORBIDDEN = (CONTROL, "unbacked_on_b", "unbacked_on_a", "receipt_contradicts_log",
                "compensating_pair", "b_delete_after_ack", "a_edit_after_ack",
                "a_delete_after_ack")
"""Every target that acts on another organisation has these questions (design §6.4)."""

EXPECT: Dict[str, Tuple[str, frozenset]] = {
    "receipt_contradicts_log": ("any", frozenset({"statement-vs-log"})),
    "receipt_contradicts_state": ("any", frozenset({"statement-vs-state"})),
    "unbacked_on_b": ("any", frozenset({"missing-on-a"})),
    "unbacked_on_a": ("any", frozenset({"missing-on-b"})),
    "compensating_pair": ("all", frozenset({"missing-on-a", "missing-on-b"})),
    "join_collision": ("any", frozenset({"join-ambiguous"})),
    "b_edit_after_ack": ("any", frozenset({"changed-after-ack", "statement-vs-log"})),
    "b_delete_after_ack": ("any", frozenset({"removed-after-ack", "gap"})),
    "void_over_receipt": ("any", frozenset({"removed-after-ack"})),
    "seq_reorder": ("any", frozenset({"renumbered"})),
    "seq_duplicate": ("any", frozenset({"repeated"})),
    "late_entry": ("any", frozenset({"settlement-contradicted"})),
    "a_edit_after_ack": ("any", frozenset({"changed-after-ack"})),
    "a_delete_after_ack": ("any", frozenset({"removed-after-ack", "gap"})),
}
"""Break kinds the planted difference must produce (record checks, and reconciliation checks
for a target that reconciles). "any": one of them; "all": every one."""

HOLDS_EFFECT = ("missing-on-a", "missing-on-b", "content-differs", "statement-vs-log",
                "statement-vs-state", "changed-after-ack", "removed-after-ack", "repeated",
                "settlement-contradicted")
"""Break kinds about whether, or how much of, an effect happened: `books.EFFECT_KINDS` without
`join-ambiguous`, which is about whose action another requester's entry is, not about A's effect.
A person's settlement of one of these that names no outcome must leave the effect held
(KRK-M66)."""
NO_OUTCOME = "keep-both"
OUTCOMES = ("executed", "not-executed")
EFFECT_READINGS = ("done", "not-done", "open")
"""What `effect_state` may say about an effect: done, not done, or open (neither: held for a
person or still waiting on B)."""

CROSS_CHECKED = ("operation", "container", "count", "items_digest", "expected_effect_digest",
                 "verdict", "outcome", "created", "updated", "deleted", "failed", "log_seq",
                 "receipt_id", "settles", "by", "pair_seq", "head", "voids")
"""Body members the other side records too, or that the reconciler reads. `a_edit_after_ack`
changes a member outside this list, so only a commitment B holds can show the change: an edit
of a cross-checked member is caught by B's own record of the same fact, which is a different
test (design §3.1)."""


class Adapter(Protocol):
    """Role A. The driving methods are KRK-16's (`p16_effect_receipt.Adapter`): `pin_counterparty_key`,
    `submit`, `deliver`, `status`, and optionally `evidence_grade`, `receipt_deadline_s`,
    `elapse`. The rest are P17's."""

    name: str
    config: str

    def bind_counterparty_record(self, peer: str, agreement: Dict[str, Any]) -> str:
        """Optional. Give the target the agreement with `peer`: ``receipt_key`` and
        ``checkpoint_key`` (kid, raw public key), ``mapping`` (the declared vocabulary mapping,
        or None), and the paths the target may use: ``record()`` (B's log for this pair, kit
        terms), ``checkpoint()`` (a fresh signed checkpoint), ``hold(token)`` (send B one of
        A's own commitments) and ``read_state(correlation_id)``. Returns how the target took
        them, for the evidence."""
        ...

    def deliver_checkpoint(self, case_id: str, token: str) -> None:
        """Optional. Hand the target B's signed checkpoint, issued with B's answer. A target
        without this path holds no checkpoint of B's (recorded)."""
        ...

    def export(self, peer: str) -> List[Dict[str, Any]]:
        """The target's record of its part with `peer`, every entry, in the kit's terms
        (`books.SCHEMA`), read from the product's own store through its own serializer
        (KRK-M12). An adapter translates; it adds no entry and no number the product lacks."""
        ...

    def export_raw(self, peer: str) -> bytes:
        """Optional. The product's own rows behind `export`, unchanged, one per line. Used for
        `kept_both` (KRK-M34). Defaults to the canonical JSON of `export`, one entry per line."""
        ...

    def holdings(self, peer: str) -> List[Dict[str, Any]]:
        """B's statements the target holds, raw: ``{"type": "receipt"|"checkpoint", "token"}``."""
        ...

    def checkpoint_key(self) -> Optional[Tuple[str, bytes]]:
        """Optional. The public key A signs its own checkpoints with, so a third party can
        verify what B holds of A. None: A signs nothing."""
        ...

    def record_grade(self) -> str:
        """Optional. The grade the product's documentation claims for its record (§2.6 of the
        design), with the quote in `vendor_claims()`."""
        ...

    def reconciles(self) -> bool:
        """Optional, default False. Does the product reconcile its record against the
        counterparty's, or say it does?"""
        ...

    def settlement_rule(self) -> Dict[str, Any]:
        """Optional; required of a target that reconciles. The product's stated rule, read
        before the run: ``closes_by_rule`` (list of `books.EXPLAINED` it closes without a
        person), ``presumption``, ``window_s``, ``tolerance_s``."""
        ...

    def reconcile(self, peer: str) -> str:
        """One run of the product's reconciliation for this peer. Returns how."""
        ...

    def breaks(self, peer: str) -> List[Dict[str, Any]]:
        """The product's own report, one dict per difference: ``ref``, ``key``
        (`books.key_str`), ``kind`` (`books.BREAK_KINDS`), ``state`` (`books.STATES`),
        ``entries`` (entry digests it names), ``settled_by`` (``person:...``, ``rule:...`` or
        None)."""
        ...

    def states(self, peer: str) -> Dict[str, str]:
        """The product's reconciled state per action, keyed by `books.key_str`."""
        ...

    def flagged(self, peer: str, ref: str) -> Tuple[bool, str]:
        """Did this break reach a person (an alert, a queue entry)? And how."""
        ...

    def settle_as_person(self, peer: str, ref: str, decision: str, by: str) -> str:
        """The path a person with standing uses to settle a break."""
        ...

    def reconcile_attempt_as_person(self, case_id: str, outcome: str, by: str) -> str:
        """A person settles one attempt as `outcome` ("executed" | "not-executed")."""
        ...

    def effect_state(self, case_ref: str) -> Dict[str, Any]:
        """Optional; read only from a target that reconciles. The product's own reading of the
        effect of the case `submit` returned, translated and nothing more (KRK-M24, KRK-M25):
        ``effect`` (one of `EFFECT_READINGS`), ``closed`` (the product runs nothing more on the
        case and holds it for nobody) and ``product`` (the product's own words, for the
        evidence). A target without it reads `effect_unread` on the effect checks, never a
        pass."""
        ...

    def operator_write(self, peer: str, entry_digest: str,
                       change: Optional[Dict[str, Any]]) -> str:
        """Optional, self-hosted targets only. Change the body members in `change` of the entry
        whose kit-terms digest is `entry_digest` (or, with None, remove the entry) with the most
        privileged credential the deployment's operators hold, through the product's documented
        storage path. Returns "changed", "removed" or "refused: <why>". Never signs anything."""
        ...

    def crash_between(self, case_id: str, step: str) -> str:
        """Optional. Make the target's process die between two of its writes the next time it
        settles `case_id` (step "settlement"). Returns how."""
        ...

    def crashed(self, case_id: str) -> bool:
        """Optional, with `crash_between`: did the induced crash happen?"""
        ...

    def variants_not_applicable(self) -> Dict[str, str]:
        ...

    def variant_notes(self) -> Dict[str, str]:
        ...


# --------------------------------------------------------------------------- the wire


class Wire:
    """The kit's own copy of everything that crossed between A and B in one pair."""

    def __init__(self) -> None:
        self.requests: List[Tuple[Dict[str, Any], str]] = []
        """(envelope, its items digest) per request."""
        self.answers: List[str] = []
        self.checkpoints: List[str] = []

    def a_side(self, books, requester: str, peer: str) -> List[Dict[str, Any]]:
        """A's side as the wire shows it, numbered and chained by the kit: a request-sent per
        request and a receipt-received per distinct answer. Used only to check the kit's
        instrument on the control."""
        from .. import receipts
        out: List[Dict[str, Any]] = []
        prev = None

        def add(kind, cid, rd, body, raw=None):
            nonlocal prev
            e = {"schema": books.SCHEMA, "side": "A", "party": requester, "peer": peer,
                 "pair_seq": len(out) + 1, "prev_digest": prev, "kind": kind,
                 "correlation_id": cid, "request_digest": rd, "answers": None, "body": body,
                 "raw_sha256": raw, "recorded_at": "1970-01-01T00:00:00Z"}
            out.append(e)
            prev = books.entry_digest(e)

        for env, items_digest in self.requests:
            add("request-sent", env["correlation_id"], receipts.request_digest(env),
                {"operation": env["operation"], "container": env["container"],
                 "count": len(env["items"]), "items_digest": items_digest,
                 "expected_effect_digest": env["expected_effect_digest"]})
        seen = set()
        for tok in self.answers:
            sha = receipts.sha256_ref(tok.encode())
            if sha in seen:
                continue
            seen.add(sha)
            c = json.loads(receipts._b64d(tok.split(".")[1]))
            add("receipt-received", c["correlation_id"], c["request_digest"],
                {"verdict": c["verdict"]}, sha)
        return out

    def holdings(self) -> List[Dict[str, Any]]:
        """Each distinct statement B sent, once: the kit's copy, not a target's holdings."""
        return ([{"type": "receipt", "token": t} for t in dict.fromkeys(self.answers)]
                + [{"type": "checkpoint", "token": t} for t in dict.fromkeys(self.checkpoints)])


def draw_items(rng: random.Random, n: int) -> List[str]:
    keys: set = set()
    while len(keys) < n:
        keys.add(f"person-{rng.getrandbits(48):012x}@example.test")
    return sorted(keys)


def build_case(receipts, rng: random.Random, salt: bytes, peer: str, tag: str,
               requester: str = REQUESTER) -> Tuple[Dict[str, Any], Any]:
    n = rng.randint(*COUNT_RANGE)
    items = draw_items(rng, n)
    expected = receipts.ExpectedEffect(operation=OPERATION, counterparty=peer,
                                       container=CONTAINER, verbs=VERBS, count=n,
                                       items_digest=receipts.items_digest(salt, items))
    envelope = {"schema": "kirkaldy.effect-request/0.1",
                "correlation_id": f"p17-{tag}-{rng.getrandbits(64):016x}",
                "batch": 0, "operation": OPERATION, "requester": requester,
                "counterparty": peer, "container": CONTAINER, "items": items,
                "expected_effect_digest": expected.digest()}
    return envelope, expected


# --------------------------------------------------------------------------- one pair


def run_pair(a: Adapter, ev: Evidence, variant: str, rng: random.Random, run_tag: str, *,
             reconciles: bool, rule: Dict[str, Any], deadline: float,
             elapse: Callable[[float], None]) -> Dict[str, Any]:
    """Drive one pair of organisations through a series with `variant` planted, and read both
    records. Returns the observation; never raises for a target's fault (`error`)."""
    from .. import books, counterparty, receipts

    tag = f"{variant}-{run_tag}".strip("-")
    peer = f"did:web:b-{variant.replace('_', '-')}-{rng.getrandbits(32):08x}.example"
    salt = rng.getrandbits(128).to_bytes(16, "big")
    rkey = receipts.Keypair.generate(f"b-receipts-{variant}")
    ckey = receipts.Keypair.generate(f"b-checkpoints-{variant}")
    store = ev.dir / f"b-{variant}.sqlite"
    if store.exists():
        store.unlink()          # a fresh pair starts from an empty B, whatever ran here before
    b = counterparty.StubCounterparty(str(store), rkey, salt, counterparty_id=peer,
                                      checkpoint_key=ckey)
    mapping = MAPPING if variant == "translated_declared" else None
    m = rng.randint(*SERIES)
    at = rng.randrange(m)
    obs: Dict[str, Any] = {"variant": variant, "peer": peer, "series": m, "at": at,
                           "salt_sha256": receipts.sha256_ref(salt), "mapping": mapping}
    wire = Wire()
    cases: List[Tuple[str, Dict[str, Any], Any]] = []
    fix: Dict[str, Any] = {}

    def keyof(env):
        return (REQUESTER, peer, env["correlation_id"], receipts.request_digest(env))

    agreement = {"receipt_key": (rkey.kid, rkey.public_bytes()),
                 "checkpoint_key": (ckey.kid, ckey.public_bytes()), "mapping": mapping,
                 "salt_sha256": receipts.sha256_ref(salt),
                 "record": lambda: b.record(REQUESTER), "checkpoint": lambda: b.checkpoint(REQUESTER),
                 "hold": lambda token: b.hold(REQUESTER, token),
                 "read_state": lambda cid: b.read_state(REQUESTER, cid)}
    try:
        a.pin_counterparty_key(rkey.kid, rkey.public_bytes())
        bind = getattr(a, "bind_counterparty_record", None)
        obs["bound"] = bind(peer, agreement) if bind else "the target takes no counterparty record"
    except Exception as e:
        obs["error"] = f"binding the counterparty raised {type(e).__name__}: {e}"
        return obs
    deliver_ck = getattr(a, "deliver_checkpoint", None)

    def answer(case_id, token, report):
        raised = []
        for _ in range(ATTEMPTS):
            try:
                a.deliver(case_id, token, report)
            except Exception as e:      # a product may refuse an answer, or crash (torn_write)
                raised.append(f"{type(e).__name__}: {e}")
            if token is not None:
                wire.answers.append(token)
        ck = b.checkpoint(REQUESTER)
        if ck is not None:
            wire.checkpoints.append(ck)
            if deliver_ck is not None:
                try:
                    deliver_ck(case_id, ck)
                except Exception as e:
                    raised.append(f"deliver_checkpoint: {type(e).__name__}: {e}")
        return raised

    try:
        for i in range(m):
            sent, exp = build_case(receipts, rng, salt, peer, tag)
            here = i == at
            if here:
                fix.update(cid=sent["correlation_id"], key=keyof(sent), count=exp.count)
                _plan(variant, b, sent, exp, rng, fix, float(rule.get("tolerance_s") or 0))
            case_id = a.submit(sent, exp)
            cases.append((case_id, sent, exp))
            if i == 0 and reconciles and variant == CONTROL:
                # KRK-M30: nothing has reached B yet. An action read as matched now is A matched
                # against A.
                a.reconcile(peer)
                obs["states_before_b"] = dict(a.states(peer) or {})
            obs.setdefault("status_before_b", {})[case_id] = a.status(case_id)
            if here and variant == "torn_write":
                hook = getattr(a, "crash_between", None)
                fix["crash"] = hook(case_id, "settlement") if hook else None
            token, report = b.execute(sent, exp, "honest", rng=rng)
            wire.requests.append((sent, exp.items_digest))
            raised = answer(case_id, token, report)
            if raised:
                obs.setdefault("deliver_raised", {})[case_id] = raised
            if here and variant == "unbacked_on_b":
                fix["oob_cid"] = b.out_of_band(REQUESTER, exp, sent["items"], rng)
            if here and variant == "torn_write" and getattr(a, "crashed", None):
                fix["crashed"] = bool(a.crashed(case_id))
        elapse(deadline + MARGIN_S)
        fixture_case = next((c for c, env, _ in cases if env["correlation_id"] == fix.get("cid")),
                            None)
        if variant == "unbacked_on_a":
            fix["person"] = _attempt_as_person(a, fixture_case, "executed")
        if variant in AFTER_ACK:
            if reconciles:
                a.reconcile(peer)
            _after_ack(a, variant, b, peer, fix, rng, obs)
        if variant == "late_entry":
            _late(a, b, peer, fix, rng, reconciles, fixture_case, answer, obs)
        if variant == "torn_write" and fixture_case is not None:
            fix["status_after_restart"] = a.status(fixture_case)
        if reconciles:
            for _ in range(ATTEMPTS):
                a.reconcile(peer)
            obs["target_breaks"] = list(a.breaks(peer) or [])
            obs["target_states"] = dict(a.states(peer) or {})
            obs["flags"] = {br["ref"]: list(a.flagged(peer, br["ref"]))
                            for br in obs["target_breaks"]}
        obs["statuses"] = {c: a.status(c) for c, _, _ in cases}
        export = list(a.export(peer))
        raw_fn = getattr(a, "export_raw", None)
        raw = raw_fn(peer) if raw_fn else _raw(books, export)
        held = list(a.holdings(peer))
    except Exception as e:
        obs["error"] = f"{type(e).__name__}: {e}"
        return obs

    ck_a = getattr(a, "checkpoint_key", lambda: None)()
    b_rec = b.record(REQUESTER)
    state_b = {e["correlation_id"]: b.read_state(REQUESTER, e["correlation_id"])
               for e in b_rec if e["correlation_id"] and e["peer"] == REQUESTER}
    kw = dict(requester=REQUESTER, counterparty=peer, holdings_b=b.holdings(REQUESTER),
              receipt_keys={rkey.kid: rkey.public_bytes()},
              b_checkpoint_keys={ckey.kid: ckey.public_bytes()},
              a_checkpoint_keys=dict([ck_a]) if ck_a else {}, mapping=mapping, state_b=state_b,
              tolerance_s=TOLERANCE_S)
    kit = books.reconcile(export, b_rec, holdings_a=held, **kw)
    obs.update(export=export, export_raw=raw.decode("utf-8", "replace"), holdings=held,
               kit=kit.to_doc(), b_record=b_rec, b_truth=b.log_truth(), tamper=b.tamper_log,
               fixture={k: (books.key_str(v) if k == "key" else v) for k, v in fix.items()},
               cases=[c for c, _, _ in cases], _kit=kit, _fix=fix, _b=b, _keys=kw,
               _wire=wire, _cases=cases)
    if variant == CONTROL:
        wa = wire.a_side(books, REQUESTER, peer)
        obs["_instrument"] = books.reconcile(wa, b_rec, holdings_a=wire.holdings(),
                                             **dict(kw, holdings_b=[], a_checkpoint_keys={},
                                                    tolerance_s=None))
        obs["instrument"] = obs["_instrument"].to_doc()
        if reconciles:
            # Evidence for the effect checks' guard only; the control requires nothing of it.
            obs["effect_states"] = {c: _read_effect(a, c) for c, _, _ in cases}
    if reconciles and obs.get("target_breaks"):
        obs["settlement"] = _settle(a, peer, obs, books)
        obs["effect"] = _effect_after(a, peer, obs, books)
    return obs


def _raw(books, export: List[Dict[str, Any]]) -> bytes:
    from .. import receipts
    return b"\n".join(receipts.canonical_json(e) for e in export)


def _attempt_as_person(a: Adapter, case_id: Optional[str], outcome: str) -> str:
    hook = getattr(a, "reconcile_attempt_as_person", None)
    if hook is None or case_id is None:
        return "the target has no path for a person to settle an attempt"
    try:
        return str(hook(case_id, outcome, PERSON))
    except Exception as e:
        return f"refused: {type(e).__name__}: {e}"


def _plan(variant: str, b, env: Dict[str, Any], exp: Any, rng: random.Random,
          fix: Dict[str, Any], tolerance_s: float = 0.0) -> None:
    """Set B's record mode for the fixture action (before B sees the request). The clock skew
    is drawn beyond the target's stated tolerance, so a break on it can only come from joining
    or ordering by clock (KRK-M31)."""
    cid = env["correlation_id"]
    k = rng.randint(1, max(1, min(K_MAX, exp.count - 1)))
    if variant in ("receipt_contradicts_log", "receipt_contradicts_state"):
        b.set_record_mode(cid, variant, k=k)
        fix["k"] = k
    elif variant == "unbacked_on_a":
        b.set_record_mode(cid, "drop_request")
    elif variant == "compensating_pair":
        fix["other_cid"] = f"{cid}/b-extra-{rng.getrandbits(32):08x}"
        b.set_record_mode(cid, variant, other_cid=fix["other_cid"])
    elif variant == "join_collision":
        b.set_record_mode(cid, variant, other_requester=OTHER_REQUESTER)
    elif variant in ("seq_duplicate", "late_entry", "declared_void"):
        b.set_record_mode(cid, variant)
    elif variant == "clock_skew":
        lo = max(SKEW_S[0], int(tolerance_s) + 60)
        fix["skew_s"] = rng.choice((-1, 1)) * rng.randint(lo, max(SKEW_S[1], lo + 60))
        b.set_record_mode(cid, variant, skew_s=fix["skew_s"])
    elif variant in ("translated_declared", "basis_undeclared"):
        b.set_record_mode(cid, "b_vocabulary", vocabulary=VOCABULARY)
    elif variant in ("b_edit_after_ack",):
        fix["k"] = k


def _after_ack(a: Adapter, variant: str, b, peer: str, fix: Dict[str, Any],
               rng: random.Random, obs: Dict[str, Any]) -> None:
    from .. import books
    cid = fix["cid"]
    if variant == "b_edit_after_ack":
        eff = next(e for e in b.record(REQUESTER) if e["correlation_id"] == cid
                   and e["kind"] == "effect-committed")
        field = "created" if eff["body"]["created"] else "updated"
        b.tamper_edit(REQUESTER, cid, "effect-committed",
                      {field: max(0, eff["body"][field] - fix["k"])})
    elif variant == "b_delete_after_ack":
        b.tamper_delete(REQUESTER, cid, "receipt-issued")
    elif variant == "void_over_receipt":
        fix["voided"] = b.void(REQUESTER, cid)
    elif variant == "seq_reorder":
        b.tamper_swap(REQUESTER, cid)
    elif variant in TAMPER_A:
        before = list(a.export(peer))
        target = _a_target(books, before, fix["key"], variant)
        if target is None:
            fix["write"] = "no entry of A's for the fixture action to change"
            return
        digest, change = target
        fix["entry"], fix["change"] = digest, change
        hook = getattr(a, "operator_write", None)
        if hook is None:
            fix["write"] = None
            return
        try:
            fix["write"] = str(hook(peer, digest, change))
        except Exception as e:
            # An error is not a refusal: only the product saying "refused" counts as prevented.
            fix["write"] = f"error: {type(e).__name__}: {e}"
        after = list(a.export(peer))
        fix["read_back"] = _read_back(books, before, after, digest, change)


def _a_target(books, export: List[Dict[str, Any]], key: Tuple[Any, ...],
              variant: str) -> Optional[Tuple[str, Optional[Dict[str, Any]]]]:
    """The A entry the insider changes: the fixture action's settlement entry if A has one, else
    its request; the change is to its first string member outside `CROSS_CHECKED` (sorted), or,
    for a removal, None."""
    mine = [e for e in export if e.get("side") == "A" and books.entry_problem(e) is None
            and books.action_key(e) == key]
    pick = (next((e for e in mine if e["kind"] == "settlement"), None)
            or next((e for e in mine if e["kind"] == "request-sent"), None))
    if pick is None:
        return None
    digest = books.entry_digest(pick)
    if variant == "a_delete_after_ack":
        return digest, None
    for f in sorted(pick["body"]):
        if f not in CROSS_CHECKED and isinstance(pick["body"][f], str):
            return digest, {f: pick["body"][f] + "-changed-by-operator"}
    return digest, {"operator_note": "changed by operator"}


def _read_back(books, before, after, digest: str,
               change: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Did the change land in the target's own export (KRK-M32)?"""
    gone = digest not in {books.entry_digest(e) for e in after}
    if change is None:
        return {"landed": gone, "detail": "the entry is gone from the export" if gone
                else "the entry is still in the export"}
    old = next(e for e in before if books.entry_digest(e) == digest)
    want = dict(old["body"], **change)
    hit = [e for e in after if e["kind"] == old["kind"] and e["body"] == want
           and e["correlation_id"] == old["correlation_id"]]
    return {"landed": gone and bool(hit),
            "detail": "the export shows the changed entry" if gone and hit
            else "the export does not show the change"}


def _late(a: Adapter, b, peer: str, fix: Dict[str, Any], rng: random.Random, reconciles: bool,
          case_id: Optional[str], answer, obs: Dict[str, Any]) -> None:
    """`late_entry`: after the window, a person settles the missing action as not executed;
    then B acts and its answer arrives."""
    from .. import books
    key = books.key_str(fix["key"])
    settled = None
    if reconciles:
        a.reconcile(peer)
        hit = [br for br in (a.breaks(peer) or []) if br.get("key") == key]
        if hit:
            settled = str(a.settle_as_person(peer, hit[0]["ref"], "not-executed", PERSON))
    if settled is None:
        settled = _attempt_as_person(a, case_id, "not-executed")
    fix["person"] = settled
    token = b.release(fix["cid"], rng)
    fix["released"] = token is not None
    if case_id is not None:
        raised = answer(case_id, token, None)
        if raised:
            obs.setdefault("deliver_raised", {})[f"{case_id}:late"] = raised


def _settle(a: Adapter, peer: str, obs: Dict[str, Any], books) -> Dict[str, Any]:
    """A scripted person settles every open break the target reported; then the originals are
    compared byte for byte (KRK-M34)."""
    before, raw_before = obs["export"], obs["export_raw"]
    done = []
    for br in obs["target_breaks"]:
        if br.get("state") != "break":
            continue
        try:
            how = str(a.settle_as_person(peer, br["ref"], NO_OUTCOME, PERSON))
        except Exception as e:
            how = f"refused: {type(e).__name__}: {e}"
        # A break about a side's numbering can name a number rather than an entry; only the
        # entries it names must be named again by the settlement.
        done.append({"ref": br["ref"], "kind": br.get("kind"), "how": how,
                     "entries": [d for d in br.get("entries") or [] if books._is_digest(d)]})
    after = list(a.export(peer))
    raw_fn = getattr(a, "export_raw", None)
    raw_after = (raw_fn(peer) if raw_fn else _raw(books, after)).decode("utf-8", "replace")
    have = {books.entry_digest(e) for e in after}
    lost = [books.entry_digest(e) for e in before if books.entry_digest(e) not in have]
    lines = set(raw_after.splitlines())
    lost_raw = [ln for ln in raw_before.splitlines() if ln and ln not in lines]
    named = set()
    for e in after:
        if e.get("kind") == "settlement" and books.by_person(e["body"].get("by")):
            named |= set(e["body"].get("settles") or [])
    unnamed = [d["ref"] for d in done if d["entries"] and not set(d["entries"]) <= named]
    return {"settled": done, "lost_entries": lost, "lost_raw_lines": len(lost_raw),
            "unnamed": unnamed, "export_after": after}


def _read_effect(a: Adapter, case_id: str) -> Dict[str, Any]:
    """The target's reading of one case's effect (`effect_state`), or why there is none. Never
    raises: a missing method, an error or a reading outside `EFFECT_READINGS` is `unread`."""
    hook = getattr(a, "effect_state", None)
    if hook is None:
        return {"unread": "the target reports no effect state (no effect_state)"}
    try:
        got = hook(case_id)
    except Exception as e:
        return {"unread": f"effect_state raised {type(e).__name__}: {e}"}
    if not isinstance(got, dict) or got.get("effect") not in EFFECT_READINGS \
            or not isinstance(got.get("closed"), bool):
        return {"unread": f"effect_state answered {json.dumps(got, default=str)[:200]}, outside "
                          f"the vocabulary {list(EFFECT_READINGS)} with a boolean 'closed'"}
    return {"effect": got["effect"], "closed": got["closed"],
            "product": json.loads(json.dumps(got.get("product"), default=str))}


def _outcome_for(books, obs: Dict[str, Any], key: Tuple[Any, ...], cid: str) -> Tuple[str, str]:
    """The outcome the scripted person gives in the second settlement, and why: the last
    outcome the target's own record held for the attempt before the probe settled anything (a
    settlement entry of side A naming one of `OUTCOMES`), else what B's store shows. So the
    second settlement agrees with the attempt's record, and a target's rule for a person who
    contradicts an earlier settlement (a second person) does not enter: the
    check is that a person's outcome releases the effect, not which outcome."""
    own = [e["body"].get("outcome") for e in obs["export"]
           if e.get("side") == "A" and e.get("kind") == "settlement"
           and books.entry_problem(e) is None and books.action_key(e) == key
           and e["body"].get("outcome") in OUTCOMES]
    if own:
        return own[-1], "the last outcome in the target's own record for the attempt"
    written = obs["_b"].store_counts(cid)["written"]
    return ("executed" if written else "not-executed"), f"B's store shows {written} items written"


def _effect_after(a: Adapter, peer: str, obs: Dict[str, Any], books) -> Dict[str, Any]:
    """Step 8. For each of the probe's cases named by a break about an effect that the scripted
    person settled with no outcome: the target's reading of the effect after that settlement;
    then a second settlement with an outcome, and the reading after it (KRK-M66)."""
    from .. import receipts
    by_key = {books.key_str((REQUESTER, peer, env["correlation_id"], receipts.request_digest(env))):
              (case_id, env) for case_id, env, _ in obs["_cases"]}
    settled = {d["ref"] for d in obs["settlement"]["settled"]
               if not str(d["how"]).startswith("refused")}
    held: Dict[str, Dict[str, Any]] = {}
    for br in obs["target_breaks"]:
        if (br.get("state") == "break" and br.get("kind") in HOLDS_EFFECT
                and br.get("ref") in settled and br.get("key") in by_key):
            case_id, env = by_key[br["key"]]
            h = held.setdefault(case_id, {"key": br["key"], "cid": env["correlation_id"],
                                          "breaks": []})
            h["breaks"].append({"ref": br["ref"], "kind": br.get("kind")})
    for case_id, h in held.items():
        h["after_no_outcome"] = _read_effect(a, case_id)
        key = tuple(None if x == "" else x for x in h["key"].split("|"))
        h["outcome"], h["outcome_basis"] = _outcome_for(books, obs, key, h["cid"])
        h["given"], took = [], False
        for br in h["breaks"]:
            try:
                how = str(a.settle_as_person(peer, br["ref"], h["outcome"], PERSON))
                took = took or not how.startswith("refused")
            except Exception as e:
                how = f"refused: {type(e).__name__}: {e}"
            h["given"].append({"ref": br["ref"], "how": how})
        if not took:
            how = _attempt_as_person(a, case_id, h["outcome"])
            took = not (how.startswith("refused") or how.startswith("the target has no path"))
            h["given"].append({"ref": None, "how": how})
        h["outcome_taken"] = took
        h["after_outcome"] = _read_effect(a, case_id)
    return held


# --------------------------------------------------------------------------- landed


def landed(variant: str, obs: Dict[str, Any]) -> Tuple[bool, str]:
    """Is the fixture in B's ground truth, or in the target's own export (KRK-M32, KRK-M3)?"""
    fix, b = obs["_fix"], obs["_b"]
    cid = fix.get("cid")
    truth = [e for e in obs["b_truth"] if e["correlation_id"] == cid]
    mine = [e for e in truth if e["peer"] == REQUESTER]
    kinds = [e["kind"] for e in mine]
    eff = [e for e in mine if e["kind"] == "effect-committed"]
    if variant in (CONTROL,) + ("clock_skew", "translated_declared", "basis_undeclared"):
        ok = "effect-committed" in kinds and "receipt-issued" in kinds
        if variant == "clock_skew":
            ok = ok and bool(fix.get("skew_s"))
        if variant in ("translated_declared", "basis_undeclared"):
            ok = ok and mine[0]["body"]["operation"] != OPERATION
        return ok, f"B logged {kinds}"
    if variant == "receipt_contradicts_log":
        from .. import receipts
        tok = next((t for t in obs["_wire"].answers
                    if json.loads(receipts._b64d(t.split(".")[1]))["correlation_id"] == cid), None)
        said = _claimed_total(tok)
        logged = sum(eff[0]["body"][f] for f in ("created", "updated", "deleted")) if eff else -1
        return (said == fix["count"] and logged == fix["count"] - fix["k"],
                f"B signed {said}, B's log says {logged}")
    if variant == "receipt_contradicts_state":
        logged = sum(eff[0]["body"][f] for f in ("created", "updated", "deleted")) if eff else -1
        have = b.read_state(REQUESTER, cid)["written"]
        return logged == fix["count"] and have == fix["count"] - fix["k"], \
            f"B's log says {logged}, B's read API {have}"
    if variant == "unbacked_on_b":
        oob = [e for e in obs["b_truth"] if e["correlation_id"] == fix.get("oob_cid")]
        return bool(oob), f"B logged {len(oob)} entries under an id A never used"
    if variant == "unbacked_on_a":
        return not mine and b.store_counts(cid)["written"] == 0, f"B logged {kinds}"
    if variant == "compensating_pair":
        extra = [e for e in obs["b_truth"] if e["correlation_id"] == fix["other_cid"]
                 and e["kind"] == "effect-committed"]
        return (not mine and bool(extra) and extra[0]["body"]["created"]
                + extra[0]["body"]["updated"] == fix["count"]), \
            f"B logged {kinds} for A's request and {len(extra)} effect for the extra id"
    if variant == "join_collision":
        foreign = [e for e in obs["b_record"] if e["peer"] == OTHER_REQUESTER]
        return bool(foreign), f"B's record for A shows {len(foreign)} entries of another requester"
    if variant in ("b_edit_after_ack", "b_delete_after_ack", "seq_reorder"):
        op = {"b_edit_after_ack": "edit", "b_delete_after_ack": "delete",
              "seq_reorder": "swap"}[variant]
        hit = [t for t in obs["tamper"] if t["op"] == op and t["correlation_id"] == cid]
        return bool(hit), f"B's tamper log: {hit}"
    if variant == "void_over_receipt":
        return "void" in kinds and "receipt-issued" in kinds, f"B logged {kinds}"
    if variant == "seq_duplicate":
        return len(eff) == 2, f"B committed {len(eff)} effects"
    if variant == "late_entry":
        return bool(fix.get("released")) and "effect-committed" in kinds, \
            f"B released its late entries: {fix.get('released')}"
    if variant == "declared_void":
        return kinds == ["request-received", "void"], f"B logged {kinds}"
    if variant in TAMPER_A:
        w = fix.get("write")
        if w is None:
            return False, "the target has no operator write path"
        if str(w).startswith("refused"):
            return True, f"the target refused the write: {w}"
        if str(w).startswith("error"):
            return False, f"the operator write did not run: {w}"
        rb = fix.get("read_back") or {}
        return bool(rb.get("landed")), f"operator write {w!r}; {rb.get('detail')}"
    if variant == "torn_write":
        if fix.get("crash") is None:
            return False, "the target has no crash path"
        return bool(fix.get("crashed")), f"crash {fix.get('crash')!r}; crashed {fix.get('crashed')}"
    raise AssertionError(variant)


def _claimed_total(token: Optional[str]) -> int:
    from .. import receipts
    if token is None:
        return -1
    c = json.loads(receipts._b64d(token.split(".")[1]))
    return sum(c["outcome"][f] for f in ("created", "updated", "deleted"))


# --------------------------------------------------------------------------- outcomes


def record_check(variant: str, obs: Dict[str, Any]) -> Check:
    """The kit's reconciler, over the target's export and B's record (design §4.3)."""
    from .. import books
    kit, fix = obs["_kit"], obs["_fix"]
    key = fix.get("key")
    kinds = kit.kinds()
    note = f" (adapter note: {obs['adapter_note']})" if obs.get("adapter_note") else ""
    if variant in HONEST:
        mine = [b for b in kit.breaks if b.key in (key, None)
                or (b.key and b.key[2] == fix.get("cid"))]
        if mine:
            return Check(variant, "export_disagrees", False,
                         f"the kit reports {sorted({b.kind for b in mine})} on an honest "
                         f"difference, from the target's export{note}")
        return Check(variant, "reconcilable", True, f"state {kit.states.get(key)!r}; "
                     f"explained {kit.explained.get(key, [])}{note}")
    if variant == "basis_undeclared":
        st = kit.states.get(key)
        return Check(variant, "found" if st == "no-basis" else "hidden", st == "no-basis",
                     f"the kit reads the action as {st!r}{note}")
    if variant == "torn_write":
        st = fix.get("status_after_restart")
        settling = [e for e in obs["export"] if books.entry_problem(e) is None
                    and books.action_key(e) == key and e["kind"] in ("settlement", "void")]
        if st == "done" and not settling:
            return Check(variant, "torn", False, f"the target reads the action as done after "
                         f"the crash and its record holds no entry that settled it{note}")
        return Check(variant, "intact", True, f"status {st!r}; settling entries "
                     f"{[e['kind'] for e in settling]}{note}")
    if variant in TAMPER_A and str(fix.get("write", "")).startswith("refused"):
        return Check(variant, "prevented", True, f"{fix['write']}{note}")
    mode, want = EXPECT[variant]
    got = want & kinds
    ok = got == want if mode == "all" else bool(got)
    return Check(variant, "found" if ok else "hidden", ok,
                 f"the kit's reconciler reports {sorted(kinds)}; wanted {mode} of "
                 f"{sorted(want)}{note}")


def reconciliation_check(variant: str, obs: Dict[str, Any]) -> Check:
    """The target's own reconciliation (design §4.3)."""
    from .. import books
    name = f"c:{variant}"
    fix = obs["_fix"]
    key = books.key_str(fix["key"]) if fix.get("key") else None
    tb = obs.get("target_breaks") or []
    kinds = {br.get("kind") for br in tb}
    if variant in HONEST:
        if tb and variant == "clock_skew":
            return Check(name, "joined_by_clock", False, f"the target reports {sorted(kinds)} "
                         f"for an action both sides recorded alike, whose clocks differ by "
                         f"{fix.get('skew_s')} s, beyond its stated tolerance (KRK-M31)")
        if tb:
            return Check(name, "false_break", None, f"the target reports {sorted(kinds)} on an "
                         f"honest difference")
        return Check(name, "explained", True, f"no break; state "
                     f"{(obs.get('target_states') or {}).get(key)!r}")
    if variant == "basis_undeclared":
        st = (obs.get("target_states") or {}).get(key)
        ok = st == "no-basis" or "content-differs" in kinds
        return Check(name, "found_flagged" if ok else "missed", ok, f"the target reads the "
                     f"action as {st!r}, breaks {sorted(kinds)}")
    if variant in TAMPER_A:
        mode, want = EXPECT[variant]
        hit = bool(want & kinds)
        return Check(name, "own_check_found" if hit else "own_check_missed", None,
                     f"the target's own reconciliation reports {sorted(kinds)}")
    if variant == "torn_write":
        st = (obs.get("target_states") or {}).get(key)
        rc = record_check(variant, obs)
        if rc.ok is False and st == "matched":
            return Check(name, "matched_while_torn", False, "the target reads the action as "
                         "matched while its own record lacks the settling entry")
        return Check(name, "explained", True, f"state {st!r}")
    mode, want = EXPECT[variant]
    hit = [br for br in tb if br.get("kind") in want]
    found = ({br["kind"] for br in hit} == want) if mode == "all" else bool(hit)
    if not found:
        return Check(name, "missed", False, f"the target reports {sorted(kinds)}; wanted {mode} "
                     f"of {sorted(want)}")
    for br in hit:
        if br.get("state") in ("settled", "explained", "matched") and not books.by_person(
                br.get("settled_by")) and br.get("kind") in books.EFFECT_KINDS:
            return Check(name, "closed_without_person", False, f"{br['kind']} closed by "
                         f"{br.get('settled_by')!r} without a person")
    flags = obs.get("flags") or {}
    silent = [br["ref"] for br in hit if br.get("state") == "break"
              and not (flags.get(br["ref"]) or [False])[0]]
    if silent:
        return Check(name, "found_silent", False, f"found {sorted({br['kind'] for br in hit})} "
                     f"and told nobody")
    st = obs.get("settlement") or {}
    if st.get("lost_entries") or st.get("lost_raw_lines") or st.get("unnamed"):
        return Check(name, "overwrote", False, f"after a person settled it: {len(st.get('lost_entries', []))} "
                     f"original entries gone, {st.get('lost_raw_lines', 0)} raw rows gone, "
                     f"settlement not naming the originals for {st.get('unnamed')}")
    return Check(name, "found_flagged", True, f"found {sorted({br['kind'] for br in hit})}, "
                 f"flagged, settled in a new entry naming both originals")


def effect_check(variant: str, obs: Dict[str, Any]) -> Optional[Check]:
    """Step 8 (KRK-M66): after a person's settlement that names no outcome, is every effect it
    was about still held open, and does it follow the person's outcome once one is given? None
    when no break about an effect named one of the probe's cases."""
    held = obs.get("effect") or {}
    if not held:
        return None
    name = f"e:{variant}"
    unread = {c: h["after_no_outcome"]["unread"] for c, h in held.items()
              if "unread" in h["after_no_outcome"]}
    if unread:
        return Check(name, "effect_unread", None, f"no reading of the effect after the "
                     f"settlement: {sorted(set(unread.values()))[0]}")
    closed = {c: h["after_no_outcome"] for c, h in held.items()
              if h["after_no_outcome"]["effect"] != "open" or h["after_no_outcome"]["closed"]}
    if closed:
        c, r = sorted(closed.items())[0]
        kinds = sorted({b["kind"] for b in held[c]["breaks"]})
        return Check(name, "closed_without_outcome", False,
                     f"after a person settled {kinds} with a decision naming no outcome "
                     f"({NO_OUTCOME!r}), the target reads the effect of {c} as {r['effect']!r}, "
                     f"case closed {r['closed']}: the record settled, read as the effect settled "
                     f"({len(closed)} of {len(held)} case(s))")
    after = {c: h["after_outcome"] for c, h in held.items()}
    no_path = [c for c, h in held.items() if not h["outcome_taken"]]
    if no_path:
        return Check(name, "no_outcome_path", None, f"held open after the no-outcome settlement; "
                     f"the target took no outcome from a person for {no_path[:3]}")
    unread = {c: r["unread"] for c, r in after.items() if "unread" in r}
    if unread:
        return Check(name, "effect_unread", None, f"held open after the no-outcome settlement; "
                     f"no reading after the outcome: {sorted(set(unread.values()))[0]}")
    want = {"executed": "done", "not-executed": "not-done"}
    wrong = {c: (held[c]["outcome"], r["effect"]) for c, r in after.items()
             if r["effect"] != want[held[c]["outcome"]]}
    if wrong:
        c, (o, got) = sorted(wrong.items())[0]
        return Check(name, "outcome_not_followed", False,
                     f"held open after the no-outcome settlement, but after a person gave the "
                     f"outcome {o!r} the target reads the effect of {c} as {got!r}")
    return Check(name, "held_then_followed", True,
                 f"{len(held)} effect(s) held open after a person's {NO_OUTCOME!r}, then read as "
                 f"the person's outcome ({sorted({h['outcome'] for h in held.values()})})")


def _effect_guard(ctl: Dict[str, Any]) -> str:
    """Why the effect checks give no verdict, from the control's readings ("" when they may):
    an honest action read as held open means an open reading proves nothing."""
    opened = [c for c, r in (ctl.get("effect_states") or {}).items() if r.get("effect") == "open"]
    if opened:
        return (f"the target reads {len(opened)} honest action(s) B completed as open, so an open "
                f"effect after a settlement cannot be told from its normal reading")
    return ""


# --------------------------------------------------------------------------- probe


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None) -> Result:
    from .. import books

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    elapse = getattr(a, "elapse", time.sleep)
    deadline = float(getattr(a, "receipt_deadline_s", lambda: 0.0)() or 0)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    bad_na = sorted(v for v in na if v in NA_FORBIDDEN or v not in VARIANTS)
    if bad_na:
        return Result.inconclusive(a.name, ID, f"the adapter declares {bad_na} not applicable; "
                                   f"{list(NA_FORBIDDEN)} may not be, and only P17's variants "
                                   f"can be", **common)
    if any(not isinstance(w, str) or not w.strip() for w in na.values()):
        return Result.inconclusive(a.name, ID, "a variant is declared not applicable without a "
                                   "reason", **common)
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    reconciles = bool(getattr(a, "reconciles", lambda: False)())
    rule = dict(getattr(a, "settlement_rule", lambda: {})() or {}) if reconciles else {}
    claimed = getattr(a, "record_grade", lambda: "not stated")()

    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order, "series": SERIES,
                          "count_range": COUNT_RANGE, "attempts": ATTEMPTS,
                          "receipt_deadline_s": deadline, "margin_s": MARGIN_S,
                          "reconciles": reconciles, "settlement_rule": rule,
                          "record_grade_claimed": claimed, "variants_not_applicable": na,
                          "variant_notes": notes, "not_built": NOT_BUILT})

    def run(variant):
        obs = run_pair(a, ev, variant, rng, run_tag, reconciles=reconciles, rule=rule,
                       deadline=deadline, elapse=elapse)
        if variant in notes:
            obs["adapter_note"] = notes[variant]
        ev.write(f"{variant}.json", {k: v for k, v in obs.items() if not k.startswith("_")})
        return obs

    ctl = run(CONTROL)
    if "error" in ctl:
        return Result.inconclusive(a.name, ID, f"control: {ctl['error']}", **common)
    truth_ok, truth = _control_truth(ctl)
    inst = ctl["_instrument"]
    inst_ok = (set(inst.states.values()) <= {"matched"} and not inst.breaks
               and len(inst.states) == ctl["series"])
    unread = [c for c, s in ctl["statuses"].items() if not isinstance(s, str)]
    if not truth_ok:
        return Result.inconclusive(a.name, ID, f"control: {truth}", **common)
    if not inst_ok:
        return Result.inconclusive(a.name, ID, f"control: the kit's own reconciler does not "
                                   f"match the kit's wire copy with B's log "
                                   f"({inst.to_doc()['breaks'][:3]}); the instrument is broken",
                                   **common)
    if unread:
        return Result.inconclusive(a.name, ID, f"control: no readable status for {unread}",
                                   **common)
    control = (f"{ctl['series']} honest actions: B's store and log hold each, the kit's wire copy "
               f"holds each request and answer, the kit's reconciler matches its wire copy with "
               f"B's log, and the target's export, holdings and status calls returned")

    checks = _control_checks(ctl)
    c_verdict, c_why = True, ""
    if reconciles:
        early = [k for k, s in (ctl.get("states_before_b") or {}).items() if s == "matched"]
        if early:
            c_verdict, c_why = False, (f"the target read {len(early)} action(s) as matched before "
                                       f"B acted (KRK-M30)")
        elif ctl.get("target_breaks"):
            c_verdict, c_why = False, (f"the target reported "
                                       f"{sorted({b.get('kind') for b in ctl['target_breaks']})} "
                                       f"on the honest series")
    extra: Dict[str, Any] = {"seed": seed, "grade_a": ctl["_kit"].grade_a,
                             "grade_b": ctl["_kit"].grade_b, "record_grade_claimed": claimed,
                             "reconciles": reconciles, "series": {CONTROL: ctl["series"]},
                             "not_built": NOT_BUILT}
    if na:
        extra["variants_not_applicable"] = na
    if not c_verdict:
        extra["reconciliation_checks"] = f"no verdict: {c_why}"
    e_why = _effect_guard(ctl) if reconciles else ""
    if e_why:
        extra["effect_checks"] = f"no verdict: {e_why}"
    elif reconciles and getattr(a, "effect_state", None) is None:
        extra["effect_checks"] = ("no verdict: the target reports no effect state "
                                  "(effect_state), so no effect settled without an outcome "
                                  "could be seen")
    for variant in order:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        obs = run(variant)
        extra["series"][variant] = obs.get("series")
        if "error" in obs:
            checks.append(Check(variant, "not_driven", None, obs["error"]))
            continue
        ok, why = landed(variant, obs)
        if not ok:
            checks.append(Check(variant, "fixture_not_landed", None, why))
            continue
        checks.append(record_check(variant, obs))
        if not reconciles:
            continue
        if not c_verdict:
            checks.append(Check(f"c:{variant}", "no_verdict", None, c_why))
            continue
        checks.append(reconciliation_check(variant, obs))
        e = effect_check(variant, obs)
        if e is not None:
            checks.append(Check(e.name, "no_verdict", None, e_why) if e_why else e)
    if reconciles:
        passed = "every planted difference was found from the two records, and by the target"
        if extra.get("effect_checks"):
            passed += f" (effect after settlement: {extra['effect_checks']})"
        failed = "a difference between the two records was not found, or not handled"
    else:
        passed = ("every planted difference was found from the two records (records "
                  "reconcilable; target does not reconcile)")
        failed = ("a difference could not be found from the two records (the target does not "
                  "reconcile; only the record checks ran)")
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary=passed, fail_summary=failed, extra=extra, **common)


def _control_truth(ctl: Dict[str, Any]) -> Tuple[bool, str]:
    b = ctl["_b"]
    for case_id, env, exp in ctl["_cases"]:
        got = b.store_counts(env["correlation_id"])["written"]
        if got != exp.count:
            return False, f"B's store shows {got} of {exp.count} items for {env['correlation_id']}"
        if not any(e["kind"] == "request-received" and e["correlation_id"] == env["correlation_id"]
                   for e in ctl["b_record"]):
            return False, f"B's log holds no entry for {env['correlation_id']}"
    if len(ctl["_wire"].answers) < ctl["series"]:
        return False, "the wire holds fewer answers than requests"
    return True, ""


def _control_checks(ctl: Dict[str, Any]) -> List[Check]:
    """The record checks the control series answers: join (R1), complete (R2), order (R3)."""
    from .. import books, receipts
    kit, export = ctl["_kit"], ctl["export"]
    keys = {(REQUESTER, ctl["peer"], env["correlation_id"], receipts.request_digest(env))
            for _, env, _ in ctl["_cases"]}
    states = {k: kit.states.get(k) for k in keys}
    bad = {books.key_str(k): s for k, s in states.items() if s not in ("matched", "explained")}
    if bad or kit.breaks:
        join = Check("join", "unjoined", False, f"the kit cannot join the target's export with "
                     f"B's record: states {bad}, breaks "
                     f"{[b.to_doc()['kind'] for b in kit.breaks]}")
    else:
        join = Check("join", "joined", True, f"every action of the series joins on the full key "
                     f"and matches")
    shas = {receipts.sha256_ref(t.encode()) for t in ctl["_wire"].answers}
    raws = {e.get("raw_sha256") for e in export if e.get("kind") == "receipt-received"}
    held = {receipts.sha256_ref(h["token"].encode()) for h in ctl["holdings"]
            if h.get("type") == "receipt" and isinstance(h.get("token"), str)}
    reqs = {(e.get("correlation_id"), e.get("request_digest")) for e in export
            if e.get("kind") == "request-sent"}
    missing_req = [env["correlation_id"] for _, env, _ in ctl["_cases"]
                   if (env["correlation_id"], receipts.request_digest(env)) not in reqs]
    missing_ans = sorted(shas - raws)
    missing_held = sorted(shas - held)
    if missing_req or missing_ans or missing_held:
        complete = Check("complete", "export_disagrees", False,
                         f"the export lacks requests {missing_req}, answers {missing_ans[:3]}; "
                         f"the target does not hold {len(missing_held)} answer(s) it received")
    else:
        complete = Check("complete", "complete", True, "every request and every distinct answer "
                         "on the wire is in the export, and the raw answers are held")
    br, fi = books.chain_breaks([e for e in export if books.entry_problem(e) is None])
    if fi or br:
        order = Check("order", "unordered", False, f"the target's entries for this peer cannot "
                      f"be ordered or checked for removal: {[f.detail for f in fi][:2]} "
                      f"{[b.kind for b in br][:4]}")
    else:
        order = Check("order", "ordered", True, "numbered per peer with no gap and chained")
    return [join, complete, order]
