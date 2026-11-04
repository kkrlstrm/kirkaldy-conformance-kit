"""P16 — Effect receipt (KRK-16).

**Guarantee.** A product (target A) records an approved action that changes another
organisation's system (the counterparty, B) as done only on a statement B signed with a key A
pinned, that names this exact request, and that reports the effect A recorded as expected when
the action was approved. Anything less leaves the action not done: blocked, refused, not
executed, or still awaiting a receipt. An executor's own report of success never completes an
effect. And when B signs that it has no record of a request the executor says it sent, A does not
close the attempt on its own: the two sides disagree, and a person decides.

**Question.** When B's receipt is about a different request, unsigned, signed by a key A never
pinned, reports a different effect from the one expected, reports a partial effect, is missing,
is replaced by the executor's own report, is a signed refusal, or is a signed "no record of this
request", does A still record the action as done? And does A close a signed no-record that the
executor disputes without a person?

This tests A's handling of B's receipt. It does not test B's honesty: a receipt that B genuinely
signed but that contradicts B's own store is X8's reconciliation, not this property.

**Probe.** The kit plays B (`conformance/counterparty.py::StubCounterparty`): a SQLite store, a
real Ed25519 key, and receipts built by B for what it wrote. Every negative receipt is one B
genuinely signed over wrong content, or one B left unsigned; signed bytes are never altered.

1. Take the run's seed (`--seed`, or one drawn by the runner; recorded in the evidence and the
   result), derive the agreement's item salt from it, and generate B's receipt key from the
   operating system's secure source, never from the seed (see `UNSEEDED`). Pin B's public key
   in A (`pin_counterparty_key`).
2. Control: on a fresh envelope with a random item count, `submit` it to A (A records the
   expected effect with the decision), have B `execute` it honestly, `deliver` B's answer to A
   `ATTEMPTS` times, let A's own receipt deadline pass (`receipt_deadline_s()` plus `MARGIN_S`),
   and read `status` and `evidence_grade` again.
3. For each variant, in an order shuffled by the seeded RNG, repeat step 2 on a fresh envelope,
   a fresh correlation id, a fresh count and a fresh B store, with B executing that variant.
4. Check the fixture landed before reading A: B's store changed by what the variant declares
   (nothing for `signed_refusal`, `signed_no_record` and `disputed_no_record`, the full count less
   the dropped items for `count_mismatch` and
   `honest_partial`), and the kit's own judgement (`receipts.judge`) rejects B's answer for the
   reason the variant declares. A fixture that did not land is recorded as information.
5. Compare A's reads with the judgement. A's status is also read once after `submit` and
   before B executes: a target (or adapter) that reads as done before anything ran cannot show
   what a receipt did, so on the control that makes the result inconclusive.

**Control** (KRK-M19). The control proves only that the probe reached the
real path; it does not require the guarantee under test. On `honest`, B's `store_counts` must
show the full write (exactly the expected count for that correlation id), the judgement must
accept B's receipt, A must not read `done` before B executes (KRK-M18), and A's final read must
be `done`, at any grade. The grade is recorded. Without all of these the result is
inconclusive: a target that never completes anything, or a probe whose B never writes, would
otherwise pass every variant.

Verifying B's receipt is the guarantee, so it is judged as a check, not as part of the control:
the `honest` check passes only when A ended `done` at grade `signed-by-B`. Any other grade is
the outcome `completed-without-verified-receipt` (fail): A completed the action without a
verified receipt, which is what a target with no receipt path does. Requiring `signed-by-B` in
the control made such a target inconclusive, when the evidence showed it fails.

**Variants** (`counterparty.VARIANTS`, all but `honest`): `wrong_request`, `unsigned`,
`unpinned_key`, `count_mismatch`, `honest_partial`, `missing`, `agent_report`,
`signed_refusal`, and `signed_no_record` (B signs a permanent no-record; the
executor reports it could not confirm the send, `"sent": false`), `disputed_no_record` (the
same receipt; the executor reports success) and `sibling_request`.

`wrong_request` and `sibling_request` both answer with B's genuine receipt for another request
with the same items and expectation. In `wrong_request` that request is one A never made. In
`sibling_request` it is one of A's own earlier requests: before the case under test, A submits
that earlier request and sends it (`deliver` with no answer), and B executes it honestly. B then
executes the current request in full and answers it with the receipt it issued for the earlier
one, replayed exactly as signed. The earlier receipt is not delivered to the earlier case first,
so a target that refuses only a receipt it has already used is not credited with checking the
binding. The fixture lands when B's store shows the current request written in full, the
judgement rejects the receipt for this request as `wrong-request`, and the judgement accepts the
same receipt for the earlier request. After the reads the receipt is delivered to the earlier
case and that reading is recorded beside the variant, for the record only. Completing the
current request on it is the outcome `done` (fail), as for every variant: A recorded an effect as
done on a receipt that names another request. A target that checks only whether a receipt names
a request it knows passes `wrong_request` and fails here (KRK-M20).

**Outside targets.** Two optional adapter hooks let P16 drive a product that
takes receipts in another format, without the probe counting the format gap as a result:

- `receipt_profile()` names a wire profile (`counterparty.PROFILES`). B then adds the members
  that format requires to the claims it signs, derived from the same log entry; B's key, the
  kit's claims and the kit's judgement are unchanged. Without it, a target that cannot parse B's
  claims rejects every receipt as malformed, and every variant reads as not done for that reason
  alone (KRK-M10, refused for the wrong reason).
- `variants_not_applicable()` maps a variant to the reason the product has no such statement or
  workflow (a receipt format with no counts has nothing for `count_mismatch` to vary). The
  variant is not driven and is recorded as `not_applicable` (information). The reason must cite
  the product. It may not be declared for `NA_FORBIDDEN`: the control, and the variants about
  whether A verifies B's signature, B's key, the request a receipt answers (both
  `wrong_request` and `sibling_request`), and the absence of a receipt. Every target that takes a receipt has those questions, and letting an adapter wave one
  away would let it hide a fail; declaring one gives no verdict.

**What reached the target.** A fixture that landed for the kit can still fail
to reach the target as the variant says. Two checks run after the kit's own (step 4), and either
makes the variant `fixture_not_landed` (information):

- under a wire profile, B records each receipt whose verdict the target's format cannot express
  (`StubCounterparty.format_gaps`); the target would reject it as unreadable, which is not a
  rejection of what it says (KRK-M21);
- an adapter that re-encodes B's answer reports, per delivery, what the product received
  (`delivered`), and the probe compares that with what B sent: whether there was a receipt, its
  verdict, how it was signed and the request it names (KRK-M23, KRK-M25). A mismatch on the
  control gives no verdict.

An adapter may also attach a note to a variant that is driven and counted (`variant_notes`); the
evidence and the check's detail carry it, and it changes no outcome (KRK-M24). A status of
`unverified` (`NOTHING_DECIDED`) means no deterministic code of the product decided anything on
B's answer; it is the outcome `nothing_decided` (information), never a hold (KRK-M22).

**Known-bad fixtures** (`known_bad/receipts_toys.py`). A correct target that must pass; nine
targets that each skip one check and must fail on the variant that exposes it (accepts any
request digest, accepts any request it knows (`sibling_request` only), accepts unsigned, accepts
any key, ignores counts, counts a partial effect as done, completes on no receipt after a
timeout, completes on the executor's report, counts a refusal as done); a tenth that completes on the executor's word and reads no receipt at all,
which must fail on the control's grade and on every variant; two for the no-record verdict
(counts a signed no-record as done; closes a disputed no-record as not executed without a
person); and one target whose control cannot hold, which must give no verdict.

**Outcome of the control.**
- `done_signed_by_B` (pass): A ended `done` at grade `signed-by-B`.
- `completed-without-verified-receipt` (fail): A ended `done` at another grade, or none.

**Outcomes per variant.**
- `not_done` (pass): A did not record the action as done, and its status is one the judgement
  allows (`ALLOWED`).
- `not_done_other_label` (information): A did not record it as done but gave another status
  (recorded verbatim). Safe, but not what the judgement says, so not counted either way.
- `done` (fail): A recorded the action as done on that answer, at any read.
- `closed-without-person` (fail): on `disputed_no_record`, A read
  `not-executed` or `refused` at any read. B and the executor disagree about whether the request
  was sent; closing the attempt settles that dispute without a person.
- `fixture_not_landed` (information): B's store or the judgement does not show the variant, or
  the target did not receive it as the variant says (above).
- `nothing_decided` (information): A's status is `unverified`; no deterministic
  code of the product decided on the answer.
- `not_applicable` (information): the adapter declared that the product has no
  such statement or workflow (`variants_not_applicable`); the variant was not driven.

The result is `fail` if the control ended `done` at a grade other than `signed-by-B`, if any
variant other than the control ends `done`, or if a disputed no-record is closed without a
person. It is `pass` only if the control ended `done` /
`signed-by-B` and every variant that landed ends not done with an allowed status. It is
inconclusive when the control does not hold, or when the control's grade is `signed-by-B` and no
variant landed with a countable reading.

**Measurement errors guarded** (`docs/FAILURE-MODES.md`).
- KRK-M1 One attempt: B's answer is delivered `ATTEMPTS` times, as a counterparty retrying
  delivery would, and status is read after each delivery. A `deliver` that raises is recorded
  (a product may reject a receipt that way) and the status is still read.
- KRK-M2 The late release: status is read after delivery, again after the deadline, and once
  more after another margin; `done` at any read counts as done.
- KRK-M3 The failure never induced: step 4 checks B's store and the judgement's reason before
  A's reading counts.
- KRK-M4 No path, counted as blocked: the control proves the same path completes the honest
  case, so a refusal elsewhere is not the absence of a path.
- KRK-M5, M6, M7, M14: not exposed (no secret search, no per-wait resource counting).
- KRK-M8 A clock read as identity: variants run in a seeded shuffled order.
- KRK-M9 A mock unlike the real thing: B has a real store and real Ed25519 signatures, and its
  receipts report what it wrote.
- KRK-M10 Refused for the wrong reason: each variant differs from the honest one in the one
  respect the judgement names, and the control shows A completes the honest one on the same path.
  Counts are drawn at random per run, so a target cannot pass by special-casing a number.
- KRK-M11 Late, counted as lost: A's own receipt deadline plus `MARGIN_S` is waited out before
  the final read, so a target that completes on a timeout is caught and one that is merely slow
  is not judged early.
- KRK-M12 A record read without its serializer: `status` and `evidence_grade` must be read from
  the product's own record, through its own decoding (the adapter docstring says so).
- KRK-M13 Wrong entry point: `submit` and `deliver` must be the paths the product documents for
  recording an expected effect and receiving a counterparty's answer.
- KRK-M15 Same-second: not exposed; no check here compares timestamps.
- KRK-M16 The baseline's own request: every variant has its own correlation id and its own B
  store, so the control's effect cannot be counted as a variant's.
- KRK-M17 A "still running" stub read as success: `awaiting-receipt` is a status of its own, and
  only `done` counts as done.
- KRK-M18 The expectation, read as the effect: step 5's read before B executes. A control that
  already reads `done` there gives no verdict.
- KRK-M19 A control that demands the guarantee: the control requires `done` at any grade, and
  the grade is judged as the `honest` check. A target that completes on the executor's report
  fails instead of giving no verdict.
- KRK-M20 The stranger sibling: `sibling_request` replays B's receipt for one of A's own earlier
  requests, so a membership check cannot pass it.
- KRK-M21 Passed by a format gap: a receipt whose verdict the target's format cannot express is
  recorded as not landed, not as the target's rejection.
- KRK-M22 The model's step, read as the product's hold: `unverified` is never an allowed status.
- KRK-M23 Landed before translation, not after: `delivered` is compared with what B sent.
- KRK-M24 The adapter's application, graded as the product: `variants_not_applicable` for
  checks only the adapter's application could answer, and `variant_notes` where such a check
  may not be declared away.
- KRK-M25 The format translator as a hidden verifier: the same comparison catches a translator
  that drops, re-signs or re-binds what it was given.
"""
from __future__ import annotations

import os
import random
import time
from typing import Any, Dict, List, Optional, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P16"
TITLE = "Effect receipt"

FIXTURES = ("known_bad/receipts_toys.py", "tests/test_p16_effect_receipt.py",
            "tests/vectors/krk16/*.json")
"""The known-bad fixtures, their required outcomes and the receipt vectors, hashed into the
result's `fixture_version` (`conformance.versions`). The stub B that builds each variant's
receipt is `counterparty.py`, which the probe imports, so it is hashed into `probe_version`."""
ENVIRONMENT = ("python", "package:cryptography")
"""Environment fields a change of which voids a P16 verdict: B signs, and the kit's judgement
verifies, with `cryptography`'s Ed25519; in-process targets run on the kit's interpreter."""
UNSEEDED = (
    "B's receipt signing keys (the pinned key, and the second key for unpinned_key) come from "
    "the operating system's secure source (Ed25519PrivateKey.generate), not from the seed. The "
    "seed is written into result.json; a key derived from it would let anyone holding the result "
    "sign receipts as B. So receipt signatures differ between runs with the same seed.",
    "Receipt times (executed_at, iat) are read from the clock.",
    "Correlation ids carry the run id (run_tag) before their seeded part, so two runs never send "
    "a target the same request id; the seeded part repeats.",
)

ATTEMPTS = 2
MARGIN_S = 2.0
COUNT_RANGE = (50, 400)

OPERATION = "crm.record.push"
COUNTERPARTY = "did:web:b.example"
CONTAINER = "people"
VERBS = ("upsert",)
B_KID = "b-receipts-p16"

CONTROL = "honest"
SIGNED = "signed-by-B"
UNVERIFIED = "completed-without-verified-receipt"
VARIANTS = ("wrong_request", "unsigned", "unpinned_key", "count_mismatch", "honest_partial",
            "missing", "agent_report", "signed_refusal", "signed_no_record",
            "disputed_no_record", "sibling_request")
SIBLING = "sibling_request"
"""The variant whose receipt is B's genuine one for A's own earlier request (KRK-M20)."""
NA_FORBIDDEN = (CONTROL, "wrong_request", "unsigned", "unpinned_key", "missing", SIBLING)
"""Variants an adapter may not declare not applicable (module docstring, "Outside targets")."""
NOTHING_DECIDED = "unverified"
"""The status an adapter reports when no deterministic code of the product decided anything on
B's answer (completion is left to a model step or the caller). Never counted as a hold (KRK-M22)."""
CLOSED_WITHOUT_PERSON = "closed-without-person"
CLOSING = ("not-executed", "refused")
"""Statuses that close an attempt as not executed. On a disputed no-record they are a fail."""

# What the judgement's reason must be for each variant's fixture to count as landed.
LANDED_REASON = {"wrong_request": "wrong-request", "unsigned": "unsigned",
                 "unpinned_key": "unpinned-key", "count_mismatch": "count-mismatch",
                 "honest_partial": "partial", "missing": "no-receipt",
                 "agent_report": "executor-report-only", "signed_refusal": "refused",
                 "signed_no_record": "no-record", "disputed_no_record": "no-record-disputed",
                 SIBLING: "wrong-request"}

# Non-done statuses that agree with each judgement status. A target that reports a missing
# receipt as blocked (and so in front of a person) has not done anything wrong.
ALLOWED = {"refused": ("refused",), "blocked": ("blocked",),
           "awaiting-receipt": ("awaiting-receipt", "blocked"),
           # A target that hands a signed no-record to a person instead of closing it has done
           # nothing wrong either.
           "not-executed": ("not-executed", "blocked")}


class Adapter(Protocol):
    name: str
    config: str

    def pin_counterparty_key(self, kid: str, public_key: bytes) -> None:
        """Pin B's receipt key (raw Ed25519 public bytes) in the target, in whatever form the
        product takes a counterparty's key."""
        ...

    def submit(self, envelope: Dict[str, Any], expected: Any) -> str:
        """Hold and approve an action whose request is `envelope`, recording `expected` (a
        `receipts.ExpectedEffect`) with the decision, through the product's own path. Returns
        the product's case id."""
        ...

    def deliver(self, case_id: str, receipt: Optional[str],
                executor_report: Optional[Dict[str, Any]]) -> None:
        """Hand B's answer (a compact JWS, or None) and the executor's own report (or None) to
        the product, by the path it documents for receiving them."""
        ...

    def status(self, case_id: str) -> str:
        """The product's own record of the action: "done", "refused", "awaiting-receipt",
        "blocked", or anything else (recorded verbatim). Read through its own serializer."""
        ...

    def evidence_grade(self, case_id: str) -> Optional[str]:
        """The evidence grade the product recorded for completion ("signed-by-B",
        "B-record-read-back", "person", "executor-report"), or None."""
        ...

    def receipt_deadline_s(self) -> float:
        """Optional. How long the product waits for a receipt before it treats it as missing.
        Defaults to 0."""
        ...

    def elapse(self, seconds: float) -> None:
        """Optional. Let `seconds` pass for the target. Defaults to sleeping."""
        ...

    def receipt_profile(self) -> Optional[str]:
        """Optional. The wire profile B signs in (`counterparty.PROFILES`), for a product that
        reads another receipt format. Defaults to None: the kit's format alone."""
        ...

    def variants_not_applicable(self) -> Dict[str, str]:
        """Optional. Variant -> why the product has no such statement or workflow, citing the
        product. Never one of `NA_FORBIDDEN`. Defaults to none."""
        ...

    def variant_notes(self) -> Dict[str, str]:
        """Optional. Variant -> a note the evidence carries beside a variant that is driven and
        counted, such as why its reading describes the adapter's application rather than the
        product (KRK-M24). A note never changes an outcome."""
        ...

    def delivered(self, case_id: str) -> List[Dict[str, Any]]:
        """Optional, and required of an adapter that re-encodes B's answer before the product
        sees it. One entry per `deliver` call, in order, saying in the kit's terms what the
        product actually received: ``receipt`` (bool), and when it is true ``verdict``,
        ``signed_as`` ("pinned-key", "other-key" or "unsigned") and ``request_digest``, the
        request the receipt names. The probe compares each entry with what B sent; a mismatch
        means the fixture did not land in the target (KRK-M23, KRK-M25)."""
        ...


assert not any(NOTHING_DECIDED in v for v in ALLOWED.values()), "KRK-M22"


def sent_as(token: Optional[str], pinned: Dict[str, bytes]) -> Dict[str, Any]:
    """What B's answer is, in the terms `Adapter.delivered` reports: read from the token without
    verifying it (the probe already knows what B signed; this only names it)."""
    import base64
    import json
    if token is None:
        return {"receipt": False}
    try:
        h, p, sig = token.split(".")
        dec = lambda seg: json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        header, claims = dec(h), dec(p)
    except Exception:
        return {"receipt": True, "verdict": None, "signed_as": None, "request_digest": None}
    alg = str(header.get("alg", "")).lower()
    signed_as = ("unsigned" if alg == "none" or not sig else
                 "pinned-key" if header.get("kid") in pinned else "other-key")
    return {"receipt": True, "verdict": claims.get("verdict"), "signed_as": signed_as,
            "request_digest": claims.get("request_digest")}


def translation_gap(sent: Dict[str, Any], got: List[Any]) -> Optional[str]:
    """Why what the product received is not what B sent, or None if every delivery matches."""
    if not isinstance(got, list) or len(got) != ATTEMPTS:
        return f"the adapter reported {got!r} for {ATTEMPTS} deliveries"
    for i, entry in enumerate(got, 1):
        if not isinstance(entry, dict):
            return f"delivery {i}: the adapter reported {entry!r}"
        diff = {k: (v, entry.get(k)) for k, v in sent.items() if entry.get(k) != v}
        if diff:
            return "; ".join(f"delivery {i}: B sent {k}={v!r}, the target received {g!r}"
                             for k, (v, g) in diff.items())
    return None


def draw_items(rng: random.Random, n: int) -> List[str]:
    """n distinct item keys. They travel in the request envelope only; receipts carry their
    salted hashes and counts."""
    keys: set = set()
    while len(keys) < n:
        keys.add(f"person-{rng.getrandbits(48):012x}@example.test")
    return sorted(keys)


def build_case(receipts, rng: random.Random, salt: bytes, variant: str,
               run_tag: str) -> Tuple[Dict[str, Any], Any]:
    """A fresh envelope and its expected effect, with a count drawn from `rng`."""
    n = rng.randint(*COUNT_RANGE)
    items = draw_items(rng, n)
    expected = receipts.ExpectedEffect(operation=OPERATION, counterparty=COUNTERPARTY,
                                       container=CONTAINER, verbs=VERBS, count=n,
                                       items_digest=receipts.items_digest(salt, items))
    envelope = {"schema": "kirkaldy.effect-request/0.1",
                "correlation_id": f"p16-{variant}-{run_tag}-{rng.getrandbits(64):016x}",
                "batch": 0, "operation": OPERATION, "requester": "did:web:a.example",
                "counterparty": COUNTERPARTY, "container": CONTAINER, "items": items,
                "expected_effect_digest": expected.digest()}
    return envelope, expected


def _expected_store(variant: str, expected: Any, counts: Dict[str, Any]) -> Tuple[bool, str]:
    """Did B's store change by what the variant declares?"""
    written = int(counts.get("written", -1))
    if variant in ("signed_refusal", "signed_no_record", "disputed_no_record"):
        return written == 0, f"B wrote {written} items (expected none)"
    if variant in ("count_mismatch", "honest_partial"):
        return 0 <= written < expected.count, (f"B wrote {written} of {expected.count} items "
                                               f"(expected fewer)")
    return written == expected.count, f"B wrote {written} of {expected.count} items"


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None) -> Result:
    from .. import counterparty, receipts         # needs `cryptography`; only P16 loads it

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    elapse = getattr(a, "elapse", time.sleep)
    deadline = float(getattr(a, "receipt_deadline_s", lambda: 0.0)() or 0)

    profile = getattr(a, "receipt_profile", lambda: None)()
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    bad_na = sorted(v for v in na if v in NA_FORBIDDEN or v not in VARIANTS)
    if bad_na:
        return Result.inconclusive(a.name, ID, f"the adapter declares {bad_na} not applicable; "
                                   f"{list(NA_FORBIDDEN)} may not be, and only P16's variants "
                                   f"can be", **common)
    if any(not isinstance(why, str) or not why.strip() for why in na.values()):
        return Result.inconclusive(a.name, ID, "a variant is declared not applicable without a "
                                   "reason", **common)
    if profile is not None and profile not in counterparty.PROFILES:
        return Result.inconclusive(a.name, ID, f"unknown wire profile {profile!r}", **common)
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    if any(v not in VARIANTS + (CONTROL,) for v in notes):
        return Result.inconclusive(a.name, ID, f"the adapter notes unknown variants "
                                   f"{sorted(set(notes) - set(VARIANTS + (CONTROL,)))}", **common)
    delivered = getattr(a, "delivered", None)

    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    salt = rng.getrandbits(128).to_bytes(16, "big")
    key = receipts.Keypair.generate(B_KID)
    order = list(VARIANTS)
    rng.shuffle(order)
    ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order,
                          "count_range": COUNT_RANGE, "attempts": ATTEMPTS,
                          "receipt_deadline_s": deadline, "margin_s": MARGIN_S,
                          "salt_sha256": receipts.sha256_ref(salt),
                          "receipt_profile": profile, "variants_not_applicable": na,
                          "variant_notes": notes,
                          "delivered_reported": delivered is not None})

    kid, pub = key.kid, key.public_bytes()
    pinned = {kid: pub}
    try:
        a.pin_counterparty_key(kid, pub)
    except Exception as e:  # the target could not take the key
        return Result.inconclusive(a.name, ID, f"pinning B's key raised {type(e).__name__}: {e}",
                                   **common)

    def run_one(variant: str) -> Dict[str, Any]:
        envelope, expected = build_case(receipts, rng, salt, variant, run_tag)
        b = counterparty.StubCounterparty(str(ev.dir / f"b-{variant}.sqlite"), key, salt,
                                          counterparty_id=COUNTERPARTY, profile=profile)
        obs: Dict[str, Any] = {"variant": variant, "count": expected.count,
                               "correlation_id": envelope["correlation_id"],
                               "request_digest": receipts.request_digest(envelope),
                               "expected_effect": expected.digest()}
        earlier: Optional[Dict[str, Any]] = None
        if variant == SIBLING:
            # One of A's own earlier requests: same items and expectation, its own correlation
            # id. A submits it and sends it (deliver with no answer yet: B's answer to it has not
            # reached A). B's receipt for it is not delivered to it before this case, so a target
            # that refuses only a receipt it has already used gets no credit for the binding.
            earlier = dict(envelope, correlation_id=(f"{envelope['correlation_id']}/earlier-"
                                                     f"{rng.getrandbits(32):08x}"))
            obs["earlier"] = {"correlation_id": earlier["correlation_id"],
                              "request_digest": receipts.request_digest(earlier)}
            try:
                earlier_case = a.submit(earlier, expected)
                a.deliver(earlier_case, None, None)
                obs["earlier"].update(case_id=earlier_case,
                                      status_after_send=a.status(earlier_case))
            except Exception as e:
                obs["error"] = f"the earlier request: {type(e).__name__}: {e}"
                return obs
        try:
            case_id = a.submit(envelope, expected)
        except Exception as e:
            obs["error"] = f"submit raised {type(e).__name__}: {e}"
            return obs
        try:
            obs["status_before_execution"] = a.status(case_id)
        except Exception as e:
            obs["error"] = f"status raised {type(e).__name__}: {e}"
            return obs
        token, report = b.execute(envelope, expected, variant, rng=rng, earlier=earlier)
        j = receipts.judge(token, pinned=pinned, envelope=envelope, expected=expected,
                           executor_report=report)
        reads: List[Tuple[str, Optional[str]]] = []
        raised: List[str] = []
        try:
            for _ in range(ATTEMPTS):
                try:
                    a.deliver(case_id, token, report)
                except Exception as e:  # a product may reject a bad receipt by raising
                    raised.append(f"{type(e).__name__}: {e}")
                reads.append((a.status(case_id), a.evidence_grade(case_id)))
            elapse(deadline + MARGIN_S)
            reads.append((a.status(case_id), a.evidence_grade(case_id)))
            elapse(MARGIN_S)
            reads.append((a.status(case_id), a.evidence_grade(case_id)))
        except Exception as e:
            obs["error"] = f"reading the target's status raised {type(e).__name__}: {e}"
        if earlier is not None and "error" not in obs:
            # The kit's view: the replayed receipt is a genuine, matching receipt for the earlier
            # request. Then, for the record only, the target's reading of it on that request.
            j0 = receipts.judge(token, pinned=pinned, envelope=earlier, expected=expected,
                                executor_report=None)
            obs["earlier"]["judgement"] = {"accept": j0.accept, "status": j0.status,
                                           "reason": j0.reason}
            obs["earlier"]["store_counts"] = b.store_counts(earlier["correlation_id"])
            try:
                a.deliver(obs["earlier"]["case_id"], token, None)
                obs["earlier"]["after_its_receipt"] = {
                    "status": a.status(obs["earlier"]["case_id"]),
                    "grade": a.evidence_grade(obs["earlier"]["case_id"])}
            except Exception as e:
                obs["earlier"]["after_its_receipt"] = {"raised": f"{type(e).__name__}: {e}"}
        if delivered is not None and "error" not in obs:
            try:
                got = delivered(case_id)
            except Exception as e:
                got = f"delivered() raised {type(e).__name__}: {e}"
            obs["delivered"] = got
            obs["translation_gap"] = translation_gap(sent_as(token, pinned), got)
        if token is not None and b.format_gaps:
            obs["format_gaps"] = list(b.format_gaps)
        if variant in notes:
            obs["adapter_note"] = notes[variant]
        obs.update({"case_id": case_id, "receipt": token, "executor_report": report,
                    "deliver_raised": raised,
                    "store_counts": b.store_counts(envelope["correlation_id"]),
                    "judgement": {"accept": j.accept, "status": j.status, "grade": j.grade,
                                  "reason": j.reason},
                    "reads": [{"status": s, "grade": g} for s, g in reads],
                    "_expected": expected})
        return obs

    def record(obs: Dict[str, Any]) -> None:
        ev.write(f"{obs['variant']}.json", {k: v for k, v in obs.items() if k != "_expected"})

    ctl = run_one(CONTROL)
    record(ctl)
    if "error" in ctl:
        return Result.inconclusive(a.name, ID, f"control: {ctl['error']}", **common)
    final = ctl["reads"][-1] if ctl["reads"] else {"status": None, "grade": None}
    landed, store_said = _expected_store(CONTROL, ctl["_expected"], ctl["store_counts"])
    if ctl["status_before_execution"] == "done":
        return Result.inconclusive(a.name, ID, "the target reads as done before B executed "
                                   "anything, so its status cannot show what a receipt did",
                                   **common)
    # The control proves the real path was exercised: B wrote everything, the judgement accepts
    # B's receipt, and A completed the action. It must not demand the grade, because verifying
    # B's receipt is the guarantee under test (KRK-M19); the grade is judged as a check below.
    if ctl.get("translation_gap"):
        return Result.inconclusive(a.name, ID, f"control: the target did not receive what B sent "
                                   f"({ctl['translation_gap']})", **common)
    held = landed and ctl["judgement"]["accept"] and final["status"] == "done"
    if not held:
        return Result.inconclusive(
            a.name, ID, f"an honest signed receipt did not complete the action (final status "
            f"{final['status']!r}, grade {final['grade']!r}; {store_said}; judgement "
            f"{ctl['judgement']['status']}/{ctl['judgement']['reason']})", **common)
    control = (f"honest receipt for {ctl['count']} items: B's store shows them written, the kit's "
               f"judgement accepts it, and the target records done (grade {final['grade']!r})")

    trail = " -> ".join(str(r["status"]) for r in ctl["reads"])
    if final["grade"] == SIGNED:
        checks: List[Check] = [Check(CONTROL, "done_signed_by_B", True,
                                     f"reads {trail}; final grade {SIGNED}")]
    else:
        checks = [Check(CONTROL, UNVERIFIED, False,
                        f"recorded done at grade {final['grade']!r}, not {SIGNED}: the target "
                        f"completed the action without verifying B's receipt; reads {trail}; "
                        f"{store_said}")]
    extra: Dict[str, Any] = {"seed": seed, "counts": {CONTROL: ctl["count"]},
                             "control_grade": final["grade"]}
    if profile is not None:
        extra["receipt_profile"] = profile
    if na:
        extra["variants_not_applicable"] = na
    for variant in order:
        if variant in na:
            ev.write(f"{variant}.json", {"variant": variant, "not_applicable": na[variant]})
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        obs = run_one(variant)
        record(obs)
        extra["counts"][variant] = obs["count"]
        if "error" in obs:
            checks.append(Check(variant, "not_driven", None, obs["error"]))
            continue
        jd = obs["judgement"]
        landed, store_said = _expected_store(variant, obs["_expected"], obs["store_counts"])
        note = f" (adapter note: {obs['adapter_note']})" if obs.get("adapter_note") else ""
        if not landed or jd["accept"] or jd["reason"] != LANDED_REASON[variant]:
            checks.append(Check(variant, "fixture_not_landed", None,
                                f"{store_said}; judgement {jd['status']}/{jd['reason']}, "
                                f"declared {LANDED_REASON[variant]}{note}"))
            continue
        if variant == SIBLING and not (obs.get("earlier", {}).get("judgement") or {}).get("accept"):
            checks.append(Check(variant, "fixture_not_landed", None,
                                f"the replayed receipt is not a matching receipt for A's earlier "
                                f"request ({obs.get('earlier')}){note}"))
            continue
        # Landed for the kit. Did it land in the target? (KRK-M21, M23, M25)
        if obs.get("format_gaps"):
            gap = obs["format_gaps"][0]
            checks.append(Check(variant, "fixture_not_landed", None,
                                f"B's {gap['verdict']!r} receipt has no form in the target's "
                                f"format ({gap['profile']}), so the target could not read what "
                                f"it says; a rejection would be the format's, not the "
                                f"target's{note}"))
            continue
        if obs.get("translation_gap"):
            checks.append(Check(variant, "fixture_not_landed", None,
                                f"landed for the kit, not in the target: "
                                f"{obs['translation_gap']}{note}"))
            continue
        statuses = [r["status"] for r in obs["reads"]]
        last = obs["reads"][-1]
        trail = " -> ".join(str(s) for s in statuses)
        if "done" in statuses:
            at = statuses.index("done")
            grade = obs["reads"][at]["grade"]
            what = (f"on B's receipt for A's own earlier request "
                    f"{obs['earlier']['correlation_id']!r}; " if variant == SIBLING else "")
            checks.append(Check(variant, "done", False,
                                f"recorded done (grade {grade!r}) at read {at + 1} {what}reads "
                                f"{trail}; judgement {jd['status']}/{jd['reason']}; "
                                f"{store_said}{note}"))
        elif jd["reason"] == "no-record-disputed" and any(st in CLOSING for st in statuses):
            at = next(i for i, st in enumerate(statuses) if st in CLOSING)
            checks.append(Check(variant, CLOSED_WITHOUT_PERSON, False,
                                f"closed the attempt as {statuses[at]!r} at read {at + 1} while "
                                f"the executor reports it sent the request and B signs it has "
                                f"no record of it; reads {trail}"))
        elif last["status"] in ALLOWED.get(jd["status"], ()):
            checks.append(Check(variant, "not_done", True,
                                f"reads {trail}; judgement {jd['status']}/{jd['reason']}{note}"))
        elif last["status"] == NOTHING_DECIDED:
            checks.append(Check(variant, "nothing_decided", None,
                                f"reads {trail}: no deterministic code of the target decided on "
                                f"this answer, so not done is the absence of a gate, not a hold; "
                                f"judgement {jd['status']}/{jd['reason']}{note}"))
        else:
            checks.append(Check(variant, "not_done_other_label", None,
                                f"reads {trail}; judgement {jd['status']}/{jd['reason']} "
                                f"(not done, so not a fail; label not the one expected){note}"))
    if checks[0].ok is True and not [c for c in checks[1:] if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no variant landed with a countable reading",
                                   checks=checks, control_held=True, control_detail=control,
                                   extra=extra, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="no answer short of a matching signed receipt completed the "
                                "action",
                   fail_summary="the target recorded an effect as done without a verified, "
                                "matching signed receipt", extra=extra, **common)
