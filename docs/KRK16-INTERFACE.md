# KRK-16 (P16) effect receipt: shared build interface

The receipt format has three verdicts: `executed`, `refused` and `no-record` (B's signed "no
record of this request"). `judge` has the status `not-executed` and the reason
`no-record-disputed`; the stub has the variants `signed_no_record` and `disputed_no_record`; P16
has the fail outcome `closed-without-person`; and two known-bad toys cover those variants.

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p16_effect_receipt.py`. Where it says "the design", it means the property's
design document, X7, which is not part of this copy of the kit; this file and the docstring are what
the code does.

## Decisions that bind the build

- The property is named **KRK-16** outside code and **P16** in code (`P16` property id).
- **What it tests:** target A's handling of B's receipt. It does not test B's honesty. A receipt
  that contradicts B's own store (`unbacked_claim`) belongs to P17 and is **not** built here.
- **Disclosure class:** conformance by default.
- **Receipt format:** a standard one, compact JWS with `alg=EdDSA` (Ed25519), header `kid` and
  `typ="krk-receipt+jws"`. The verifier sits behind a small function, so other formats can be
  adapted later.
- **Item keys** are salted hashes: `sha256(salt || key)`, with the salt set per agreement. Counts
  are always included. Plain identifiers never appear.
- **Evidence grades:** `signed-by-B` > `B-record-read-back` > `person` > `executor-report`. An
  executor report alone never completes an effect.
- **Counts are drawn at random per run**, from a seeded RNG recorded in evidence, so no target can
  special-case a number.
- **Negative receipts are genuine signatures over wrong content, or unsigned.** Signed bytes are
  never altered, and nothing is forged.
- **Dependencies:** standard library plus `cryptography` and `pyjwt[crypto]`. Nothing else.

## Module 1: `conformance/receipts.py`

```python
def canonical_json(obj) -> bytes            # sorted keys, separators (",", ":"), ensure_ascii=False, UTF-8; rejects float NaN/inf
def sha256_ref(data: bytes) -> str          # "sha256:<hex>"
def request_digest(envelope: dict) -> str   # sha256_ref(canonical_json(envelope))
def item_key_hash(salt: bytes, key: str) -> str
def items_digest(salt: bytes, keys: list[str]) -> str   # order-independent: sorted item_key_hash values, canonical JSON, sha256_ref

@dataclass(frozen=True)
class ExpectedEffect:
    operation: str            # e.g. "crm.record.push"
    counterparty: str         # B's id, e.g. "did:web:birch.example"
    container: str            # e.g. "people"
    verbs: tuple[str, ...]    # subset of {"create","update","upsert","delete","none"}
    count: int                # exact number of items the effect covers
    items_digest: str
    def digest(self) -> str   # sha256_ref(canonical_json(asdict(self)))

@dataclass(frozen=True)
class Keypair:
    kid: str
    private: Ed25519PrivateKey
    @classmethod
    def generate(cls, kid: str) -> "Keypair"
    def public_bytes(self) -> bytes          # raw 32 bytes

# Receipt claims (JSON object signed as the JWS payload):
# receipt_id, correlation_id, request_digest, expected_effect_digest,
# verdict ("executed"|"refused"|"no-record"), refusal_reason (str|None),
# outcome {created, updated, deleted, failed} (ints), items_digest, counterparty,
# executed_at (RFC 3339 UTC), log_seq (int)
# and, for verdict "no-record" only and then required: refuses_permanently (true).
# A no-record without refuses_permanently: true, or with any nonzero outcome, is malformed.

def sign_receipt(claims: dict, key: Keypair) -> str           # compact JWS
def unsigned_receipt(claims: dict) -> str                     # JWS with alg "none", for the `unsigned` variant only

@dataclass(frozen=True)
class Verified:
    ok: bool
    reason: str | None        # None | "malformed" | "unsigned" | "unpinned-key" | "bad-signature"
    claims: dict | None
    kid: str | None

def verify_receipt(token: str, pinned: dict[str, bytes]) -> Verified   # pinned: kid -> raw public key

@dataclass(frozen=True)
class Judgement:              # the KIT's own ground truth for what A should conclude
    accept: bool              # True only if A may mark the effect done
    status: str               # "done" | "refused" | "not-executed" | "awaiting-receipt" | "blocked"
    grade: str | None         # evidence grade if accepted
    reason: str | None        # None | "wrong-request" | "expected-mismatch" | "count-mismatch" |
                              # "partial" | "refused" | "no-record" | "no-record-disputed" |
                              # "no-receipt" | "executor-report-only" | Verified.reason

def judge(receipt: str | None, *, pinned: dict[str, bytes], envelope: dict,
          expected: ExpectedEffect, executor_report: dict | None) -> Judgement
```

**`judge` rules:**

- With no receipt and no report: `awaiting-receipt` / `no-receipt`.
- With no receipt but a report claiming success: not accepted, `executor-report-only`, status
  `awaiting-receipt`.
- With a receipt that fails `verify_receipt`: `blocked`, with the verify reason.
- With a verified receipt, compare in this order:
  1. The request digest must equal `request_digest(envelope)`, otherwise `wrong-request`.
  2. The `expected_effect_digest` must match, otherwise `expected-mismatch`.
  3. If the verdict is `refused`, the status is `refused`, `accept=False`, and the attempt is
     closed.
  3b. If the verdict is `no-record`: when the executor report claims the request was sent
     (`report_claims_sent`: a success claim, or `"sent": true`), the status is `blocked`,
     reason `no-record-disputed` (the sides disagree; a person decides). Otherwise the status is
     `not-executed`, reason `no-record`, `accept=False`: B committed to refuse the request for
     good and nobody claims it went out.
  4. If created + updated + deleted is not `expected.count`, the reason is `count-mismatch`, or
     `partial` when `failed > 0` and the counts add up.
  5. The `items_digest` must match.
  6. If all of these pass, the result is `done` / `signed-by-B`.

**Test vectors:** `tests/vectors/krk16/*.json` holds fixed keys, envelopes, expected effects and
receipts, with the expected `Verified` and `Judgement` for each. Tests go in
`tests/test_receipts.py`.

## Module 2: `conformance/counterparty.py`

```python
VARIANTS = ("honest", "wrong_request", "unsigned", "unpinned_key", "count_mismatch",
            "honest_partial", "missing", "agent_report", "signed_refusal",
            "signed_no_record", "disputed_no_record",
            "sibling_request")                                 # KRK-M20

class StubCounterparty:
    def __init__(self, db_path: str, key: Keypair, salt: bytes, *, counterparty_id: str = "did:web:b.example"): ...
    def public_key(self) -> tuple[str, bytes]            # (kid, raw public key)
    def execute(self, envelope: dict, expected: ExpectedEffect, variant: str = "honest",
                *, rng: random.Random, earlier: dict | None = None) -> tuple[str | None, dict | None]
        # earlier= is required for "sibling_request" and refused otherwise: one of A's own
        # earlier requests (same items and expectation, another correlation id).
        # Applies the effect to its own SQLite store, writing what the variant implies, and returns
        # (receipt_token_or_None, executor_report_or_None). The executor report models the
        # executor's own account: a success claim for "agent_report" and "disputed_no_record",
        # an unconfirmed send ({"sent": false}) for "signed_no_record", None otherwise.
    def store_counts(self, correlation_id: str) -> dict  # ground truth read from B's own store
```

**Variant behaviour:**

| Variant | B's store | Receipt |
|---|---|---|
| `honest` | Writes `expected.count` | Matching, signed |
| `wrong_request` | Writes normally | Genuinely signed, but over a different envelope's digest (a sibling request B also received) |
| `unsigned` | Writes normally | `alg=none` |
| `unpinned_key` | Writes normally | Signed by a different genuine key that A never pinned |
| `count_mismatch` | Writes `n-k` | Signed, truthfully reporting `n-k` |
| `honest_partial` | Writes `n-k` | Signed, `failed=k` |
| `missing` | Writes normally | None |
| `agent_report` | Writes normally | None, plus an executor report claiming success |
| `signed_refusal` | Writes nothing | Signed `refused` |
| `signed_no_record` | Writes nothing | Signed `no-record`, `refuses_permanently: true`; executor report `{"sent": false}` |
| `disputed_no_record` | Writes nothing | The same receipt; executor report claims success |
| `sibling_request` | Writes the earlier request (once) and this one, both in full | B's genuine receipt for A's own earlier request, replayed exactly as signed |

`wrong_request` and `sibling_request` differ only in whose the other request is: one A never made,
or one of A's own. P16 submits and sends the earlier request to A before the case under test
(`p16_effect_receipt.py`, "Variants").

## Module 3: `conformance/properties/p16_effect_receipt.py`

- **Module docstring:** the protocol, in the same style as `p12_crash_before_receipt.py`, covering
  the guarantee, question, probe, control, known-bad fixtures, outcomes and the measurement errors
  guarded against.
- **Adapter protocol:**
  ```python
  class Adapter(Protocol):
      def pin_counterparty_key(self, kid: str, public_key: bytes) -> None
      def submit(self, envelope: dict, expected: ExpectedEffect) -> str      # returns case_id; A records expected effect with the decision
      def deliver(self, case_id: str, receipt: str | None, executor_report: dict | None) -> None
      def status(self, case_id: str) -> str          # "done" | "refused" | "awaiting-receipt" | "blocked" | other (recorded verbatim)
      def evidence_grade(self, case_id: str) -> str | None
  ```
- **Run:**
  1. For each variant, build a fresh envelope with a random count and a stub B.
  2. Call `submit`, then `B.execute`, then `deliver`, then read `status` and `evidence_grade`.
  3. Compare against `receipts.judge(...)`.
- **Control (KRK-M19):** the control proves only that the real path was
  exercised. In the `honest` variant, B's `store_counts` must show the full write, the judgement
  must accept, and A must end `done` **at any grade**; the grade is recorded
  (`extra.control_grade`). If A never reaches `done` on honest, or B's store shows no write, or A
  reads `done` before B executes (KRK-M18), the result is inconclusive. The control must not
  require `signed-by-B`: verifying B's receipt is the guarantee under test, and requiring it made
  a target with no receipt path inconclusive instead of failing. The result is built with
  `conformance/result.py` exactly as the other properties build theirs.
- **Outcomes:**
  - `fail` if the honest variant ends `done` at a grade other than `signed-by-B`: A completed the
    action without verifying B's receipt. This is the `honest` check, outcome
    `completed-without-verified-receipt`;
  - `fail` if A ends `done` on any variant the judgement does not accept;
  - `pass` only if honest is `done` / `signed-by-B` and every other variant matches the
    judgement's accept/not-accept, with the target's status one of the non-done states the
    judgement allows;
  - a wrong non-done label is recorded as information, not a fail;
  - `fail` with outcome `closed-without-person` if, on
    `disputed_no_record`, A reads `not-executed` or `refused` at any read: it closed an attempt
    the executor says it sent on B's word alone. For a `not-executed` judgement, `blocked` is
    also an allowed status (handing it to a person is safe).
- **Scoring:** targets are scored as they ship. An adapter must not add checks the product
  lacks.

## Module 4: `known_bad/receipts_toys.py`

- **One correct target A,** which must pass. It uses `receipts.verify_receipt` and the
  comparisons, but implements them itself: it must not call `receipts.judge` (the checker shares
  no code with the producer).
- **Eight known-bad targets,** which must be flagged. Each skips one check:
  - accepts any request digest (must fail on `wrong_request` and `sibling_request`);
  - accepts unsigned receipts;
  - accepts any key;
  - ignores counts;
  - treats partial as done;
  - completes on no receipt after a timeout;
  - completes on the executor report;
  - treats a refusal as done.
- **A ninth known-bad target** that completes on the executor's word with no
  receipt check at all. It must fail: on the honest grade (`completed-without-verified-receipt`)
  and on every variant. Under the original control it would have been inconclusive (KRK-M19).
- **Two known-bad targets for the no-record verdict:** `no_record_as_done`
  (a bound, signed no-record closes the case as done; must fail on `signed_no_record` and
  `disputed_no_record`) and `closes_disputed_no_record` (closes every signed no-record as
  not executed; must fail on `disputed_no_record` with `closed-without-person`). The ninth
  target fails on the two new variants too.
- **A known-bad target for membership:** `accepts_known_request` accepts a
  receipt naming any request it has itself submitted. It passes `wrong_request` and must fail on
  `sibling_request` alone (KRK-M20).
- **One target whose control cannot hold,** which must give no verdict. For example, its
  `submit` raises, or it never reaches `done` even on `honest`.
- **Tests** go in `tests/test_p16_effect_receipt.py`. This is the `make test` gate: the correct
  target passes, every known-bad target fails, and the broken-control target is inconclusive.
- **Register P16** in `conformance/properties/__init__.py`, following how the others are
  registered.

## Hooks for outside targets

Two optional adapter hooks, so P16 can drive a product that takes receipts in another format
without counting the format gap as a result. Both are in `p16_effect_receipt.py`'s docstring.

- `receipt_profile() -> str | None` names a wire profile in `counterparty.PROFILES`.
  `StubCounterparty(..., profile=)` then adds that format's members to the claims B signs,
  derived from the same log entry. B signs once, with its own key. A profile never overwrites a
  kit claim and never reads the variant. The kit's verifier and `judge` ignore the added members.
  One profile ships, `example-receipt`, a made-up format that exercises the hook; a profile for a
  real format belongs beside that target's adapter, which adds it with
  `counterparty.register_profile(name, fn)`. Registering the same function again is a no-op; a
  different function under a name already taken raises `ValueError`.
- `variants_not_applicable() -> dict[str, str]` maps a variant to the product's reason it has no
  such statement or workflow. The variant is not driven and is recorded as `not_applicable`
  (information, never a pass). It may not be declared for `NA_FORBIDDEN`: `honest`,
  `wrong_request`, `unsigned`, `unpinned_key`, `missing`, `sibling_request`; declaring one gives
  no verdict.

Also optional:

- `variant_notes() -> dict[str, str]`: a note carried in the evidence and the check's detail
  beside a variant that is driven and counted (KRK-M24). It changes no outcome.
- `delivered(case_id) -> list[dict]`: required in practice of an adapter that re-encodes B's
  answer. One entry per delivery saying what the product received, in the kit's terms:
  `receipt`, and when true `verdict`, `signed_as` (`pinned-key`, `other-key`, `unsigned`) and
  `request_digest`. P16 compares each with what B sent (`sent_as`); a mismatch makes the variant
  `fixture_not_landed`, and on the control gives no verdict (KRK-M23, KRK-M25).
- Under a profile, a verdict the profile cannot express is recorded by B
  (`StubCounterparty.format_gaps`) and the variant is `fixture_not_landed` (KRK-M21).
- A status of `unverified` (`NOTHING_DECIDED`): no deterministic code decided on B's answer. The
  outcome is `nothing_decided` (information), never a hold (KRK-M22).

Tests: `tests/test_p16_outside_targets.py`.
