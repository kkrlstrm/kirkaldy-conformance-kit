# KRK-18 (P18) payload bound, single use: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p18_payload_bound.py`. Where it says "the design", it means the property's
design document, X3, which is not part of this copy of the kit; this file and the docstring are what
the code does.

## Decisions that bind the build

- **KRK-18** outside code, **P18** in code. Graded side B; a role-A family of six
  checks is secondary and reported apart from the property.
- **After an honest retry, A's own record must agree with what B did**. It is a fail,
  conformance class, when A's reading of the outcome contradicts the effect counted in B's store
  (`record_matches_effect`, `contradicts_effect`). Role-A results carry `extra.disclosure =
  "conformance"`.
- **"The same request"** is the authorisation id plus the request digest. A client
  idempotency key outside the authorisation is not a defence.
- **A refusal answer to a repeat of an executed request is a fail** (`denied_done`).
- **Memory** at least until expiry plus the stated tolerance, or forever; it survives restart and
  failover and is shared across endpoints and tenants.
- **A refusal that uses up the authorisation is a fail** (`consumed_by_refusal`).
- **A false refusal of an equivalent serialisation is information**; checking one reading and
  acting on another is a fail.
- **Exact binding by default** for every operation the agreement does not mark `class`.
- **Evidence grades** `recorder` > `B-store-read` > `B-answer`; at `B-answer` every variant that
  counts effects is `not_driven`.
- **Parts** only when the authorisation lists them.
- **Self-hosted targets only** in version 1.
- **A B with only an API key** runs like any other and fails what it cannot answer.
- **Disclosure:** conformance by default; `vulnerability` where the agreement claims replay
  protection and a variant shows a second effect, a changed effect, or one under an authorisation
  addressed elsewhere.
- **KRK-16 and KRK-17 are unchanged.** P18 imports `receipts` for canonical JSON, digests and
  keys, and reuses `mockserver` as the recorder.
- **Never forge.** The stub A signs only with its own keys; a changed payload is a changed body
  beside unchanged authorisation bytes.

## Module 1: `conformance/authz.py`

```python
SCHEMA = "kirkaldy.request-authorisation/0.1"; TYP = "krk-authz+jws"
CANONICAL = "kirkaldy.canonical-json/0.1"; RAW = "raw-bytes"; BASES = (CANONICAL, RAW)
AMBIGUITIES = ("not-json", "duplicate-key", "unsafe-integer", "float")   # priority order

def ambiguous(request: bytes) -> str | None
def explain_ambiguity(request: bytes) -> dict[str, str]
def parse(request: bytes) -> Any                         # NotBindable on ambiguous input
def canonical_bytes(request: bytes) -> bytes
def binding_digest(request: bytes, basis: str = CANONICAL) -> str
def lenient_digest(request: bytes) -> str                # the sloppy A's digest (fixtures only)
def new_authorisation_id() -> str                        # "az-" + 16 hex, from `secrets`
def exact_binding(request, *, basis, parts=None, mapping=None, summary=None, digest=None) -> dict
def class_binding(ceiling: dict, *, basis=CANONICAL) -> dict
def authorisation_claims(*, issuer, audience, operation, binding, max_uses, not_before,
                         not_after, decision_digest, authorisation_id=None, extra=None) -> dict
def claims_problem(claims) -> str | None
def sign_authorisation(claims, key) -> str; def unsigned_authorisation(claims) -> str
def verify_authorisation(token, pinned: dict[str, bytes]) -> receipts.Verified
def claims_of(token) -> dict | None                      # unverified, for evidence

@dataclass(frozen=True)
class Presentation: pid, endpoint, tenant, request: bytes, authorisation, headers
```

`binding` has exactly `kind`, `basis`, `request_digest`, `parts`, `mapping`, `summary`, `ceiling`.
`summary` is the approver's view of the request beside the digest (not in the design; see below).
Vectors: `tests/vectors/krk18/` (raw request files written as byte literals, `requests.json`,
`authorisations.json`, `make_vectors.py`), checked first against an independent JSON reader in
`tests/test_authz.py`.

## Module 2: `conformance/requester.py` (the stub A)

```python
VARIANTS = (...24, as P18...)
def new_issuer() -> str                                  # per pair, from the OS (KRK-M36)
def draw_values(rng, *, operation, n_items) -> dict     # ref from the OS
def request_bytes(values) -> bytes; def reserialise(values) -> bytes
def with_duplicate(values, member, second) -> bytes; def fullwidth(s) -> str
def translate(values, mapping) -> dict                   # A's vocabulary into B's

class StubRequester:
    def __init__(self, issuer=ISSUER, *, key=None, profile=None, clock_offset_s=0.0, db_path=None)
    def public_key(self) -> (kid, bytes); def trust_anchor(self) -> dict; def now(self) -> float
    def request(self, values) -> bytes
    def authorise(self, request, *, audience, operation, kind="exact", basis, parts=None,
                  mapping=None, max_uses=None, window_s=(-60, 900), digest=None, summary=None,
                  ceiling=None, decision_digest=None, extra=None) -> str | None
    def plan(self, variant, agreement, *, rng) -> Plan
    def control_plan(self, agreement, *, rng, m) -> Plan
    issued: list[dict]; format_gaps: list[dict]

@dataclass class Req: label, values, raw, token, headers, endpoint, tenant
@dataclass class Step: op ("present"|"race"|"hook"|"elapse"|"read"), role ("capability"|"variant"),
                       label, presentation, presentations, drop_answer, hook, args, seconds
@dataclass class Plan: variant, steps, requests, meta, gap, mapping

class Transport:
    def __init__(self, present_fn, *, clock=time.time)
    def send(self, p, *, drop_answer=False, start_at=0.0) -> dict | None
    def release_together(self, ps, *, delay_s=0.1) -> list[dict]
    def sent(self, pid) -> int
    wire_log: list[dict]; answers: dict[pid, dict]
class AnswerLost(Exception)                              # role A: the transport dropped B's answer
```

P19 extends this class (grants, delegation, a status source, withdrawal, a clock offset) through
`now()`, `_sign`, `issued`, `authorise(extra=)` and `db_path`; none of P19's parts are built.
`PROFILES` (wire profiles for the authorisation) is empty: no outside format is built yet.

## Module 3: the recorder (`conformance/mockserver.py`)

`POST .../effect/...` keeps the body byte for byte (`raw_b64`), its members (`effect`) and
`began_at` (body member, else header `X-Began-At`). `MockServer.effects(prefix)` and
`mockserver.effects(records, prefix)` read them back. P18 gives each pair its own path prefix.

## Module 4: `conformance/properties/p18_payload_bound.py`

**Role B adapter** (`Adapter`):

| Method | Required | Use |
|---|---|---|
| `role()` | no (default "B") | "B", or "A" for the role-A family |
| `agreement()` | yes | the product's stated terms (keys in the docstring), read before the run |
| `pin_requester_key(issuer, kid, public_key, mapping=None)` | yes | A's key for one pair, with the mapping that pair's agreement declares |
| `bind_recorder(url)` | yes | route B's executor's effects to the recorder |
| `present(p)` | yes | one `Presentation`, raw, no client retry; answer with `began_at`/`ended_at` from inside B where it has them |
| `classify(answer)` | yes | one of `CLASSES`, from quoted product codes |
| `evidence_grade()` | yes | one of `GRADES` |
| `received(pid)` | no | B's own record of the bytes it received (KRK-M37) |
| `effects(since)` | at `B-store-read` | B's store read through its serializer |
| `restart(kind)`, `instances()` | no | `{"before", "after", "how"}` boot or instance ids (KRK-M44) |
| `dependency(available)` | no | `refused_then_retry` |
| `crash_between(step)`, `crashed()` | no | `crash_between_use_and_effect` |
| `set_memory_horizon(seconds or None)` | no | None restores the product's own setting |
| `elapse(seconds)` | no | defaults to sleeping |
| `authorisation_profile()`, `variants_not_applicable()`, `variant_notes()` | no | as KRK-16; `NA_FORBIDDEN` may not be declared |

**Role A adapter** (`RoleAAdapter`): `role()` = "A"; `bind_counterparty(peer, send,
receipt_key)` (the path the target's executor uses: `send(request, authorisation, headers)`
returns `{"receipt", "answer", "code", "use_key"}` or raises `requester.AnswerLost`);
`authorisation_key()` (optional); `submit(envelope, expected)`; `send(case_id)`;
`retry(case_id)`; `status(case_id)`; `outcome(case_ref)` (optional).

`outcome(case_ref)` is the target's own reading of the action's outcome, translated and nothing
more (KRK-M24, KRK-M25): one of `OUTCOME_READINGS` (`done`, `not-done`, `open`, `disputed`), or
`{"outcome": <one of them>, "product": {...}}` with the product's own words for the evidence. An
adapter must not decide the reading from B's answers or B's store; it reports what the product
recorded. It is read once, right after the retry in the `retry_same` round.

| Check | Fails when |
|---|---|
| `record_matches_effect` | the reading is `not-done` while B's store holds the effect, or `done` while it holds none (`contradicts_effect`) |

`agrees` is a pass. `disputed` is a pass (`disputed_held`) only where B's answers to the target
after the lost one conflict with B's store (a denial while the effect stands, or a claim while it
does not): the target then holds a disagreement it really has, which contradicts nothing. With no
such conflict it is information (`disputed_without_conflict`), so a target that reads everything
as disputed cannot pass by it. `open` is information (`left_open`): it says nothing either way,
and a target that never settles must not pass. No `outcome` method, a reading outside the list,
or an `outcome` that raises is `not_readable` / `unreadable`, information, never a pass. The
control asks nothing of `outcome` (KRK-M19). The duplicate round is graded by
`honours_duplicate`; its reading is added to the detail only. B's effect comes from
`b_effect(b, correlation_id)`: the requests B's store logged as executed and the item rows it
wrote, never B's answer to the repeat (KRK-M45).

Guards a test may switch off to show the error: `capability_ran`, `restart_happened`,
`overlapped`, `_landed_bytes`, `b_effect`, and `requester.UNBOUND`.

## Module 5: `known_bad/binding_toys.py`

`ToyBinding(variant, flaw=None, grade="recorder")`, `FLAWS` (23), `make(flaw)`; `bad` is
`no_check`. Knobs: `restart_wrapper_only`, `no_timing`, `serialise`, `unrecorded_endpoint`,
`clock_ahead_s`. `ToyRequesterA(variant, flaw=None)`, `A_FLAWS` (6), `make_a(flaw)`; knob
`careful_reading` (reads B's `authorisation-reused` refusal of a retry after a lost answer as
disputed). `refusal_as_outcome` fails `retry_same` and `record_matches_effect`: a strict B
refuses a repeat only when its bytes differ, so the toy changes them under the same id.
`conformance/knownbad.cases("P18")` registers every toy of both roles.

## The strict stub B (`conformance/counterparty.py`)

`StubCounterparty(..., single_use=True, repeat_answer="original"|"duplicate",
requester_keys={kid: pub})`, with `expect(correlation_id, expected)`, `receive(raw,
authorisation=None, headers=None, *, rng)` and `received_requests`. Use key: the authorisation id
when one is presented, else the correlation id. Off by default.

## Departures from the design's §6

- `pin_requester_key` takes the issuer and the pair's declared mapping; each pair gets a fresh
  issuer id, not only a fresh key, so no use record of one pair can meet another's.
- Exact authorisations carry `binding.summary`, the approver's view of the request beside the
  digest, as a payment mandate carries its cart. Without it the `accepts_subset` toy could not
  exist: an authorisation holding only a digest gives a B no item set to compare a subset with.
- Three fail outcomes are added: `ran_ambiguous`, `ran_under_class`, `ran_without_basis`; and
  one information outcome at the `B-answer` grade, `answer_only`.
- `replay_other_endpoint` and `replay_other_tenant` present at the wrong audience **first**, then
  at the right one: presented second, a B with shared memory answers "duplicate" from the wrong
  endpoint and the audience check is never exercised. A refusal at the right audience after the
  wrong one is `consumed_by_refusal`.
- `split_declared` authorisations carry `max_uses` equal to the number of parts.
- `crash_between_use_and_effect` asks the adapter to crash "between the two writes, in whichever
  order B does them" (`crash_between("use-and-effect")`), not at a named step.
- The role-A adapter reaches B through `bind_counterparty(peer, send, receipt_key)` rather than
  KRK-16's `deliver`, because in role A the target's executor sends the bytes; the kit does not.
- `NA_FORBIDDEN` includes `replay_after_restart`; a variant in it that does not land with a
  verdict makes a result with no failures inconclusive.
- The role-A family has a sixth check, `record_matches_effect`, not in
  the design's §6.8, and the optional adapter method `outcome(case_ref)` it reads.
