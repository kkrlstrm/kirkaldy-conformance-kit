# The B-issuer profile (authority held at B): the interface as built, phase 1a (P18B)

This file states the names and signatures the build uses; where the B-issuer design (not part of
this copy of the kit) differs, this file describes the code and the last section lists the
differences. The protocol itself is the docstring of
`conformance/properties/p18b_payload_bound_b.py`. Phase 1a builds P18B only; P16B, P19B and P20B are
later phases, in new files.

## Decisions that bind the build

- **Profile `b-issuer/0.1`.** Code id `P18B`, title "Payload bound, single use (authority at B)",
  outside code "KRK-18 (authority at B)".
- **A registry of its own**. `conformance/properties/__init__.py` has
  `ALL_BISSUER = {"P18B": ...}` beside `ALL`, and `ALL` stays exactly P1 to P21. Lookups by id use
  `properties.module(pid)` / `known(pid)`, which read both; iteration over `ALL` is unchanged, so the
  full known-bad gate, the matrix's columns and the P1-P15 toy catalogue test are as before.
- **New modules only**. No file in the closures of P1 to P21, in their fixture
  lists, or in `DEFAULT_FIXTURES` was changed. P18B imports P18's
  module and changes nothing in it.
- **The judge is P18's.** Variants whose question carries are judged by `p18.judge` itself, on
  steps logged in P18's shape, with `plan.meta["authorised"]` set to B's signed terms of the object
  accepted (rule 3). The rest are judged in P18B with P18's helpers and outcome names.
- **The binding rule** is design §1.6, rules 1 to 9, for every target under the profile.
- **Never forge** (§4.2): the kit holds no key of B's, presents B's objects as B sent them, and never
  presents an id B did not issue.
- **The hook** supplies only a person's inputs, through one of three kinds; the decline check runs
  once per run and is never part of a control.
- **Evidence** per §2.4: effects from B's store through B's read path; B's account of an effect
  is never counted.
- **Restatement** is information and a finding; **resource reconciliation** is a
  fail.
- **`split_undeclared`** is the probe's own structural NA for the revision shape only; it may
  not be declared NA for consent-id or rar-token.
- **Dependencies:** none added. The verifier is written on `cryptography`.
- **Self-hosted targets only**.

## Module 1: `conformance/bissuer.py`

```python
PROFILE = "b-issuer/0.1"; SHAPES = ("revision", "consent-id", "rar-token")
HOOKS = ("documented-automation", "declared-test-route", "driven-page")
BASES = ("jcs", "json-values"); SUMMARY_SENTENCE; FORBIDDEN_WORDS = ("person's consent",)

@dataclass(frozen=True) class Authority:   # issuer, shape, objects, hook, revocation,
    def problem(self) -> str | None        # agent_keys_from, keys, quotes, source
def declared_authority(adapter) -> Authority   # adapter.authority() only (the runner's reading)
def authority_of(adapter) -> Authority         # authority(), then agreement()["authority"], then A

@dataclass class BObject:   # kind, id, raw, signed, kid, alg, terms, terms_digest, issued_to,
                            # tenant, endpoint, instance, expires_at, issued_at, supersedes,
                            # counter_proposal, claims, received_at, pair, verified, why
class BObjectLog:           # add, get, all, superseded(oid) -> BObject | None, docs

def verify_signature(raw, published) -> Verified   # compact JWS, EdDSA | ES256; the payload bytes
def verify_b_object(raw, published) -> Verified    # the same, payload read as strict JSON claims
def thumbprint(jwk) -> str; def thumbprints(published) -> list[str]   # RFC 7638
def jcs(obj) -> bytes                              # RFC 8785; NotIJSON where it has no form
def terms_digest(terms, basis="jcs") -> str; def digest_matches(stated, terms) -> bool | None
def restatement(requested, terms, *, basis="jcs", mapping=None, members=None) -> dict | None
def label(authority) -> dict; def grade_label(grade) -> str; def hook_sentence(kind) -> str
```

Vectors: `tests/vectors/bissuer/jcs.json` (RFC 8785's number table and two object examples, RFC
7638's RSA thumbprint, RFC 8037's Ed25519 thumbprint and signature), checked by
`tests/test_bissuer.py`. The thumbprints and the signature were confirmed by computation; the JCS
number table is marked for re-checking against the RFC text before a published run.

## Module 2: `conformance/stand_in.py`

```python
class AgentIdentity:     # client_id, kid, private (Ed25519 from the OS); fresh(), jwk(), sign()
@dataclass class ConsentRecord:   # pair, identity, hook, person, decision, handle, shown, steps,
                                  # credential, at, asked_by
class PersonHook(Protocol):       # kind, log; approve(handle, *, pair), decline(handle, *, pair)
class StandInAgent(Protocol):
    identity() -> AgentIdentity
    consent(hook, *, tenant, pair, decision="approve") -> ConsentRecord
    request(raw, *, pid, tenant, endpoint) -> Presentation          # the kit sends it
    counter(obj, raw, *, pid, tenant, endpoint) -> Presentation     # revision shape
    read(answer, *, endpoint) -> list[BObject]
    person_needed(obj) -> dict | None                               # the hook's handle
    complete(obj, *, pid, tenant, endpoint) -> Presentation | None  # rar-token: redeem
    acceptance_body(obj, *, approval="person") -> dict
    accept(obj, body, *, pid, tenant, endpoint, headers=None, credential_tenant=None) -> Presentation
    class_body(values) -> dict; class_use(body, *, pid, tenant, endpoint, headers=None) -> Presentation
def hook_problem(hook, declared) -> str | None
```

`Presentation` is `authz.Presentation`, imported unchanged; `requester.Transport` sends it.

## Module 3: `conformance/properties/p18b_payload_bound_b.py`

`ID`, `TITLE`, `OUTSIDE_NAME`, `FIXTURES` (`known_bad/bissuer_core.py`,
`known_bad/bissuer_binding_toys.py`, `tests/test_p18b_payload_bound_b.py`,
`tests/vectors/bissuer/*.json`), `ENVIRONMENT` (`python`, `package:cryptography`), `UNSEEDED`,
`VARIANTS` (P18's 24 and `other_holder`), `NA_FORBIDDEN_ALL`, `na_forbidden(shape)`,
`STRUCTURAL_NA`, `GRADES` (`B-store-read`, `B-answer`), `probe(a, ev, *, run_tag="", seed=None)`.

**Adapter** (role B, B-issuer):

| Method | Required | Use |
|---|---|---|
| `authority()` | yes | §6.8; `issuer` must be `"B"`; the runner reads only this |
| `agreement()` | yes | P18's keys, plus `binding_basis`, `test_resources`, `background_writers`, `instances`, `store_survives_restart` |
| `agent(n, identities=None)` | yes | `n` fresh `StandInAgent`s, or one per given identity (the same agent at a second instance) |
| `hook()` | yes | the `PersonHook`, of the kind `authority().hook.kind` names |
| `present(p)` | yes | one presentation through B's real entry point, raw; `began_at`/`ended_at` from B's own timing |
| `classify(answer)` | yes | one of P18's `CLASSES`, from quoted codes |
| `store(since)` | yes | B's store through its read path: effects with `op_id` and the values used |
| `resource_history(resources)` | yes | every change B's store shows on the test resources: `resource`, `op_id`, `ref`, `writer` |
| `published_keys()` | yes | B's JWKS, through the kit's baseline path |
| `evidence_grade()` | yes | `B-store-read` or `B-answer` |
| `peer()` | for `replay_other_counterparty` | a second instance of the product (another organisation, its own keys), with this adapter's methods |
| `restart(kind)`, `instances()` | no | as P18 (KRK-M44) |
| `dependency(available)`, `crash_between(step)`, `crashed()`, `set_memory_horizon(s)`, `elapse(s)` | no | B's own aids, as P18 |
| `resets()` | no | every call the adapter made to B's reset aid (KRK-M145) |
| `variants_not_applicable()`, `variant_notes()` | no | as P18; `na_forbidden(shape)` may not be declared |

**Outcomes** added to P18's: `effect_without_acceptance` (fail, `resource_reconciliation`),
`restated_changed` (information and a finding, `restatement`), `consent_not_enforced` and
`consent_enforced` (information, `decline_check`), `reconciled`, `restated_faithfully`.

**Result fields.** `extra.authority = {"issuer": "B", "profile": "b-issuer/0.1", "shape", "hook"}`,
`extra.grade_label` (`"B-store-read, authority at B"`), `extra.findings` (restatements, objects
that did not verify), `extra.disclosure`, `extra.resets` when the adapter reset B. The summary
opens with `bissuer.SUMMARY_SENTENCE` and then names the hook kind.

## Module 4: the toys

`known_bad/bissuer_core.py`: `ToyIssuerB(shape, variant="good", flaw=None, *, org=None, key=None)`,
the correct B in three shapes (module docstring), with `ToyAgent` (the stand-in) and `ToyHook`
(`driven-page`). Two endpoints (`api-2` an alias of `api-1`), two tenants, two instances, one
SQLite file. Knobs for the failure-mode pins: `reset_effects_on_restart`, `no_counter`,
`peer_shares_keys`, `background`, `prior_history`, `driver_reconsents`, `reset_between_pairs`,
`signs_with_unpublished_key`, `issues_on_decline`.

`known_bad/bissuer_binding_toys.py`: `FLAWS` (25 that must fail), `FINDINGS`
(`restates_silently`), `NOT_IN_SHAPE`, `applies(flaw, shape)`, `toy(config)`, `make(shape, flaw,
**knobs)`, `cases()`, `expected(config)`. Configurations are `<shape>:good`, `<shape>:slow-good`,
`<shape>:bad` (`no_check`), `<shape>:no-control`, `<shape>:bad:<flaw>` and
`<shape>:finding:restates_silently`: 87 in all.

## Registration and routing

- `conformance/properties/__init__.py`: `ALL_BISSUER`, `known`, `module`, `is_bissuer`.
- `conformance/versions.py`: `_property_module` and `current` look up both registries.
- `conformance/knownbad.py`: `cases("P18B")` and `_toy("P18B", ...)` read the toy file; a
  `finding:` case passes only with its finding; `known-bad --record` with no `-p` still runs P1 to
  P21 only, and `-p P18B` gates P18B.
- `conformance/runner.py`: the default property list is `ALL` then `ALL_BISSUER`;
  `authority_refusal(a, pid)` refuses P16/P18/P19/P20 for an adapter whose `authority()` states B,
  and a B-issuer property for one that does not; the refusal is inconclusive and the probe is not
  called (KRK-M130).
- `conformance/matrix.py`: B-issuer results are left out of the property columns and given a
  section of their own ("Authority held at B"), one row per target, configuration and property,
  with shape, hook and grade, and their own count (§5.3).

None of these five files is in any probe or fixture closure (checked before editing).

## Departures from the design's §6

- **The toy B is in process and speaks no HTTP** (§6.6 said "an in-process HTTP B"). Routes are a
  header (`X-Toy-Route`). The probe's transport is P18's `requester.Transport` either way.
- **`AgentKeySource` is not built.** It serves P20B's link 2; P18B reads no agent keys at B. It
  will go in a new module, so `stand_in.py` need not change.
- **The stand-in builds every presentation, including the request for B's object, and the kit
  sends it,** so the request, the counter-proposal and the token redemption are in the kit's wire
  log too. `request` therefore returns a `Presentation`, and `read`, `person_needed`, `complete`,
  `acceptance_body`, `class_body` and `class_use` are added; `submit` is folded into `accept`;
  `revoke` (P19B) is not built. `PersonHook` keeps a `log` (KRK-M139) and has no `revoke` yet.
- **No `pyjwt`.** The verifier uses `cryptography` only, so `ENVIRONMENT` declares
  `package:cryptography` and not `package:pyjwt`.
- **The `recorder` grade is not built.** No B-issuer adapter can point B's executor at a recorder
  yet; an adapter that reports it reads inconclusive.
- **`accesses(since)` is not used.** Race overlap is read from B's own `began_at`/`ended_at` in its
  answers, as P18 reads it.
- **`restates_silently` gives no verdict**, not a fail: the B-issuer design makes a silent
  restatement information, and a B that restates every request leaves the stand-in nothing to accept. The gate
  requires `inconclusive` with the `restated_changed` finding.
- **No `matches_by_shape` toy.** With no mapping profile declared, `translated_declared` and
  `mapping_undeclared` are structurally not applicable; with one declared they are `not_driven`,
  because no form is built.
- **The runner reads only `authority()`**, never `agreement()["authority"]`: on some
  receivers `agreement()` builds a loop. The probe reads both.
- **Restatement and reconciliation are run-level checks**, one `Check` each over every pair,
  rather than a check per pair.
- **KRK-M134's guard** is the union of every store read in a pair, by B's operation id, rather
  than an explicit "read before the kill plus read after".
- **Forms the design left open, as built:** `other_holder` ends with the first identity's own
  acceptance, which must run once (else `consumed_by_refusal`); `replay_other_counterparty` uses
  the same agent identity at both instances and presents at the target first; `duplicate_key` (b)
  duplicates `approved_by` (revision), `consent_id` (consent-id) or `amount` (rar-token);
  `unbound_member` adds an `instruction` member naming other terms in every shape, beside the
  headers; `validity_beyond_memory` obtains the object after the retention is shortened, so a B
  that caps validity at its retention passes; `expired` waits out the object's own stated
  lifetime through `elapse`.
- **`tests/test_catalog.py`'s reserved numbers** were widened (96-129 for P22 and P23; 135-138, 144,
  146 for later B-issuer phases). It is an existing test file, in no closure.
