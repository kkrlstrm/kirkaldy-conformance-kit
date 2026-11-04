# KRK-25 (P25) counterparty disclosure: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p25_counterparty_disclosure.py`. Where it says "the design", it means the
property's design document, X6, which is not part of this copy of the kit; this file and the
docstring are what the code does.

## Decisions that bind the build

- **KRK-25** outside code, **P25** in code. Graded side B (version 1). Role A is version 2; an adapter whose `role()` is not ``B`` reads inconclusive.
- **The narrow version**: only the residue not covered by P20, P18 or KRK-7. Every
  attribution form keeps the effect equal to its sibling's; a fixture whose effect differs reads
  `not_landed` (KRK-M175).
- **One property, five clauses**, reported apart in `extra["clauses"]`: (a) ``actor``
  (`actor_shown`, `approval_basis`, `chain`), (b) ``principal`` (`principal_shown`,
  `outlives_delegation`, `chain`), (c) ``basis`` (`asserted_principal`, `foreign_disclosure`,
  `self_asserted`), (d) ``level`` (`level_exceeded`), (e) ``requirement`` (`missing_disclosure`,
  `self_asserted`'s required sub-check).
- **Two profiles in one module**: ``a-issued`` and ``b-held``, read from
  `disclosure_profile()` and checked against `bissuer.authority_of` (issuer ``B`` must be
  ``b-held``, and only it).
- **Signing key**: A signs a disclosure under its ``standing`` key. `standing.PURPOSES` is
  unchanged.
- **New modules only**: `conformance/disclosure.py`,
  `conformance/discloser.py`, `conformance/properties/p25_counterparty_disclosure.py`,
  `known_bad/disclosure_toys.py`, `tests/test_p25_counterparty_disclosure.py`,
  `tests/vectors/krk25/vectors.json` and `tests/test_failure_modes_x6.py`. No probe or fixture
  hash of P1 to P23 or P18B moved.
- **P25's closure** (as built): `attenuation`, `authz`, `bissuer`, `discloser`, `disclosure`,
  `evidence`, `issuer`, `mockserver`, `netbind`, `receipts`, `requester`, `result`, `stand_in`,
  `standing`, `status`, `timing` and the property module. None was edited except the two new ones.
  A later change to any of them lapses P25, which is the intended coupling.
- **Claim basis** is the runner's (`conformance.claim_basis`), as for every property. The
  probe reads every form its profile has and does not read `not_claimed()`. A must-land form that
  did not land leaves the result inconclusive even when it is not claimed.
- **Seeded; fresh identifiers from the operating system; fixtures genuine.** Principals, agents,
  organisations, keys, pairwise secrets, salts, refs and authorisation ids come from the operating
  system (KRK-M186). The seed draws the form order, the order of W, L and D in a trial, amounts.

## Module 1: `conformance/disclosure.py`

```python
SCHEMA = "kirkaldy.disclosure/0.1"; TYP = "krk-disclosure+jws"; ACT_TYP = "krk-act+jws"
ACTOR_KINDS = ("agent", "person"); LEVELS = ("named", "pairwise", "organisation", "none")
BASES = ("a-attested", "b-consent", "agent-asserted", "unattested")      # strongest first
APPROVALS = ("person", "agent-asserted", "standing-permission")
CLAUSES = ("actor", "principal", "basis", "level", "requirement")
REQUIREMENTS = ("disclosure-required", "agents-barred")
HEADER = "KRK-Disclosure"; ASSERT_HEADER = "On-Behalf-Of"; ASSERT_MEMBER = "on_behalf_of"
QUERY = "?"          # a Presentation.headers key starting with it is a query parameter

def pairwise(secret, principal, audience) -> str        # HMAC-SHA256(principal NUL audience), hex
def commitment(principal, salt) -> str                  # "sha256:" + SHA-256(salt NUL principal)
def plain_hash(identifier) -> str                       # the kit's KRK-M184 needle
def disclosure_claims(*, issuer, audience, actor, principal, request_digest,
                      authorisation_id, agent_key, issued_at, not_after) -> dict
def claims_problem(claims) -> str | None
def sign(claims, key) -> str; unsigned(claims) -> str; verify(token, pinned) -> Verified
def basis_of(claims, *, verified_by) -> str; stronger(a, b) -> bool
def expected(...) -> Attribution
def flatten(obj) -> dict[str, str]                      # walks #json and #jws
def in_token(path) -> bool; echo_paths(flat, request_tokens) -> list[str]
def normaliser(declared) -> callable | None
def find(flat, needles, *, normalise=None) -> dict[str, list[str]]; find_folded(flat, needles)
def infer_fields(rows, *, exclude=()) -> list[str]; transport_paths(rows) -> list[str]
def over_level(flat, level, needles, *, normalise=None) -> list[str]
```

The principal shapes are exactly ``{level, id}``, ``{level, pseudonym}`` (64 lowercase hex) and
``{level, commitment}`` (``sha256:<64 hex>``). Times are epoch milliseconds.

## Module 2: `conformance/discloser.py`

```python
class StubDiscloser(StubIssuer):
    pair_secret: bytes
    def principal(self) -> str                      # fresh, mixed case
    def person(self, principal) -> Keypair          # the person's own key; never in A's statement
    def pseudonym(self, principal, audience) -> str; commit(self, principal) -> str
    def principal_claim(self, principal, level, audience) -> dict
    def needles(self, principal, audience) -> dict
    def disclose(self, request: bytes, *, agent, principal, level, audience,
                 authorisation_id=None, signer="a",     # "a" | "agent" | "none"
                 holder=None, agent_org=None, broken=None) -> Disclosure
    def disclosure_log(self) -> list[Disclosure]
    def act_token(self, *, agent, principal, audience, holder=None) -> str
    def authorise(self, raw, *, subject, audience, operation, holder=None, grant_id=None,
                  key=None) -> (token, claims)
    def presentation(self, raw, *, subject, audience, operation, disclosure=None,
                     extra_headers=None, holder=None) -> (Presentation, claims)
    def chain_presentation(self, grant, values, *, audience, disclosure) -> Presentation
    def read_request(self, subject, op_id, *, audience, holder=None) -> Presentation
```

A′ (another organisation that discloses for its own principal) is a second `StubDiscloser`
sharing A's grant registry, signing with its own standing key; nothing calls `disclose` with a
``peer`` argument (design §6.3 named one).

## Module 3: `conformance/properties/p25_counterparty_disclosure.py`

```python
ID = "P25"; TITLE = "Counterparty disclosure"; PROFILES = ("a-issued", "b-held")
VARIANTS, FORMS, CLAUSE_OF, B_HELD_ONLY, A_ISSUED_ONLY        # as the design's §6.4
MUST_LAND = {"a-issued": (("actor_shown", "agent"), ("asserted_principal", "header"),
                          ("foreign_disclosure", "other_request")),
             "b-held": (("actor_shown", "agent"),)}             # + principal_shown at every
                                                                # agreed level, + the control
NA_FORBIDDEN = ("control", "actor_shown", "principal_shown", "asserted_principal",
                "foreign_disclosure")                           # variants never declared n/a
TRIALS = {"*": 5}; DEV_TRIALS = {"*": 3}; PLAN_ENV = "ACK_P25_PLAN"
GRADES = ("b-store", "b-record", "b-signed", "b-response", "library-decision")
def probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result
```

Plan keys: ``trials`` (``dev`` or published), ``n``, ``variants``, ``forms``
(``{variant: [form, ...]}``).

Per-trial outcomes: pass ``attributed``, ``refused_as_expected``; fail ``misattributed``,
``actor_not_shown``, ``unattributed``, ``over_disclosed``, ``performed_undisclosed``;
information ``collateral_refusal``, ``not_landed``, ``format_gap``, ``stored_token``,
``record_late``, ``echoed``, ``no_attribution``, ``undeclared_normalisation``, ``no_sibling``,
``not_stated``. A form passes if every trial passed, fails on any failing trial, and otherwise
has no reading. `extra["disclosure_forms"]` gives the class of each failing form:
``vulnerability`` for `asserted_principal`, `foreign_disclosure`, `missing_disclosure` and
`level_exceeded` forms that read ``misattributed``, ``over_disclosed`` or
``performed_undisclosed`` (§1.8), else ``conformance``.

## Module 4: the adapter

Both profiles:

```python
name; config; version(); vendor_claims(); not_applicable(); start(); stop()
role() -> "B"                                       # optional
disclosure_profile() -> "a-issued" | "b-held"
agreement() -> {"counterparty", "endpoints", "tenants"}
levels() -> {operation: {"supported", "agreed", "quote", "source"}}
requirements() -> {operation: {"requirement": "disclosure-required" | "agents-barred"
                               | "approval-required", "quote", "source"}}
pseudonyms() -> {"scope": "per-counterparty" | "global", "unit", "quote", "source"} | None
direct_path() -> {...} | None
normalisation() -> {"case": "fold", "strip": bool} | None
formats() -> [str]                                  # must include disclosure.SCHEMA (a-issued)
labels_basis() -> {"labels": {basis or approval: B's word}, "quote", "source"} | None
evidence_grade() -> one of GRADES
bind_recorder(url) -> str
present(p) -> answer; classify(answer) -> "accepted" | "refused" | "error"
operation_of(answer) -> B's operation id | None
attribution_record(op_id) -> raw, B's read path; store_rows(op_id) -> [rows] | None
answer_as(caller, op_id) -> B's answer      # caller: a read Presentation (a-issued) or a stand-in
direct_presentation(principal, raw, *, key, pid, endpoint) -> Presentation
end_delegation(agent, *, by, **kw) -> object
received(pid) -> {"headers", "request"} | None      # optional: what B received (KRK-M182)
strict_rules() -> {...} | None                      # optional, stated before the run (§3.10 rule 2)
variants_not_applicable() -> {variant: why}         # optional; never one in NA_FORBIDDEN
```

``a-issued`` adds `bind_requester(anchor, source_url)`, `bind_peer(anchor, source_url)`,
`enrol_person(principal, kid, public)`, `issuers()` and `accepts_holder_hops()`.

``b-held`` adds `authority()` (issuer ``B``), `new_person() -> handle`, `hook(person=handle)`
(a `stand_in.PersonHook`, checked with `stand_in.hook_problem`), `agent(n)` (stand-ins with the
`stand_in.StandInAgent` protocol, unchanged), `published_keys(tenant)` (JWKS),
`identities(consent_record) -> {"agent", "principal_named", "principal_pairwise"}` (each value
must appear in B's consent object as the kit verified it), and, for
`missing_disclosure/required_absent`, `undisclosed_use(agent, body, *, pid, tenant, endpoint)`.

## Module 5: `known_bad/disclosure_toys.py`

`ToyDisclosureB` (``a-issued``) and `ToyHeldB` (``b-held``), with `ToyHeldAgent` and
`ToyHeldHook`. `cases()` and `toy(config)` for the gate. `FLAWS` (20) with `FAILS` and
`HELD_FLAWS` (16) with `HELD_FAILS` give each flaw's exact failing forms; `KNOBS` are the
failure-mode pins' settings, never used by the gate.

| Config | Required |
|---|---|
| ``good``, ``good-strict``, ``b-held-good`` | pass |
| ``bad`` (= ``records_caller_only``), ``b-held-bad``, every ``bad:<flaw>``, ``b-held-bad:<flaw>`` | fail |
| ``no-control``, ``b-held-no-control``, ``info:stores_token`` | inconclusive |

## Registration

`conformance/properties/__init__.py` (`ALL` gains P25), `conformance/knownbad.py` (`cases`,
`_toy`, the docstring), `tests/conftest.py` (`TOYS["P25"]`), `tests/test_known_bad_gate.py` and
`tests/test_bissuer_registry.py` (their property lists), `tests/test_catalog.py` (149 to 169
reserved for P24), the Makefile (`make known-bad PROPS=P25`) and the README's property table.

## Measurement errors

KRK-M170 to KRK-M189 are in `docs/FAILURE-MODES.md`, each pinned in
`tests/test_failure_modes_x6.py`.
