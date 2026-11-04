# KRK-24 (P24) purpose and terms bound: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p24_mandate_bound.py`. Where it says "the design", it means the property's
design document, X2, which is not part of this copy of the kit; this file and the docstring are what
the code does.

## Decisions that bind the build

- **KRK-24** outside code, **P24** in code. Graded side B, version 1. The kit plays
  the principal, the principal's trusted surface (which signs confirmations) and the agent.
- **New modules only**: `conformance/terms.py`, `conformance/mandator.py`,
  `conformance/role_mandate.py`, the property module, `known_bad/mandate_toys.py`, the vectors in
  `tests/vectors/krk24/`, and the tests `tests/test_p24_mandate_bound.py` and
  `tests/test_failure_modes_x2.py`. `issuer.py`, `attenuation.py`, `role_b.py` and P19's module
  are imported, never edited: P24's stub methods are on the subclass `StubMandator`. No file in the
  import closure of P1 to P23 or P18B changed, and every probe and fixture version is unchanged
  (checked before and after the build).
- **Registration lists only** elsewhere: `conformance/properties/__init__.py` (`ALL` is P1 to P24),
  `conformance/knownbad.py` (P24's cases and toys), `tests/conftest.py`, the Makefile
  (`make known-bad PROPS=P24`), `tests/test_known_bad_gate.py` (the property list), `tests/test_catalog.py`
  (149 reserved) and `tests/test_bissuer_registry.py` (its assertion that `ALL` is P1 to P23).
- **Static** (decision 8): no timing harness beyond the stability window S.
- **Claim basis** is the runner's (`conformance/claim_basis.py`), outside every probe closure. P24
  writes `extra["forms"]` (variant → form → reading; form id `<variant>/<form>`) and
  `extra["disclosure_forms"]` (failing form → class).
- **No outside target** was run in the build.

## Module 1: `conformance/terms.py`

```python
GRANT_V4_SCHEMA = "kirkaldy.grant/0.4"          # typ krk-grant+jws, as 0.2
CONFIRMATION_SCHEMA, CONFIRMATION_TYP = "kirkaldy.confirmation/0.1", "krk-confirmation+jws"
TERM_KINDS = ("goal_id", "purpose", "slots", "fixed", "floor", "serves", "confirm", "text")
PROFILE_KINDS = ("purpose", "slots", "fixed", "floor", "serves", "confirm", "sealed", "text")
UNREADABLE, NOT_COVERED, LESS, MORE, OTHER, UNCONFIRMED, OTHER_GOAL   # reasons
UNKNOWN, MALFORMED                                                    # shape reasons

def terms_problem(t, *, sealed_ok=True) -> (reason, detail) | None
def grant_v4_problem(claims) -> (reason, detail) | None
def without_terms(claims) -> dict                 # a 0.4 grant read as 0.2, for attenuation
def confirmation_problem(c) -> str | None
def seal(value, salt) -> {"_sealed": str}
def open_sealed(terms, disclosures) -> dict | Unreadable
def sealed_paths(terms) -> [path]
def purpose_covers(purpose_map, code, operation, resources) -> bool   # exact keys
def units(items, item_key="id") -> {item: units} | None
def assignment(have, slots) -> (units assigned, {(item, slot): units})  # integer max flow
def fill(items, slots, *, item_key="id") -> str | None   # None, or LESS / MORE / OTHER / UNREADABLE
def clamp_items(items, slots, *, item_key="id") -> [items] | None
def fixed_ok(request, fixed, bindings=None) -> str | None
def floor_ok(request, floor, bindings=None) -> str | None
def goal_of(terms_chain) -> goal id | None
def meets(effect, terms_chain, *, purpose_map, bindings, item_key, linked="_none",
          confirmation=None, disclosures=None, request_digest=None, grant_id=None,
          requires=()) -> str | None             # "<reason>: <detail>", or None
def reason_of(why) -> reason | None
```

- **The seal** is the unpadded base64url SHA-256 of the canonical JSON of `[salt, value]`. A
  disclosure is `[salt, path, value]`; a path joins members and list indexes with `/` from the top
  of `terms` (`purpose`, `fixed/payee`, `slots/1/acceptable`). Sealable: a term member's value
  (never `goal_id`), an element of `slots`, a slot's `acceptable` or one of its elements, a value
  in `fixed` or `floor`.
- **`fixed`** compares canonical JSON byte for byte. An amount equal in value but written with
  other minor units is `OTHER` (not byte-equal); a lower or higher amount in the same currency is
  `LESS` or `MORE`.
- **`confirmation`** in `meets` is `(party that signed it, its claims)`, the signature checked by
  the caller. The confirmation must name the action's goal and the presented grant, and bind the
  action's request digest (P18's binding digest, basis as the agent's authorisation states).
- **`requires`**: the term kinds B requires for the operation. `purpose` with no purpose in any
  hop is `NOT_COVERED`; `serves` with no linked authorisation, or one that names no goal, is
  `OTHER_GOAL`.

## Module 2: `conformance/mandator.py`

```python
LINKED_HEADER, CONFIRMATION_HEADER, DISCLOSURES_HEADER = \
    "KRK-Grant-Linked", "KRK-Confirmation", "KRK-Disclosures"
PURPOSE_HEADER, GOAL_HEADER = "KRK-Purpose", "KRK-Goal"      # the agent's own statements
HEADERS                                                    # every header a landing check compares

class Seal(value)                                          # a member sealed at signing
def seal_terms(t) -> (sealed terms, [[salt, path, value]])
def plain_terms(t) -> terms as approved
class Mandate(grant, terms, disclosures)                   # .id .token .goal_id

class StubMandator(issuer.StubIssuer):
    def goal(self, *, slots=None, fixed=None, floor=None, purpose=None, confirm=None,
             text=None, sealed=(), goal_id=None) -> terms.Goal
    def issue_v4(self, subject, constraints, terms, *, principal, parent=None,
                 not_before=None, not_after=None, grant_id=None, raw=False,
                 holder=None) -> Mandate
    def restate(self, parent: Mandate, subject, terms, *, constraints=None, org=None,
                principal=None) -> Mandate            # holder-signed; never wider in a limit
    def linked(self, goal_id | None, constraints, *, principal, subject=None,
               holder=None) -> Mandate                 # terms {goal_id, serves}
    def confirm(self, m: Mandate, values, *, by="principal" | "agent", loose=False) -> str
    def present(self, chain, values, *, audience, linked=None, confirmation=None,
                disclosures=None, asserted_purpose=None, named_goal=None, loose=False,
                window_s=(-900, 900)) -> authz.Presentation

def principal_keys(keyset) -> {kid: key}     # A's active keys for purpose "grant"
def headers_digest(headers, request) -> "sha256:..."
```

The principal's key is A's grant key: the key B pins for A signs both the mandate and the
principal's confirmations. `confirm(by="agent")` signs with the mandate subject's own key
(`agent_confirmed`). The design's `restate(parent, subject, *, change)` takes the full restated
terms instead of a change.

## Module 3: `conformance/role_mandate.py`

`MandateB(role_b.RoleB)`: `term_profile()` (default `[]`), `purpose_map()` (None),
`purpose_map_source()` (None; `{quote, location}`), `requires_terms()` (`{}`;
`{operation: [kinds]}`), `term_bindings()` (`{}`; `{operation: {term member: request member}}`),
`item_key()` (`"id"`), `condition_mode()` (`"none"`; `refuse` or `hold`), `hold_resolution_s()`
(None), `disclosure_profile()` (None; `kirkaldy.sealed/0.1`), `mandate_profile()` (None: grant
0.4), `advisory_terms()` (`{}`), `documents_terms()` (False), `confirmation_binds_action()` (True;
KRK-M160). Optional adapter members P24 reads: `received(ref)` (`{"digest"}`, what B received,
KRK-M156, M162) and `is_repeat_refusal(answer)` (KRK-M169).

## Module 4: `conformance/properties/p24_mandate_bound.py`

`VARIANTS`, `FORMS` (43 forms) and `INFORMATION_ONLY` (`free_text/text_narrower`) as the design's
§6.5. `TRIALS = {"*": 5}`, `DEV_TRIALS = {"*": 3}`; the plan (`ACK_P24_PLAN`, or `plan=`) takes
`trials` (`"dev"`, `"published"` or a number), `variants` and `forms`.

- **Actions** carry `operation`, `ref`, `amount`, `resources`, `items` (`{item_key, quantity}`),
  `payee`, `instrument` and `execution_date`, named through B's bindings.
- **Kit operations**: `shop.checkout.complete`, `shop.order.commit` (conditioned),
  `shop.payment.execute` (linked), `data.record.read`, `data.record.delete`, `data.record.purge`.
  Purpose forms draw codes, operations and resources from B's map only (`_purpose_pick`); a form
  B's statements give nothing to draw from reads `format_gap` (`NotLanded`).
- **`NO_W_IN`**: the design's list, plus `outside_ceiling/counterparty` and `window` (W's grant
  admits nothing at B), `restated_terms/fixed_changed` (root and child fix different payees) and
  `free_text/text_narrower`.
- **`CLAMPABLE`**: `goal_items/extra_item` and `over_quantity`, credited at `recorder` and
  `b-signed` only (`clamp_credited`).
- **The stability window** (`stability_window`): B's stated hold resolution, else 10 s. It is
  waited after a trial in which any answer was pending; otherwise the recorder settles for 2 s.
- **Must land** (`must_land`): `outside_ceiling/amount` and `operation` and `unknown_term/in_terms`
  (a format gap excused), and the core forms of every kind B declares (`CORE_FORMS`), with
  `sealed` needing `slot_hidden` or `fixed_hidden`.
- **Control shapes**: `plain` (required), `conditioned`, `linked`, `holder`, each on fresh
  mandates, every sealed member disclosed. A shape that fails makes its variant (`condition`,
  `cross_goal`, `restated_terms`) read `shape_refused`.
- **Disclosure class** (`VULNERABLE_FORMS`): design §1.8, where B documents a term check
  (`documents_terms()`); `purpose` forms only where `purpose_map_source()` is stated.
- **Guards**, one function each: `truth` (KRK-M151, M152, M165), `landed_disclosures` (M154),
  `headers_digest` (M156, M162), `statements_digest` (M167), `stability_window` (M158),
  `clamp_credited` (M164), `is_wildcard_reading` (M152).

## Module 5: `known_bad/mandate_toys.py`

`ToyMandate(config, flaw)`, `make(flaw)`, `toy(config)`, `cases()`, `FLAWS` (30), `FAILS` (each
flaw's failing forms, written from the table, checked by the tests), `COLLATERAL`
(`reuses_item` also refuses `not_acceptable`'s sibling). Gate cases: `good`, `good-hold`,
`good-clamp` (pass); `bad` and `bad:<flaw>` for the 29 other flaws (fail);
`info:hold_forever` and `no-control` (inconclusive).

## Measurement-error pins

`tests/test_failure_modes_x2.py`: KRK-M150 to KRK-M169, one test each.

## Probe change log

| # | Change | Reason | Run that prompted it |
|---|---|---|---|
| 1 | First version. | P24 build. | none |
| 2 | In a published run, every `condition` and `hidden_terms` trial is watched for S whatever B answered, not only a trial with a pending answer (`STABLE_VARIANTS`, `_settle`); `extra.stability_every_trial` names the variants. The probe version moved; the fixture did not. | A B that answers refused and performs the action between 2 s and S later was missed. Pinned by `test_KRK_M158_refused_at_the_answer_and_performed_before_S_fails_when_published`. | none (found reading the design against the build) |
| 3 | Every result writes `extra.must_land_missed`, the forms that must land and did not, also when a form failed. The probe version moved; the fixture did not. | With the claim-basis rule change (`docs/CHANGE-LOG.md`, entry 8). | none |
