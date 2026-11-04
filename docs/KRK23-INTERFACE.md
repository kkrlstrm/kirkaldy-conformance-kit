# KRK-23 (P23) reversibility as declared: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p23_reversibility.py`. Where it says "the design", it means the property's
design document, X10, which is not part of this copy of the kit; this file and the docstring are
what the code does.

## Decisions that bind the build

- **KRK-23** outside code, **P23** in code. Graded side B. The kit plays A and A′
  and owns the world and its downstream parties.
- **One property, three clauses**, reported apart in `extra["clauses"]`: (a) class truth
  (`reversal`, `downstream_consequence`, `window`, `compensation_effect`), (b) class ceiling
  (`class_ceiling`, `class_downgrade`), (c) answered reversal (`partition`, `overtake`,
  `duplicate`, `no_standing`, `b_initiated`, and every `done_while_present`, `dropped` or
  `record_disagrees` wherever it is seen).
- **New modules only**: `conformance/world.py`,
  `conformance/reversibility.py`, `conformance/reverser.py`, the property module and
  `known_bad/reversal_toys.py`. No file in the import closure of P16 to P21 changed, and their
  `probe_version` and `fixture_version` are unchanged. P23 imports `authz.py`, `receipts.py`,
  `requester.py` and `timing.py` unchanged; it does not import P19's module.
- **The effect is read at the world** (decision 6, KRK-M18, KRK-M113). B's answers and record are
  compared with the world, never used as it.
- **Serial trials**. Each trial starts only once every action and reversal presented before
  it has had its stated time to land (`_Run.busy_until`, KRK-M127).
- **Stricter readings decided in advance**: a B that declares an operation irreversible and
  refuses its reversal passes; a B that defers commit until the window ends passes when the
  unreversed actions land; a reversal honoured outside the window is information.
- **No hosted targets**. No outside target was run in the build.

## Module 1: `conformance/world.py`

`World(clock)` is one partition. B is bound with `credential(label="b")` and calls it through
`connect(url, credential)`: a `LocalClient` for the in-process `world://` URL, an `HttpClient`
for `serve()`'s `http://` URL (`POST /call/<op>`, `Authorization: Bearer`).

| B-facing call | Arguments | Notes |
|---|---|---|
| `create` | `fields, email, note, links` | links are edges `src->dst` |
| `create_many` | `items, note` | one object per item |
| `update` | `object_id, fields` | merge; a member set to null is removed |
| `delete` | `object_id` | soft delete; also unlinks every live edge of the object |
| `restore` | `object_id` | existence only; links are not restored |
| `link`, `unlink` | `src, dst` | |
| `deliver` | `to, subject, body` | the mailbox's party, or `external:<to>` |
| `recall` | `message_id` | refused `already_read` once read |
| `transfer` | `frm, to, amount, memo` | integer minor units |
| `reverse_transfer` | `transfer_id` | a void; refused `funds_moved` once spent onward |
| `publish`, `retract` | `topic, body` / `item_id` | |
| `read`, `find` | `kind, eid` / `kind, **match` | reads change nothing |

Kit-facing: `mark()`, `diff(a, b)`, `changes(since, until, caller)`, `entity_at(key, seq)`,
`entity_at_time(key, t)`, `seq_at(t)`, `snapshot()`, `holdings(party)`, setup (`kit_object`,
`kit_link`, `kit_account`, `kit_mailbox`, `kit_topic`, `kit_call`), planted consequences
(`read_message`, `deliver_fanout`, `spend`), faults (`fault(mode, until, item, slow_s, hang_s)`
with `down`, `hang`, `error`, `slow`, `refuse_item`; `clear_faults`), `hold(token,
retry_after_s)` and `held_attempts(token)`. History entries carry `seq`, `t`, `caller` (`b`, `kit`,
`kit-plant`), `op`, `key`, `before`, `after`.

## Module 2: `conformance/reversibility.py`

```python
CLASSES = ("reversible", "compensable", "irreversible")
ASPECTS = ("object", "fields", "links", "balance", "delivery", "history")
RESIDUES = ("history_entry", "notice", "fee", "copy_at_subscriber", "read_receipt")
UNTIL = ("message_read", "fanout_delivered", "funds_moved")
COUNTER_EFFECTS = ("transfer", "retract", "recall", "void", "restore")
AUTHZ_V2_SCHEMA = "kirkaldy.request-authorisation/0.2"

claim_problem(claim) -> str | None
claim_for(claims, operation) -> dict | None
class_for(claims, operation, request) -> str        # conditions from the request the kit sent
class_le(a, b) -> bool
window_open(claim, *, t_e, t_q, events, tol_s, eps_s) -> "inside"|"outside"|"crossing"|"condition_held"
judge(claim, footprint, *, others, siblings, holdings, counter_ops, x_transfer, x_tokens,
      history_trace) -> Judgement
authorise_v2_claims(...), claims_problem_v2(claims), sign_v2(claims, key), verify_v2(token, pinned)
reversal_values(original_claims, original_request, *, means_operation, request_id, agent)
```

Conditions take one predicate each: `equals`, `in`, `domain_in`, `domain_not_in`. `Judgement`
carries `restored`, `aspects_not_restored`, `aspects_restored`, `residues_declared`,
`residues_undeclared`, `new_effects`, `other_touched`, `counter_effects`, `x_relanded`, and the
derived `partial` and `clean`. Vectors: `tests/vectors/krk23/vectors.json`, written by hand.

**Authorisation 0.2** is P18's 0.1 claims with `schema` changed and `max_class`, `agent`
(`{"id", "grants"}`) and `reverses` (`{"authorisation_id", "request_digest"}` or null) added. P18's
reader refuses it as malformed; `verify_v2` reads it.

## Module 3: `conformance/reverser.py`

```python
class ReversalRequester(StubRequester):
    def authorise_v2(self, request, *, operation, max_class, endpoint, agent=None, grants=None,
                     reverses=None) -> str
    def forward(self, values, *, operation, max_class, endpoint, agent, grants=None,
                label="") -> Presentation
    def request_reversal(self, original, *, means, agent, grants=None, endpoint=None,
                         request_id=None, label="") -> Presentation
    def repeat(self, p, label="") -> Presentation        # same bytes, same token
    def peer(self, name="a_prime") -> ReversalRequester   # A′, its own key
    @staticmethod
    def claim_in_request(values, cls) -> dict
    def withdraw_agent(self, agent) -> str               # A's signed notice
```

The design's `as_party` argument is not built: a reversal from A′ is made by calling
`request_reversal` on A′'s own requester, so the signer is always the organisation that asks. The
design's `withdraw` (P19's grant withdrawal) is replaced by `withdraw_agent`, a signed notice the
adapter presents (`present_withdrawal`) and reads back (`agent_withdrawn`), because P23's
authorisations carry the agent's grants themselves and use no P19 status list.

## Module 4: `conformance/properties/p23_reversibility.py`

`VARIANTS`, `FORMS`, `SELF_HOSTED_ONLY` and `NA_FORBIDDEN` as the design's §6.4. Trial counts:

| Plan | base `reversal` form | every other form |
|---|---|---|
| default (`TRIALS`, toys) | 30 | 5 |
| `{"trials": "dev"}` (`DEV_TRIALS`) | 5 | 2 |
| `{"trials": "published"}` (`PUBLISHED_TRIALS`) | 100 | 5 |

The base form is the form of the first operation B declares reversible or compensable whose
mode is immediate. A real target's plan comes from `ACK_P23_PLAN` (JSON, or a bare word for
`trials`); `variants` and `forms` narrow a plan.

**Which operation a form uses** comes from B's `world_profile()` (operation -> world calls, e.g.
`"objects:create"`) and its claims: `reversal/<form>` needs an operation of that world call
declared reversible or compensable (`CALL_OF`); `compensation_effect` and the duplicate forms
use a compensable operation where B declares one; `after_reapply` uses `objects:create`.
`class_absent` needs an operation in the world profile with no claim. A form with no such
operation reads `not_applicable` with the reason.

**Bounds.** R is the claim's `completion_bound_s` (30 s with none, and the missing bound is a
finding); S = `max(R, 30 s)`; H = `max(3R, R + 120 s)`; `rec` is `recovery_bound()["rec_s"]`, else
the largest R. The downstream forms alternate: even trials ask before the consequence, odd trials
after it.

## Module 5: the adapter

The design's §6.5 protocol, with these additions and changes:

| Method | Default | Use |
|---|---|---|
| `ceiling_profile()` | `None` | `"kirkaldy.request-authorisation/0.2"` when B reads `max_class`; otherwise the ceiling forms read `not_applicable` |
| `self_hosted()` | `not remote()` | the `SELF_HOSTED_ONLY` forms |
| `present_withdrawal(token)`, `agent_withdrawn(agent)` | absent | `no_standing/withdrawn_agent` |
| `documents_reversibility_control()` | `False` | the disclosure class |
| `reversal_modes()` | `["immediate"]` | entries `{"mode", "operations": [...] or "*", "commit_delay_s"}` |
| `reversal_standing()` | `None` | `{"parties", "agents": "org"|"reverse-grant", "withdrawn_agent": "keeps"|"loses"}` |
| `reversal_status(p)`, `b_record(p)` | absent | `p` is the reversal or the original `Presentation` |

`classify_reversal` answers one of `reversed`, `accepted`, `pending`, `partial`, `refused`,
`error`. A `world`-grade adapter only drives the restoration variants; at a lower grade they read
`not_applicable` and only the ceiling forms run (spec §3.8).

## Module 6: `known_bad/reversal_toys.py`

`toy(config)` for `good`, `good-deferred`, `good-conservative`, `slow-good`, `bad`, `no-control`
and `bad:<flaw>` for each of the 34 flaws in `FLAWS`. `FAILS` names the variant each flaw is built
to fail; `tests/test_p23_reversibility.py::ALSO_FAILS` names every variant each flaw fails where
that is more than one. The toy evaluates classes with its own code.

`good`'s catalogue adds two operations to the design's §4.7: `crm.contact.archive` (reversible,
soft delete) so that `reversal/object_delete` is exercised while `crm.contact.delete` stays
irreversible, and `crm.contacts.import` (reversible, several items) for `multi_item` and
`refuse_one_item`. `crm.contact.merge` has no claim (`class_absent`).

## Registration

- `conformance/properties/__init__.py`: P23 in `ALL`.
- `conformance/knownbad.py`: P23's cases and toys.
- `tests/conftest.py`: P23 in `known_bad.toys.TOYS`.
- `Makefile`: `make known-bad PROPS=P23`.
- `tests/test_known_bad_gate.py`: its list of properties and P23's cases.
- `tests/test_catalog.py`: KRK-M96 to KRK-M112 (P22's, built elsewhere) may be skipped.
