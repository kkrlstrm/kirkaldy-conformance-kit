# KRK-22 (P22) cumulative ceiling across counterparties: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p22_cumulative_ceiling.py`. Where it says "the design", it means the
property's design document, X9, which is not part of this copy of the kit; this file and the
docstring are what the code does. Built in the kit only, with the kit's correct toys as the public
known-good.

**Probe change log (spec §3.10).** Each change applies to every target; results recorded under
the earlier probe lapse. The kit-wide log is `docs/CHANGE-LOG.md`.

| Logged | Change | Reason, and the run that prompted it |
|---|---|---|
| KRK-M148 | claim basis, for every property: the runner judges P22 on claimed forms only, from the adapter's `not_claimed()` and `claim_basis()`; the probe and its hash are unchanged (`docs/CHANGE-LOG.md`) | spec §3.4 |
| KRK-M210 | `reversal/confirmed` takes the declared reversal rules in turn, trial by trial, `gross` first, in place of a seeded draw per trial (`_make_fixture`); the probe version moved, the fixture did not | the kit's own known-bad gate: `a-bad:nets_under_gross` read pass under some seeds, where every trial drew `net-recorded` |

## Decisions that bind the build

- **KRK-22** outside code, **P22** in code. **Two roles**, each graded in its own run:
  role A, the holder (`role_ceiling.Holder`), with the kit playing the agent and every spender; role
  B, a spender (`role_ceiling.SpenderB`), with the kit playing A, the holder and stub B2.
- **Counts judge; times place.** Every verdict is a sum of effects at the kit's recorder
  (`ceiling.charges`, `ceiling.judge`). The holder's own account is information (`over_counted`,
  `ledger_behind`), never a verdict (KRK-M96). Verdicts need the `recorder` grade.
- **Hard ceiling**, graded against the ceiling plus a documented overshoot where the target states
  one, quoted before the run (`ceiling_profile()["overshoot_kit"]`).
- **Over-counting is information**; **reversals are gross by default** and free headroom only
  under `net-recorded`, and only on the spender's recorded reversal; **children share their
  ancestors' account**; **no conversion, every limit holds**; **windows on absolute
  anchors**, judged on the kit's clock with the offset search; **refusing while partitioned is
  information** (`offline_window`); **race evidence** as P18 reads it; **new modules only**; **self-hosted only** in
  version 1; a format with **no cumulative ceiling** reads not applicable.

## Module 1: `conformance/ceiling.py`

```python
GRANT_V3_SCHEMA = "kirkaldy.grant/0.3"                 # typ krk-grant+jws, as 0.2
RESERVATION_SCHEMA, RESERVATION_TYP = "kirkaldy.reservation/0.1", "krk-reservation+jws"
SPEND_SCHEMA, SPEND_TYP = "kirkaldy.spend/0.1", "krk-spend+jws"
FORWARD_SCHEMA, FORWARD_TYP = "kirkaldy.forward/0.1", "krk-forward+jws"   # not in the design
LIMIT_KINDS, WINDOW_KINDS, REVERSAL_RULES, MECHANISMS, TOPOLOGIES
SCALE = 18                                              # amounts in 10^-18 of the currency
def cumulative_problem(c) -> (reason, detail) | None    # malformed | unknown-constraint
def grant_v3_problem(claims) -> (reason, detail) | None # 0.2's rules plus `cumulative`
def reservation_problem(c), spend_problem(c), forward_problem(c) -> str | None
PROBLEMS = {typ: shape check}                           # for standing.verify(problem_of=...)
def reservation_claims(...), spend_claims(...), forward_claims(...) -> dict
def quantity(values, limit, *, bindings=None) -> int | None   # exact, kit units; None: uncountable
def values_quantity(values, limits) -> [limit-shaped] | None
@dataclass(frozen=True) class Charge(effect_ref, spender, ceiling_ids, quantities, t_kit, sign,
                                     reverses, attributed)
def charges(effects, issuance, *, bindings=None, ceilings, default_ceiling_ids=()) -> [Charge]
def account(charges, *, ceilings, rule="gross") -> {cid: {"totals", "uncountable"}}
def window_feasible(charges, limit_index, ceiling_id, window, limit, *, anchor_kit, tolerance_s,
                    commit_lag_s=0.0, rule="gross") -> (passes, worst)
def judge(charges, ceilings, *, rule, tolerance_s, commit_lag_s, overshoot) ->
    {"within", "excess", "windows", "where", "uncountable", "totals"}
def attribution(charges, confirmations, spender, *, limits, ceiling_id, rule) ->
    {"totals", "confirmed", "over", "uncountable"}
```

An effect the ceiling cannot count (another currency or count unit, a float, beyond 2^53 - 1) that
was committed is itself outside the ceiling. A negative spend frees nothing. Vectors:
`tests/vectors/krk22/vectors.json`, written by `make_vectors.py` with every answer by hand: 14
quantity cases, 12 accounts (sums across spenders, mixed minor units, another currency, both
reversal rules, a negative spend, two- and three-hop chains, a holder hop, two limits, the 2^53
boundary, an unattributed effect), 10 judgements (including a documented overshoot and one unit
short of it), 12 windows (fixed offset searches on and either side of boundaries, rolling windows
with tolerance and commit lag), 5 attributions.

## Module 2: `conformance/ledger.py`

```python
class StubHolder(issuer, *, mechanism="reservation"|"allocation"|"online", expiry_s, tolerance_s,
                 capture_lag_s, rule="gross", clock=None)
    open_root(principal, limits, *, window=None, rule=None, agent=None, per_request=None) -> Grant3
    allocate(root, spender, limits) -> Grant3 | None     # a share, signed by the holder
    learn(grant)                                          # a child's own ceiling
    reserve(req) / authorise(req) / capture(req) / release(req) / reverse(req)
    set_reachable(spender, "up"|"down"|"hang"|"error"); set_clock_offset(s);
    fail_next_captures(spender, n); log(); confirmations(spender); account(cid)
    serve() -> url; serve_local() -> url
class StubSpender(name, *, recorder_url, profile="kirkaldy"|"forwarding", clock, effect_delay_s)
    bind_holder(anchor, url, deliver=None); present({"issuance"|"forward", "values", "ref"});
    set_report("deliver"|"drop"|"hold-until-heal", delay_s=0); set_clock_offset(s);
    reverse(effect_ref, values, *, ref, ceiling_ids, quantity) -> reversal ref
issue_root(A, subject, cumulative, *, principal), delegate(A, parent, subject, *, own=None,
holder_hop=False, org=None), reissue(A, root), verify_chain(tokens, anchors), call_holder(url,
route, doc), call_spender(url, doc), request_digest(values)
```

Grant 0.3 roots are signed with `issuer.StubIssuer`'s grant key; children by A or, for a holder hop,
by the parent's agent key (`standing.verify_holder_chain` reads both). Nothing in `issuer.py`
changed.

## Module 3: `conformance/role_ceiling.py`

`Holder` (Protocol): `role`, `mechanism`, `topology`, `ceiling_profile`, `constraint_bindings`,
`terms`, `open_root`, `bind_spender`, `holder_keys`, `request`, `classify`, `evidence_grade`; optional
`HOLDER_OPTIONAL` (`overshoot`, `delegate`, `reissue`, `regrant`, `cancel`, `claim_reversal`,
`deliver`, `account`, `read_back`, `restart`, `replicas`, `partition_replicas`, `max_in_flight`,
`documents_hard_limit`, `variants_not_applicable`, `exposes_times`, `set_clock`, `sessions`).
`SpenderB(RoleB)`: `mechanism` (`allocation`), `ceiling_profile` (`{}`), `terms`, `bind_holder`,
`reports`, `spender_identity`, `endpoints`, `max_in_flight`, `documents_hard_limit`.

`ceiling_profile()` is a dict: `limit_kinds`, `currencies`, `windows`, `reversals`, `features`
(`delegation`, `holder-hops`, `reversals`, `sessions`), `min_window_s`, `holder_hops`, and
optionally `overshoot` / `overshoot_kit`. `terms()` maps `expiry_s`, `tolerance_s`,
`capture_lag_s`, `commit_lag_s`, `propagation_s` to `{"value", "source"}`.

## Module 4: `conformance/properties/p22_cumulative_ceiling.py`

```python
ROLES = ("A", "B"); VARIANTS; FORMS; ROLE_FORMS = {"A": ..., "B": ...}; MECHS
K = {"two_bs": 2, "n_way": 8, "endpoints": 4, "with_other_spenders": 2}
TRIALS = {"*": 5, "concurrent": 30, "timed": 5}; DEV_TRIALS = {"*": 3, "concurrent": 10, "timed": 2}
NA_FORBIDDEN = {"A": (...), "B": (...)}                 # as the design's §6.4
def fixture(variant, form, rng, *, role, mechanism, limits=None, window=None, rule="gross")
def truth(fixture) -> dict                              # raises if the fixture means nothing
def probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result
```

A plan (`ACK_P22_PLAN`, or `plan=`) takes `trials` (`dev`, `published` or a dict), `variants`,
`forms` and `expiry_s`. Concurrent forms try up to twice their count to get that many overlapping
rounds. The result's `extra` carries `forms` (every form's reading), `race` (overlapping rounds and
the rule-of-three bound per concurrent form), `information` (per form), `format_gaps`, `disclosure` and the statements.

## Module 5: `known_bad/ceiling_toys.py`

`ToyHolder(config, flaw=None, *, mechanism=None, clock="virtual")`, `ToySpender(...)`, `make_a`,
`make_b`, `make`, `toy`, `cases`; `FLAWS_A` (30), `FLAWS_B` (25), `FAILS_A`, `FAILS_B`,
`ALSO_FAILS_A`, `ALSO_FAILS_B` (forms a flaw is stated to fail besides its own), `MECH_B`, `GOOD_A`
(`good`, `good-allocation`, `good-online`, `good-forwarding`, `good-strict`, `slow-good`),
`GOOD_B` (`good`, `good-allocation`, `good-strict`, `slow-good`), `INFO_A`/`INFO_B`
(`charges_retries`). Gate configurations are `a-…` and `b-…`: every good toy must pass, `a-bad`
(`per_b_counter`), `b-bad` (`per_request_only`) and each `bad:<flaw>` must fail,
`a-no-control`/`b-no-control` must give no verdict, `info:charges_retries` must pass.

## Registration

`conformance/properties/__init__.py` lists P22; `conformance/knownbad.cases("P22")` returns the
toys of both roles and `_toy` builds them; `tests/conftest.py` registers P22 in `known_bad.toys.TOYS`
(a plain `good`/`bad`/`no-control` is role A's). `make known-bad PROPS=P22` records the
gate. P16 to P21's probe and fixture hashes are unchanged.

## Departures from the design's §6

- **A fourth format, the forward** (`kirkaldy.forward/0.1`): a forwarding holder signs it so the
  stub spender can check that a request came from H (§2.3's "checks only that the request came from
  H" needed a statement to check).
- **The holder protocol** adds `holder_keys()` (the stubs pin them; the design's `bind_spender`
  passes only the spender's key), `regrant(root, agent)` for `redelegated/regrant`, an optional
  `session` keyword on `request`, and `exposes_times()`. `deliver(route, statement)` takes the
  route.
- **Role B's allocation share is also a pseudo-ceiling** (`share:<id>`) in the kit's account, so a
  windowed share is judged by the same window search as the root; an excess over it reads
  `over_share`. Role B under `reservation` uses `ceiling.attribution` against the holder's log, as
  designed.
- **Role B's mechanisms**: forms that the design marks for a mechanism land only under it (`MECHS`);
  the redelegated and window forms of role B land under `allocation` only.
- **The holder hop in role B** is signed by the parent's agent key into an agent whose key A's stub
  holds, not a separate organisation C (`StubIssuer.peer` was not used).
- **The sibling's ceiling** is twenty times W's (at least N times W's largest per-spender plan for
  N up to four). In `units/large_integer` W's ceiling is already 2^53 - 1, so L cannot be larger and
  L's crossing spend is not read.
- **Mapping a target's times** (an estimated offset and its uncertainty `u`, §4.4 and KRK-M65) is
  not built: the toys share the kit's clock, and a holder's `not_after` and a window's anchor are
  read with zero offset. Needed before the first outside timed run.
- **`headroom_stuck`** is not reported apart: the holder's own account counts held reservations,
  so a reservation never freed reads `over_counted`.
- **Not built**: a metering toy (the probe reads a stated overshoot, but no toy states one), and
  re-allocation of a withdrawn share after P19's T (role A's allocation toy never re-allocates).
