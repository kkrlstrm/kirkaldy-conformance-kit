# KRK-21 (P21) no widening along a delegation chain: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p21_no_widening.py`. Where it says "the design", it means the property's
design document, X5, which is not part of this copy of the kit; this file and the docstring are what
the code does.

**Probe change log (spec §3.10).** Each change applies to every target; results recorded under
the earlier probe lapse.

| Logged | Change | Reason, and the run that prompted it |
|---|---|---|
| KRK-M95 | every static trial waits for a pull-only B's fetch | a development reading of the reference implementation |
| KRK-M95b | `root_exceeds_standing/before_first_fetch`; the control measures B's poll | the KRK-M95 wait hid a pull-only receiver that acts before its first fetch |
| KRK-M95c | `incomplete_chain`; holder-only mode; the depth count; the disclosure-class rule; `library-decision` | a review of what P21's fixtures could show |
| KRK-M148 | claim basis, for every property: the runner judges P21 on claimed forms only, from the adapter's `not_claimed()` and `claim_basis()`; the probe and its hash are unchanged (`docs/CHANGE-LOG.md`) | spec §3.4 |
| CHANGE-LOG 12 | registered delegation formats (`conformance/delegation_formats.py`) and the made-up example format, with its toys in the known-bad gate; `extra.must_land_missed` | an adapter outside the kit must be able to write its product's delegation format without that format's code being part of the probe |

## Decisions that bind the build

- **KRK-21** outside code, **P21** in code. Graded side B.
- **The outcome is graded**: `clamped` and `chain_refused` both pass; the result's
  `extra.modes` says which per variant.
- **Six dimensions** with written semantics in `conformance/attenuation.py`; a dimension or
  format feature B cannot carry is a format gap, a finding, never a pass. The result names the
  dimensions covered (`extra.dimensions_covered`) and those not expressible.
- **Constraints are critical**; `advisory_members()` is read and recorded.
- **Wider grants are genuinely signed**: `delegate_wider` raises unless the child really is
  wider; `delegate_v2` raises if it is.
- **Holder hops**: a B that takes none reads `not_applicable` at the `holder` position.
- **`narrowed_parent`** is timed with P19's harness, unchanged, in this module. A trial
  within T has a mode, from the requests inside the narrowed ceiling sent after `t_n + T`:
  accepted is `clamped`; all refused is `chain_refused`, a pass. The narrowed parent makes the
  child a wider hop, so a strict B refuses the whole chain. The trial's evidence keeps the
  observation as `observed: narrowed_as_withdrawn` beside `mode: chain_refused`; an earlier
  version read it `narrowed_as_withdrawn`, information.
- **One request rests on one chain**; **incomparable numbers are refused**;
  **`translated_hop`** is P21's delegated case; **the root against the standing** uses P20's
  assertion where B reads limits; **a hang on a cycle** is information; `too_deep`
  for a B that states no maximum chain is a finding, also when its adapter declares
  `stated-depth` and `max_depth()` returns None.
- **New modules only**.

## Module 1: `conformance/attenuation.py`

```python
DIMENSIONS = ("max_amount", "operations", "resources", "audience", "window", "delegation")
GRANT_V2_SCHEMA = "kirkaldy.grant/0.2"
def constraints_problem(c) -> (reason, detail) | None     # malformed | unknown-constraint
def grant_v2_problem(claims) -> (reason, detail) | None
def allowed(chain, standing=None) -> Allowed | Refusal
    # Refusal reasons: malformed, unknown-constraint, cycle, self-parent, two-parents,
    # not-rooted, depth-exceeded. Allowed.hops_wider lists each wider hop.
def wider(child, parent) -> [dimension]
def inside(request, allowed, *, bindings=None, at=None, tolerance_s=0, party=None) -> why | None
def normalise_amount(amount) -> (value, currency, minor_units) | None
def amount_le(a, b) -> bool | None                       # None: not comparable exactly
def covers(parent_pattern, child_pattern) -> bool        # exact id, or a trailing "/*"
```

Grant 0.2 claims: `grant_id`, `issuer`, `subject`, `agent_key`, `principal`, `constraints`,
`parent`, `issued_at` (ms), `not_before`, `not_after` (whole seconds, both required), `status`,
and optionally `audience` (one party) and `crit`. Vectors: `tests/vectors/krk21/vectors.json`
(written by `make_vectors.py`, every expected answer by hand: thirteen pattern cases, eleven
amount cases, thirteen hop cases, fifteen chains, ten requests, three standing limits).

## Module 2: P21's parts of `conformance/issuer.py`

```python
issue_v2(subject, constraints, *, principal, parent=None, not_before=None, not_after=None,
         grant_id=None, crit=None, raw=False, audience_claim=None, omit=(), holder=None)
delegate_holder(parent, subject, constraints=None, *, org=None, principal=None, ...,
                parent_id=None, check=True)
delegate_v2(parent, subject, constraints, *, signer="a" | "holder", org=None)
delegate_wider(parent, subject, *, dimension, value, signer="a" | "holder", org=None, window=None)
cycle(subjects, *, kind="id" | "self", principal, constraints, signer="a" | "holder", org=None)
with_member(like, member, value, *, crit=None, omit=())
issue_v1(subject, operation, ceiling, *, principal, parent_id=None, grant_id=None, ..., omit=())
under_raw(tokens, values, *, audience, subject, holder, grant_id, operation, loose=False)
```

A second chain travels in `KRK-Grant-2` / `KRK-Grant-Chain-2` (`issuer.GRANT2_HEADER`,
`CHAIN2_HEADER`). P19's `narrow` narrows a parent; `read_back` reads 0.2 grants too.

## Module 3: `conformance/properties/p21_no_widening.py`

```python
VARIANTS, FORMS, POSITIONS = ("a", "holder"), POSITIONED   # as the design's §6.4
TRIALS = {"*": 5, "narrowed_parent": 5};  DEV_TRIALS = {"*": 3, "narrowed_parent": 2}
NA_FORBIDDEN = ("control", (wider_child, amount), (middle_narrow, amount),
                (dropped_constraint, omitted), (unknown_constraint, in_parent),
                (unknown_constraint, in_child), (cycle, id_cycle), (cycle, self_parent),
                (numeric, precision), (numeric, negative))
def fixture(variant, form, rng, *, party, dims, max_depth, mapping, tolerance) -> Fixture
def truth(fixture, *, now, at, tolerance_s, party) -> dict    # the kit's own reading
def probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result
```

Adapter statements read before the run (`role_b.RoleB` defaults): `grant_profile()` (None = 0.2;
or `kirkaldy.grant/0.1`), `constraint_profile()` (`["max_amount"]`), `format_features()` (none; of
`operation-lists`, `second-chain`, `mappings`, `stated-depth`, `crit`, `units`, `currency`,
`standing-limits`), `constraint_bindings()`, `advisory_members()`, `mappings()`, `max_depth()`,
`accepts_holder_hops()`, `issuers()` (C is bound with `bind_peer` where B takes holder hops),
`standing_channels()` and `keys_from()` (P20's, for KRK-M95 below), and the optional
`documents_attenuation()` (disclosure).

**Waiting for B's fetch** (KRK-M95). For a B whose standing channels are pull
only, `root_exceeds_standing` presents once B has fetched W's and L's root principals'
assertions, and where B also reads standing limits (`standing-limits`) every static trial does,
A's 404 counting as an answer; where B reads key statements (`keys_from` `statement`), a holder-position chain
through a hop C's agent signed presents once B has fetched C's key statement, which lists C's
agents' keys for purpose `request`. Recorded as `fetched_before_present`. The
wait's limit is P19's, `max(2 P, 5 s) + 1 s`; for a pull-only B that reads standing limits the
control measures P from B's fetches of the control principal's standing, and each wait re-reads
it (KRK-M95b; before, P was measured only in `narrowed_parent`).

**Before B's first fetch** (KRK-M95b). `root_exceeds_standing/before_first_fetch`
presents W (inside the chain, above the standing limit A publishes) to a pull-only B at once,
before B has fetched anything for its root principal, and grades W's effect alone: an effect is
`outside_effect`, any refusal is `held` (mode n/a). L and W-in are not presented; the trial
records `presented_before_fetch`. Not applicable to a B that is not pull-only.

**Incomplete chains** (KRK-M95c). `incomplete_chain`, a vulnerable variant,
presents chains that do not reach a root: `stops_before_root` (root, middle and leaf signed; the root
withheld), `no_ancestors` (a child with none of its ancestors) and `mutual_no_root` (two grants naming
each other). W must be refused; L is the chain made complete and rooted; W-in is not presented. In the
first two the withheld ancestor's bound excludes W's request. `Fixture.present` lists the hops sent
(the rest are signed and recorded in the trial's `withheld`); `Fixture.presented` names the presented
grant of a cycle. All three are in `NA_FORBIDDEN`. Before this, every chain P21 sent was complete, so a
B that never requires a root passed every form.

**Holder-only.** A B whose optional `delegation_forms()` returns `["holder"]` runs holder-only: the control presents the holder-signed
two-hop chain only; every variant runs at `holder` (positioned forms keyed `<form>@holder`, the rest
under their own name); each positioned form at `a` reads `format_gap` (`POSITION_A_GAP`), and the
gaps list one entry `position/a`. The forms in `NA_FORBIDDEN` must land at `holder`. A holder-only B
must state a holder organisation (`accepts_holder_hops()` and `issuers()` > 1), or the run is
inconclusive.

**Depth.** `max_depth()` counts grants, the root included. `run.json` records `statements.depth`
(`stated`, `used`).

**Registered delegation formats** (`conformance/delegation_formats.py`). `grant_profile()` may
name a format registered with `delegation_formats.register_profile(name, fmt)`, where `fmt` is a
`DelegationFormat`. An adapter registers its product's format from its own directory, so the
format's code is hashed as adapter code. P21 applies the format's statements before the run:
`delegation_forms` `("holder",)` runs holder-only; `cannot_carry` features are removed from
`format_features()` and those the adapter stated are recorded in `statements.not_carried_by_profile`;
`carries` features are added; `max_grants` bounds `max_depth()` (the smaller is used, and
`statements.depth` records `profile_limit`, `profile_quote` and `reading`); `status_gap` makes
`narrowed_parent` a `format_gap` with that reason. Per run: `open(clock, orgs)` before B is bound
(C is made first, so the state can name both organisations), `anchor(state, org)` members merged
into each trust anchor, `write_chain(state, hops, *, org, holder_org, holder, principal, now,
utc_s, presented)` for every chain (grants in fixture order, each with `id`, `token`, `subject`,
`signer`, `holder`), and `close(state)`, also after a run that raised. The kit's example,
`EXAMPLE` (`example-delegation/1`), is made up: holder-only, no crit list, one chain per request,
a limit of five grants and no status reference. `register_profile` refuses a name the kit's own
grants use, and a second format under a name already taken.

**Must-land forms.** `extra.must_land_missed` lists the forms in `NA_FORBIDDEN` (at `holder` for a
holder-only B) that have no verdict and are not a format gap or not applicable, also when a variant
failed, so the claim-basis rule can read a claimed-only pass that rests on them as inconclusive.

**Disclosure class.** `outside_parent_bound(fixture, now=, at=, tolerance_s=, party=)`
says which bound, stated by a grant above W's presented grant (withheld grants included), W's request
lies outside, or None. A failing form of a variant in `VULNERABLE_VARIANTS` is vulnerability class
only where it is not None. Fail-safe: a member such a grant states that the vocabulary cannot read,
or an amount it cannot read exactly, counts as a bound the effect may exceed, and a chain with no
root rests on no bound A stated. Each trial records `parent_bound`; the result's
`extra.disclosure_forms` gives each failing form's class and bound, and `extra.disclosure` is
`vulnerability` when B documents attenuation and any failing form is. The forms of vulnerable
variants that read conformance by construction: `dropped_constraint/empty_list`, `null_member`;
`wildcard_default/default_window`; `combined` (all three); `unknown_constraint/in_child`,
`marked_critical`; `numeric/negative`.

**Grades**. `GRADES` is P19's ladder and `library-decision`, below `b-response`. A
result at `library-decision` starts its summary "Library-level reading" and carries
`extra.level: "library"` (`"deployed"` otherwise).

**Every trial**: the kit builds W, L and W-in in its own vocabulary, checks with `truth` that W's
request lies inside the leaf and outside the intersection and that L's and W-in's lie inside
(raising if not: the fixture would not mean what it says, KRK-M81, M83), signs the chains in B's
grant profile, and presents L, W and W-in in a seeded order. **Grant 0.1** carries `max_amount`
(an integer), one operation per grant and the window; the rest are format gaps.

**Departures from the design's §6.** `wider_child`/`operations` uses one operation per grant (the
parent's and another), so a format with one operation per grant can say it; `default_window`
presents while the parent is valid (the child's missing end is the only fault); `time_before`
starts the parent beyond B's tolerance; delegation depth appears only in the forms about it.

## Module 4: `known_bad/attenuation_toys.py`

`ToyAttenuation(config, flaw=None, *, T=60.0, clock="virtual")`, `make`, `toy`. `FLAWS` (22),
`FAILS`, `FORM`, `PULL_ONLY_FLAWS`; `good` (clamped), `good-strict` (chain refused), `pull-good`
(`good`, reading standing only by fetching it, as the reference implementation's `limits` channel
does; KRK-M95b), `bad` (`leaf_only`), `no-control`, `bad:hangs_on_cycle` (information);
`bad:chain_before_fetch` reads as `pull-good` does; `bad:walks_supplied_only` reads the last grant
supplied as the root (KRK-M95c). `ToyExampleFormat(flaw=None)` reads the example delegation format
only, holder-only (`example-good`; `example-bad:<flaw>` for each flaw in `EXAMPLE_FLAWS`, which is
`leaf_only`); its reader shares no code with the writer. `ToyAttenuation._leaf_binding(p, chain)`
gives the kid and grant id the request's authorisation is checked against, for a reader whose ids
differ on the wire. The known-bad gate runs `good`, `good-strict`, `pull-good`, `bad`,
`no-control`, one `bad:<flaw>` per flaw, `example-good` and one `example-bad:<flaw>` per example
flaw (29).
