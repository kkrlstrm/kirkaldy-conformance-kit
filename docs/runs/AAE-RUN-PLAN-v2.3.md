# Kirkaldy test plan: KRK-21 (P21) against the AAE reference verifier, at library level

Plan version 2.3, 2026-11-10. Written and fixed before any run under it, and published before
the first one (spec §3.10). Every result made under this plan records this version and the commit
of this file. A change after any run is entered in the change log at the end, with its reason and
the run that prompted it; the plan is never rewritten silently.

Versions 1 to 2.1 (2026-11-03) were private plans for development runs at three trials per form.
Version 2.2 is the plan for the published runs: three independent runs at five trials per form,
against two commits of the verifier, the one in which a finding was reported privately and the
one that fixes it. Version 2.3 keeps version 2.2's text and moves the kit pins in §5.1 to the
kit's release 0.3. The change log summarises every earlier version.

## 0. What this version changes

- **Version 2.3: the kit pins.** The kit commit, P21's probe version and the claim-basis rule
  version in §5.1 move from the public kit at `0e16252` to the kit's release 0.3. P21's own
  module, its fixtures, its toys and the adapter are unchanged; P21's probe version moves because
  P21 imports P19's module, which release 0.3 changes. Nothing else in the plan changes.

Version 2.2's changes, all kept:

- **Two targets, one adapter.** The reference verifier at `aca8bcf` (vector set 1.6.0, the commit
  every earlier version tested) and at the commit tagged `v1.7.0` (vector set 1.7.0). The adapter
  has one configuration for each; they differ only in the commit they check (§5.2).
- **Published counts.** Five trials per form, three independent runs per target, each with its
  own recorded seed (§8).
- **The public kit.** The run uses P21 as published in the public kit, at a pinned commit (§5.1).
- **Disclosure class.** Read by the class rule of KRK-21 in spec v0.2. Where the kit's per-form
  class differs, the result reports the spec's class and records the kit's beside it (§10).
- **Every claimed form is reported**, whether or not it is part of the finding in §13 (§9.3).

## 1. Purpose

A reading, at library level, of whether the AAE reference verifier refuses a delegated request
that lies outside the intersection of the grants in its chain (KRK-21, graded on side B), with
fixtures written and signed by the tester's own keys, before and after the fix in vector set
1.7.0.

## 2. Tester and independence

- Tester: Kai Karlstrom, Kirkaldy.
- No commercial relationship or business discussion with AAE's author or CryptoKRI GmbH
  (MolTrust). Unfunded. Kirkaldy did not author AAE and contributes no mechanism to it. No
  remediation or product is offered to MolTrust.
- Contact with MolTrust has been limited to the private report of the finding this plan re-tests
  (§13) and the replies about it.

## 3. Targets

### 3.1 Repository and component

- Repository `github.com/MoltyCel/aae-conformance-vectors`. Licence Apache-2.0, NOTICE
  "Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust)".
- **Component under test:** `examples/python-verify.py`, function `verify(secured_aae, ctx)`, the
  only verifier in the repository that walks a delegation chain, reached through the repository's
  own reference adapter, `adapters/python-reference/adapter.py`, over its runner protocol
  `aae-conformance-runner/1` (family `native`). Nothing in the target is modified.

### 3.2 The two commits

| Configuration | Commit | Vector set | Status of the commit |
|---|---|---|---|
| `default` | `aca8bcf77300a07dd5552a7dcab208178616a6f6` (2026-10-30) | 1.6.0 | the commit at which the finding in §13 was reported |
| `v1.7.0` | the commit the tag `v1.7.0` peels to, read anonymously on the tag day and recorded with every run | 1.7.0 | the commit that carries MolTrust's fix |

The `v1.7.0` configuration cannot start a run until that commit is written into the adapter
(§5.2). A run against any other commit is not a run under this version.

### 3.3 Claim-basis revision

The verifier names the revision it implements: "Implements the draft-kroehl-agentic-trust-aae-00
Section 5 verification algorithm" (`examples/python-verify.py`, lines 4 and 5, at `aca8bcf`). The
claim basis is therefore
[draft-kroehl-agentic-trust-aae-00](https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-00.txt)
(-00), with
[-02](https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-02.txt) quoted beside it where
it says the same (spec §3.4). Text found only in -02 is not a claim basis for this verifier.

Before the `v1.7.0` runs, the verifier's own statement of its revision is read at the tag. If it
still names -00, §6 applies unchanged. If it names another revision, no `v1.7.0` run is made under
this version: the claim basis is re-recorded from that revision as version 2.4 and published first.

### 3.4 Runtime and environment check

- AAE runs from a fresh anonymous clone of the repository, checked out detached at the
  configuration's commit, in a uniquely named scratch directory, with the packages AAE's CI
  installs (`cryptography jsonschema jcs pytest==9.1.1` at `aca8bcf`; the line in
  `.github/workflows/conformance.yml` at the tag is read and used for `v1.7.0`) in a virtual
  environment of its own. Python and package versions are recorded.
- The kit runs in its own virtual environment; its Python version is recorded.
- **Environment check before each target's runs,** in the clone, as AAE's CI runs it:
  `examples/python-verify.py`, `examples/enforce-verify.py`, both families and resume through the
  Python runner with the reference adapter, and `tools/run_negative_controls.py`. At `aca8bcf` the
  expected counts are 15/15, 26/26, 83/83 and 11/11. At `v1.7.0` they are the counts the step
  names in `conformance.yml` at the tag state. Any other count stops that target's runs.
- The adapter refuses to start if the clone is not at the configuration's commit, if the tag
  `v1.7.0` does not peel to that commit (configuration `v1.7.0`), or if the clone has changes.
  After the runs, the clone must still be at its commit with no changes.

### 3.5 Not tested

- MolTrust's hosted evaluator, or any other MolTrust service. Kirkaldy tests a hosted service only
  under testing terms its operator publishes, or with its written permission.
- The enforce kernel (`examples/enforce-verify.py`), which evaluates one mandate against one
  transaction and walks no chain.
- Conformance as the draft's own conformance section defines it.

## 4. Library level: what this can and cannot conclude

This is a test of a verification function, not of a deployed receiver.

- **Can conclude:** whether this function, given a chain and a request built from P21's fixtures,
  answers ACCEPT for a request that lies outside the intersection of the chain's grants, form by
  form, and with which step and reason code it refuses.
- **Cannot conclude:**
  - whether any system commits an effect. There is no receiver and no recorder. ACCEPT stands for
    the decision to act. The evidence grade is `library-decision`, below every grade that reads an
    effect, and a reading at this grade is never reported at a higher one;
  - anything that changes over time at B (a parent narrowed after its child was issued,
    revocation): the function holds no state and makes no fetch;
  - whether the relying party's surrounding code is right. The current time, the outcome of step 4
    (subject binding), the consumed-id set and the DID documents are inputs (§5.3);
  - which issuers a relying party trusts as roots. That is the caller's policy, outside the
    draft's verification algorithm.

## 5. Kit, probe and adapter

### 5.1 The kit and P21

- **Kit:** the public `kirkaldy-conformance-kit` at release 0.3, commit
  `5af5c7de50266bd296930431e9dcbe94b54041d9`. This is the commit of the release as prepared; on
  the day it is replaced by the commit the release's public tag points to, and that commit is
  recorded with every result. The targets repository pins its kit (`core`) to the same commit.
  That pin is outside the adapter's directory and does not change the adapter's digest.
- **P21 at that commit:** probe
  `sha256:7df11d6b7df1583e5a6e24826750c559bb7ddc8f6ddd18b38be7ca429625310b`, fixtures
  `sha256:168d378e70db81e500fc24006a1ae8f547ea55b36433b08f3f022cfd359796a5`; claim-basis rule
  `sha256:d9990e8839e2f965505f192902beaa8a564360c6011c601626d3f8c776f517d7`. A run at any other
  probe, fixture or rule version is not a run under this version.
- **Known-bad gate:** P21's gate is recorded at these versions before the first run, and must read
  every toy as required. Its record id is reported with each result.
- If the tagged commit or a later kit release moves any of these versions before the runs, the
  runs wait for version 2.4, which names the new versions and is published first.

### 5.2 The adapter

- P21's role-B adapter for this verifier, `targets/aae/`, in Kirkaldy's targets repository. **The
  adapter is not published.** Its digest (every file in its directory and what it imports) is
  recorded with every result.
- It hands each presentation to AAE's `verify()` through AAE's reference adapter, one process per
  presentation, and returns AAE's answer. It writes no envelope, verifies no signature, compares no
  hop, checks no request against a grant and filters no presentation: AAE decides every answer.
- **Configurations.** `default` checks `aca8bcf`. `v1.7.0` checks the commit the tag `v1.7.0`
  peels to; until that commit is written in, making the adapter for it raises an error, so no run
  can start. Both configurations make the same statements and the same requests; only the commit
  and the tag they check differ. After this plan is published, the only change made to the adapter
  before the runs is writing in that commit, in a commit of its own, whose id is recorded with the
  results.

### 5.3 What the adapter sends

- `input.secured_aae`: the presented envelope, exactly as P21 sends it.
- `input.context.delegation_chain`: the ancestors P21 sends, in AAE's documented order, root
  first (P21 sends them parent first, so the list is reversed). Nothing is dropped, added or
  re-signed.
- `did_documents`: every did:web DID document that resolves, as served by the kit's DID host, for
  each DID the presented envelopes name. None is filtered.
- `current_time`: the presentation time. `requested_action` and `action_context` (`amount` and
  `currency` as written, in minor units; `domain` is B's own host) from the request.
  `consumed_ids` is empty; no revocation responses are sent.
- `subject_binding: {challenge_response_valid: true}` for every presentation. AAE takes step 4's
  outcome as an input. Beside each answer, and never read into it, the adapter records whether the
  kit's per-request authorisation verifies under the presented subject's `authentication` key, so
  the result shows that a relying party running the challenge-response would have reached the same
  outcome.
- An answer `ACCEPT` is read as accepted, `REJECT` as refused (step and reason code recorded). A
  non-zero exit, output that is not JSON, or no answer within AAE's 10 s limit is `error` or `hung`,
  never accepted.

### 5.4 The envelope profile and statements

- **Profile `aae-02`.** P21's stand-in writes and signs every envelope at fixture time with its own
  keys, once. A root is signed by the root organisation as its issuer. A delegated envelope is
  signed by its parent's subject, which is its issuer and `delegator_did` (-00 §5 step 1, case
  (a)). AAE's test keys are not used.
- **Holder-only.** The verifier's only delegation form is holder-signed. The control and every
  positioned form run at position `holder`; P21's position `a` (one organisation signs every hop)
  has no form in this verifier and is not claimed (§6.2).
- **Depth.** The adapter states a maximum of 9 envelopes, quoting -02 §5 step 9 ("the smaller of 8
  and the smallest max_depth observed anywhere in the chain"). This decides only `cycle/too_deep`,
  which is not claimed (§6.2).
- **Grade** `library-decision`; the result is labelled a library-level reading.
- **Statements:** constraint profile `max_amount`, `operations`, `audience`, `window`,
  `delegation`; format features `operation-lists`, `stated-depth`, `crit`, `currency`; holder hops
  accepted; two issuers; no standing, status or withdrawal channel; clock tolerance 0 s;
  attenuation documented (-00 §3: "Delegated AAEs MUST NOT grant actions not present in the parent
  AAE. Delegated AAEs MUST be strictly subordinate to their parent AAE").

## 6. Forms and claim basis

Every form P21 runs, with the -00 text that states the verifier does what the form tests. A form
with no claim reads `not_claimed`: it is reported, never counted against AAE, and leaves the
verdict (spec §3.4). The adapter states the same table to the kit, which applies it.

### 6.1 Claimed

| Form (at `holder`) | AAE's claim, quoted from -00 | Where |
|---|---|---|
| control | "If the AAE contains a delegation field, the relying party MUST verify every ancestor AAE in the chain." | §5 step 9 |
| `wider_child/amount`, `numeric/large_integer` | "The delegated value MUST be less than or equal to the parent value." | §3 |
| `wider_child/operations` | "The delegated mandate.actions MUST be a subset of the parent mandate.actions." | §3 |
| `wider_child/audience` | "The delegated value MUST be a subset of the parent value." (allowlist constraints) | §3 |
| `wider_child/time_after`, `time_before` | "The delegated validity.not_before MUST be greater than or equal to the parent validity.not_before, and the delegated validity.not_after MUST be less than or equal to the parent validity.not_after." | §3 |
| `middle_narrow/amount`, `operations` | "For each delegation link, the relying party MUST verify ... that constraint monotonicity and depth limits hold as defined in Section 3." | §5 step 9 |
| `wildcard_default/wildcard_operation` | the actions subset rule above; -00 defines no wildcard: "Each string is a permitted action identifier." | §3, §2.2 |
| `wildcard_default/default_audience` | "Every constraint present in the parent AAE that is marked required: true, or for which the required member is absent and is therefore treated as required: true (Section 2.3), MUST also be present in the delegated AAE" | §3 |
| `wildcard_default/default_window` | "not_after: REQUIRED." · "Reject the AAE if any required member is absent, has the wrong JSON type, or otherwise violates the structural requirements of this document." | §2.4; §5 step 2 |
| `combined/two_parents` | "delegator_aae_id: REQUIRED in delegation context. The id of the parent AAE." · "If a relying party cannot determine whether a delegated element is equal to or more restrictive than the corresponding parent element, the delegated AAE MUST be rejected." | §3 |
| `delegation_exceeded/not_delegable`, `depth_exceeded` | "A relying party MUST reject a delegated AAE whose depth exceeds its max_depth, and MUST reject any delegation whose parent is a root AAE that has no delegation_policy." | §3 |
| `cycle/id_cycle`, `cycle/self_parent` | "To detect cycles, the relying party MUST maintain the set of AAE id values already visited in the current verification path and MUST reject the chain immediately if any id appears more than once." | §5 step 9 |
| `unknown_constraint/in_parent` | the required-constraint rule above, and the "cannot determine" rule above | §3 |
| `unknown_constraint/in_child` | "If a constraint is unrecognized, the relying party MUST reject the AAE unless that constraint is explicitly marked required: false." | §5 step 7 |
| `unknown_constraint/marked_critical`, `near_name` | "A relying party MUST reject an AAE if any constraint marked required: true is unrecognized or cannot be evaluated." | §2.3 |
| `numeric/precision` (where the child's value is above the parent's) | "max_transaction_value: Maximum value of any single transaction. MUST include value (number) and currency (ISO 4217)." and the monotonicity rule above | §2.3; §3 |
| `numeric/currency` | "the delegated constraint MUST use the same currency as the parent constraint" | §3 |
| `numeric/encoding` | "MUST include value (number)" · "Reject the AAE if any required member is absent, has the wrong JSON type" | §2.3; §5 step 2 |
| `incomplete_chain/stops_before_root`, `no_ancestors` | "If the AAE contains a delegation field, the relying party MUST verify every ancestor AAE in the chain." · "A relying party MUST be able to retrieve the parent AAE in order to verify a delegation chain." (-02 §5 step 9: "if no supplied ancestor carries that id, the verdict is DENY") | §5 step 9; §3 |
| `incomplete_chain/mutual_no_root` | the same, and the cycle rule above | §5 step 9; §3 |

### 6.2 Not claimed

| Form | Why |
|---|---|
| every positioned form at P21's position `a` | -00 allows an organisation to sign for its agent only where the delegator's DID document authorises it, and this verifier states no such form ("or, for case (b), the relying party does not understand the authorization mechanism — the AAE MUST be rejected", §5 step 1) |
| `wider_child/resources`, `middle_narrow/resources`, `wildcard_default/prefix_broader`, `dropped_constraint` (`omitted`, `empty_list`, `null_member`) | -00 defines three constraint types (`max_transaction_value`, `allowed_domains`, `rate_limit`), none a resource pattern (§2.3). AAE's rule for a dropped constraint is read through `default_audience` and `unknown_constraint/in_parent` |
| `combined/union_dimensions`, `combined/summed_amount` | -00 verifies one envelope and its ancestors (§5) |
| `translated_hop/mapping_widens`, `mapping_undeclared` | no mapping between action names is declared |
| `cycle/too_deep` | the limit of 9 envelopes is -02 text; -00 leaves the recursion limit implementation-defined ("no greater than the smallest max_depth value observed in the chain", §5 step 9) |
| `numeric/units` | AAE's value is a number with no minor-units member (§2.3) |
| `numeric/negative` | the constraint is a "Maximum value of any single transaction" (§2.3); neither revision states a lower bound. Reported as information, since -00 documents the action `pay` (§4) |
| `numeric/precision` where the request is outside only because the kit requires a whole number of minor units | AAE's value has no minor units |
| `root_exceeds_standing` (`amount`, `resources`, `before_first_fetch`) | AAE has no evidence of the root principal's standing |
| `narrowed_parent` | not applicable: the function holds no state and reads no status |

## 7. Stricter than required, written before the run

Spec §3.10 rule 2: a target that refuses more than a property requires is not failed for that
refusal, provided it stated the choice before the run in its documentation. The choices -00 states,
which this plan reads as stated:

- **Required parent constraints carry to the child** (§3, the required-constraint rule above). A
  sibling L refused for this reads `collateral_refusal`: information, never a fail.
- **Windows nest** (§3). A child refused for a window wider than its parent's, though used inside
  it, is AAE's stated choice.
- **Allowlists and actions compare as exact sets** (§3, "a subset of the parent value").
- **A differing currency is refused** (§3).
- **An organisation signing for its agent is refused** unless the mechanism is understood (§5
  step 1). This is why position `a` is not claimed.

## 8. Counts, seeds and order

- **Trials:** P21's published counts, five trials per form (`ACK_P21_PLAN={"trials":
  "published"}`), which makes each run a published run: the kit refuses to start it if any form
  is neither claimed with a basis nor stated not claimed.
- **Runs:** three independent runs per configuration, each with a seed drawn by the runner from
  the operating system's random source and recorded. No seed is chosen or re-drawn.
- **Order:** the environment check (§3.4) for `v1.7.0`, its three runs, then the environment check
  for `default` and its three runs. A run that stops on an error is reported and the next run is
  not started until the cause is known.
- Every form is judged in every run.

## 9. Reading the result

### 9.1 Per trial and per form

P21's outcomes: `held` (with mode `clamped`, `chain_refused` or `n/a`), `outside_effect`,
`collateral_refusal`, `shape_refused`, `hung`, and `error`. Per form within a run: any
`outside_effect` reads `outside_effect`; all counted trials held reads `held`; otherwise the most
frequent information outcome.

### 9.2 Per run and per configuration

- A run whose control does not hold gives no verdict.
- Each run's verdict is read on claimed forms only (§6): `fail` if a claimed form reads
  `outside_effect`, `pass` if every claimed form holds, otherwise `inconclusive`.
- **A configuration's result** combines its three runs: `fail` if any run fails; `pass` only if
  all three pass; otherwise `inconclusive`. Each form's reading is reported for each run, and any
  form whose reading differs between runs is named.

### 9.3 What is reported

Every claimed form, for both configurations, with its reading and class, in one table, whether
or not it is part of the finding in §13. A claimed form is never left out of the table because its
class is conformance. Not-claimed forms are listed with their reason and, where §6.2 says so, with
their reading as information.

## 10. Disclosure class

The class of each failing claimed form follows KRK-21's class rule in spec v0.2: conformance;
vulnerability where the product documents that delegated authority can only narrow and the effect
lies outside a bound that a grant above the presented one states (withheld grants included). A
member of such a grant that cannot be read, or an amount that cannot be compared exactly, counts as
a bound the effect may exceed, and a chain with no root rests on no bound the root issuer stated.
AAE documents that delegated authority only narrows (§5.4).

The probe's per-form class (`extra.disclosure_forms`) is recorded as the probe gives it. At the
kit commit in §5.1 the probe assigns a per-form class only to variants on its list of vulnerable
variants, which does not include `cycle`, so it reads a failing `cycle/id_cycle` or
`cycle/self_parent` as conformance. Neither chain has a root, so under the spec's rule both are
vulnerability. Where the two differ, the result reports the spec's class and records the probe's
beside it. Aligning the probe with the spec is a probe change, made separately under spec §3.10 and
logged in the kit's change log; it is not part of these runs.

## 11. Expectations, written before the runs

The adapter's expectations file states a prediction for every form, for each configuration. It
was committed before any run it covers (the `v1.7.0` predictions on 2026-11-10, before the tag),
is not edited after, and is available with the raw evidence on request (§12). In summary:

- **`aca8bcf`:** the control holds; the three `incomplete_chain` forms and the two claimed `cycle`
  forms read `outside_effect`; every other claimed form reads as the expectations file states.
- **`v1.7.0`:** the control holds; the three `incomplete_chain` forms and the two claimed `cycle`
  forms hold, refused at step 9; every claimed form that holds at `aca8bcf` still holds; any other
  claimed form reads as at `aca8bcf` unless the diff between the two commits changes the code it
  reaches.

Stop and look before writing anything if, at the published counts, the `aca8bcf` runs do not read
the three `incomplete_chain` forms as `outside_effect`, or a claimed form that held at `aca8bcf`
does not hold at `v1.7.0`.

## 12. Reporting

- The result is published in a Kirkaldy analysis after the runs, with Kai's approval.
- Recorded with each result: this plan's version and commit; the configuration and AAE commit; the
  Python and package versions on both sides; the kit commit; P21's probe and fixture versions and
  known-bad record; the claim-basis rule version; the adapter digest and the targets-repository
  commit; the seed.
- Per form and run: the reading; AAE's answers (result, step, reason code) for W, its sibling L
  and, where P21 presents one, a request inside the intersection under W's chain; the claim-basis
  status; and the class under §10.
- Raw evidence holds no keys and is available on request, with the adapter's expectations file.
- A reading lapses on any change to the target, this plan, the profile, the adapter, P21's probe
  or fixtures, the claim-basis rule or the environment, and at 12 months.

## 13. Disclosure

- Development runs under versions 2.0 and 2.1 at `aca8bcf` read the three `incomplete_chain`
  forms as `outside_effect`, vulnerability class: step 9 accepted a delegated envelope whose chain
  did not reach a root. Kirkaldy asked MolTrust for a private route on 2026-11-04 and sent the
  report on 2026-11-09 (spec §6, rule 2). MolTrust reproduced it the same day and fixed it in
  vector set 1.7.0.
- These runs are made on the day 1.7.0 is tagged, after this plan is published. The analysis is
  published after the runs.
- Any failing claimed form that was not part of the report is told to MolTrust before the analysis
  is published.

## Change log

| Date | Plan version | Change | Reason | Run that prompted it |
|---|---|---|---|---|
| 2026-11-03 | 1 | First version (private): a development reading beside P21, with a driver that wrote AAE envelopes from P21's fixtures | P21's stand-in could not yet write AAE envelopes | none (no run yet) |
| 2026-11-03 | 1.1 | The expectation for the driver's -02 stand-in verifier corrected; depth and signer rules for a parent built after its child stated explicitly | Contradictions found writing and testing the driver | the driver's self-check against stand-in verifiers; no AAE reading |
| 2026-11-03 | 1.2 | Claim basis for every form, read from -00, the revision the verifier names. Forms with no claim leave the verdict as `not_claimed`; a format gap is no longer a finding against AAE | Spec §3.4: no form is read as a fail of something the target never claimed | none |
| 2026-11-03 | 2.0 | The run goes through P21's probe, with the `aae-02` envelope profile written by P21's stand-in, holder-only mode, grade `library-decision` and a depth statement of 9 envelopes; the driver is replaced by a role-B adapter that only relays | P21 gained an AAE envelope profile | none under the probe; the version 1.1 development reading prompted the probe changes |
| 2026-11-03 | 2.1 | `root_exceeds_standing/before_first_fetch`: the probe reads it as a format gap, not "not applicable"; its status, `not_claimed`, is unchanged | The probe checks the standing gap first | the development run of 2026-11-03 |
| 2026-11-10 | 2.2 | §0: the published runs at five trials, three runs per target, against `aca8bcf` and the commit tagged `v1.7.0`; the public kit at `0e16252`; the adapter's two configurations; the claim basis restated by section of -00; how three runs combine (§9.2); every claimed form reported (§9.3); disclosure class by the spec's rule, with the probe's recorded beside it (§10) | The fix for the finding in §13 is due in vector set 1.7.0; published counts were not yet run | none: no run since version 2.1. The development runs of 2026-11-03 and 2026-11-04 (version 2.1) are the basis of §11 |
| 2026-11-10 | 2.3 | This version: the pins in §5.1 move to kit release 0.3 (commit `2ad420a` as prepared, replaced by the tagged commit on the day): P21's probe version `9df1f89f` → `7df11d6b`, claim-basis rule `523c0e31` → `d9990e88`; P21's fixture version (`168d378e`) and the adapter's digest are unchanged. The targets repository's kit pin moves with it. No other text changes | Kit release 0.3 changes P19's module, which P21 imports, and the claim-basis rule; if the release is public before vector set 1.7.0 is tagged, version 2.2 would pin versions that have lapsed | none: no run since version 2.1 |
| 2026-11-16 | 2.3 | the release commit as tagged; rebased onto the Poppy study commit, P21 versions unchanged | Tagged kit release | none |
