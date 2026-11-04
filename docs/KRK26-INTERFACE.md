# KRK-26 (P26) the ceiling survives translation: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p26_translation.py`. Where it says "the design", it means the property's
design document, X11, which is not part of this copy of the kit; this file and the docstring are
what the code does.

## Decisions that bind the build

- **KRK-26** outside code, **P26** in code. Built in the kit only.
- **Three topologies, graded separately**: **T** (the target translates; the kit plays A,
  the agent and the faithful receiver R′), **R** (the target receives the original beside a form
  the kit's T′ signed), **TR** (the target maps the original into its own terms and acts). A
  receiver that holds only the translated form is not graded here.
- **The outcome is graded, not the mechanism.** Refusing, translating faithfully and translating
  narrower all pass; the result says which (`modes`: `exact`, `clamped`, `refused`).
- **The profile is the target's**: declared before the run, pinned by digest, read again
  at the end (KRK-M190, M194). The kit never supplies one. An undeclared pair, value or unit is
  refused.
- **Conversion through a declared rate only**, rounded toward the original's bound:
  floor a maximum, ceil a minimum, end earlier, start later. Stricter rounding is information
  (`stricter_rounding`). P21 and P22 keep refusing every conversion; nothing in their closures
  changed.
- **A dropped constraint fails** when the translator issues anyway; a member the target
  documents as informational counts as dropped. A drop the target documents is
  `documented_widening`, information.
- **Static.** No form waits. Every presentation carries its kit time (`at`); the toys read it as
  their clock. Real targets need an adapter that maps `at` onto the target's clock (not built).
- **New modules only.** `conformance/translation.py`, `conformance/translation_formats.py`,
  `conformance/translator_stub.py`, `conformance/properties/p26_translation.py`,
  `known_bad/translation_toys.py`, `tests/test_p26_translation.py`,
  `tests/test_failure_modes_x11.py`, `tests/vectors/krk26/vectors.json`. P26 imports
  `receipts.py` (Ed25519 keys, canonical JSON, compact JWS) and `evidence.py` and `result.py`
  unchanged; it does not import `attenuation.py` or `requester.py` (see "Built differently").
- **No outside target** was run in the build.

## Module 1: `conformance/translation.py`

Standard library only; `fractions.Fraction` on integers; no float (KRK-M193).

| Name | What it does |
|---|---|
| `PROFILE_SCHEMA` | `kirkaldy.translation-profile/0.1` |
| `TOPOLOGIES` | `("T", "R", "TR")` |
| `profile_problem(p)` | shape: schema, `fields` onto the source members, enumerated `values`, exact rates, no pair declared twice, `time`, `unmapped: "refuse"` |
| `semantics_problem(sem, profile)` | every member has `semantics` (`enforced` / `informational` / `ignorable_extension`), a `quote`, and for an enforced member `absent` (`unbounded` / `nothing`) |
| `profile_digest(p)` | SHA-256 over JCS; a float or an integer beyond 2^53 − 1 is refused |
| `pair_for(profile, currency, target=None)`, `count_pair(...)` | the declared pair, or None |
| `convert(amount, pair, *, bound)` | exact; `"max"` floors, `"min"` ceils; `Refusal` with no pair or other minor units |
| `back_value(amount, pair)` | a target amount in source minor units, exact |
| `convert_back(amount, pair, *, bound)` | the reverse leg, rounded toward the bound |
| `convert_time(n, src, tgt, *, bound)` | `"end"` floors, `"start"` ceils |
| `realised(target_value, profile, field)` | the source values a target value can realise; None when unmapped |
| `image(original, profile, sem, *, currency=None, count_unit=None)` | the widest faithful translated members, or a `Refusal` (`rate-undeclared`, `incomparable`, `cannot-carry`, `unmapped-value`, `unit-undeclared`, `malformed`) |
| `back(translated, profile, sem, ...)` | the widest source set the members admit, exactly |
| `no_wider(translated, original, profile, sem)` | the dimensions where `back` exceeds the original |
| `effect_outside(effect, original, profile, *, tolerance=0)` | the dimensions where one committed effect lies outside the original, in its own terms |
| `source_effect_outside(effect, original)` | the same for an effect under a source-format O′ (round trip) |

**The original** (`kirkaldy.authority/0.1`): `constraints` with `max_amount`, `min_amount`
(`{value, currency, minor_units}`, value an integer or a string of digits), `max_count`
(`{value, unit}`), `operations`, `resources` (an id or a prefix ending in `/*`), `audience`,
`payee`, `categories`, `regions`, `channels`; `not_before` (optional) and `not_after` in
`time_unit` (`s` or `ms`); `crit`. Every constraint is critical.

**An effect** is the request the recorder committed: `operation` (a target value), `amount`,
`count`, `resource`, `audience`, `payee`, `at` (target time unit), `category`, `region`,
`channel`, `request_id`.

Vectors: `tests/vectors/krk26/vectors.json`, every expected value computed by hand: 11
conversions over 7 pairs (with two double-precision traps), 3 refusals, 3 reverse legs, 2
direction cases, 4 time cases, 7 images, 7 refused images, 12 `no_wider` cases, 19
`effect_outside` cases and 2 `source_effect_outside` cases.

## Module 2: `conformance/translation_formats.py`

Imported only by P26 (design §13 item 3).

| Name | What it does |
|---|---|
| `SOURCE`, `SOURCE_TYP` | `kirkaldy.authority/0.1`, `krk-authority+jws` |
| `TARGET`, `TARGET_TYP` | `kirkaldy.translated/0.1`, `krk-translated+jws`: the kit's own target format (toys and T′) |
| `write_authority(claims, key)`, `read_authority(raw, pinned)` | A's original, compact JWS over canonical JSON |
| `write_translated(members, key, *, issuer, sub, orig, iat, token_id)` | a translated form; `orig` None writes an unbound form |
| `read_translated(raw, pinned)` | `{members, unreadable, signed_by, orig, sub, iat, envelope}`; never drops a member silently (KRK-M191) |
| `write_round_trip(claims, key)` | O′, signed by the translator that wrote it |
| `digest(raw)` | the binding a translated form names its original by |

No writer or reader for an outside format is built in version 1; each comes with the adapter
for the target that uses it.

## Module 3: `conformance/translator_stub.py`

| Class | Role |
|---|---|
| `StandInA` | A: `issue(claims) -> bytes`, own key, fresh authority id, `issued` keeps every original (KRK-M209) |
| `StubTranslator` | T′ (topology R): `translate` (the image), `translate_wider(original, raw, members)`, `unbound(members, ...)`; every form it signs is logged in `signed` |
| `FaithfulReceiver` | R′ (topology T): `enact(decoded, request)`; commits at the recorder only if every enforced member admits the request; an unreadable member or one without stated semantics is a gap |
| `SourceReceiver` | S′: enacts a request under O′ (round trip) |
| `Recorder` | `commit(effect, by=)`, `for_request(id)`; stores currency, minor units and unit with each effect |
| `admits(members, request, profile, sem, *, tolerance)` | the reading R′ uses |

## Module 4: `conformance/properties/p26_translation.py`

`VARIANTS` and `FORMS` are the design's §6.4. `TOPOLOGY_VARIANTS`: T and TR every variant but
`two_forms`; R `currency`, `window`, `two_forms`. `REFUSE`: the forms whose W-in is not presented.
`NA_FORBIDDEN`: the design's list. `TRIALS = 5`, `DEV_TRIALS = 3`, `PUBLISHED_TRIALS = 5`
(`ACK_P26_PLAN` = `{"trials": "dev" | "published" | n}`). `GRADES_OF`: T `translated-signed`,
`translated-response`; R the `recorder` and `b-*` grades and `library-decision`; TR the
`recorder` and `b-*` grades.

`probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result`. `extra`: `forms` (variant → form →
`{reading, ok, detail, trials, counted, dimension?, modes?, info?}`), `modes`, `topology`,
`evidence_grade`, `profile_digest`, `profile_owner`, `rate_source`, `disclosure`,
`disclosure_forms`, `documents_preserving`, `dimensions_not_carried`, `level`, `kit_parties`,
`originals_issued`, `seed`, `progress`.

### The adapter

| Method | Topology | Required |
|---|---|---|
| `topology()` | all | yes |
| `translation_profile()` → `{profile, owner, quote, url}` | all | yes |
| `translated_profile()` → member → `{semantics, absent, quote, resolution?}` | all | yes |
| `evidence_grade()` | all | yes |
| `prepare(ctx)` | all | yes; `ctx`: `a_keys`, `receiver`, `profile_digest`, and `recorder` (R, TR), `translator_keys` (R) |
| `received()` | all | yes; the original bytes the target last received |
| `translate(raw, ask)` → `{translated, refusal}` or `{error}` | T | yes; `ask` carries `at` and may carry `currency`, `operations`, `audience`, `resources` |
| `read_translated(raw)` | T | yes; decode only |
| `keys()` → `{"translator": {kid: public bytes}}` | T | yes |
| `translate_back(raw, ask)` → `{original, refusal}` | T | for `round_trip` |
| `stages()` | T | for `staged` |
| `present(p)` → `{accepted, reason}` | R, TR | yes; `p`: `original`, `translated` (R), `request`, `at` |
| `original_visible()` | R | yes; None means `two_forms` does not run (KRK-M202) |
| `advisory_members()`, `rate_source()`, `configuration()`, `clock_tolerance_s()` | all | optional |
| `documents_preserving()`, `documents_stages()`, `documented_widenings()`, `forms_not_applicable()` | all | optional |
| `not_claimed()`, `claim_basis()` | all | optional (the probe reads `not_claimed()` only for `NA_FORBIDDEN`) |

## Module 5: `known_bad/translation_toys.py`

`ToyTranslation(base, flaw, topology)`; configurations `good@<t>`, `good-strict@<t>`,
`no-control@<t>` and `bad:<flaw>@<t>`; `cases()` is the gate's list (73 toys). `FLAWS` maps the 30
flaws to their variant. `TOY_PROFILE` declares seven currency pairs (USD→USD, EUR→USD 108/100,
CHF→USD 7/10, KWD(3)→USD 33/10, GBP→JPY(0) 190, DAI(18)→USD, SGD→USD at
6305039478318693/9007199254740991), two count pairs (message→batch 1/10, batch→batch), ten
fields and six operation values. `TOY_SEMANTICS` documents nine enforced members, one
informational (`regions_hint`) and one ignorable extension (`ext`), so `categories` has no
counterpart, `regions` only an informational one and `channels` only the extension.

## Built differently from the design

1. **The source format is `kirkaldy.authority/0.1`, not grant 0.2.** Grant 0.2 has no payee,
   minimum, count or the three extra dimensions the dropped-constraint forms need. It is written
   by `translation_formats.py`, which only P26 imports.
2. **`translation.py` does not import `attenuation`** (design §6.1). It has its own `covers` and
   amount checks, tested on its own vectors, so a change to P21's vocabulary cannot move P26 and
   the image shares no code with anything (KRK-M193).
3. **`rate_inverted` draws only rates at or below 4/5.** A rate above 1 applied backwards narrows,
   so the design's 1.25–2.5 range cannot separate the weak check.
4. **In T, the W request is drawn from the translated form the target issued**, at its edge in the
   dimension under test. In R it is drawn from the form T′ signed, and in TR from the weak reading
   the form predicts, checked to lie outside the original first.
5. **W-in reuses W's original and translated form**, and comes after W in the seeded order (§4.1:
   "under W's own translation").
6. **`unbound_pair`** presents a translated form T′ signed from a wider original and bound to
   none; a receiver that checks only that the forms agree catches it too.
7. **The control's operation** is a source value exactly one one-to-one target value realises, so
   a translator that picks the widest target value still holds a control (KRK-M19). Where the
   profile has no such value, the control draws its operation in T from the
   translated form the target issued, in R from the form T′ signed and in TR from the kit's image,
   and says which in `extra["control_operation"]`, the control detail and the summary.
8. **`round_trip` runs in T only**; in TR the toy states that it exposes no reverse direction.
9. **Not built:** a served, versioned rate (KRK-M194, M208 are guarded by refusing a non-static rate
   source), outside format writers and readers, the `library-decision` adapter path, and timed
   presentation against a real clock.

## Probe change log

| # | Change | Reason | Run that prompted it |
|---|---|---|---|
| 1 | First version. | P26 build. | none |
| 2 | `currency/face_value` and `units/minor_units` (`NA_BY_PROFILE`) read `not_applicable` with the probe's reason, info `no_separating_pair`, when no declared pair separates their weak check, and then count as present for the result; `extra.not_applicable_by_profile` lists them. A stated `forms_not_applicable` for them is still ignored. The control's operation, when no source value only one target value realises, is drawn from what the translator issued (T: the target's translated form; R: T′'s; TR: the kit's image) and the result says so (`extra.control_operation`). The probe and fixture versions moved (new tests in `tests/test_p26_translation.py`). | A profile with no separating pair read inconclusive for every such target; the control had no operation to draw. | none (found in the build) |
| 3 | Every result writes `extra.must_land_missed`, the forms that must land and did not, also when a form failed. The probe version moved; the fixture did not. | With the claim-basis rule change (`docs/CHANGE-LOG.md`, entry 8). | none |
