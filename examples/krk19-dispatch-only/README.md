# Worked example: a dispatch-only receiver under KRK-19

This example runs P19 (KRK-19, withdrawal within T) against a synthetic receiver that checks an
authorisation's status once, when it accepts a request for dispatch, and never again before the
effect commits. It runs the in-flight variant twice, under two claims:

- **Stated bound** (KRK-19 as written): B commits no effect under a withdrawn authorisation later
  than T after the withdrawal was served, T being the bound B states. An effect inside T is
  allowed.
- **Valid at commit**: no effect commits under an authorisation that is no longer valid at the
  moment it commits.

No product is tested. Nothing is added to `targets/`, `conformance/` or `known_bad/`, and no
probe, fixture or claim-rule version moves (checked by the script, below).

## What is here

| Path | What it is |
|---|---|
| `adapters/dispatch_only/adapter.py` | The receiver and its P19 adapter. Its docstring states the mechanism, the bound and the reason for it. |
| `run_example.py` | Records P19's known-bad gate, runs the probe, reads the evidence into the in-flight timeline, and checks that no version moved. |
| `results/readings.json` | The readings of the runs reported below (seed 19). Raw evidence is written beside it and not committed. |

## The receiver

For each request it verifies A's grant, chain and per-request authorisation, then fetches the
grant's status from A's source (`/status/item/<grant id>`) and refuses a withdrawn chain or a
failed fetch. Then it posts the effect to the recorder. If the recorder answers 503, it retries
after the recorder's `Retry-After` or 2 s, whichever is sooner, at most two attempts in all, and
**the retry does not check status again**.

Its bound: an effect can commit at most 1 s (status fetch) + 2 x 2 s (attempts) + 2 s (one wait)
= 7 s after the dispatch check that allowed it. It states T = 10 s.

P19's in-flight variant presents a request just before the withdrawal and has the recorder hold
its effect with 503 and `Retry-After` T + 5 s. That hold is longer than T by design, so a
receiver that waited out the full `Retry-After` and then committed without a fresh check would
fail under any T. This receiver caps its wait at 2 s. The request is held in flight for about
2 s, and the stated T of 10 s is longer than that hold.

The three configurations differ only in the bound stated; the receiver's code and constants are
the same.

| Configuration | Stated T |
|---|---|
| `stated-bound` | 10 s |
| `valid-at-commit-zero` | 0 s, the commit-time claim written as a zero bound |
| `valid-at-commit` | 0.001 s, the smallest positive bound at the receiver's stated 1 ms resolution |

## Running it

From the kit's root, with the kit's virtual environment (`make setup`):

```bash
.venv/bin/python examples/krk19-dispatch-only/run_example.py
```

It takes about ten minutes: about two for P19's known-bad gate, which `run` requires and which is
recorded in this example's own store, and three to four for each timed run on the real clock. It
sets `KIRKALDY_TARGETS_PATH` to `adapters/` and `KIRKALDY_RESULTS_DIR` to `results/`, and runs
P19 with the development plan `{"variants": ["in_flight"]}` at the method's 5 trials for that
variant. `--seed` and `--results` change the seed and the results root.

## Results

Every time is seconds on the kit's one clock, measured from `t_w`, the stub A's commit of the
snapshot that shows the withdrawal (t_w = 0). The held request's dispatch check happened between
its send and B's `queued` answer. The commit is the recorder's.

### Run 1: stated bound, T = 10 s

**pass** on `in_flight` (development plan: one variant, 5 trials): `refused_within_T`, N = 5,
max 2.007 s, median 2.006 s, 0 late.

| Trial | Held request sent | B answered `queued` | Withdrawal served | Held effect committed | Inside T | After T | New requests under W refused from |
|---|---|---|---|---|---|---|---|
| 0 | -0.006 | -0.003 | 0 | 2.006 | 2.006 | none | 0.002 |
| 1 | -0.006 | -0.003 | 0 | 2.002 | 2.002 | none | 0.001 |
| 2 | -0.005 | -0.002 | 0 | 2.007 | 2.007 | none | 0.002 |
| 3 | -0.003 | -0.000 | 0 | 2.007 | 2.007 | none | 0.001 |
| 4 | -0.006 | -0.002 | 0 | 2.003 | 2.003 | none | 0.002 |

In every trial one effect under the withdrawn authorisation committed after the withdrawal and
inside T: the held request, about 2.0 s after `t_w`. Every new request under it (52 or 53 per
trial) was refused, the first within 2 ms. (A time shown as -0.000 is a few tenths of a
millisecond before the withdrawal.)

The result does carry the 2 s, but not as its own reading. P19 records each trial's latest effect
after the withdrawal (`last_effect_s`) and takes the trial's time as the larger of that and the
refusal onset, so the check reads "max 2.007 s" while B refused new requests from 0.001 s. It
does not say that 2.007 s is an effect committed after the withdrawal, and it keeps only the
latest such effect per trial.

### Run 2: valid at commit

**T = 0 s: inconclusive, before any trial.** P19 refuses the bound as input: "T_s must be a
positive number or None, not 0.0". The control does not run, no trial runs, and no evidence
grade is read. P19 as written cannot take a zero bound.

**T = 0.001 s: fail** on `in_flight`: `refused_late`, N = 5, max 2.011 s, median 2.005 s, 5 of
5 trials late.

| Trial | Held request sent | B answered `queued` | Withdrawal served | Held effect committed | Inside T | After T | New requests under W refused from |
|---|---|---|---|---|---|---|---|
| 0 | -0.006 | -0.003 | 0 | 2.001 | none | 2.001 | 0.001 |
| 1 | -0.006 | -0.003 | 0 | 2.008 | none | 2.008 | 0.001 |
| 2 | -0.006 | -0.003 | 0 | 1.999 | none | 1.999 | 0.002 |
| 3 | -0.003 | -0.000 | 0 | 2.010 | none | 2.010 | 0.001 |
| 4 | -0.006 | -0.003 | 0 | 2.005 | none | 2.005 | 0.002 |

The trace has the same shape as run 1: the held effect commits about 2 s after the withdrawal,
and every new request under W is refused. Only the stated bound changed, and the same commit is
now late. The result also reports the bound as below what the method can measure (`below_floor`
true, measurement floor 0.251 s).

### Evidence grade

Both graded readings are at the `recorder` grade, the highest of KRK-19's four (§3.8): each
effect is the commit at the kit's recorder, downstream of B, timed on the kit's clock. The zero
bound was refused before any grade was read. The disclosure class of the failing run is
`conformance`.

### Versions

The script hashes every property's probe and fixture versions and the claim-basis rule before
and after, and reads the kit's own `known-bad --status` before and after. Nothing moved and the
status read the same. P19's probe version is
`sha256:59209b69202a33b8685261003b288de5c9d4b15935bba821531e6bc337f56550`, its fixture version
`sha256:0d6e0cf26818f48263359f5bf4398e8805e0e44a9acd8fe8007797d3562b737c`, and the claim-basis
rule `sha256:523c0e318ef295f34a0fd573132920656006307a3cccab6ad78e687a7f46a322`.

## What it shows

1. **Effects inside T are a separate reading.** Under the stated bound, the dispatch-only
   receiver passes while one effect per trial commits about 2 s after the withdrawal. That is
   what KRK-19 as written allows, and a reader of the result should see it directly. The script
   reads it from the evidence files: per trial, every effect under the withdrawn authorisation
   that committed after `t_w`, with its time, split into inside T and after T. Version 0.3 is
   planned to report this reading in the result itself.
2. **A commit-time bound needs its own reading rule.** §3.7 rule 4 asks for presentations spaced
   at most T/20 apart, with one just before the bound and one just after it. At T = 0 neither can
   be placed, and P19 refuses the bound. At T = 0.001 s the spacing stays at its 0.2 s minimum,
   the presentation just before the bound would fall before the withdrawal and is not sent, and
   the result reports the bound as below what the method can measure. The in-flight variant does
   not depend on that spacing: it compares the recorder's commit time with T directly (§3.7 rule
   2), and here it decides the reading. Version 0.3 is planned to state how a commit-time bound
   is read against rule 4.

This example changes no probe. A development plan of one variant is not a published run, and
the pass in run 1 covers only the in-flight variant.
