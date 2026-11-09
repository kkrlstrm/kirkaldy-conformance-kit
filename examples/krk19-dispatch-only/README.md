# Worked example: one trace, two claims, a dispatch-only receiver under KRK-19

This example records **one execution** of P19's in-flight variant (KRK-19, withdrawal within T)
against a synthetic receiver that checks an authorisation's status once, when it accepts a
request for dispatch, and never again before the effect commits. It saves that execution as a
trace, then grades **the same saved trace** against two claims:

- **Stated bound** (KRK-19 as written): "B commits no effect under a withdrawn authorisation
  later than 10 s after the withdrawal is served by A's status source." An effect inside T is
  allowed.
- **Commit time**: "B commits no effect under an authorisation that is not valid at the moment
  the effect commits."

The probe runs once. Both verdicts read the same file and carry its SHA-256, so they cannot
differ because two runs differed. In the trace, authority is valid when the held request is
dispatched, the withdrawal reaches the receiver, and the in-flight operation commits about 2 s
later. That trace passes the first claim and fails the second.

No product is tested. Nothing is added to `targets/`, `conformance/` or `known_bad/`, and no
probe, fixture or claim-rule version moves (checked by the script, below).

## What is here

| Path | What it is |
|---|---|
| `adapters/dispatch_only/adapter.py` | The receiver and its P19 adapter. Its docstring states the mechanism, the bound and the reason for it. Both claims are quoted from its `BOUNDS`. |
| `run_example.py` | Records P19's known-bad gate, runs the probe once, saves the trace, grades it against both claims, and checks that no version moved. `--grade-only` grades the saved trace without running anything. |
| `results/one-trace.json` | The recorded execution: P19's own in-flight evidence file, unchanged, with the run's header (seed, bound as stated, evidence grade, control, the probe's own reading, probe and fixture versions). SHA-256 `b474af8897fa2bbecddb449ff22c8e7d26a937c1849d727d2d6567349eea2039`. |
| `results/verdicts.json` | The two verdicts, each with the trace's SHA-256, every effect after the withdrawal with its time, position against the bound and evidence grade, and the notes below. |

## The receiver

For each request it verifies A's grant, chain and per-request authorisation, then fetches the
grant's status from A's source (`/status/item/<grant id>`) and refuses a withdrawn chain or a
failed fetch. Then it posts the effect to the recorder. If the recorder answers 503, it retries
after the recorder's `Retry-After` or 2 s, whichever is sooner, at most two attempts in all, and
**the retry does not check status again**.

Its bound: an effect can commit at most 1 s (status fetch) + 2 x 2 s (attempts) + 2 s (one wait)
= 7 s after the dispatch check that allowed it. It states T = 10 s.

P19's in-flight variant presents a request just before the withdrawal and has the recorder hold
its effect with 503 and `Retry-After` T + 5 s (15 s here). That hold is longer than T by design,
so a receiver that waited out the full `Retry-After` and then committed without a fresh check
would fail under any T. This receiver caps its wait at 2 s, so the request is held in flight for
about 2 s.

## Running it

From the kit's root, with the kit's virtual environment (`make setup`):

```bash
.venv/bin/python examples/krk19-dispatch-only/run_example.py               # record once, then grade
.venv/bin/python examples/krk19-dispatch-only/run_example.py --grade-only  # grade the saved trace
```

Recording takes about five minutes: about two for P19's known-bad gate, which `run` requires
and which is recorded in this example's own store, and three to four for the timed run on the
real clock. It sets `KIRKALDY_TARGETS_PATH` to `adapters/` and `KIRKALDY_RESULTS_DIR` to
`results/`, and runs P19 on `dispatch_only@stated-bound` with the development plan
`{"variants": ["in_flight"]}` at the method's 5 trials for that variant, seed 19. A new
recording replaces `one-trace.json`, and its times will differ by milliseconds.

`--grade-only` reads only `results/one-trace.json` and takes about a second.

## The trace

Every time is seconds on the kit's one clock, measured from `t_w`, the stub A's commit of the
snapshot that shows the withdrawal (t_w = 0). The held request's dispatch check happened between
its send and B's `queued` answer, so authority was valid at dispatch. The commit is the
recorder's. The control held.

| Trial | Held request sent | B answered `queued` | Withdrawal served | Held effect committed | New requests under W after t_w | Refused | Refused from |
|---|---|---|---|---|---|---|---|
| 0 | -0.0048 | -0.0021 | 0 | 2.0035 | 52 | 52 | 0.0010 |
| 1 | -0.0053 | -0.0017 | 0 | 2.0037 | 52 | 52 | 0.0016 |
| 2 | -0.0053 | -0.0022 | 0 | 1.9987 | 53 | 53 | 0.0013 |
| 3 | -0.0026 | -0.0005 | 0 | 2.0050 | 52 | 52 | 0.0009 |
| 4 | -0.0052 | -0.0020 | 0 | 2.0033 | 53 | 53 | 0.0015 |

In each trial the receiver made one attempt that the recorder held, then retried 2 s later
without a new status check, and the retry committed. That held effect is the only effect under
the withdrawn authorisation after `t_w`. All 262 new requests under it were refused.

## Verdict 1: stated bound, T = 10 s: pass

Graded with P19's own trial rule (`conformance.timing.classify_trial`) and variant rule
(`conformance.timing.aggregate`), applied read-only to the saved trace. Reading:
`refused_within_T`. Every trial reads `within`, the same outcome and latest effect that the
probe wrote when it ran.

Effects under the withdrawn authorisation after `t_w`:

| Trial | Effect | Committed | Against T = 10 s | Evidence grade |
|---|---|---|---|---|
| 0 | held request | 2.0035 | inside | `recorder` |
| 1 | held request | 2.0037 | inside | `recorder` |
| 2 | held request | 1.9987 | inside | `recorder` |
| 3 | held request | 2.0050 | inside | `recorder` |
| 4 | held request | 2.0033 | inside | `recorder` |

**What this shows.** The receiver refused every new request under the withdrawn authorisation
within 2 ms of the withdrawal. The one request it had accepted for dispatch just before
the withdrawal committed about 2.0 s after it, inside 10 s, in all 5 trials. KRK-19 as written
allows that effect, so the claim passes. P19's result today carries the 2 s only as the trial's
time (the larger of the refusal onset and the latest effect), not as an effect committed after
the withdrawal. The list above is that reading.

**What it does not show.** It does not show the receiver's worst case: its constants allow an
effect up to 7 s after the dispatch check, and this trace exercised a hold of about 2 s. It
covers one variant under a development plan of 5 trials; it is not a published run and says
nothing about the other KRK-19 variants. The commit time is the recorder's (see below).

## Verdict 2: commit time: fail

P19 cannot take this claim: it refuses a zero bound before any trial ("T_s must be a positive
number or None"). The trace is graded by this example's own rule (`grade_commit_time` in
`run_example.py`): the authorisation is no longer valid from `t_w`, so every effect under it that
the recorder committed more than the method's resolution after `t_w` is a violation, and one
inside that resolution is unresolved and gets no verdict. The resolution is 0.05 s, the larger of
50 ms and the receiver's stated 1 ms. Reading: `refused_late`, all 5 trials `late`.

Effects under the withdrawn authorisation after `t_w`:

| Trial | Effect | Committed | Against a bound of 0 | Evidence grade |
|---|---|---|---|---|
| 0 | held request | 2.0035 | after | `recorder` |
| 1 | held request | 2.0037 | after | `recorder` |
| 2 | held request | 1.9987 | after | `recorder` |
| 3 | held request | 2.0050 | after | `recorder` |
| 4 | held request | 2.0033 | after | `recorder` |

No effect is inside the bound, and none falls within the 0.05 s resolution.

**What this shows.** The same bytes fail a commit-time claim. The effect accepted for dispatch
before the withdrawal committed about 2.0 s after it, when the authorisation was no longer
valid. Nothing in the receiver or the trace changed between the two verdicts; only the claim
did. The violation is about 40 times the method's resolution.

**What it does not show.** The rule is this example's, not a kit property, and the spec does not
yet say how a commit-time claim is read. The trace was recorded under the stated-bound
configuration, so the probe held the effect with `Retry-After` 15 s and spaced its presentations
for T = 10 s. For this receiver that does not change the effect's time, because it waits at
most 2 s whatever `Retry-After` asks; for a receiver that honours `Retry-After`, a trace
recorded under one bound is not the trace another bound would produce. It does not show what a
downstream system would do if it checked authority again before applying the effect: the
recorder applies everything it is sent.

## The recorder is a stand-in

Both verdicts are at the `recorder` grade, the highest of KRK-19's four (spec §3.8). That grade
says where the effect was timed, and it is worth being exact about what that point is.

The recorder is a controlled stand-in for the real mutation. It is the kit's own HTTP endpoint,
placed where B's effect lands, and an effect's time is when the recorder wrote it, on the kit's
clock. In a deployed integration the consequential mutation is whatever B's call changes
downstream (a row, a message, a file). It can sit behind further queues, retries or services,
and commit later than the call that requested it. The `recorder` grade means the effect was timed
at this stand-in, downstream of B and outside B's own account of itself. It is not the time of a
mutation in another organisation's system. In this example both ends are synthetic: the receiver
is written for it, and the recorder is the kit's.

## Versions

The script hashes every property's probe and fixture versions and the claim-basis rule before
and after, and reads the kit's own `known-bad --status` before and after. Nothing moved and the
status read the same. P19's probe version is
`sha256:59209b69202a33b8685261003b288de5c9d4b15935bba821531e6bc337f56550`, its fixture version
`sha256:0d6e0cf26818f48263359f5bf4398e8805e0e44a9acd8fe8007797d3562b737c`, and the claim-basis
rule `sha256:523c0e318ef295f34a0fd573132920656006307a3cccab6ad78e687a7f46a322`. The trace records
the same probe and fixture versions.

## What it shows for the spec

1. **Effects inside T are a separate reading.** Under the stated bound, the dispatch-only
   receiver passes while one effect per trial commits about 2 s after the withdrawal. That is
   what KRK-19 as written allows, and a reader of the result should see it directly, with its
   time. Version 0.3 is planned to report this reading in the result itself.
2. **A commit-time claim needs its own reading rule.** P19 refuses a zero bound, and §3.7 rule 4
   (presentations spaced at most T/20 apart, one just before the bound and one just after it)
   cannot be applied at zero. The in-flight variant does not depend on that spacing: it compares
   the recorder's commit time with the bound directly (§3.7 rule 2), and it decides this trace.
   Version 0.3 is planned to state how a commit-time claim is read.

This example changes no probe. A development plan of one variant is not a published run, and
the pass covers only the in-flight variant.

An earlier version of this example ran P19 three times, under T = 10 s, T = 0 and T = 0.001 s
([`685bc3b`](https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/685bc3bd3115a0c7b9893572bf5351083b74e9bc/examples/krk19-dispatch-only)).
This version records once and grades the one trace twice.
