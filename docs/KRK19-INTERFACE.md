# KRK-19 (P19) withdrawal within T: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p19_withdrawal_within_t.py`. Where it says "the design", it means the
property's design document, X4, which is not part of this copy of the kit; this file and the
docstring are what the code does.

## Decisions that bind the build

- **KRK-19** outside code, **P19** in code. Graded side B. Role A (how fast A
  publishes) is version 2: an adapter whose `role()` is `"A"` reads inconclusive.
- **The kit measures; it does not choose T.** T is read before the run from the adapter
  (`withdrawal_bound`), with its source: `documented`, `configured`, `carried` or `unstated`. A T
  whose source is `carried` (protocol data, set by A, which is the stub) never decides B's
  verdict: it is kept as `bound.carried_T_s` and B is graded as stating no bound. With no stated T, W replaces T, the pass label is
  `refused_within_W`, the summary leads with "no stated bound; measured worst case x s over N
  trials", and `extra.effective_bound_s` and `extra.finding` carry the measured worst case and the
  missing bound.
- **One clock.** Every measured time is read from one clock object on the host that runs the stub
  A, the recorder and the driver (`timing.RealClock`, `time.monotonic`). Only a toy may declare a
  virtual clock (`timing.VirtualClock`); a real adapter that declares one reads inconclusive
  (KRK-M56). B's own timestamps give an offset estimate, reported beside the reading and never
  used to order or judge (`extra.b_clock_offset_s`, KRK-M65).
- **`t_w` is the stub's commit** of the snapshot that first shows the change, confirmed by reading
  the published state back in B's profile (KRK-M26, KRK-M50).
- **Effects count where they land**: an effect committed at the recorder after `t_w + T`, or a
  presentation sent after `t_w + T` and accepted, is late, whenever the request arrived.
- **A refusal counts only if it is about the withdrawal**: each trial pairs W with a live sibling
  L; L refused is `collateral_refusal` except where refusing L is the fail-safe
  (`source_unreachable`, `stale_signed_snapshot` served or rolled back).
- **The worst case is the result**: the maximum with its bracket, the median, p90 and p99 only
  from 30 and 100 trials, late and not-refused counts, the rule-of-three bound; never a mean.
- **"Late" and "never" are kept apart**: not refused by `t_w + W` is `not_refused_within_W`.
- **Stuck closed is a fail**, and so is a recovery after the stated recovery bound,
  `recovered_late`: the continuation presents until W whatever the bound, with boundary
  slots either side of the bound, so only no recovery at all reads `stuck_closed`.
- **The probe's own schedule**. Presentations are sent at their slots without waiting for
  earlier answers; a trial whose bracket crosses T reads `inconclusive`, and a variant with one
  passes only with as many clean trials as the plan asks for (Module 5, "Sending and the
  inconclusive rule").
- **Evidence as the run goes**: `NN-progress.jsonl`, and `python -m conformance derive`
  for a run cut short (Module 5).
- **Negative fixtures are genuine**: the stub signs only with its own keys and its agents';
  an older snapshot is served or stapled as the bytes it signed then; the clock offset is set
  before signing. Nothing is re-signed, altered or backdated.
- **Disclosure**: `conformance` unless the bound is `documented` or `configured` (or the
  adapter says the target documents enforcement) and a variant fails as `not_refused_within_W`,
  `accepted_open`, or in `stale_signed_snapshot`, `parent_withdrawn` or `same_session`; then
  `vulnerability`.
- **Self-hosted targets only; restarts only there**. Outages are induced on the stub only.
- **B is not graded on new requests A signs after withdrawing**. For a B that
  takes only requests A signed itself, P19 reads a withdrawal through requests A signed before
  it. An A that keeps signing under a grant it has withdrawn is A's fault, not B's; grading that
  belongs to P19 role A, version 2. No code reads it.
- **An absent grant reads by issue time** (see Module 1).
- **KRK-16, KRK-17 and KRK-18 are unchanged.** P19 uses P18's per-request authorisation format
  (`authz`) with the extra member `grant_id`, and P18's `requester.py` with P19's parts added.

## Module 1: `conformance/status.py`

Three formats, each a compact JWS (EdDSA) over canonical JSON:

| Format | typ | Claims |
|---|---|---|
| `kirkaldy.grant/0.1` | `krk-grant+jws` | `grant_id`, `issuer`, `audience`, `subject`, `agent_key {kid, public_key}`, `principal`, `operation`, `ceiling {max_amount}`, `parent`, `issued_at` (ms), `not_before`, `not_after`, `status {source, index}` |
| `kirkaldy.status/0.1` | `krk-status+jws` | `issuer`, `source`, `version`, `issued_at` (ms), `ttl_s`, `expires_at`, `entries {grant_id: {state, ceiling}}`, `standing {principal: standing|withdrawn}` |
| `kirkaldy.status-notice/0.1` | `krk-notice+jws` | the same, holding only what changed |

`issued_at` was added for KRK-M46, with the schema left at 0.1 since the format is
unreleased. It is A's clock when A signs the grant, the clock a snapshot's `issued_at`
is read from; `not_before` is not the issue time (the stub sets it an hour back).

**A grant absent from a snapshot**:

| The grant's `issued_at`, against the snapshot's | Reads | Why |
|---|---|---|
| at or after `issued_at` (the same instant included) | `not-yet-listed`: in force only until B's next fetch, which B must make within T | A signed the snapshot before the grant existed, so it cannot list it. At the same instant a correct A, which lists a grant in every snapshot it signs after issuing it, signed the snapshot first. Index-based lists work the same way: an unset bit means valid |
| before `issued_at` | `unknown`: refused | A signed the snapshot after the grant existed and did not list it, so the source does not know the grant and cannot say whether it was withdrawn. Fails safe |
| either time missing or unreadable | `unknown`: refused | absence cannot be ordered |

"Not yet listed" never lengthens how long B may use a snapshot; B's age limit still applies (an
expired snapshot is that limit's question, not this rule's), and B's next snapshot lists the grant
or reads it as unknown. A grant read as not yet listed is still subject to its parents' entries and
its principal's standing in the same snapshot. Both times are A's, so the reading does not depend on
B's clock; it does depend on A's clock not running backwards between the two signatures (the
`status.py` docstring says what each direction does).

**A principal absent from `standing`**: a snapshot that lists a grant states the
standing of the grant's principal. A principal missing from `standing` in a snapshot that lists one
of its grants reads `unknown`, and B refuses (fails safe). A grant that is not yet listed is not
covered, since the snapshot was signed before it existed; the reading lasts until B's next fetch.
Under the earlier format a missing principal read as having standing (KRK-M47).

In the bitstring profile every index below `size` is listed and an unset bit is
valid; an index at or past `size` is absent and reads by the table.

Grant states: `valid`, `revoked`, `suspended`, `narrowed` (with a ceiling). One wire profile,
`bitstring-status-list` (`kirkaldy.status-bitstring/0.1`, `krk-status-bitstring+jws`): one bit per
status index, zlib and base64url; narrowing, suspension and standing are format gaps
(`bitstring_gaps`). The OAuth Token Status List and SSF/CAEP push profiles are not built.

```python
def sign(claims: dict, key: Keypair, typ: str) -> str
def verify(token, pinned: dict, typ: str) -> Verified     # malformed | unsigned | unpinned-key | bad-signature
def chain_state(snapshot: dict, chain: list[dict]) -> {"state", "ceiling", "why", "not_yet_listed"}
    # state: valid | narrowed | not-yet-listed (IN_FORCE) | revoked | suspended
    #        | standing-withdrawn | unknown
def absent_state(snapshot: dict, grant: dict) -> ("not-yet-listed" | "unknown", why)
def within(values: dict, ceiling: dict | None) -> str | None
```

Vectors: `tests/vectors/krk19/vectors.json` (written by `make_vectors.py`, RFC 8032 keys, every
expected answer written by hand). Each chain case carries its snapshot's `issued_at` and
`expires_at`; the absence cases are `not-yet-listed`, `not-yet-listed-parent-revoked`,
`not-yet-listed-parent-narrowed`, `not-yet-listed-standing-withdrawn`,
`absent-from-a-later-snapshot`, `sibling-absent-from-a-later-snapshot`, `parent-missing`,
`issued-in-the-same-instant`, `issued-after-the-snapshot-expired` and `no-snapshot-times`.

## Module 2: `conformance/requester.py` (P19's parts)

`StubRequester(issuer, *, clock=None, status_profile="kirkaldy", ttl_s=30, audience=...)` keeps
everything P18 uses and adds:

```python
issue(subject, operation=OPERATION, ceiling=None, *, principal, parent=None) -> Grant
delegate(parent, subject, ceiling=None, *, principal=None) -> Grant      # never wider
regrant(like) -> Grant
under(grant, values, *, audience, signer="agent" | "a", staple=None, window_s=...) -> Presentation
withdraw(gid) / suspend(gid) / reinstate(gid) / narrow(gid, ceiling) / withdraw_standing(p) -> Withdrawal
reissue() -> snapshot record          set_clock_offset(seconds)
serve() -> source URL                 set_source("up"|"down"|"hang"|"error"|"stale"|"rollback"
                                                 |"push-drop"|"push-deliver", version=None)
fetch_local(path, client) -> (status, token)       # in-process B's on a virtual clock
fetch_log(since) / push_log() / snapshots() / latest_before(t) / current()
baseline_read() -> (reached, token, detail)        # the kit's own path, never given to B
read_back({gid or "principal:<p>": state}) -> {key: bool}
push_to(receiver_url)                              trust_anchor_x4()
```

Headers outside the binding: `KRK-Grant` (the presented grant), `KRK-Grant-Chain` (parents,
nearest first), `KRK-Status-Staple`. The source serves `/status/list` and `/status/item/<gid>`
with `Cache-Control: no-store`; a fetch finding the current snapshot older than `reissue_s`
(`max(0.1, ttl_s/10)`) gets a fresh version.

## Module 3: `conformance/timing.py`

`RealClock`, `VirtualClock` (both with `now`, `wall`, `sleep`, `sleep_until`, `call_at`,
`call_every`, `cancel`); `window_s(T)`, `stability_s(T)`, `delta_s(T)`, `epsilon_s(res)`,
`floor_s`, `below_floor`; `schedule(T, rng, *, window, resolution_s, start_s) -> [Slot]`;
`phase_target(f, P, rng, "random"|"worst")`; `Pres`, `TrialLog`, `TrialOutcome`;
`classify_trial(log)`, `aggregate(outcomes, T, *, fail_label)`, `statistics(outcomes, T)`,
`percentile_check(statistic, outcomes, T)`.

## Module 4: `conformance/mockserver.py`

`MockServer(clock=)` stamps every record with `t_kit`; `hold(ref, retry_after_s)` answers the next
effect carrying that ref with 503 and `Retry-After`, committing nothing; `held(prefix)`;
`effects_after(index, prefix)` reads each record once.

## Module 5: `conformance/properties/p19_withdrawal_within_t.py`

```python
VARIANTS = ("withdrawn", "worst_phase", "same_session", "source_unreachable", "recovery",
            "parent_withdrawn", "standing_withdrawn", "narrowed", "in_flight",
            "presigned_after_withdrawal", "regrant", "stale_signed_snapshot",
            "skewed_issuer_clock", "restart_after_refusal")
FORMS = {"source_unreachable": ("down", "hang", "error", "push_lost"),
         "regrant": ("new_grant", "reinstated"),
         "stale_signed_snapshot": ("stapled", "served", "rollback")}
TRIALS = {"withdrawn": 30, "worst_phase": 5, "*": 5}      # per variant and form
DEV_TRIALS = {"withdrawn": 5, "worst_phase": 2, "*": 1}
SETTLE_S = 2.0; READY_S = 30.0; NARROW_TO = 50_000
def probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result
```

The adapter (role B):

```python
class Adapter(Protocol):
    name: str; config: str
    clock: str                                    # "real"; "virtual" for toys only
    def role(self) -> str: ...                    # "B"
    def withdrawal_bound(self) -> dict: ...       # T_s, statistic, source, quote, url, setting,
                                                  # recovery_s, clock_tolerance_s, resolution_s
    def channels(self) -> list: ...               # of "pull-list", "pull-item", "push", "stapled"
    def agreement(self) -> dict: ...              # counterparty, endpoints, tenants, max_validity_s
    def bind_requester(self, anchor, source_url, *, receiver=None) -> str: ...
    def bind_recorder(self, recorder_url) -> str: ...
    def present(self, p, *, session=None) -> dict: ...   # B's answer; "b_time" optional
    def classify(self, answer) -> str: ...        # accepted | refused | in-progress | error
    def evidence_grade(self) -> str: ...          # recorder | b-signed | b-record | b-response
    # optional
    def presentation_forms(self) -> list: ...     # "agent" (default) and/or "a-presigned"
    def status_profile(self) -> str | None: ...   # "kirkaldy" (default) or "bitstring-status-list"
    def push_receiver(self) -> str | None: ...
    def open_session(self, grant_token, endpoint) -> str | None: ...
    def reached_guarantee(self, variant, answer) -> bool: ...
    def restart(self) -> {"before", "after", "how"}: ...
    def set_clock(self, clock) -> None: ...       # virtual clock only
    def variants_not_applicable(self) -> dict: ...
    def variant_notes(self) -> dict: ...
    def remote(self) -> bool: ...                 # B runs on other machines
    def ping(self) -> float: ...                  # one round trip to B's machine, seconds
    def max_in_flight(self) -> int: ...           # fewer than MAX_IN_FLIGHT at once
    def present_deferred(self, p, session, deliver) -> None: ...  # toys on a virtual clock only
```

**Sending and the inconclusive rule** (KRK-M48). `_Dispatcher` sends each
presentation at its slot, whether or not earlier ones have been answered. On the real clock each
`present` runs on a worker thread; at most `MAX_IN_FLIGHT` (32, or the adapter's
`max_in_flight()` if lower) await an answer at once, and the companions (L, W-in, W2; W in a
recovery continuation) are sent only while fewer than 32 − `COMPANION_RESERVE` (4) are, so W
keeps its places. A slot that finds the bound reached is skipped and recorded in the trial's
`scheduler.skipped`. Each answer is awaited for at most `answer_timeout_s(T)` (2T, from 10 s to
60 s; 30 s with no T); after that the presentation is `timed_out`, class `error`, read as neither
answer (at the `recorder` grade an effect still counts as an acceptance), and a later answer is
kept as `answer_after_timeout`. Send and answer times come from the run's one clock. Set-up, the
control and the held request still wait for their answers; they are not timed. A restart waits
for every presentation in flight first.

The bracket runs from the last presentation under W that B accepted (or `t_w`) to the first one
it refused after it. `timing.crosses(lo, hi, T, resolution)` is true when `lo <= T` and
`hi > T + ε + SEND_SLACK_S` (ε the boundary slots' distance, `SEND_SLACK_S` 50 ms). Such a trial
reads `inconclusive` (an information outcome, no verdict), keeping its time and bracket.
`timing.aggregate(outcomes, T, need=N)`: a fail in any trial is the variant's fail; otherwise, if
any trial is inconclusive, the variant passes only if at least N trials passed, N being the
plan's count for the variant over its forms; else it reads `inconclusive`. The probe runs exactly
N, so at the published counts one inconclusive trial withholds the pass. Other information
outcomes keep their old effect. A variant that reads inconclusive withholds the run's pass: with
nothing failed, the result is inconclusive. Statistics add `inconclusive` and `bracket_width_s`
(min, median, max over every trial); `exceedance` counts every failed trial.

**Recovery**. `timing.judge_recovery`: `stuck_closed` (L not accepted again within
W), `accepted_after_recovery` (W accepted after T), `recovered_late` (L refused after the stated
recovery bound), `inconclusive` (the bracket from L's last refusal to its first acceptance crosses
the bound), else `recovered`. The continuation's outcome carries `first_L_accepted_s` and that
bracket.

**Evidence as the run goes**. `NN-progress.jsonl`, one JSON line per event, each
flushed and synced as written: `run` (seed, T, W, plan, the trials needed per variant, the
scheduler's limits), `control`, `ping` (`at`: `trial`, `interval` every `NETWORK_EVERY_S` = 30 s
on the clock's own scheduler, or `end`; `rtt_s`, or `error`), `trial` (the same document as in
the variant file, plus `scheduler`: sent, skipped, timed out, late answers, the largest in-flight
count, answer times by class), `variant` (its reading and statistics), `error`, `end`. Every
presentation records `t_sent`, `t_answered`, `answered`, `timed_out` and `in_flight` (how many
were awaiting an answer when it was sent). The per-variant files are still written at the end of
each variant.

`python -m conformance derive <results/<run>/<target>/P19> [--out file]` (`p19.derive`) reads
the progress file, or, for a run made before it, the per-variant files, into JSON: for each
variant the trials found and needed, the reading as recorded and re-read with the current rules
(`timing.rejudge` for the crossing rule, `timing.judge_recovery` for recovery), the statistics,
the crossing trials, in-flight and skip counts; recovery continuations; answer times by class;
the network samples; restarts and instances; which variants did not run or are incomplete; and
whether the run ended and wrote `result.json`. It is a reading of evidence, never a result.

**A B on other machines**. An adapter whose `remote()` is true is pinged once per
trial and five times at the end, on the kit's clock. The result's `extra.network` reports the
round trips (minimum, median, maximum, failures) and brackets each effect under the withdrawn
authority after `t_w` between its earliest possible commit (the recorder's receipt less the
largest round trip measured, never before its presentation was sent) and the recorder's receipt.
The late call reads the earliest point, so B is never charged for the network. Without
`remote()`, nothing changes. The kit's own listeners (the recorder and the stub A's source) bind
127.0.0.1 unless `ACK_BIND_HOST` names another address, and name `ACK_ADVERTISE_HOST` in the
URLs they give B (`conformance/netbind.py`); IPv6 addresses bind an IPv6 server.

Differences from design §6.3: `present` takes an `authz.Presentation` (P18's) rather than a request
dict; `endpoints()` is the agreement's `endpoints`; `effects()` is the kit's recorder only (the
lower grades read B's answers); `max_rate()` is not read. `presentation_forms` is added: a B that
takes only A-signed requests is presented, after the withdrawal, only requests A signed before it
(a pool signed per trial), since an honest A signs nothing under a withdrawn grant.

`NA_FORBIDDEN`: the control, `withdrawn`, `source_unreachable`, `recovery`;
`presigned_after_withdrawal` where B takes A-signed requests; `stale_signed_snapshot` for a pull
B; `worst_phase` for a pull-list B. The probe itself reads `worst_phase` not applicable without a
pull-list channel, `same_session` without `open_session`, `presigned_after_withdrawal` without the
`a-presigned` form, `restart_after_refusal` without `restart`, and forms that cannot apply
(`push_lost` without push; `served` and `rollback` without a pull channel).

A development plan (`plan=` or `ACK_P19_PLAN`, JSON or a path; real targets only) sets `trials`
(a mapping, or `"dev"`), `window_s`, `stability_s` and `variants`; it is recorded in
`extra.plan`, and the summary starts "Development plan".

## Module 6: `known_bad/withdrawal_toys.py`

`ToyWithdrawal(config="good" | "bad" | "no-control" | "slow-good", flaw=None, *, T=60.0,
clock="virtual")` and `make(flaw=None, **kw)`. `FLAWS` (19) and `FAILS` (flaw -> the variant it
is built to fail), with `slow_and_late` (acts on a withdrawal 1.2 T late and answers slowly;
fails `withdrawn`, KRK-M48) and `recovers_late` (fails `recovery` as
`recovered_late`). `slow-good` is the correct toy answering 0.6 T after an acceptance and 0.1 T after a
refusal, through `present_deferred`; it must pass. Every toy states a recovery bound of T/2. The
known-bad gate runs `good`, `bad` (`no_check`), `no-control`, `slow-good` and one `bad:<flaw>` per
flaw, at the published trial counts on a virtual clock. Every toy that checks status reads its snapshot through
`status.chain_state`, so an absent grant reads by the table in Module 1.
