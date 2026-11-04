"""P19 — Withdrawal within T (KRK-19, cross-organisation X4).

**Guarantee.** For every authorisation B accepted from A, once A's status source serves its
withdrawal (or sends notice of it), every effect B commits under the withdrawn authority is
committed no later than ``t_w + T``; B's refusal holds for the rest of the observation window
through retries, restarts and older signed status; when B cannot reach A's source, B refuses once
its last good status is older than its bound; and B accepts again what A has not withdrawn once
the source is back.

**Question.** After the issuing organisation withdraws an authorisation, does the product stop
committing effects under it within the time it states, in every trial and at the worst phase,
and does it keep refusing through retries, restarts, stale signed status and an unreachable
status source, while still accepting what was not withdrawn?

**Who is graded.** B. The kit plays A with the stub (`conformance/requester.py`):
its own keys, grants it signs, a status source it serves and can take down, notices it can send
or drop. Effects are counted at the kit's recorder downstream of B (`mockserver.py`), with their
commit times on the kit's clock. Role A (how fast A publishes) is version 2; an adapter whose
`role()` is ``"A"`` reads inconclusive.

**Decisions that bind the probe:** B's own stated T decides the verdict, a shorter limit A sets
is information; with no stated T, W replaces T, the measured worst case is reported as the
effective bound and the missing bound as a finding; the configured value counts where the
documentation ties it to withdrawal; a bound with no statistic is a maximum, a percentile is
checked only with enough trials; 30 random-phase trials and 5 worst-phase for the main variant
and 5 for each other, no mean; refusing everything after an outage and never recovering is a
fail, ``stuck_closed``; what counts is when B commits the effect; the stub may present an older
snapshot it genuinely signed and offset its own clock, nothing else; conformance class unless the
target documents enforcement and a variant shows a withdrawn authority honoured with no bound;
self-hosted targets only, restarts only there; cascade and standing stay in P19.

**Probe** (design §4.2).

1. Draw the seed. Read B's stated bound (`withdrawal_bound`: T, its statistic and source, the
   recovery bound, clock tolerance, timestamp resolution), its channels, the request forms it
   takes and its agreement, before anything runs. Start the recorder and the stub A's source on
   the run's one clock; bind B to the stub (`bind_requester`) and to the recorder.
2. Control (below). For a pull-list B, the fetch interval the stub observes during the control
   sets the phase window.
3. Each variant (and form), in a seeded shuffled order, for each trial: a fresh agent subject
   with a withdrawn-to-be grant W and a live sibling L (same agent, same operation, same
   ceiling, another principal); W and L each accepted on fresh requests before the withdrawal,
   the last at least `SETTLE_S` before it (KRK-M15); the phase targeted from B's fetch log
   (KRK-M54); the fixture applied, and counted only once the published state reads back in B's
   format (KRK-M26, KRK-M50); then fresh presentations under W and L on the jittered schedule of
   `timing.schedule`, rotating over every endpoint (KRK-M58), until the refusal onset plus S or
   ``t_w + W``.
   Each presentation is sent at its slot whether or not earlier ones have been answered
   (`_Dispatcher`): at most `MAX_IN_FLIGHT` await an answer at once, each for at
   most `answer_timeout_s`, and its send and answer times are read from the run's one clock. A
   slot that finds the bound reached is skipped and recorded, so a slow B widens the bracket and
   never the spacing.
4. After each trial the recorder settles (the larger of any retry delay it asked for and 2 s) and
   every effect under W is read with its kit-clock commit time.
5. `timing.classify_trial` gives each trial's outcome; `timing.aggregate` and
   `timing.statistics` the variant's. A trial whose bracket crosses T reads ``inconclusive``,
   and a variant with one passes only with enough clean trials (`timing.aggregate`, KRK-M48).

**Evidence as the run goes**. ``NN-progress.jsonl`` gets one line per event, each
flushed to disk as it happens: the run's parameters, the control, every trial with its
presentations and scheduler counts, every ping (for a B on other machines, once per trial and
every `NETWORK_EVERY_S` through the run), each variant's reading, and the end. A run cut short
keeps everything up to the cut; `derive` reads it, or the per-variant files of a run made before
this, into the same statistics.

**Control** (design §4.1; spec §3.1). Before any variant, on a fresh agent: the stub issues W and
L; a fresh request under each is presented to every endpoint B declares and accepted, with
exactly one effect per accepted presentation at the recorder; the kit's own baseline client reads
the current state in B's format; and B's answers are readable. A grant B learns of only at its
next fetch may be refused first (KRK-M46; the status format reads a grant absent from a
snapshot signed before it as not yet listed, but a B may fail safe until its next
fetch): the control presents again, fresh each time, until each is accepted, for up to
`READY_S`. The control never requires that B fetches status, takes notices,
refuses anything, gives refusal codes or states a T (KRK-M19). A B with no channel at all passes
the control and fails ``withdrawn`` (the ``no_check`` toy).

**Within each trial** (§4.1): W refused before the withdrawal makes the trial information
(``refused_before_withdrawal``); L refused after it is ``collateral_refusal`` (KRK-M52), except in
``source_unreachable`` and ``stale_signed_snapshot/served``, where refusing L is the expected
fail-safe and ``recovery`` supplies the attribution.

**Variants** (`VARIANTS`, design §3.1), each with the toy B that fails it
(`known_bad/withdrawal_toys.py`):

| Variant | Planted | Pass |
|---|---|---|
| `withdrawn` | W revoked; every presentation on a new session | refused within T, every trial |
| `worst_phase` | W revoked 50 ms after a fetch by B ends (pull-list B) | refused within T |
| `same_session` | presentations alternate a session opened before `t_w` with new ones | refused within T on both |
| `source_unreachable` | at `t_w` the source refuses (``down``), hangs, answers 503, or drops the notice (``push_lost``) | refused within T (`accepted_open` fails) |
| `recovery` | the source comes back after each `source_unreachable` trial | L accepted again (`stuck_closed` fails); W never |
| `parent_withdrawn` | the parent of W revoked; W itself untouched | refused within T |
| `standing_withdrawn` | W's principal loses standing at A | refused within T |
| `narrowed` | W's ceiling narrowed (or W revoked and a narrower W′ issued where the profile cannot narrow) | outside refused within T; inside accepted |
| `in_flight` | W presented just before `t_w`; the recorder answers B's effect with 503, retry after T + 5 s | no effect after `t_w + T` |
| `presigned_after_withdrawal` | requests A signed before `t_w`, presented after `t_w + T` | refused |
| `regrant` | ``new_grant``: after the onset, W2 for the same agent; ``reinstated``: W suspended, then reinstated | W2 accepted, W still refused; W accepted again |
| `stale_signed_snapshot` | ``stapled``: the newest snapshot signed before `t_w` stapled; ``served``: served to B from `t_w`; ``rollback``: served after B saw the withdrawal | refused within T; never accepted again |
| `skewed_issuer_clock` | the stub's clock offset by `max(2T, tolerance + T)` before it signs | refused within T |
| `restart_after_refusal` | B restarted after its refusal onset (self-hosted) | still refused |

Every presentation is a fresh request, so single use (X3) never explains a refusal (KRK-M51).

**Outcomes.** Per trial: ``within`` (``within_W`` with no stated T), ``late``, ``not_within_W``,
``flapped``, and information outcomes (`timing.INFO_OUTCOMES`). Per variant:
``refused_within_T`` / ``refused_within_W`` (pass), ``refused_late``, ``not_refused_within_W``,
``flapped``, ``accepted_open`` (``source_unreachable``), ``stuck_closed``, ``recovered_late``
(after the stated recovery bound) and
``accepted_after_recovery`` (``recovery``), ``regrant_not_honoured``, ``revived`` and
``reinstatement_not_honoured`` (``regrant``), all fails. The words "never" and "ignores
withdrawal" are not used: not refused by `t_w + W` is ``not_refused_within_W``, reported with W
(KRK-M11).

**Result.** ``fail`` if any landed variant fails. ``pass`` only if the control held, every
variant in `NA_FORBIDDEN` that applies landed with a verdict, no variant read ``inconclusive``,
and every landed variant passed. ``inconclusive`` if the control did not hold, or nothing failed
but a variant that must land did not, or a variant's brackets crossed its bound. With no stated T the summary leads with "no stated bound; measured worst case x s over N
trials", never "pass" alone. The result carries the evidence grade, the bound as read with its
source, the statistics of every variant, and the disclosure class.

**A development plan** (`plan=`, or the environment variable `PLAN_ENV` holding JSON) may set
smaller trial counts, a shorter window and stability window, or a subset of variants, for a
first reading. It is recorded in the result (``extra.plan``), and its summary says so. The plan
``{"trials": "published"}`` alone is not a development plan: it sets the published counts
(`PUBLISHED_TRIALS`, 100 for ``withdrawn``) and nothing else, and is recorded the same way.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P19"
TITLE = "Withdrawal within T"

FIXTURES = ("known_bad/withdrawal_toys.py", "tests/test_p19_withdrawal_within_t.py",
            "tests/vectors/krk19/*.json")
"""The toys, their required outcomes, and the KRK-19 vectors. The stub A, `status.py`,
`timing.py` and the recorder are imported by the probe and hashed into `probe_version`.

**A B on other machines**: an adapter whose `remote()` is true is pinged on the
kit's clock (`ping`), the round trips are reported in `extra.network`, and an effect is judged at
the earliest moment the network allows (the recorder's receipt less the largest round trip, never
before its presentation was sent), so B is never charged for the network. Every other adapter
reads exactly as before."""
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = (
    "The stub A's keys, every agent's key, grant ids, authorisation ids and each request's ref "
    "come from the operating system, never from the seed (KRK-M36).",
    "Times (when B fetches, when a trial's phase falls, every kit-clock reading) are B's and the "
    "clock's; the seed draws the variant order, the jitter, the phase within B's fetch interval "
    "and the requests' values.",
)

VARIANTS = ("withdrawn", "worst_phase", "same_session", "source_unreachable", "recovery",
            "parent_withdrawn", "standing_withdrawn", "narrowed", "in_flight",
            "presigned_after_withdrawal", "regrant", "stale_signed_snapshot",
            "skewed_issuer_clock", "restart_after_refusal")
CONTROL = "control"
FORMS = {"source_unreachable": ("down", "hang", "error", "push_lost"),
         "regrant": ("new_grant", "reinstated"),
         "stale_signed_snapshot": ("stapled", "served", "rollback")}
SETTLE_S = 2.0
"""Between W's last acceptance and the withdrawal, and between the withdrawal and a re-grant
(KRK-M15, KRK-M63): longer than any timestamp resolution a target states up to 1 s."""
TRIALS = {"withdrawn": 30, "worst_phase": 5, "*": 5}
"""Trials per variant and form. A published run uses 100 for ``withdrawn``."""
DEV_TRIALS = {"withdrawn": 5, "worst_phase": 2, "*": 1}
"""Smaller counts for a first reading (a development plan)."""
PUBLISHED_TRIALS = {"withdrawn": 100, "worst_phase": 5, "*": 5}
"""The counts of a published run: 100 for ``withdrawn``, so p99 is estimable, and
the method's own counts for everything else. Chosen with a plan of exactly
``{"trials": "published"}``, which is not a development plan: nothing else changes."""
READY_S = 30.0
"""How long the control and each trial's set-up may wait for B to accept a new grant: B may
read a grant absent from its snapshot as unknown until its next fetch, failing safe
(KRK-M46)."""
NARROW_TO = 50_000
"""``narrowed`` lowers W's ceiling from 99 999 to this; requests above it are outside."""
IN_FLIGHT_MARGIN_S = 5.0
CHANNELS = ("pull-list", "pull-item", "push", "stapled")
FORMS_OF_REQUEST = ("agent", "a-presigned")
"""``agent``: the agent signs each request under the grant. ``a-presigned``: B takes only
requests A signed itself, so every presentation under W after the withdrawal is one A signed
before it (honest: A signs nothing under a withdrawn grant)."""
GRADES = ("recorder", "b-signed", "b-record", "b-response")
CLASSES = ("accepted", "refused", "in-progress", "error")
BOUND_SOURCES = ("documented", "configured", "carried", "unstated")
NA_FORBIDDEN = (CONTROL, "withdrawn", "source_unreachable", "recovery",
                "presigned_after_withdrawal", "stale_signed_snapshot", "worst_phase")
"""Variants an adapter may not declare not applicable (design §6.3). ``presigned_after_
withdrawal`` only where B takes A-signed requests, ``stale_signed_snapshot`` (its ``served``
form) only for a pull B, ``worst_phase`` only for a pull-list B: elsewhere the probe itself
reads them not applicable, with the reason."""
VULNERABLE = ("not_refused_within_W", "accepted_open")
VULNERABLE_VARIANTS = ("stale_signed_snapshot", "parent_withdrawn", "same_session")
PLAN_ENV = "ACK_P19_PLAN"
MAX_IN_FLIGHT = 32
"""At most this many presentations await B's answer at once (design §4.3, Load).
An adapter may declare fewer (`max_in_flight`). A slot that finds the bound reached is not sent
and is recorded as skipped, so the gap shows in the trial's bracket, never in its spacing."""
COMPANION_RESERVE = 4
"""Places kept for the presentation under W: its companions (L, W-in, W2, and W in a recovery
continuation, where L is the one measured) are sent only while fewer than the bound less this
are in flight."""
NETWORK_EVERY_S = 30.0
"""For a B on other machines, a ping every this many seconds through the run, besides the one
at the start of each trial."""


def answer_timeout_s(T: Optional[float]) -> float:
    """How long the kit waits for one answer: twice T, at least 10 s and at most 60 s; 30 s with
    no stated T. A presentation with no answer by then is ``timed_out``: class ``error``, read as
    neither answer (at the ``recorder`` grade an effect still counts as an acceptance), and an
    answer that comes later is kept in the evidence but not read."""
    return min(60.0, max(10.0, 2.0 * float(T))) if T else 30.0


class Adapter(Protocol):
    """Role B. Every method is the product's own path; the adapter adds no check of its own."""

    name: str
    config: str
    clock: str
    """``"real"`` for every real target; ``"virtual"`` for toys only (KRK-M56)."""

    def role(self) -> str: ...

    def withdrawal_bound(self) -> Dict[str, Any]:
        """``{"T_s": float | None, "statistic", "source": one of BOUND_SOURCES, "quote", "url",
        "setting", "recovery_s", "clock_tolerance_s", "resolution_s"}``, read before the run
        (design §5)."""
        ...

    def channels(self) -> List[str]:
        """Any of `CHANNELS`; [] if B has no way to learn of a withdrawal."""
        ...

    def agreement(self) -> Dict[str, Any]:
        """``counterparty`` (B's own id), ``endpoints``, ``tenants``, ``max_validity_s``."""
        ...

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        """Pin A's keys and point B at the stub's source, in whatever form B takes them."""
        ...

    def bind_recorder(self, recorder_url: str) -> str: ...

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        """Send one `authz.Presentation` through the product's real entry point, unchanged."""
        ...

    def classify(self, answer: Dict[str, Any]) -> str:
        """One of `CLASSES`, by the product's documented codes."""
        ...

    def evidence_grade(self) -> str: ...

    # optional
    def presentation_forms(self) -> List[str]: ...
    def status_profile(self) -> Optional[str]: ...
    def push_receiver(self) -> Optional[str]: ...
    def open_session(self, grant_token: str, endpoint: str) -> Optional[str]: ...
    def reached_guarantee(self, variant: str, answer: Dict[str, Any]) -> bool: ...
    def restart(self) -> Dict[str, Any]: ...
    def set_clock(self, clock: Any) -> None: ...
    def variants_not_applicable(self) -> Dict[str, str]: ...
    def variant_notes(self) -> Dict[str, str]: ...
    def max_in_flight(self) -> int:
        """At most this many presentations awaiting an answer (never above `MAX_IN_FLIGHT`)."""
        ...
    def present_deferred(self, p: Any, session: Optional[str],
                         deliver: Callable[[Dict[str, Any]], None]) -> None:
        """Toys on a virtual clock only: as `present`, but B hands its answer to `deliver` when
        it answers, which may be later on the virtual clock (a slow B). The kit still reads the
        answer's time from its own clock, when `deliver` is called."""
        ...


# --------------------------------------------------------------------------- sending


class _Dispatcher:
    """Sends presentations on the probe's own schedule (KRK-M48).

    The probe once sent one presentation and waited for its answer before the next, so its
    spacing was B's answer time: a B that answered in seconds left many trials with a bracket
    that crossed T (KRK-M48). Now `submit` sends and returns at once. On the real clock each
    presentation runs on a worker thread (at most `limit` at a time); on a virtual clock (toys
    only) a toy answers at once through `present`, or later through `present_deferred`. Every
    send and answer time is read from the run's one clock. `poll` collects answers that have
    arrived and times out the ones overdue; `wait` and `drain` wait for one or for all."""

    WAIT = False
    """True makes `submit` wait for each answer, as the probe once did (KRK-M48). Only a
    test sets it, to show the reading KRK-M48 describes."""

    def __init__(self, run: "_Run", limit: int, timeout: float) -> None:
        self.run, self.limit, self.timeout = run, max(1, int(limit)), float(timeout)
        self.virtual = getattr(run.clock, "kind", "real") == "virtual"
        self._lock = threading.Lock()
        self._done: List[Tuple[Any, float, Dict[str, Any], float, float]] = []
        self._pending: Dict[int, Any] = {}
        self.busy = 0
        """Sent and not yet answered, timed-out ones included (their request is still out)."""
        self._pool: Any = None
        self.totals = {"sent": 0, "skipped": 0, "timed_out": 0, "late_answers": 0,
                       "max_in_flight": 0}
        self.begin_trial()

    def begin_trial(self) -> None:
        self.trial = {"sent": 0, "skipped": 0, "timed_out": 0, "late_answers": 0,
                      "max_in_flight": 0}

    def _count(self, key: str, n: int = 1) -> None:
        self.trial[key] += n
        self.totals[key] += n

    def _peak(self) -> None:
        self.trial["max_in_flight"] = max(self.trial["max_in_flight"], self.busy)
        self.totals["max_in_flight"] = max(self.totals["max_in_flight"], self.busy)

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    # sending --------------------------------------------------------------------------------

    def submit(self, p: Any, under: str, *, session: Optional[str] = None, tag: str = "",
               companion: bool = False) -> Optional[Any]:
        """Send one presentation now and return its `timing.Pres` (unanswered until `poll`
        reads the answer), or None if the in-flight bound leaves no place for it."""
        from ..timing import Pres
        self.poll()
        cap = max(1, self.limit - (COMPANION_RESERVE if companion else 0))
        with self._lock:
            if self.busy >= cap:
                full = True
            else:
                full = False
                ref = str(json.loads(p.request.decode("utf-8")).get("ref"))
                pr = Pres(under, self.run.clock.now(), cls="pending", endpoint=p.endpoint,
                          session=session or "", tag=tag, ref=ref, answered=False,
                          in_flight=self.busy)
                self.busy += 1
                self._pending[id(pr)] = pr
        if full:
            self._count("skipped")
            return None
        self._count("sent")
        self._peak()
        if self.virtual:
            w0 = self.run.clock.wall()
            deferred = getattr(self.run.a, "present_deferred", None)
            if callable(deferred):
                try:
                    deferred(p, session, lambda ans: self._arrive(pr, w0, ans))
                except Exception as e:  # noqa: BLE001 - B's failure is an answer
                    self._arrive(pr, w0, {"status": None,
                                          "raised": f"{type(e).__name__}: {e}"[:300]})
            else:
                self._arrive(pr, w0, self._call(p, session))
        else:
            if self._pool is None:
                from concurrent.futures import ThreadPoolExecutor
                self._pool = ThreadPoolExecutor(max_workers=self.limit,
                                                thread_name_prefix="p19-present")
            self._pool.submit(self._work, pr, p, session)
        if self.WAIT:
            self.wait(pr)
        else:
            self.poll()
        return pr

    def send(self, p: Any, under: str, *, session: Optional[str] = None, tag: str = "") -> Any:
        """Send one presentation and wait for its answer (set-up, the control, the held
        request): these are not timed, so waiting costs no resolution."""
        while True:
            pr = self.submit(p, under, session=session, tag=tag)
            if pr is not None:
                self.wait(pr)
                return pr
            self._sleep()

    def _work(self, pr: Any, p: Any, session: Optional[str]) -> None:
        pr.t_sent = self.run.clock.now()          # the send itself, on this worker thread
        w0 = self.run.clock.wall()
        self._arrive(pr, w0, self._call(p, session))

    def _call(self, p: Any, session: Optional[str]) -> Dict[str, Any]:
        try:
            ans = self.run.a.present(p, session=session)
            if not isinstance(ans, dict):
                ans = {"status": None, "body": ans}
        except Exception as e:  # noqa: BLE001 - B's failure is an answer, recorded as such
            ans = {"status": None, "raised": f"{type(e).__name__}: {e}"[:300]}
        return ans

    def _arrive(self, pr: Any, w0: float, ans: Any) -> None:
        t1, w1 = self.run.clock.now(), self.run.clock.wall()
        if not isinstance(ans, dict):
            ans = {"status": None, "body": ans}
        with self._lock:
            self.busy -= 1
            if pr.timed_out:
                pr.answer_after_timeout = {  # type: ignore[attr-defined]
                    "t_answered": t1, "answer": _short(ans)}
                late = True
            else:
                self._done.append((pr, w0, ans, t1, w1))
                late = False
        if late:
            self._count("late_answers")

    # reading answers ------------------------------------------------------------------------

    def poll(self) -> None:
        with self._lock:
            done, self._done = self._done, []
            for pr, *_ in done:
                self._pending.pop(id(pr), None)
            now = self.run.clock.now()
            expired = [pr for pr in self._pending.values() if now - pr.t_sent > self.timeout]
            for pr in expired:
                pr.timed_out = True
                self._pending.pop(id(pr), None)
        for pr, w0, ans, t1, w1 in done:
            self.run.take_answer(pr, w0, ans, t1, w1)
        for pr in expired:
            pr.cls = "error"
            pr.t_answered = now
            pr.answer = {"raised": f"no answer within {self.timeout:g} s"}  # type: ignore
            self.run.refresh_effects()
            self.run.fill(pr)
        if expired:
            self._count("timed_out", len(expired))

    def pending(self) -> int:
        with self._lock:
            return len(self._pending)

    def _sleep(self) -> None:
        if self.virtual:
            self.run.clock.sleep(0.01)
        else:
            time.sleep(0.002)

    def wait(self, pr: Any) -> None:
        while True:
            self.poll()
            if pr.answered or pr.timed_out:
                return
            self._sleep()

    def drain(self) -> None:
        """Wait until every presentation sent has been answered or has timed out."""
        while True:
            self.poll()
            if not self.pending():
                return
            self._sleep()


def _settled(p: Any) -> bool:
    return bool(p.answered or p.timed_out)


LOOP_TAGS = ("regular", "boundary-before", "boundary-after")


def _streak(pres: List[Any]) -> Optional[float]:
    """The kit time of the first refusal under W in the current run of refusals, read over the
    trial's scheduled presentations in send order up to the first one still unanswered (so an
    answer that has not come yet never ends or starts a streak)."""
    streak = None
    for p in pres:
        if p.under != "W" or p.tag.split(":")[0] not in LOOP_TAGS:
            continue
        if not _settled(p):
            break
        if p.accepted:
            streak = None
        elif p.refused and streak is None:
            streak = p.t_sent
    return streak


class _Progress:
    """``NN-progress.jsonl``: one JSON line per event, flushed and synced as it is
    written, so a run cut short keeps every line before the cut."""

    def __init__(self, ev: Evidence) -> None:
        self.path = ev.write("progress.jsonl", "")
        self._lock = threading.Lock()

    def add(self, kind: str, **doc: Any) -> None:
        rec = {"kind": kind, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **doc}
        line = json.dumps(_jsonable(rec), sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())


# --------------------------------------------------------------------------- one run


class _Run:
    """Everything one probe run shares: the clock, the stub A, the recorder, B's statements."""

    def __init__(self, a: Adapter, ev: Evidence, *, clock: Any, stub: Any, recorder: Any,
                 prefix: str, agreement: Dict[str, Any], bound: Dict[str, Any],
                 channels: List[str], forms: List[str], grade: str, rng: random.Random,
                 window: float, stability: float) -> None:
        self.a, self.ev, self.clock, self.stub, self.recorder = a, ev, clock, stub, recorder
        self.prefix, self.agreement, self.bound = prefix, agreement, bound
        self.channels, self.forms, self.grade, self.rng = channels, forms, grade, rng
        self.T: Optional[float] = bound.get("T_s")
        self.window, self.stability = window, stability
        self.resolution = bound.get("resolution_s")
        eps = list(agreement.get("endpoints") or ["default"])
        self.endpoints = eps
        tns = list(agreement.get("tenants") or [])
        self.tenant = tns[0] if tns else None
        self.counterparty = agreement["counterparty"]
        mx = agreement.get("max_validity_s")
        self.req_window = (-900.0, min(900.0, float(mx) - 60) if isinstance(mx, (int, float))
                           and mx > 120 else 900.0)
        """Per-request validity, relative to the signer's clock: from 15 minutes back, so the
        clock-offset fixture never makes an A-signed request not yet valid at B."""
        self.signer = "agent" if "agent" in forms else "a"
        self.reached = getattr(a, "reached_guarantee", None)
        self.sessions = callable(getattr(a, "open_session", None))
        self._eff_idx = 0
        self._effects: Dict[str, List[float]] = {}
        self.max_interval = 0.0
        self.rtt = 0.0
        self.b_offsets: List[Tuple[float, float]] = []
        self.variant = CONTROL
        try:
            self.remote = bool(getattr(a, "remote", lambda: False)())
        except Exception:  # noqa: BLE001
            self.remote = False
        self.pings: List[float] = []
        self.net_failures = 0
        self._net_lock = threading.Lock()
        self.effect_brackets: List[Dict[str, Any]] = []
        self.progress: Optional[_Progress] = None
        self.t0 = clock.now()
        limit = MAX_IN_FLIGHT
        try:
            declared = getattr(a, "max_in_flight", None)
            if callable(declared):
                limit = max(1, min(MAX_IN_FLIGHT, int(declared())))
        except Exception:  # noqa: BLE001
            limit = MAX_IN_FLIGHT
        self.disp = _Dispatcher(self, limit, answer_timeout_s(self.T))

    def log(self, kind: str, **doc: Any) -> None:
        if self.progress is not None:
            self.progress.add(kind, t_kit_s=round(self.clock.now() - self.t0, 4), **doc)

    # the network (a B on other machines) ---------------------------------------

    def sample_network(self, n: int = 1, at: str = "trial") -> None:
        """Round trips to B's machine, on the kit's clock (`ping`, adapters of a remote B only).
        Each sample goes to the progress file as it is taken."""
        if not self.remote:
            return
        for _ in range(n):
            try:
                rtt = float(self.a.ping())
            except Exception as e:  # noqa: BLE001 - a failed ping is counted, never a reading
                with self._net_lock:
                    self.net_failures += 1
                self.log("ping", at=at, variant=self.variant, rtt_s=None,
                         error=f"{type(e).__name__}: {e}"[:200])
                continue
            with self._net_lock:
                self.pings.append(rtt)
            self.log("ping", at=at, variant=self.variant, rtt_s=round(rtt, 6))

    @property
    def net_allowance(self) -> float:
        """How much earlier than the recorder's receipt an effect may have been committed at B:
        the largest round trip measured to B's machine (one way is at most that). Zero for a B
        on the kit's own host, so local readings are unchanged."""
        return max(self.pings) if (self.remote and self.pings) else 0.0

    # requests ------------------------------------------------------------------------------

    def audience(self, endpoint: str) -> Dict[str, Any]:
        return {"counterparty": self.counterparty, "endpoint": endpoint, "tenant": self.tenant}

    def values(self, *, lo: int = 100, hi: int = 99_999) -> Dict[str, Any]:
        from .. import requester
        v = requester.draw_values(self.rng)
        v["amount"] = self.rng.randint(lo, hi)
        return v

    def presentation(self, grant: Any, endpoint: str, *, values: Optional[Dict[str, Any]] = None,
                     signer: Optional[str] = None, staple: Optional[str] = None) -> Any:
        return self.stub.under(grant, values or self.values(), audience=self.audience(endpoint),
                               signer=signer or self.signer, staple=staple,
                               window_s=self.req_window)

    def send(self, p: Any, under: str, *, session: Optional[str] = None, tag: str = "") -> Any:
        """Send one presentation and wait for its answer (untimed sends: set-up, the control)."""
        return self.disp.send(p, under, session=session, tag=tag)

    def take_answer(self, pr: Any, w0: float, ans: Dict[str, Any], t1: float,
                    w1: float) -> None:
        """Read one answer that has arrived (on the probe's thread)."""
        t0 = pr.t_sent
        bt = ans.get("b_time")
        if isinstance(bt, (int, float)) and not isinstance(bt, bool):
            # B's own timestamp on its answer: its offset from the kit, information only; no
            # order and no verdict reads it (§4.4, KRK-M65).
            self.b_offsets.append((float(bt) - (w0 + w1) / 2.0, (t1 - t0) / 2.0))
        try:
            cls = "error" if ans.get("raised") else self.a.classify(ans)
        except Exception:  # noqa: BLE001
            cls = "error"
        if cls not in CLASSES:
            cls = "error"
        reached = True
        if cls == "refused" and self.reached is not None:
            try:
                reached = bool(self.reached(self.variant, ans))
            except Exception:  # noqa: BLE001
                reached = True
        pr.t_answered, pr.cls, pr.reached = t1, cls, reached
        pr.answer = _short(ans)  # type: ignore[attr-defined]
        pr.answered = True
        if self.rtt == 0.0 or (t1 - t0) < self.rtt:
            self.rtt = max(0.0, t1 - t0)
        self.refresh_effects()
        self.fill(pr)

    def refresh_effects(self) -> None:
        new, self._eff_idx = self.recorder.effects_after(self._eff_idx, self.prefix)
        for e in new:
            ref = str((e.get("effect") or {}).get("ref"))
            self._effects.setdefault(ref, []).append(e["t_kit"])

    def effect_times(self, ref: str) -> List[float]:
        return list(self._effects.get(str(ref), []))

    def fill(self, pr: Any) -> None:
        """Acceptance where the grade observes it: an effect at the recorder, else B's word."""
        ts = self.effect_times(pr.ref)
        if self.grade == "recorder":
            pr.effect_t = min(ts) if ts else None
            pr.accepted = bool(ts)
        else:
            pr.accepted = pr.cls == "accepted"
            pr.effect_t = pr.t_answered if pr.accepted else None

    def open(self, grant: Any, endpoint: str) -> Optional[str]:
        if not self.sessions:
            return None
        try:
            return self.a.open_session(grant.token, endpoint)
        except Exception:  # noqa: BLE001
            return None

    # B's fetches ---------------------------------------------------------------------------

    def fetches(self, since: float = float("-inf")) -> List[Dict[str, Any]]:
        return [e for e in self.stub.fetch_log(since) if e.get("t_end") is not None]

    def note_intervals(self) -> None:
        from ..timing import fetch_intervals
        iv = fetch_intervals(self.stub.fetch_log())
        if iv:
            self.max_interval = max(self.max_interval, max(iv))

    def next_fetch_end(self, after: float, limit_s: float) -> Optional[float]:
        """Wait for a fetch by B that ends after `after`; its end time, or None."""
        deadline = self.clock.now() + limit_s
        step = 0.05
        while self.clock.now() <= deadline:
            done = [e["t_end"] for e in self.fetches(after) if e["t_end"] > after
                    and e.get("outcome") == "ok"]
            if done:
                return min(done)
            self.clock.sleep(step)
        return None

    def settle(self, until: float) -> None:
        self.clock.sleep_until(max(until, self.clock.now()))
        self.refresh_effects()


def _short(ans: Any) -> Any:
    if not isinstance(ans, dict):
        return ans
    out = {k: ans[k] for k in ("status", "raised", "b_time") if k in ans}
    body = ans.get("body")
    out["body"] = body if not isinstance(body, (str, bytes)) else str(body)[:300]
    if isinstance(body, dict):
        out["body"] = {k: v for k, v in body.items() if k not in ("receipt",)}
    return out


def _pres_doc(p: Any, t_w: Optional[float]) -> Dict[str, Any]:
    base = t_w if t_w is not None else 0.0
    doc = {"under": p.under, "t_sent": round(p.t_sent - base, 4),
           "t_answered": round(p.t_answered - base, 4), "cls": p.cls, "accepted": p.accepted,
           "effect_t": None if p.effect_t is None else round(p.effect_t - base, 4),
           "reached": p.reached, "endpoint": p.endpoint, "session": p.session, "tag": p.tag,
           "ref": p.ref, "answer": getattr(p, "answer", None), "answered": p.answered,
           "timed_out": p.timed_out, "in_flight": p.in_flight}
    late = getattr(p, "answer_after_timeout", None)
    if late:
        doc["answer_after_timeout"] = {"t_answered": round(late["t_answered"] - base, 4),
                                       "answer": late["answer"]}
    return doc


# --------------------------------------------------------------------------- the control


def _ready(run: _Run, grant: Any, under: str, endpoint: str, *, deadline: float,
           log: List[Any]) -> bool:
    """Present fresh requests under `grant` at `endpoint` until one is accepted, until
    `deadline` (B may learn of a new grant only at its next fetch)."""
    from ..timing import delta_s
    while True:
        p = run.send(run.presentation(grant, endpoint), under, session=run.open(grant, endpoint),
                     tag="ready")
        log.append(p)
        if p.accepted:
            return True
        if run.clock.now() >= deadline:
            return False
        run.clock.sleep(max(0.2, delta_s(run.T)))


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    stub = run.stub
    subject = f"agent-{secrets.token_hex(4)}"
    W = stub.issue(subject, principal=f"pw-{secrets.token_hex(3)}@a.example")
    L = stub.issue(subject, principal=f"pl-{secrets.token_hex(3)}@a.example")
    log: List[Any] = []
    deadline = run.clock.now() + READY_S
    for ep in run.endpoints:
        for g, u in ((W, "W"), (L, "L")):
            if not _ready(run, g, u, ep, deadline=deadline, log=log):
                return False, f"a fresh request under {u} at endpoint {ep!r} was not accepted " \
                              f"within {READY_S:g} s", {"presentations": log}
    run.settle(run.clock.now() + 0.5)
    for p in log:
        run.fill(p)
        if run.grade != "recorder":
            continue                     # below the recorder grade, B's answers are the evidence
        n = len(run.effect_times(p.ref))
        if p.accepted and n != 1:
            return False, f"an accepted presentation ({p.ref}) has {n} effects at the " \
                          f"recorder", {"presentations": log}
        if not p.accepted and n:
            return False, f"a presentation B did not accept ({p.ref}) has an effect", \
                {"presentations": log}
    if any(p.cls == "error" and (getattr(p, "answer", {}) or {}).get("raised") for p in log
           if p.accepted):
        return False, "an accepted presentation had no readable answer", {"presentations": log}
    ok, tok, detail = stub.baseline_read()
    if not ok:
        return False, f"the kit's baseline client could not read the stub's source ({detail})", \
            {"presentations": log}
    obs: Dict[str, Any] = {"presentations": log, "baseline": detail}
    if "pull-list" in run.channels:
        # Observe B's fetch interval (never required: KRK-M19).
        limit = max(10.0, 2.0 * (run.T or 30.0))
        end = run.clock.now() + limit
        while run.clock.now() < end and len(run.fetches()) < 3:
            run.clock.sleep(0.25)
        run.note_intervals()
        from ..timing import fetch_intervals
        iv = fetch_intervals(stub.fetch_log())
        obs["fetch_intervals_s"] = [round(x, 3) for x in iv]
        obs["fetches_observed"] = len(run.fetches())
    return True, "", obs


# --------------------------------------------------------------------------- one trial


class _Trial:
    def __init__(self, run: _Run, variant: str, form: str, k: int) -> None:
        self.run, self.variant, self.form, self.k = run, variant, form, k
        self.pres: List[Any] = []
        self.notes: Dict[str, Any] = {}
        self.t_w: Optional[float] = None
        self.phase_s: Optional[float] = None
        self.info: Optional[str] = None
        self.info_detail = ""
        self.settle_until = 0.0
        self.w_refs: List[str] = []
        self.pool: List[Any] = []
        self.pi = 0

    def stop_info(self, outcome: str, detail: str) -> None:
        self.info, self.info_detail = outcome, detail


# The guards, one function each, so a test can show the reading each one prevents
# (docs/FAILURE-MODES.md, KRK-M50 to KRK-M65).


def _outage_breaches(run: "_Run", t_w: float) -> List[Dict[str, Any]]:
    """KRK-M59: fetches by B that succeeded during an outage. Any one means B reached the
    source another way, and the outage did not land."""
    return [e for e in run.fetches(t_w) if e.get("outcome") == "ok"]


def _staple_for(stub: Any, t_w: float, wd: Any) -> Tuple[Optional[str], Optional[int], str]:
    """KRK-M61: the newest snapshot the stub signed before `t_w`, if it predates the withdrawal
    (its version is older than the one that first shows it): (bytes, version, why not)."""
    st = stub.latest_before(t_w)
    if st is None:
        return None, None, "no snapshot was signed before the withdrawal"
    if st["version"] >= wd.version:
        return None, st["version"], (f"the newest snapshot before t_w is version "
                                     f"{st['version']}, not older than the withdrawal's "
                                     f"{wd.version}")
    return st["profile_token"], st["version"], ""


def _failsafe(variant: str, form: str) -> bool:
    """KRK-M52: where refusing the live sibling is the expected fail-safe rather than
    collateral: B can get no fresh status from the source."""
    return variant == "source_unreachable" or (
        variant == "stale_signed_snapshot" and form in ("served", "rollback"))


def _split_at(log: Any, mid: float) -> Any:
    """KRK-M63: the part of a trial up to a re-grant at kit time `mid`. A presentation at the
    re-grant's own instant was sent before it: on a virtual clock nothing moves during a
    presentation, so the refusal that triggered the re-grant shares its time."""
    import dataclasses
    return dataclasses.replace(log, presentations=[
        p for p in log.presentations if p.t_sent <= mid], w_effects=[
        e for e in log.w_effects if e <= mid])


def _expect_for(variant: str, form: str, w: Any, parent: Any, principal: str,
                profile: str, wd: Any) -> Dict[str, str]:
    if variant == "parent_withdrawn":
        return {parent.id: "revoked"}
    if variant == "standing_withdrawn":
        return {f"principal:{principal}": "withdrawn"}
    if variant == "narrowed":
        if wd.replacement:
            return {w.id: "revoked", wd.replacement: "valid"}
        return {w.id: "narrowed"}
    if variant == "regrant" and form == "reinstated":
        return {w.id: "suspended"}
    return {w.id: "revoked"}


def _run_trial(run: _Run, variant: str, form: str, k: int) -> Tuple[Any, Any]:
    """One trial. Returns (TrialLog, extra judgement dict) for classification."""
    from .. import timing
    from ..timing import TrialLog
    stub, clock, T = run.stub, run.clock, run.T
    run.variant = variant
    tr = _Trial(run, variant, form, k)
    run.disp.begin_trial()
    run.sample_network(1)
    subject = f"agent-{secrets.token_hex(4)}"
    pw = f"pw-{secrets.token_hex(3)}@a.example"
    pl = f"pl-{secrets.token_hex(3)}@a.example"
    extra: Dict[str, Any] = {}
    skew = 0.0
    if variant == "skewed_issuer_clock":
        tol = float(run.bound.get("clock_tolerance_s") or 0.0)
        skew = max(2 * T, tol + T) if T else tol + 120.0
        stub.set_clock_offset(skew)
        stub.reissue()
        extra["clock_offset_s"] = skew
        if "pull-list" in run.channels:
            run.note_intervals()
            got = run.next_fetch_end(clock.now(), limit_s=max(2 * run.max_interval, 5.0) + 1)
            extra["fetched_offset_snapshot"] = got is not None
    parent = None
    try:
        if variant == "parent_withdrawn":
            parent = stub.issue(subject, principal=pw)
            W = stub.delegate(parent, subject)
        else:
            W = stub.issue(subject, principal=pw)
        L = stub.issue(subject, principal=pl)
        ep0 = run.endpoints[0]
        old_session = None
        if variant == "same_session":
            old_session = run.open(W, ep0)
            if old_session is None:
                tr.stop_info("not_landed", "B opened no session for W, so a session opened "
                                           "before the withdrawal cannot be presented on")
        # Before t_w: each accepted on fresh requests.
        deadline = clock.now() + READY_S
        pre: List[Any] = []
        okw = tr.info is None and _ready(run, W, "W", ep0, deadline=deadline, log=pre)
        okl = tr.info is None and _ready(run, L, "L", ep0, deadline=deadline, log=pre)
        if variant == "narrowed" and okw:
            # an out-of-ceiling request under W, accepted before the narrowing
            p = run.send(run.presentation(W, ep0, values=run.values(lo=NARROW_TO + 1)), "W",
                         session=run.open(W, ep0), tag="pre-outside")
            pre.append(p)
            okw = p.accepted
        if variant == "same_session" and okw and old_session is not None:
            p = run.send(run.presentation(W, ep0), "W", session=old_session, tag="pre-session")
            pre.append(p)
            okw = p.accepted
        tr.pres.extend(pre)
        tr.w_refs.extend(p.ref for p in pre if p.under == "W")
        if tr.info is None and not (okw and okl):
            refused = any(p.under == "W" and p.refused for p in pre)
            tr.stop_info("refused_before_withdrawal" if refused and not okw else "not_ready",
                         f"before the withdrawal W accepted: {okw}, L accepted: {okl}")
        if tr.info:
            return _finish(run, tr, W, L), extra
        clock.sleep(SETTLE_S)

        # Phase (pull-list only).
        if "pull-list" in run.channels and variant not in ("source_unreachable",):
            run.note_intervals()
            P = run.max_interval
            f = run.next_fetch_end(clock.now(), limit_s=max(2 * P, 5.0) + 1) if P else None
            if f is None:
                if variant == "worst_phase":
                    tr.stop_info("not_landed", "no fetch by B was observed, so its worst phase "
                                               "cannot be targeted")
                    return _finish(run, tr, W, L), extra
            else:
                target = timing.phase_target(f, P, run.rng,
                                             "worst" if variant == "worst_phase" else "random")
                clock.sleep_until(target)
                tr.phase_s = clock.now() - f
        elif variant == "worst_phase":
            tr.stop_info("not_landed", "B declares no pull-list channel")
            return _finish(run, tr, W, L), extra

        slots = timing.schedule(T, run.rng, window=run.window, resolution_s=run.resolution,
                                start_s=(T + timing.epsilon_s(run.resolution))
                                if (variant == "presigned_after_withdrawal" and T) else 0.0)
        # Requests under W after the withdrawal that only A could sign are signed now, before it.
        pool: List[Any] = tr.pool
        presigned = variant == "presigned_after_withdrawal" or run.signer == "a"
        if presigned:
            n = 2 * len(slots) + 20
            for i in range(n):
                ep = run.endpoints[i % len(run.endpoints)]
                vals = run.values(lo=NARROW_TO + 1) if variant == "narrowed" else run.values()
                pool.append(run.presentation(W, ep, values=vals, signer="a"))
        held_ref = None
        if variant == "in_flight":
            retry = (T if T else 30.0) + IN_FLIGHT_MARGIN_S
            p = run.presentation(W, ep0)
            held_ref = json.loads(p.request.decode("utf-8"))["ref"]
            run.recorder.hold(held_ref, retry)
            hp = run.send(p, "W", session=run.open(W, ep0), tag="in-flight")
            tr.pres.append(hp)
            tr.w_refs.append(hp.ref)
            extra.update(held_ref=held_ref, retry_after_s=retry, held_answer=hp.cls)
            tr.settle_until = clock.now() + retry + 2.0

        # The fixture.
        before = stub.current()
        s_old = None
        if variant == "source_unreachable":
            mode = "down" if form == "push_lost" else form
            stub.set_source("push-drop")
            stub.set_source(mode)
        if variant == "stale_signed_snapshot" and form == "served":
            stub.set_source("stale", version=before["version"])
        if variant == "stale_signed_snapshot" and form == "rollback":
            s_old = stub.reissue()           # a fresh pre-withdrawal snapshot, signed now
        if variant == "parent_withdrawn":
            wd = stub.withdraw(parent.id)
        elif variant == "standing_withdrawn":
            wd = stub.withdraw_standing(pw)
        elif variant == "narrowed":
            wd = stub.narrow(W.id, {"max_amount": NARROW_TO})
        elif variant == "regrant" and form == "reinstated":
            if stub.status_profile != "kirkaldy":
                tr.stop_info("not_landed", f"the {stub.status_profile} profile has no "
                                           f"suspension (KRK-M62)")
                return _finish(run, tr, W, L), extra
            wd = stub.suspend(W.id)
        else:
            wd = stub.withdraw(W.id)
        tr.t_w = t_w = wd.t_commit
        extra["withdrawal"] = {"kind": wd.kind, "version": wd.version,
                               "replacement": wd.replacement}
        # Landed?
        if variant == "source_unreachable":
            reached, _tok, detail = stub.baseline_read()
            extra["baseline_during_outage"] = detail
            if reached:
                tr.stop_info("fixture_not_landed", f"the kit's baseline client still reached "
                                                   f"the source ({detail}) (KRK-M59)")
                return _finish(run, tr, W, L), extra
        else:
            expect = _expect_for(variant, form, W, parent, pw, stub.status_profile, wd)
            got = stub.read_back(expect)
            if not all(got.values()):
                tr.stop_info("fixture_not_landed", f"the published state does not read back as "
                                                   f"{expect}: {got} (KRK-M26)")
                return _finish(run, tr, W, L), extra
            wd.t_landed = clock.now()
            extra["read_back"] = got
        W_in = stub.grants[wd.replacement] if wd.replacement else W
        staple = None
        if variant == "stale_signed_snapshot" and form == "stapled":
            staple, sv, why_not = _staple_for(stub, t_w, wd)
            extra["staple_version"] = sv
            if staple is None:
                tr.stop_info("fixture_not_landed", f"{why_not} (KRK-M61)")
                return _finish(run, tr, W, L), extra

        # The schedule: each slot is sent at its time, whatever is still awaiting an answer
        #; the refusal streak is read from the answers that have come back.
        S = run.stability
        disp = run.disp
        streak: Optional[float] = None       # kit time of the first refusal in the current run
        mid_at: Optional[float] = None       # when a mid-trial action happened
        W2 = None
        rolled = False
        restarted = None
        skipped: List[Dict[str, Any]] = []
        tr.notes["skipped"] = skipped

        def companion(q: Any, under: str, sess: Optional[str], off: float) -> None:
            got = disp.submit(q, under, session=sess, tag="regular", companion=True)
            if got is None:
                skipped.append({"offset_s": round(off, 4), "under": under})
            else:
                tr.pres.append(got)

        for i, slot in enumerate(slots):
            target = t_w + slot.offset_s
            clock.sleep_until(target)
            disp.poll()
            ep = run.endpoints[i % len(run.endpoints)]
            # W
            if presigned:
                if tr.pi >= len(pool):
                    tr.notes["pool_exhausted_at_s"] = round(slot.offset_s, 4)
                    break
                p = pool[tr.pi]
                ep = p.endpoint
            else:
                vals = run.values(lo=NARROW_TO + 1) if variant == "narrowed" else None
                p = run.presentation(W, ep, values=vals, staple=staple)
            if variant == "same_session":
                sess = old_session if i % 2 == 0 else run.open(W, ep)
            else:
                sess = run.open(W, ep)
            pw_ = disp.submit(p, "W", session=sess, tag=slot.kind + (
                ":old-session" if variant == "same_session" and i % 2 == 0 else ""))
            if pw_ is None:
                skipped.append({"offset_s": round(slot.offset_s, 4), "under": "W",
                                "kind": slot.kind})
            else:
                if presigned:
                    tr.pi += 1
                tr.pres.append(pw_)
                tr.w_refs.append(pw_.ref)
            # L, and the variant's own presentations
            companion(run.presentation(L, ep), "L", run.open(L, ep), slot.offset_s)
            if variant == "narrowed":
                companion(run.presentation(W_in, ep, values=run.values(hi=NARROW_TO)), "W-in",
                          run.open(W_in, ep), slot.offset_s)
            if W2 is not None:
                companion(run.presentation(W2, ep), "W2", run.open(W2, ep), slot.offset_s)
            # the refusal streak, from the answers that have come back
            streak = _streak(tr.pres)
            now = clock.now()
            # mid-trial actions, after the onset
            if variant == "regrant" and streak is not None and mid_at is None \
                    and now >= t_w + SETTLE_S:
                if form == "new_grant":
                    W2 = stub.regrant(W)
                    extra["regrant"] = {"grant_id": W2.id}
                else:
                    stub.reinstate(W.id)
                    extra["reinstated"] = True
                mid_at = clock.now()
                extra["t_regrant_s"] = mid_at - t_w
                continue
            if variant == "restart_after_refusal" and streak is not None and restarted is None:
                disp.drain()          # no presentation is cut by the restart
                try:
                    restarted = dict(run.a.restart() or {})
                except Exception as e:  # noqa: BLE001
                    restarted = {"raised": f"{type(e).__name__}: {e}"[:200]}
                mid_at = clock.now()
                extra["restart"] = restarted
                extra["t_restart_s"] = mid_at - t_w
                continue
            if variant == "stale_signed_snapshot" and form == "rollback" and not rolled:
                saw = [e for e in run.fetches(t_w) if e.get("outcome") == "ok"
                       and (e.get("version") or 0) >= wd.version]
                if saw:
                    stub.set_source("rollback", version=s_old["version"])
                    rolled = True
                    mid_at = clock.now()
                    extra.update(rollback_version=s_old["version"],
                                 t_rollback_s=mid_at - t_w)
            # stop
            need_mid = variant in ("regrant", "restart_after_refusal") or (
                variant == "stale_signed_snapshot" and form == "rollback")
            if streak is not None and now - streak >= S and now >= tr.settle_until:
                if not need_mid:
                    break
                if mid_at is not None and now - mid_at >= max(S, T or 0.0):
                    if variant != "regrant" or form != "new_grant" or any(
                            q.under == "W2" and q.accepted for q in tr.pres):
                        break
        disp.drain()
        tr.notes["slots_used"] = i + 1 if slots else 0
        if variant == "source_unreachable":
            outage_ok = _outage_breaches(run, t_w)
            extra["fetches_during_outage"] = len(run.fetches(t_w))
            if outage_ok:
                tr.stop_info("fixture_not_landed", f"B fetched the source successfully during the "
                                                   f"outage ({len(outage_ok)} time(s)): B "
                                                   f"reached it another way (KRK-M59)")
        if variant == "stale_signed_snapshot" and form == "served":
            got = [e for e in run.fetches(t_w) if e.get("outcome") == "stale"]
            extra["stale_fetches"] = len(got)
        if variant == "stale_signed_snapshot" and form == "rollback":
            got = [e for e in run.fetches(t_w) if e.get("outcome") == "rollback"]
            extra["rollback_fetches"] = len(got)
            if not rolled:
                tr.stop_info("not_landed", "B never fetched the withdrawn state inside the "
                                           "window, so no rollback could follow it")
            elif not got:
                tr.stop_info("not_landed", "B never fetched again after the rollback was set")
        if variant == "in_flight":
            held = [e for e in run.recorder.held(run.prefix)
                    if (e.get("effect") or {}).get("ref") == held_ref]
            extra["held_attempts"] = len(held)
            if not held:
                tr.stop_info("not_landed", "B made no effect call for the request presented "
                                           "just before the withdrawal, so nothing was held in "
                                           "flight")
        if variant == "restart_after_refusal":
            if restarted is None:
                tr.stop_info("not_reached", "B never refused, so it was never restarted")
            elif not restart_happened(restarted):
                tr.stop_info("not_landed", f"the restart hook reported no new boot id for B "
                                           f"({restarted}) (KRK-M64)")
        if variant == "regrant" and mid_at is None:
            tr.stop_info("not_reached", "W was never refused inside the window, so no re-grant "
                                        "was issued")
        extra["W2"] = W2.id if W2 else None
        extra["mid_at"] = mid_at
        return _finish(run, tr, W, L), extra
    finally:
        if skew:
            stub.set_clock_offset(0.0)
        stub.set_source("up")
        stub.set_source("push-deliver")
        if variant == "source_unreachable" and tr.t_w is not None and tr.info is None:
            extra["recovery"] = _recovery(run, tr, W, L)


def _finish(run: _Run, tr: _Trial, W: Any, L: Any) -> Any:
    from ..timing import TrialLog
    run.settle(max(tr.settle_until, run.clock.now() + (2.0 if tr.t_w is not None else 0.0)))
    for p in tr.pres:
        run.fill(p)
    if run.grade == "recorder":
        w_eff = [t for r in set(tr.w_refs) for t in run.effect_times(r)]
        allow = run.net_allowance
        if allow > 0.0:
            # An effect is bracketed between the send of its presentation and the
            # recorder's receipt; it is judged at the earliest point the network allows, the
            # receipt less the largest round trip measured, never before the send. So a late
            # call never charges B for the network.
            sent = {}
            for p in tr.pres:
                if p.under == "W":
                    sent[p.ref] = min(sent.get(p.ref, p.t_sent), p.t_sent)
            judged = []
            for r in set(tr.w_refs):
                for t_rec in run.effect_times(r):
                    lo = max(sent.get(str(r), t_rec - allow), t_rec - allow)
                    judged.append(lo)
                    if tr.t_w is not None and t_rec > tr.t_w:
                        run.effect_brackets.append({
                            "variant": tr.variant, "trial": tr.k, "ref": str(r),
                            "earliest_s": round(lo - tr.t_w, 4),
                            "recorder_s": round(t_rec - tr.t_w, 4)})
            w_eff = judged
    else:
        # Below the recorder grade only B's answers are evidence: an effect the recorder happens
        # to hold is not read (KRK-M60's pin found the probe reading both).
        w_eff = [p.effect_t for p in tr.pres if p.under == "W" and p.effect_t is not None]
    t_w = tr.t_w if tr.t_w is not None else run.clock.now()
    failsafe = _failsafe(tr.variant, tr.form)
    log = TrialLog(tr.variant, tr.form, t_w, run.T, run.window, run.stability,
                   presentations=list(tr.pres), w_effects=w_eff, failsafe=failsafe,
                   info=tr.info, info_detail=tr.info_detail, ended_at=run.clock.now(),
                   phase_s=tr.phase_s, resolution_s=run.resolution)
    log.grants = {"W": W.id, "L": L.id}  # type: ignore[attr-defined]
    log.notes = tr.notes  # type: ignore[attr-defined]
    return log


def _scheduler_doc(log: Any, counts: Dict[str, int]) -> Dict[str, Any]:
    """One trial's sending, for the evidence: the dispatcher's counts, the
    in-flight count at each send, answer times by class, and the slots skipped."""
    pres = [p for p in log.presentations if p.t_sent >= log.t_w]
    by: Dict[str, List[float]] = {}
    for p in pres:
        if p.answered and not p.timed_out:
            by.setdefault(p.cls, []).append(p.t_answered - p.t_sent)
    ans = {}
    for cls, xs in sorted(by.items()):
        xs.sort()
        ans[cls] = {"n": len(xs), "min_s": round(xs[0], 4), "median_s": round(xs[len(xs) // 2], 4),
                    "max_s": round(xs[-1], 4)}
    notes = getattr(log, "notes", {}) or {}
    return {**counts, "in_flight_at_send_max": max((p.in_flight for p in pres), default=0),
            "answer_s": ans, "skipped": list(notes.get("skipped") or [])[:50],
            "slots_used": notes.get("slots_used")}


def _recovery(run: _Run, tr: _Trial, W: Any, L: Any) -> Dict[str, Any]:
    """After a `source_unreachable` trial: the source is back; does B accept L again, and keep
    refusing W? (design §3.1 ``recovery``)."""
    from .. import timing
    clock, T = run.clock, run.T
    disp = run.disp
    t_r = clock.now()
    bound = run.bound.get("recovery_s")
    bound = float(bound) if bound else None
    # Present until W whatever the bound, so a recovery after the bound reads
    # `recovered_late` and only no recovery at all reads `stuck_closed`. The boundary slots sit
    # either side of the recovery bound.
    limit = run.window
    pres: List[Any] = []
    first_l = None
    skipped = 0
    slots = timing.schedule(T, run.rng, window=limit, resolution_s=run.resolution,
                            boundary_at=bound)
    for i, slot in enumerate(slots):
        clock.sleep_until(t_r + slot.offset_s)
        disp.poll()
        ep = run.endpoints[i % len(run.endpoints)]
        pl = disp.submit(run.presentation(L, ep), "L", session=run.open(L, ep), tag="recovery")
        if pl is None:
            skipped += 1
        else:
            pres.append(pl)
        pw = None
        if run.signer == "agent":
            pw = disp.submit(run.presentation(W, ep), "W", session=run.open(W, ep),
                             tag="recovery", companion=True)
        elif tr.pi < len(tr.pool):
            pw = disp.submit(tr.pool[tr.pi], "W", tag="recovery:signed-before-t_w",
                             companion=True)
            if pw is not None:
                tr.pi += 1
        if pw is not None:
            pres.append(pw)
        if first_l is None:
            for q in pres:                      # the answered prefix, in send order
                if q.under != "L":
                    continue
                if not _settled(q):
                    break
                if q.accepted:
                    first_l = q.t_sent - t_r
                    break
        if first_l is not None and clock.now() - t_r >= max(T or 0.0, first_l + 3 * timing.delta_s(T)):
            break
    disp.drain()
    run.settle(clock.now() + 2.0)
    for p in pres:
        run.fill(p)
    ls = sorted((p for p in pres if p.under == "L"), key=lambda p: p.t_sent)
    late_w = [p for p in pres if p.under == "W" and p.accepted
              and p.t_sent - t_r > (T or 0.0)]
    j = timing.judge_recovery([(p.t_sent - t_r, p.accepted, p.refused) for p in ls],
                              late_w[0].t_sent - t_r if late_w else None, bound, limit,
                              run.resolution)
    if j["outcome"] == "recovered":
        j["detail"] += ("; W still refused" if any(p.under == "W" for p in pres) else
                        "; no W request was left to present")
    return {"limit_s": limit, "recovery_bound_s": bound, "skipped": skipped, **j,
            "presentations": [_pres_doc(p, t_r) for p in pres]}


# --------------------------------------------------------------------------- judging a trial


def _judge_trial(run: _Run, log: Any, extra: Dict[str, Any]) -> Any:
    from .. import timing
    variant, form = log.variant, log.form
    if log.info is None and variant == "regrant":
        mid = extra.get("mid_at")
        before = _split_at(log, mid)
        o = timing.classify_trial(before)
        if o.ok is not True:
            return o
        after = [p for p in log.presentations if p.t_sent > mid]
        lim = mid + (run.T or run.window)
        if form == "new_grant":
            w2 = [p for p in after if p.under == "W2" and p.accepted and p.t_sent <= lim]
            revived = [p for p in after if p.under == "W" and p.accepted]
            if revived:
                return timing.TrialOutcome("revived", False, detail=f"W accepted "
                                           f"{revived[0].t_sent - log.t_w:.2f} s after the "
                                           f"withdrawal, once W2 was issued", form=form)
            if not w2:
                return timing.TrialOutcome("regrant_not_honoured", False, detail="W2 was not "
                                           "accepted within the bound of its issue", form=form)
            return timing.TrialOutcome("regrant_honoured", True, time_s=o.time_s,
                                       bracket=o.bracket, detail=f"{o.detail}; W2 accepted "
                                       f"{w2[0].t_sent - mid:.2f} s after its issue, W still "
                                       f"refused", form=form)
        back = [p for p in after if p.under == "W" and p.accepted and p.t_sent <= lim]
        if not back:
            return timing.TrialOutcome("reinstatement_not_honoured", False, detail="W was not "
                                       "accepted again within the bound of its reinstatement",
                                       form=form)
        return timing.TrialOutcome("reinstated_honoured", True, time_s=o.time_s,
                                   bracket=o.bracket, detail=f"{o.detail}; W accepted again "
                                   f"{back[0].t_sent - mid:.2f} s after reinstatement",
                                   form=form)
    o = timing.classify_trial(log)
    if variant == "narrowed" and o.ok is True:
        lim = log.t_w + (run.T or 0.0)
        inside = [p for p in log.presentations if p.under == "W-in" and p.t_sent > lim]
        if inside and not any(p.accepted for p in inside):
            return timing.TrialOutcome("narrowed_as_withdrawn", None, detail="requests inside "
                                       "the narrowed ceiling were refused too, so the refusal "
                                       "is not shown to be about the narrowing", form=form,
                                       time_s=o.time_s, bracket=o.bracket)
    return o


# --------------------------------------------------------------------------- the probe


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    if raw.strip().startswith("{"):
        return json.loads(raw)
    with open(raw, encoding="utf-8") as f:
        return json.load(f)


def _trials_for(plan: Dict[str, Any], variant: str) -> int:
    t = plan.get("trials") or TRIALS
    if t == "dev":
        t = DEV_TRIALS
    elif t == "published":
        t = PUBLISHED_TRIALS
    return int(t.get(variant, t.get("*", 1)))


def _forms_for(variant: str, channels: List[str]) -> List[str]:
    """The forms of `variant` that apply to a B with these channels."""
    pull = any(c in channels for c in ("pull-list", "pull-item"))
    forms_v = list(FORMS.get(variant, ("",)))
    if variant == "source_unreachable":
        forms_v = [f for f in forms_v if f != "push_lost" or "push" in channels]
        if channels and not pull:
            forms_v = [f for f in forms_v if f == "push_lost"]
    if variant == "stale_signed_snapshot" and not pull:
        forms_v = [f for f in forms_v if f == "stapled"]
    return forms_v


def _need(plan: Dict[str, Any], variant: str, channels: List[str]) -> int:
    """How many trials the plan asks for in `variant`, over all its forms: the clean trials it
    needs before an inconclusive one can be outweighed (`timing.aggregate`)."""
    return _trials_for(plan, variant) * len(_forms_for(variant, channels))


def restart_happened(ret: Any) -> bool:
    """The restart hook reported a new boot id for B (KRK-M64)."""
    return isinstance(ret, dict) and bool(ret.get("before")) and ret.get("before") != ret.get(
        "after")


def _is_toy(a: Any) -> bool:
    mod = type(a).__module__ or ""
    return mod.startswith(("known_bad.", "tests.", "test_")) or mod == "__main__"


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import requester, status
    from ..mockserver import MockServer
    from ..timing import make_clock, stability_s, window_s

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    role = getattr(a, "role", lambda: "B")()
    if role != "B":
        return Result.inconclusive(a.name, ID, f"role {role!r}: P19 grades B in version 1; role "
                                   f"A (how fast A publishes) is version 2 (design §6.6)",
                                   **common)
    try:
        bound = dict(a.withdrawal_bound() or {})
        channels = list(a.channels() or [])
        forms = list(getattr(a, "presentation_forms", lambda: ["agent"])() or [])
        agreement = dict(a.agreement() or {})
        grade = a.evidence_grade()
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    T = bound.get("T_s")
    if T is not None and (not isinstance(T, (int, float)) or T <= 0):
        return Result.inconclusive(a.name, ID, f"T_s must be a positive number or None, not "
                                   f"{T!r}", **common)
    if bound.get("source") not in BOUND_SOURCES:
        return Result.inconclusive(a.name, ID, f"the bound's source must be one of "
                                   f"{BOUND_SOURCES}", **common)
    if T is not None and bound["source"] == "unstated":
        return Result.inconclusive(a.name, ID, "a T with source 'unstated'", **common)
    if T is not None and bound["source"] == "carried":
        # A value in protocol data is set by A, which here is the stub: it never decides B's
        # verdict. B is graded as stating no bound; the value is kept.
        bound = {**bound, "carried_T_s": T, "T_s": None}
        T = None
    bad_ch = [c for c in channels if c not in CHANNELS]
    if bad_ch or not forms or any(f not in FORMS_OF_REQUEST for f in forms):
        return Result.inconclusive(a.name, ID, f"channels {channels} / request forms {forms} "
                                   f"are not among {CHANNELS} / {FORMS_OF_REQUEST}", **common)
    if not agreement.get("counterparty"):
        return Result.inconclusive(a.name, ID, "the agreement names no counterparty id for B",
                                   **common)
    if grade not in GRADES:
        return Result.inconclusive(a.name, ID, f"unknown evidence grade {grade!r}", **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not _is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock; a real "
                                   "target's caches age only in real time (KRK-M56)", **common)
    if kind not in ("real", "virtual"):
        return Result.inconclusive(a.name, ID, f"clock must be 'real' or 'virtual', not "
                                   f"{kind!r}", **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    pull = any(c in channels for c in ("pull-list", "pull-item"))
    forbidden = [v for v in NA_FORBIDDEN if v not in ("presigned_after_withdrawal",
                                                      "stale_signed_snapshot", "worst_phase")]
    if "a-presigned" in forms:
        forbidden.append("presigned_after_withdrawal")
    if pull:
        forbidden.append("stale_signed_snapshot")
    if "pull-list" in channels:
        forbidden.append("worst_phase")
    bad = sorted(v for v in na if v in forbidden or v not in VARIANTS)
    if bad:
        return Result.inconclusive(a.name, ID, f"the adapter declares {bad} not applicable; "
                                   f"{forbidden} may not be, and only P19's variants can be",
                                   **common)
    if any(not isinstance(w, str) or not w.strip() for w in na.values()):
        return Result.inconclusive(a.name, ID, "a variant is declared not applicable without a "
                                   "reason", **common)
    notes: Dict[str, str] = dict(getattr(a, "variant_notes", lambda: {})() or {})
    profile = getattr(a, "status_profile", lambda: None)() or "kirkaldy"
    if profile not in status.PROFILES:
        return Result.inconclusive(a.name, ID, f"unknown status profile {profile!r}", **common)

    # A development plan from the environment applies to real targets only: a toy (the
    # known-bad gate) always runs the published method.
    plan = dict(plan if plan is not None else ({} if _is_toy(a) else (_plan_from_env() or {})))
    # {"trials": "published"} changes only the counts, to the published ones, so it is not a
    # development plan; anything else in a plan is.
    published = plan == {"trials": "published"}
    development = bool(plan) and not published
    win = float(plan.get("window_s") or window_s(T))
    stab = float(plan.get("stability_s") or stability_s(T))
    only = list(plan.get("variants") or VARIANTS)
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = [v for v in VARIANTS if v != "recovery"]
    rng.shuffle(order)
    clock = make_clock(kind)
    if kind == "virtual":
        a.set_clock(clock)
    recorder = MockServer(clock=clock.now)
    stub = requester.StubRequester(requester.new_issuer(), clock=clock, status_profile=profile,
                                   ttl_s=int(T) if T else 60,
                                   audience=agreement["counterparty"])
    stub.hang_s = (T or 30.0) + 5.0
    url = stub.serve()
    ev.write("run.json", {"seed": seed, "variant_order": [CONTROL] + order, "bound": bound,
                          "channels": channels, "presentation_forms": forms,
                          "agreement": _jsonable(agreement), "evidence_grade": grade,
                          "clock": kind, "status_profile": profile, "window_s": win,
                          "stability_s": stab, "plan": plan, "variants_not_applicable": na,
                          "variant_notes": notes})
    progress = _Progress(ev)
    run = None
    try:
        receiver = None
        if "push" in channels:
            receiver = getattr(a, "push_receiver", lambda: None)()
            if receiver:
                stub.push_to(receiver)
        bound_how = a.bind_requester(stub.trust_anchor_x4(), url, receiver=receiver)
        prefix = f"/p19/{run_tag}{secrets.token_hex(4)}"
        rec_how = a.bind_recorder(recorder.url + prefix)
        run = _Run(a, ev, clock=clock, stub=stub, recorder=recorder, prefix=prefix,
                   agreement=agreement, bound=bound, channels=channels, forms=forms,
                   grade=grade, rng=rng, window=win, stability=stab)
        run.progress = progress
        run.log("run", seed=seed, variant_order=[CONTROL] + order, bound=bound, T_s=T,
                window_s=win, stability_s=stab, plan=plan, channels=channels,
                presentation_forms=forms, evidence_grade=grade, clock=kind,
                remote=run.remote, need={v: _need(plan, v, channels) for v in VARIANTS
                                         if v != "recovery"},
                scheduler={"max_in_flight": run.disp.limit,
                           "companion_reserve": COMPANION_RESERVE,
                           "answer_timeout_s": run.disp.timeout},
                network_every_s=NETWORK_EVERY_S if run.remote else None)
        return _probe(run, a, ev, common, bound, channels, forms, grade, na, notes, plan,
                      development, only, order, seed, bound_how, rec_how)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        if run is not None:
            run.disp.close()
        recorder.close()
        stub.close()
        clock.close()


def _jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], bound: Dict[str, Any],
           channels: List[str], forms: List[str], grade: str, na: Dict[str, str],
           notes: Dict[str, str], plan: Dict[str, Any], development: bool, only: List[str],
           order: List[str], seed: int, bound_how: str, rec_how: str) -> Result:
    from .. import timing
    T = run.T
    held, why, obs = _control(run)
    ev.write("control.json", {"held": held, "why": why, "bind_requester": bound_how,
                              "bind_recorder": rec_how,
                              **{k: v for k, v in obs.items() if k != "presentations"},
                              "presentations": [_pres_doc(p, None) for p in
                                                obs.get("presentations", [])]})
    run.log("control", held=held, why=why,
            **{k: v for k, v in obs.items() if k != "presentations"})
    if not held:
        run.log("end", status="inconclusive", summary=f"control did not hold: {why}")
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    control = ("a fresh request under W and under L accepted at every endpoint, one effect each "
               "at the recorder, and the kit's baseline client read the stub's source")
    sampler = None
    if run.remote:
        # Round trips through the run, on their own schedule.
        sampler = run.clock.call_every(lambda: NETWORK_EVERY_S,
                                       lambda: run.sample_network(1, at="interval"))
    try:
        return _variants(run, a, ev, common, bound, channels, forms, grade, na, notes, plan,
                         development, only, order, seed, control)
    finally:
        if sampler is not None:
            run.clock.cancel(sampler)


def _variants(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], bound: Dict[str, Any],
              channels: List[str], forms: List[str], grade: str, na: Dict[str, str],
              notes: Dict[str, str], plan: Dict[str, Any], development: bool, only: List[str],
              order: List[str], seed: int, control: str) -> Result:
    from .. import timing
    T = run.T
    pull = any(c in channels for c in ("pull-list", "pull-item"))
    outcomes: Dict[str, List[Any]] = {}
    recovery: List[Any] = []
    gaps_note: Dict[str, str] = {}
    trial_docs: Dict[str, List[Dict[str, Any]]] = {}
    for variant in order:
        if variant in na or variant not in only:
            continue
        forms_v = _forms_for(variant, channels)
        if variant == "worst_phase" and "pull-list" not in channels:
            gaps_note[variant] = "B declares no pull-list channel, so phase has no meaning; " \
                                 "only random-phase trials run (design §4.4)"
            continue
        if variant == "same_session" and not run.sessions:
            gaps_note[variant] = "B has no sessions (no open_session)"
            continue
        if variant == "presigned_after_withdrawal" and "a-presigned" not in forms:
            gaps_note[variant] = "B takes only agent-signed requests under a grant, never a " \
                                 "request A signed itself"
            continue
        if variant == "restart_after_refusal" and not callable(getattr(a, "restart", None)):
            gaps_note[variant] = "no restart hook: a hosted B is never restarted"
            continue
        for form in forms_v:
            n = _trials_for(plan, variant)
            for k in range(n):
                log, extra = _run_trial(run, variant, form, k)
                o = _judge_trial(run, log, extra)
                outcomes.setdefault(variant, []).append(o)
                if "recovery" in extra:
                    r = extra["recovery"]
                    br = r.get("bracket")
                    recovery.append(timing.TrialOutcome(
                        r["outcome"], r["ok"], detail=r["detail"], form=form,
                        time_s=r.get("first_L_accepted_s"),
                        bracket=tuple(br) if br else None))
                doc = {"form": form, "k": k, "outcome": o.to_doc(), "extra": _jsonable(extra),
                       "t_w_kit": log.t_w, "phase_s": log.phase_s,
                       "scheduler": _scheduler_doc(log, dict(run.disp.trial)),
                       "presentations": [_pres_doc(p, log.t_w) for p in log.presentations]}
                trial_docs.setdefault(variant, []).append(doc)
                run.log("trial", variant=variant, **doc)
        if variant in trial_docs:
            ev.write(f"{variant}.json", {"variant": variant, "trials": trial_docs[variant]})
            lab, ok = timing.aggregate(outcomes.get(variant, []), T,
                                       need=_need(plan, variant, channels))
            st = timing.statistics(outcomes.get(variant, []), T)
            st.pop("trials", None)
            run.log("variant", variant=variant, reading=lab, ok=ok, statistics=st)
    if recovery:
        outcomes["recovery"] = recovery
    checks: List[Check] = []
    stats: Dict[str, Any] = {}
    for variant in VARIANTS:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        if variant in gaps_note:
            checks.append(Check(variant, "not_applicable", None, gaps_note[variant]))
            continue
        os_ = outcomes.get(variant)
        if not os_:
            if variant in only:
                checks.append(Check(variant, "not_run", None, "no trial ran"))
            continue
        stats[variant] = timing.statistics(os_, T)
        need = len(os_) if variant == "recovery" else _need(plan, variant, channels)
        inc = [o for o in os_ if o.outcome == timing.INCONCLUSIVE]
        clean = sum(1 for o in os_ if o.ok)
        withheld = None
        if inc and clean < need:
            withheld = (f"{len(inc)} of {len(os_)} {'continuations' if variant == 'recovery' else 'trials'} "
                        f"inconclusive, {clean} passed, {need} needed; e.g. "
                        f"{inc[0].form + ': ' if inc[0].form else ''}{inc[0].detail}")
        if variant == "recovery":
            fails = [o for o in os_ if o.ok is False]
            if fails:
                c = Check(variant, fails[0].outcome, False, f"{fails[0].form + ': ' if fails[0].form else ''}{fails[0].detail}")
            elif withheld:
                c = Check(variant, timing.INCONCLUSIVE, None, withheld)
            elif any(o.ok for o in os_):
                c = Check(variant, "recovered", True, f"L accepted again after each of "
                          f"{sum(1 for o in os_ if o.ok)} outages, the latest "
                          f"{stats[variant].get('max_s')} s after the source came back"
                          + (f" (stated bound {bound.get('recovery_s'):g} s)"
                             if bound.get("recovery_s") else ""))
            else:
                c = Check(variant, os_[0].outcome, None, os_[0].detail)
        elif variant == "regrant":
            fails = [o for o in os_ if o.ok is False]
            if fails:
                c = Check(variant, fails[0].outcome, False, f"{fails[0].form}: {fails[0].detail}")
            elif withheld:
                c = Check(variant, timing.INCONCLUSIVE, None, withheld)
            elif any(o.ok for o in os_):
                c = Check(variant, "regrant_honoured", True, "; ".join(
                    sorted({f"{o.form}: {o.outcome}" for o in os_ if o.ok})))
            else:
                lab, ok = timing.aggregate(os_, T)
                c = Check(variant, lab, None, os_[0].detail)
        else:
            lab, ok = timing.aggregate(os_, T, fail_label="accepted_open"
                                       if variant == "source_unreachable" else None, need=need)
            s = stats[variant]
            worst = next((o for o in os_ if o.ok is False), None)
            detail = (f"N={s['n_counted']}; max {s.get('max_s')} s, median {s.get('median_s')} "
                      f"s; late {s['late']}, not within W {s['not_within_W']}, flapped "
                      f"{s['flapped']}")
            if s["n_information"]:
                detail += f"; information {s['n_information']}"
            if worst is not None:
                detail += f"; e.g. {worst.form + ': ' if worst.form else ''}{worst.detail}"
            elif lab == timing.INCONCLUSIVE and withheld:
                detail += f"; {withheld}"
            elif ok is None and os_:
                detail += f"; e.g. {os_[0].detail}"
            if T is None and ok:
                lab = "refused_within_W"
            c = Check(variant, lab, ok, detail)
        if variant in notes:
            c = Check(c.name, c.outcome, c.ok, f"{c.detail} (adapter note: {notes[variant]})")
        checks.append(c)

    fails = [c for c in checks if c.ok is False]
    pull_list = "pull-list" in channels
    must = ["withdrawn", "source_unreachable", "recovery"]
    if "a-presigned" in forms:
        must.append("presigned_after_withdrawal")
    if pull:
        must.append("stale_signed_snapshot")
    if pull_list:
        must.append("worst_phase")
    must = [m for m in must if m in only]
    unlanded = [c.name for c in checks if c.name in must and c.ok is None
                and c.outcome != timing.INCONCLUSIVE]
    unresolved = [c.name for c in checks if c.outcome == timing.INCONCLUSIVE]
    timed = [o for v in ("withdrawn", "worst_phase") for o in outcomes.get(v, [])
             if o.ok is not None and o.time_s is not None]
    n_timed = len([o for v in ("withdrawn", "worst_phase") for o in outcomes.get(v, [])
                   if o.ok is not None])
    worst_s = max((o.time_s for o in timed), default=None)
    worst_s = None if worst_s is None else round(worst_s, 3)
    documents = bound.get("source") in ("documented", "configured") or bool(
        bound.get("documents_enforcement"))
    vuln = documents and any(c.outcome in VULNERABLE or (c.name in VULNERABLE_VARIANTS)
                             for c in fails)
    extra: Dict[str, Any] = {
        "seed": seed, "bound": _jsonable(bound), "T_source": bound.get("source"),
        "channels": channels, "presentation_forms": forms, "evidence_grade": grade,
        "clock": getattr(a, "clock", "real"), "window_s": run.window,
        "stability_s": run.stability, "statistics": stats,
        "disclosure": "vulnerability" if vuln else "conformance",
        "format_gaps": _jsonable(run.stub.format_gaps), "rtt_s": round(run.rtt, 4),
        "below_floor": timing.below_floor(T, run.rtt, run.resolution),
        "measurement_floor_s": round(timing.floor_s(T, run.rtt, run.resolution), 4),
        "worst_case_s": worst_s, "n_timing_trials": n_timed,
        "scheduler": {**run.disp.totals, "limit": run.disp.limit,
                      "companion_reserve": COMPANION_RESERVE,
                      "answer_timeout_s": run.disp.timeout,
                      "note": "presentations sent on the probe's own schedule, not after each "
                              "answer; a slot that found the in-flight limit "
                              "reached was skipped"},
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if run.remote:
        run.sample_network(5, at="end")
        ps = sorted(run.pings)
        extra["network"] = {
            "remote": True, "n": len(ps), "failures": run.net_failures,
            "rtt_min_s": round(ps[0], 4) if ps else None,
            "rtt_median_s": round(ps[len(ps) // 2], 4) if ps else None,
            "rtt_max_s": round(ps[-1], 4) if ps else None,
            "effect_allowance_s": round(run.net_allowance, 4),
            "effect_brackets": run.effect_brackets[:200],
            "note": "B on other machines: round trips from the kit to B's "
                    "machine, on the kit's clock. Each effect under the withdrawn authority "
                    "after t_w is bracketed between its earliest possible commit (the "
                    "recorder's receipt less the largest round trip, never before its "
                    "presentation was sent) and the recorder's receipt; the late call reads "
                    "the earliest point, so B is never charged for the network. B's status "
                    "fetches cross the same network; their time is in every reading and is at "
                    "most one round trip per fetch."}
    if run.b_offsets:
        offs = sorted(o for o, _ in run.b_offsets)
        res = float(bound.get("resolution_s") or 0.0)
        extra["b_clock_offset_s"] = {
            "median": round(offs[len(offs) // 2], 3),
            "uncertainty_s": round(max(u for _, u in run.b_offsets) + res, 3),
            "n": len(offs), "note": "B's timestamps on its answers against the kit's wall "
            "clock; information beside the reading, never used to order or judge (KRK-M65)"}
    if plan:
        extra["plan"] = plan
    if bound.get("statistic"):
        pc = timing.percentile_check(bound["statistic"], outcomes.get("withdrawn", []), T)
        if pc:
            extra["percentile_check"] = pc
    if T is None:
        extra["finding"] = "no stated bound on how soon a withdrawal takes effect"
        extra["effective_bound_s"] = worst_s
    if na:
        extra["variants_not_applicable"] = na
    head = (f"no stated bound; measured worst case "
            f"{'%.2f s' % worst_s if worst_s is not None else 'none (never refused)'} over "
            f"{n_timed} trials. " if T is None else "")
    dev = "Development plan (smaller counts; not a published run). " if development else ""
    r = _result(a, run, checks, fails, unlanded, unresolved, dev, head, control, extra, common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r


def _result(a: Any, run: _Run, checks: List[Check], fails: List[Check], unlanded: List[str],
            unresolved: List[str], dev: str, head: str, control: str, extra: Dict[str, Any],
            common: Dict[str, Any]) -> Result:
    T, bound = run.T, run.bound
    if not fails and (unlanded or unresolved):
        why = []
        if unlanded:
            why.append(f"variants that must land did not: {unlanded}")
        if unresolved:
            why.append(f"variants whose brackets crossed their bound read inconclusive "
                       f": {unresolved}")
        return Result.inconclusive(a.name, ID, f"{dev}{head}no variant failed, but "
                                   f"{'; and '.join(why)}", checks=checks,
                                   control_held=True, control_detail=control, extra=extra,
                                   **common)
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, f"{dev}no variant landed with a verdict",
                                   checks=checks, control_held=True, control_detail=control,
                                   extra=extra, **common)
    bound_txt = f"its stated T of {T:g} s ({bound.get('source')})" if T else \
        f"the {run.window:g} s window"
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary=f"{dev}{head}every withdrawn authority was refused within "
                                f"{bound_txt} in every trial, held, failed safe and recovered",
                   fail_summary=f"{dev}{head}a withdrawn authority was honoured past "
                                f"{bound_txt}, or B did not hold, fail safe or recover",
                   extra=extra, **common)


# --------------------------------------------------------------------------- reading evidence


def _numbered(d: Path, name: str) -> Optional[Path]:
    """The evidence file ``NN-<name>`` in `d` (the first, if several)."""
    hits = sorted(d.glob(f"[0-9][0-9]-{name}"))
    return hits[0] if hits else None


def _outcome_of(doc: Dict[str, Any]) -> Any:
    from ..timing import TrialOutcome
    o = doc or {}
    return TrialOutcome(o.get("outcome", "?"), o.get("ok"), time_s=o.get("time_s"),
                        bracket=tuple(o["bracket"]) if o.get("bracket") else None,
                        last_effect_s=o.get("last_effect_s"),
                        onset_endpoint=o.get("onset_endpoint", ""), detail=o.get("detail", ""),
                        phase_s=o.get("phase_s"), form=o.get("form", ""))


def _spread(xs: List[float]) -> Optional[Dict[str, Any]]:
    from ..timing import order_stat
    if not xs:
        return None
    xs = sorted(xs)
    return {"n": len(xs), "min_s": round(xs[0], 4), "median_s": round(order_stat(xs, 0.5), 4),
            "p90_s": round(order_stat(xs, 0.9), 4), "max_s": round(xs[-1], 4)}


def derive(path: Any) -> Dict[str, Any]:
    """Read a P19 run's evidence into the statistics its result would carry, for a run cut short
    before it wrote ``result.json`` as well as for a complete one. Read-only.

    The source is ``NN-progress.jsonl`` when the run wrote one (every trial, ping and variant
    reading as it happened); otherwise the per-variant files
    ``NN-<variant>.json`` that earlier runs wrote at the end of each variant, so a variant still
    running when the run stopped is missing from those.

    Each trial is read twice: **as recorded** (the outcome the kit gave it at run time) and
    **re-read** with the kit's current rules, so evidence written before KRK-M48's fix gets the
    crossing rule (`timing.rejudge`) and its recovery continuations the recovery bound
    (`timing.judge_recovery`). Variants are aggregated with `timing.aggregate` and
    `timing.statistics`. This is a reading of evidence, never a result: it carries no verdict,
    no control check beyond what the evidence records, and no known-bad reference."""
    from .. import timing
    d = Path(path)
    if d.is_file():
        d = d.parent
    run_path = _numbered(d, "run.json")
    if run_path is None:
        raise FileNotFoundError(f"no NN-run.json in {d}: not a P19 evidence directory")
    run_doc = json.loads(run_path.read_text(encoding="utf-8"))
    bound = run_doc.get("bound") or {}
    T = bound.get("T_s")
    res = bound.get("resolution_s")
    rbound = bound.get("recovery_s")
    window = float(run_doc.get("window_s") or timing.window_s(T))
    plan = run_doc.get("plan") or {}
    channels = list(run_doc.get("channels") or [])
    order = [v for v in (run_doc.get("variant_order") or []) if v != CONTROL]
    prog_path = _numbered(d, "progress.jsonl")
    events: List[Dict[str, Any]] = []
    if prog_path is not None:
        for line in prog_path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue                      # a line cut by the stop: skipped, and counted
    trials: List[Tuple[str, Dict[str, Any]]] = []
    if events:
        source = os.path.basename(str(prog_path))
        trials = [(e["variant"], e) for e in events if e.get("kind") == "trial"]
    else:
        source = "per-variant files"
        for f in sorted(d.glob("[0-9][0-9]-*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "trials" in doc and doc.get("variant"):
                trials += [(doc["variant"], t) for t in doc["trials"]]
    result_path = d / "result.json"
    out: Dict[str, Any] = {
        "evidence": str(d), "source": source, "result_json": result_path.is_file(),
        "ended": any(e.get("kind") == "end" for e in events) if events else None,
        "seed": run_doc.get("seed"), "T_s": T, "window_s": window, "recovery_bound_s": rbound,
        "plan": plan, "variants": {}, "recovery": None, "answer_time_s": {},
        "network": None, "restarts": [], "instances": {},
        "note": "derived from the evidence the probe wrote; not a result and not a verdict"}
    by_v: Dict[str, List[Dict[str, Any]]] = {}
    for v, t in trials:
        by_v.setdefault(v, []).append(t)
    lat: Dict[str, List[float]] = {}
    inst: Dict[str, int] = {}
    rec_as, rec_re = [], []
    rec_docs: List[Dict[str, Any]] = []
    for v in [x for x in order if x in by_v] + sorted(x for x in by_v if x not in order):
        ts = by_v[v]
        as_rec = [_outcome_of(t.get("outcome")) for t in ts]
        reread = [timing.rejudge(o, T, res) for o in as_rec]
        need = _need(plan, v, channels)
        lab0, ok0 = _derive_label(v, as_rec, T, None)
        lab1, ok1 = _derive_label(v, reread, T, need)
        st = timing.statistics(reread, T)
        st.pop("trials", None)
        sched = [t.get("scheduler") or {} for t in ts]
        inflight = [p.get("in_flight") for t in ts for p in t.get("presentations") or []
                    if p.get("in_flight") is not None]
        out["variants"][v] = {
            "n_trials": len(ts), "need": need, "complete": len(ts) >= need,
            "as_recorded": {"reading": lab0, "ok": ok0,
                            "outcomes": _count(o.outcome for o in as_rec)},
            "reread": {"reading": lab1, "ok": ok1, "outcomes": _count(o.outcome for o in reread)},
            "statistics": st,
            "crossing": [{"form": t.get("form"), "k": t.get("k"), "bracket": list(o.bracket)}
                         for t, o in zip(ts, reread) if o.outcome == timing.INCONCLUSIVE],
            "in_flight_max": max(inflight) if inflight else None,
            "skipped": sum(len(s.get("skipped") or []) for s in sched) if any(sched) else None,
            "timed_out": sum(int(s.get("timed_out") or 0) for s in sched) if any(sched) else None}
        for t in ts:
            ex = t.get("extra") or {}
            if ex.get("restart"):
                out["restarts"].append({"variant": v, "k": t.get("k"),
                                        "t_restart_s": ex.get("t_restart_s"), **ex["restart"]})
            r = ex.get("recovery")
            if r:
                pres = r.get("presentations") or []
                ls = sorted((p for p in pres if p.get("under") == "L"),
                            key=lambda p: p["t_sent"])
                late_w = [p["t_sent"] for p in pres if p.get("under") == "W" and p.get("accepted")
                          and p["t_sent"] > (T or 0.0)]
                j = timing.judge_recovery(
                    [(p["t_sent"], bool(p.get("accepted")),
                      p.get("cls") == "refused" and not p.get("accepted")) for p in ls],
                    min(late_w) if late_w else None, rbound, window, res)
                rec_as.append(timing.TrialOutcome(r.get("outcome", "?"), r.get("ok"),
                                                  form=t.get("form", "")))
                br = j.get("bracket")
                rec_re.append(timing.TrialOutcome(j["outcome"], j["ok"], detail=j["detail"],
                                                  form=t.get("form", ""),
                                                  time_s=j.get("first_L_accepted_s"),
                                                  bracket=tuple(br) if br else None))
                rec_docs.append({"form": t.get("form"), "k": t.get("k"),
                                 "as_recorded": r.get("outcome"), "reread": j["outcome"],
                                 "first_L_accepted_s": j.get("first_L_accepted_s"),
                                 "bracket": br})
            for p in t.get("presentations") or []:
                if p.get("t_answered") is not None and p.get("t_sent") is not None \
                        and p.get("answered", True) and not p.get("timed_out"):
                    lat.setdefault(p.get("cls", "?"), []).append(p["t_answered"] - p["t_sent"])
                body = (p.get("answer") or {}).get("body") or {}
                if isinstance(body, dict) and body.get("instance"):
                    inst[body["instance"]] = inst.get(body["instance"], 0) + 1
    if rec_re:
        st = timing.statistics(rec_re, None)
        st.pop("trials", None)
        out["recovery"] = {"n": len(rec_re), "as_recorded": _count(o.outcome for o in rec_as),
                           "reread": _count(o.outcome for o in rec_re),
                           "first_L_accepted_s": _spread([o.time_s for o in rec_re
                                                          if o.time_s is not None]),
                           "continuations": rec_docs}
    out["answer_time_s"] = {k: _spread(v) for k, v in sorted(lat.items())}
    out["instances"] = inst
    pings = [e for e in events if e.get("kind") == "ping"]
    if pings:
        ok = [e["rtt_s"] for e in pings if e.get("rtt_s") is not None]
        out["network"] = {"source": "progress", "n": len(ok),
                          "failures": sum(1 for e in pings if e.get("rtt_s") is None),
                          "rtt_s": _spread(ok),
                          "by_when": _count(e.get("at", "?") for e in pings),
                          "first_t_kit_s": pings[0].get("t_kit_s"),
                          "last_t_kit_s": pings[-1].get("t_kit_s")}
    elif result_path.is_file():
        net = (json.loads(result_path.read_text(encoding="utf-8")).get("extra") or {}).get(
            "network")
        if net:
            out["network"] = {"source": "result.json", **{k: v for k, v in net.items()
                                                          if k != "effect_brackets"}}
    ran = set(by_v)
    out["not_run"] = [v for v in order if v not in ran and v != "recovery"]
    out["incomplete"] = sorted(v for v, doc in out["variants"].items() if not doc["complete"])
    return out


def _derive_label(variant: str, outcomes: List[Any], T: Optional[float],
                  need: Optional[int]) -> Tuple[str, Optional[bool]]:
    """A variant's reading as the probe labels it: `timing.aggregate`, with ``accepted_open``
    for ``source_unreachable``, a failed trial of any other kind (``revived``, ...) as the fail,
    and ``regrant_honoured`` for a passing ``regrant``."""
    from .. import timing
    lab, ok = timing.aggregate(outcomes, T, need=need, fail_label="accepted_open"
                               if variant == "source_unreachable" else None)
    other = next((o for o in outcomes if o.ok is False), None)
    if ok is not False and other is not None:
        return other.outcome, False
    if ok and variant == "regrant":
        return "regrant_honoured", True
    return lab, ok


def _count(xs: Any) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for x in xs:
        c[x] = c.get(x, 0) + 1
    return dict(sorted(c.items()))
