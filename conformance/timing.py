"""The kit's clock for KRK-19 (P19), and the timing method: schedule, phase, brackets, outcomes and
statistics (`X4-WITHDRAWAL-WITHIN-T-DESIGN.md` §2.3, §4.4, §4.5).

**One clock.** Every time P19 measures is read from one clock object on the one host that runs
the stub A, the recorder and the driver: `RealClock` (``time.monotonic``) for every real target,
or `VirtualClock` for toys only (KRK-M56). No check compares A's, B's or the kit's wall clocks.
`wall()` exists only to put a time on what the stub A signs (issued_at, validity windows); it is
never used to order or to judge.

A clock also schedules work (`call_at`, `call_every`), so that a toy B's status poller is the
same code on either clock: real threads on `RealClock`, callbacks fired in order while the probe
`sleep`s on `VirtualClock`. This module shares no code with any target.
"""
from __future__ import annotations

import heapq
import itertools
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- clocks


class RealClock:
    """``time.monotonic`` for the measurement; ``time.time`` only for what the stub signs."""

    kind = "real"

    def __init__(self) -> None:
        self._stops: Dict[int, threading.Event] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def now(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def sleep_until(self, t: float) -> None:
        while True:
            d = t - self.now()
            if d <= 0:
                return
            time.sleep(min(d, 0.05))

    def call_at(self, t: float, fn: Callable[[], None]) -> int:
        return self.call_every(lambda: max(0.0, t - self.now()), fn, once=True)

    def call_every(self, interval: Callable[[], float], fn: Callable[[], None], *,
                   once: bool = False) -> int:
        """Run `fn` after `interval()` seconds, then again after a fresh `interval()`, until
        `cancel`. On its own daemon thread."""
        with self._lock:
            h = next(self._ids)
            stop = self._stops[h] = threading.Event()

        def loop() -> None:
            while not stop.is_set():
                if stop.wait(max(0.0, float(interval()))):
                    return
                try:
                    fn()
                except Exception:  # noqa: BLE001 - a toy's poller failing is the toy's state
                    pass
                if once:
                    return

        threading.Thread(target=loop, daemon=True).start()
        return h

    def cancel(self, handle: Optional[int]) -> None:
        with self._lock:
            ev = self._stops.pop(handle, None) if handle is not None else None
        if ev is not None:
            ev.set()

    def close(self) -> None:
        for h in list(self._stops):
            self.cancel(h)


class VirtualClock:
    """Time that passes only when the probe sleeps: for toys, so a run at T = 60 s takes seconds
    (design §4.7). Callbacks scheduled with `call_at` / `call_every` fire in time order during
    `sleep`, each at its own due time."""

    kind = "virtual"

    def __init__(self, start: float = 10_000.0, wall0: Optional[float] = None) -> None:
        self._t0 = self._t = float(start)
        self._wall0 = time.time() if wall0 is None else float(wall0)
        self._heap: List[Tuple[float, int, int]] = []
        self._fns: Dict[int, Tuple[Callable[[], float], Callable[[], None], bool]] = {}
        self._seq = itertools.count(1)
        self._lock = threading.RLock()

    def now(self) -> float:
        return self._t

    def wall(self) -> float:
        return self._wall0 + (self._t - self._t0)

    def call_at(self, t: float, fn: Callable[[], None]) -> int:
        with self._lock:
            h = next(self._seq)
            self._fns[h] = (lambda: 0.0, fn, True)
            heapq.heappush(self._heap, (max(t, self._t), next(self._seq), h))
            return h

    def call_every(self, interval: Callable[[], float], fn: Callable[[], None], *,
                   once: bool = False) -> int:
        with self._lock:
            h = next(self._seq)
            self._fns[h] = (interval, fn, once)
            heapq.heappush(self._heap, (self._t + max(0.0, float(interval())), next(self._seq), h))
            return h

    def cancel(self, handle: Optional[int]) -> None:
        with self._lock:
            self._fns.pop(handle, None)

    def sleep(self, seconds: float) -> None:
        self.sleep_until(self._t + max(0.0, seconds))

    def sleep_until(self, target: float) -> None:
        while True:
            with self._lock:
                if not self._heap or self._heap[0][0] > target:
                    self._t = max(self._t, target)
                    return
                due, _, h = heapq.heappop(self._heap)
                ent = self._fns.get(h)
                if ent is None:
                    continue
                self._t = max(self._t, due)
                interval, fn, once = ent
                if once:
                    self._fns.pop(h, None)
                else:
                    heapq.heappush(self._heap, (self._t + max(1e-6, float(interval())),
                                                next(self._seq), h))
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:
        with self._lock:
            self._fns.clear()
            self._heap.clear()


def make_clock(kind: str) -> Any:
    if kind == "virtual":
        return VirtualClock()
    if kind == "real":
        return RealClock()
    raise ValueError(f"clock must be 'real' or 'virtual', not {kind!r}")


# --------------------------------------------------------------------------- the method's numbers

UNSTATED_WINDOW_S = 900.0
"""The observation window with no stated T: 15 minutes for the repeated trials.
The one long trial of up to 24 hours is not run in version 1."""
DELTA_MIN_S, DELTA_MAX_S = 0.2, 5.0
EPSILON_MIN_S = 0.05
WORST_PHASE_S = 0.05
"""Worst-phase trials withdraw this long after a fetch by B ends (design §4.4)."""
UNSTATED_FAST_S = 120.0
UNSTATED_DELTA_S, UNSTATED_DELTA_MAX_S, UNSTATED_GROWTH = 1.0, 30.0, 1.5


def window_s(T: Optional[float]) -> float:
    """W: ``max(3T, T + 120 s)`` with a stated T, else `UNSTATED_WINDOW_S`."""
    return max(3 * T, T + 120.0) if T else UNSTATED_WINDOW_S


def stability_s(T: Optional[float]) -> float:
    """S: ``max(T, 30 s)``, the time B must keep refusing after its first refusal."""
    return max(T, 30.0) if T else 30.0


def delta_s(T: Optional[float]) -> float:
    """Δ: ``clamp(T/20, 0.2 s, 5 s)`` with a stated T (KRK-M55), else 1 s at first."""
    if not T:
        return UNSTATED_DELTA_S
    return min(DELTA_MAX_S, max(DELTA_MIN_S, T / 20.0))


def epsilon_s(resolution_s: Optional[float]) -> float:
    """ε: the larger of 50 ms and B's stated timestamp resolution."""
    return max(EPSILON_MIN_S, float(resolution_s or 0.0))


def floor_s(T: Optional[float], rtt_s: float, resolution_s: Optional[float]) -> float:
    """The measurement floor: the smallest spacing plus ε plus the round trip to B."""
    return delta_s(T) + epsilon_s(resolution_s) + max(0.0, rtt_s)


def below_floor(T: Optional[float], rtt_s: float, resolution_s: Optional[float]) -> bool:
    """A stated T below twice the floor is below what this method can measure (§4.4)."""
    return bool(T) and T < 2 * floor_s(T, rtt_s, resolution_s)


@dataclass(frozen=True)
class Slot:
    offset_s: float
    """Seconds after `t_w`."""
    kind: str = "regular"
    """``regular``, ``boundary-before`` or ``boundary-after`` (each ε from `t_w + T`)."""


def schedule(T: Optional[float], rng: Any, *, window: Optional[float] = None,
             resolution_s: Optional[float] = None, start_s: float = 0.0,
             boundary_at: Optional[float] = None) -> List[Slot]:
    """Every presentation slot of one trial, as offsets from `t_w` (design §4.4): from
    `start_s`, spaced by Δ plus a jitter drawn from ``[0, Δ/2]`` so the schedule cannot lock to
    B's poll period (KRK-M54), until the window ends; with a stated T, two boundary slots ε
    either side of ``t_w + T`` (or of `boundary_at`, which the recovery continuation sets to the
    recovery bound). With no stated T, Δ is 1 s for two minutes and then grows by half each slot
    up to 30 s, so a long window does not load B.

    The slots are the probe's own schedule: since KRK-M48 the probe sends each one at its
    time whether or not earlier presentations have been answered (`p19._Dispatcher`), so B's
    answer time never stretches the spacing (KRK-M48)."""
    w = window if window is not None else window_s(T)
    out: List[Slot] = []
    t = start_s
    d = delta_s(T)
    while t < w:
        out.append(Slot(round(t, 6)))
        if not T and t >= UNSTATED_FAST_S:
            d = min(UNSTATED_DELTA_MAX_S, d * UNSTATED_GROWTH)
        t += d + rng.uniform(0.0, d / 2.0)
    edge = boundary_at if boundary_at is not None else T
    if edge:
        e = epsilon_s(resolution_s)
        for off, kind in ((edge - e, "boundary-before"), (edge + e, "boundary-after")):
            if start_s <= off < w:
                out.append(Slot(round(off, 6), kind))
    return sorted(out, key=lambda s: s.offset_s)


SEND_SLACK_S = 0.05
"""How late the kit's own sender may be on a boundary slot before the gap counts against the
reading: the probe's thread wakes a few milliseconds after a slot's time."""


def crosses(lo: float, hi: float, bound: Optional[float],
            resolution_s: Optional[float] = None) -> bool:
    """KRK-M48: whether a bracket ``(lo, hi]`` starts at or before `bound` and
    ends after it by more than the method resolves there. The boundary slots put a presentation
    ε after the bound, so a bracket ending within ``ε + SEND_SLACK_S`` of it is as fine as the
    method measures; one ending later leaves part of the time after the bound unpresented, and
    the reading cannot say whether B was still accepting then."""
    if not bound:
        return False
    return lo <= bound and hi > bound + epsilon_s(resolution_s) + SEND_SLACK_S


def fetch_intervals(fetch_log: Sequence[Dict[str, Any]]) -> List[float]:
    """Intervals between the starts of B's successive fetches."""
    starts = sorted(e["t_start"] for e in fetch_log)
    return [b - a for a, b in zip(starts, starts[1:])]


def last_fetch_end(fetch_log: Sequence[Dict[str, Any]]) -> Optional[float]:
    ends = [e["t_end"] for e in fetch_log if e.get("t_end") is not None]
    return max(ends) if ends else None


def phase_target(fetch_end: float, period: float, rng: Any, mode: str) -> float:
    """The kit-clock time to withdraw at (design §4.4, KRK-M54): drawn uniformly in
    ``[f, f + P]`` for a random-phase trial, or `WORST_PHASE_S` after `f` for a worst-phase one,
    `f` the end of B's latest fetch and `P` the largest fetch interval seen so far."""
    if mode == "worst":
        return fetch_end + WORST_PHASE_S
    if mode == "random":
        return fetch_end + rng.uniform(0.0, max(0.0, period))
    raise ValueError(mode)


def order_stat(sorted_values: Sequence[float], q: float) -> float:
    """The ⌈qN⌉-th value (1-based) of `sorted_values`."""
    n = len(sorted_values)
    k = max(1, min(n, math.ceil(q * n)))
    return sorted_values[k - 1]


# --------------------------------------------------------------------------- one trial


@dataclass
class Pres:
    """One presentation of a trial, every time on the kit clock."""

    under: str
    """``W`` (the withdrawn authority, or for ``narrowed`` its part outside the new ceiling),
    ``L`` (the live sibling), ``W-in`` (``narrowed``: inside the new ceiling), ``W2`` (a
    re-grant)."""
    t_sent: float
    t_answered: float = 0.0
    cls: str = "error"
    """B's answer class: ``accepted`` | ``refused`` | ``in-progress`` | ``error``."""
    effect_t: Optional[float] = None
    """When the recorder committed this presentation's effect, if it did."""
    accepted: bool = False
    """Effect at the recorder (at the ``recorder`` grade), else B's answer."""
    reached: bool = True
    """False when the adapter attributes a refusal to something other than the withdrawal."""
    endpoint: str = ""
    session: str = ""
    tag: str = ""
    ref: str = ""
    """The request's own ``ref``, which the recorder attributes effects by."""
    answered: bool = True
    """False while the presentation awaits B's answer, and for good once it has timed out."""
    timed_out: bool = False
    """No answer within the dispatcher's timeout: class ``error``, never read as either answer
    (at the ``recorder`` grade an effect still counts as an acceptance)."""
    in_flight: int = 0
    """Presentations awaiting an answer when this one was sent, itself excluded."""

    @property
    def refused(self) -> bool:
        return self.cls == "refused" and not self.accepted


@dataclass
class TrialLog:
    variant: str
    form: str
    t_w: float
    T: Optional[float]
    window: float
    stability: float
    presentations: List[Pres] = field(default_factory=list)
    w_effects: List[float] = field(default_factory=list)
    """Every effect under the withdrawn authority, including those of presentations sent before
    `t_w` and committed after it (in flight)."""
    failsafe: bool = False
    """``source_unreachable`` and ``stale_signed_snapshot/served``: refusing the sibling is the
    expected fail-safe, not collateral."""
    info: Optional[str] = None
    """An information outcome the probe decided before classification (``fixture_not_landed``,
    ``refused_before_withdrawal``, ...), with `info_detail`."""
    info_detail: str = ""
    ended_at: float = 0.0
    phase_s: Optional[float] = None
    """Seconds since B's last fetch ended, at `t_w`."""
    resolution_s: Optional[float] = None
    """B's stated timestamp resolution, which sets ε for the crossing check (`crosses`)."""


@dataclass
class TrialOutcome:
    outcome: str
    ok: Optional[bool]
    time_s: Optional[float] = None
    """``max(upper(R), E)``: the trial's time to refusal."""
    bracket: Optional[Tuple[float, float]] = None
    """``(s_{m-1} - t_w, s_m - t_w]`` around the refusal onset."""
    last_effect_s: Optional[float] = None
    onset_endpoint: str = ""
    detail: str = ""
    phase_s: Optional[float] = None
    form: str = ""

    def to_doc(self) -> Dict[str, Any]:
        return {"outcome": self.outcome, "ok": self.ok, "time_s": _r(self.time_s),
                "bracket": [_r(x) for x in self.bracket] if self.bracket else None,
                "last_effect_s": _r(self.last_effect_s), "onset_endpoint": self.onset_endpoint,
                "detail": self.detail, "phase_s": _r(self.phase_s), "form": self.form}


def _r(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(float(x), 3)


INFO_OUTCOMES = ("fixture_not_landed", "collateral_refusal", "stopped_before_guarantee",
                 "not_landed", "refused_before_withdrawal", "not_ready", "no_presentations",
                 "not_reached", "cut_short", "inconclusive")
FAIL_OUTCOMES = ("late", "not_within_W", "flapped")
INCONCLUSIVE = "inconclusive"
"""A trial (or a recovery continuation) whose bracket crosses its bound (`crosses`): the probe
did not present finely enough around the bound to read it, so it has no verdict (KRK-M48)."""
PASS_OUTCOMES = ("within", "regrant_honoured", "reinstated_honoured")


def crossing_detail(lo: float, hi: float, bound: float, what: str = "T") -> str:
    return (f"the bracket {lo:.2f}–{hi:.2f} s crosses {what} = {bound:g} s: no presentation "
            f"under it was answered between {lo:.2f} s and {hi:.2f} s, so whether B refused by "
            f"{what} is not shown (KRK-M48)")


def rejudge(o: TrialOutcome, T: Optional[float],
            resolution_s: Optional[float] = None) -> TrialOutcome:
    """A recorded passing outcome read again with the crossing rule: a pass
    whose bracket crosses T becomes `INCONCLUSIVE`, keeping its time and bracket; everything
    else is returned unchanged. `classify_trial` applies the same rule as it classifies; this
    is for evidence written before the rule existed (`p19.derive`)."""
    if o.outcome in PASS_OUTCOMES and o.bracket and T and crosses(o.bracket[0], o.bracket[1],
                                                                  T, resolution_s):
        return TrialOutcome(INCONCLUSIVE, None, time_s=o.time_s, bracket=o.bracket,
                            last_effect_s=o.last_effect_s, onset_endpoint=o.onset_endpoint,
                            detail=crossing_detail(o.bracket[0], o.bracket[1], T),
                            phase_s=o.phase_s, form=o.form)
    return o


def classify_trial(log: TrialLog) -> TrialOutcome:
    """One trial's outcome (design §4.5): ``within`` (or ``within_W`` with no stated T),
    ``late``, ``not_within_W``, ``flapped``, or an information outcome. The late/within call
    reads only kit-clock times of presentations and effects (§2.3): an effect committed after
    ``t_w + T``, or a presentation sent after it and accepted, is late whatever B's clock says.

    The bracket runs from the last presentation under W that B accepted (or `t_w`) to the first
    one it refused after it; a presentation with no answer in between narrows nothing. A trial
    that would read ``within`` but whose bracket crosses T by more than the method resolves
    (`crosses`) reads `INCONCLUSIVE` instead (KRK-M48): nothing accepted after T
    was seen, but nothing was presented finely enough to show that B would have refused there."""
    def out(outcome: str, ok: Optional[bool], detail: str, **kw: Any) -> TrialOutcome:
        return TrialOutcome(outcome, ok, detail=detail, phase_s=log.phase_s, form=log.form, **kw)

    if log.info:
        return out(log.info, None, log.info_detail)
    t_w, T = log.t_w, log.T
    W = sorted((p for p in log.presentations if p.under == "W" and p.t_sent >= t_w),
               key=lambda p: p.t_sent)
    L = [p for p in log.presentations if p.under == "L" and p.t_sent >= t_w]
    if not W:
        return out("no_presentations", None, "nothing was presented under the withdrawn "
                   "authority after the withdrawal")
    unreached = [p for p in W if p.cls == "refused" and not p.accepted and not p.reached]
    if unreached:
        return out("stopped_before_guarantee", None, f"{len(unreached)} refusal(s) the adapter "
                   f"attributes to something other than the withdrawal")
    if not log.failsafe:
        coll = [p for p in L if p.refused]
        if coll:
            return out("collateral_refusal", None, f"the live sibling was refused "
                       f"{len(coll)} time(s) after the withdrawal, first at "
                       f"{coll[0].t_sent - t_w:.2f} s, so a refusal of the withdrawn one cannot "
                       f"be told from B refusing everything (KRK-M52)")
    acc = [i for i, p in enumerate(W) if p.accepted]
    ref = [i for i, p in enumerate(W) if p.refused]
    last_acc = acc[-1] if acc else None
    onset = next((i for i in ref if last_acc is None or i > last_acc), None)
    late_eff = [e - t_w for e in log.w_effects if e > t_w]
    E = max(late_eff) if late_eff else None
    flapped = bool(ref) and last_acc is not None and last_acc > ref[0]
    if onset is None:
        if log.ended_at and log.ended_at < t_w + log.window - 1e-6 and not acc:
            return out("cut_short", None, "the trial ended before its window without a refusal "
                       "or an acceptance")
        last = W[-1].t_sent - t_w
        return out("not_within_W", False, f"still accepted {last:.1f} s after the withdrawal, "
                   f"at the end of a {log.window:g} s window" + (" (and it had refused "
                   "before, then accepted again)" if flapped else ""), last_effect_s=E,
                   time_s=None)
    hi = W[onset].t_sent - t_w
    # From the last presentation B accepted, not merely the previous one: a presentation with no
    # answer (an error, a timeout) between them says nothing about when B began refusing.
    lo = W[last_acc].t_sent - t_w if last_acc is not None and last_acc < onset else 0.0
    t = max(hi, E or 0.0)
    kw = dict(time_s=t, bracket=(max(0.0, lo), hi), last_effect_s=E,
              onset_endpoint=W[onset].endpoint)
    if flapped:
        k = next(i for i in acc if i > ref[0])
        return out("flapped", False, f"refused at {W[ref[0]].t_sent - t_w:.2f} s, then accepted "
                   f"again at {W[k].t_sent - t_w:.2f} s ({W[k].endpoint or 'endpoint ?'})", **kw)
    if T:
        late_e = [e for e in late_eff if e > T]
        late_p = [p for p in W if p.accepted and p.t_sent - t_w > T]
        if late_e or late_p:
            why = (f"an effect committed {max(late_e):.2f} s after the withdrawal"
                   if late_e else f"a presentation sent {late_p[-1].t_sent - t_w:.2f} s after "
                   f"it was accepted")
            return out("late", False, f"{why}; T is {T:g} s; refused from {hi:.2f} s "
                       f"(bracket {max(0.0, lo):.2f}–{hi:.2f} s)", **kw)
        if crosses(max(0.0, lo), hi, T, log.resolution_s):
            return out(INCONCLUSIVE, None, crossing_detail(max(0.0, lo), hi, T), **kw)
        return out("within", True, f"refused from {hi:.2f} s (bracket {max(0.0, lo):.2f}–"
                   f"{hi:.2f} s), nothing under it after {T:g} s, held", **kw)
    return out("within_W", True, f"refused from {hi:.2f} s (bracket {max(0.0, lo):.2f}–"
               f"{hi:.2f} s), held; no stated T", **kw)


# --------------------------------------------------------------------------- a variant


def aggregate(outcomes: Sequence[TrialOutcome], T: Optional[float], *,
              fail_label: Optional[str] = None,
              need: Optional[int] = None) -> Tuple[str, Optional[bool]]:
    """A variant's outcome from its trials: any ``not_within_W`` is `not_refused_within_W`,
    else any ``flapped`` is `flapped`, else any ``late`` is `refused_late`; all counted trials
    within is the pass (`refused_within_T`, or `refused_within_W` with no stated T). With no
    counted trial, the commonest information outcome.

    **Inconclusive trials.** A fail in any trial is the variant's fail, whatever
    else happened. Otherwise, if any trial is `INCONCLUSIVE`, the variant passes only if at least
    `need` of its trials passed, `need` being the number the plan asks for (all of them when not
    given); an inconclusive trial is never one of those. The probe runs exactly `need` trials, so
    at the published counts one inconclusive trial withholds the pass, and the variant reads
    `INCONCLUSIVE` (no verdict). Other information outcomes (a fixture that did not land, a
    collateral refusal) keep their old effect: they are not counted, and do not withhold."""
    counted = [o for o in outcomes if o.ok is not None]
    names = {o.outcome for o in counted}
    if "not_within_W" in names:
        return fail_label or "not_refused_within_W", False
    if "flapped" in names:
        return "flapped", False
    if "late" in names:
        return fail_label or "refused_late", False
    if any(o.outcome == INCONCLUSIVE for o in outcomes):
        clean = sum(1 for o in counted if o.ok)
        if clean < (need if need is not None else len(outcomes)):
            return INCONCLUSIVE, None
    if not counted:
        infos = [o.outcome for o in outcomes]
        if not infos:
            return "not_run", None
        return max(sorted(set(infos)), key=infos.count), None
    return ("refused_within_T" if T else "refused_within_W"), True


def judge_recovery(l_pres: Sequence[Tuple[float, bool, bool]], w_late: Optional[float],
                   bound: Optional[float], window: float,
                   resolution_s: Optional[float] = None) -> Dict[str, Any]:
    """A recovery continuation (design §3.1 ``recovery``), from the live
    sibling's presentations after the source came back: ``(t_sent - t_r, accepted, refused)``
    in send order, and the send time of the first presentation under W accepted after T, if
    any. The recovery time is bracketed between the last refusal of L before its first
    acceptance (or `t_r`) and that acceptance.

    - ``stuck_closed`` (fail): L never accepted again within the window;
    - ``accepted_after_recovery`` (fail): W accepted after T;
    - ``recovered_late`` (fail): L first accepted after the stated recovery bound,
      and refused at or after it (or the bracket starts after it);
    - `INCONCLUSIVE`: the bracket crosses the stated bound (`crosses`, KRK-M48);
    - ``recovered`` (pass): within the bound, or within the window when no bound is stated."""
    first = next((i for i, (_, acc, _r) in enumerate(l_pres) if acc), None)
    if first is None:
        return {"outcome": "stuck_closed", "ok": False, "first_L_accepted_s": None,
                "bracket": None, "detail": f"the live sibling was not accepted again within "
                                           f"{window:g} s of the source coming back"}
    hi = l_pres[first][0]
    lo = max([t for t, _a, ref in l_pres[:first] if ref], default=0.0)
    doc: Dict[str, Any] = {"first_L_accepted_s": round(hi, 3), "bracket": [round(lo, 3),
                                                                            round(hi, 3)]}
    if w_late is not None:
        doc.update(outcome="accepted_after_recovery", ok=False,
                   detail=f"W accepted {w_late:.2f} s after the source came back")
    elif bound and lo > bound:
        doc.update(outcome="recovered_late", ok=False,
                   detail=f"L refused {lo:.2f} s after the source came back and first accepted "
                          f"again at {hi:.2f} s, after the stated recovery bound of {bound:g} s")
    elif bound and crosses(lo, hi, bound, resolution_s):
        doc.update(outcome=INCONCLUSIVE, ok=None,
                   detail=crossing_detail(lo, hi, bound, "the recovery bound"))
    else:
        doc.update(outcome="recovered", ok=True,
                   detail=f"L accepted again {hi:.2f} s after the source came back (bracket "
                          f"{lo:.2f}–{hi:.2f} s" + (f", bound {bound:g} s)" if bound else ")"))
    return doc


def statistics(outcomes: Sequence[TrialOutcome], T: Optional[float]) -> Dict[str, Any]:
    """The statistics table of design §4.5: N counted and per information outcome; the maximum
    time to refusal with its bracket; the median; p90 and p99 only from 30 and 100 trials
    (``not estimable at N`` otherwise); the late and not-within-W counts; and, with none late,
    the rule-of-three bound 3/N at 95% confidence. The mean is never reported (KRK-M53)."""
    counted = [o for o in outcomes if o.ok is not None]
    n = len(counted)
    info: Dict[str, int] = {}
    for o in outcomes:
        if o.ok is None:
            info[o.outcome] = info.get(o.outcome, 0) + 1
    timed = sorted((o for o in counted if o.time_s is not None), key=lambda o: o.time_s)
    times = [o.time_s for o in timed]
    late = sum(1 for o in counted if o.outcome == "late")
    never = sum(1 for o in counted if o.outcome == "not_within_W")
    flapped = sum(1 for o in counted if o.outcome == "flapped")
    doc: Dict[str, Any] = {"n_counted": n, "n_information": info, "late": late,
                           "not_within_W": never, "flapped": flapped, "n_timed": len(times),
                           "inconclusive": info.get(INCONCLUSIVE, 0)}
    widths = sorted(o.bracket[1] - o.bracket[0] for o in outcomes if o.bracket)
    if widths:
        # Every trial's bracket, the inconclusive ones included: how finely the probe resolved
        # the onset in this variant.
        doc["bracket_width_s"] = {"min": _r(widths[0]), "median": _r(order_stat(widths, 0.5)),
                                  "max": _r(widths[-1])}
    if times:
        worst = timed[-1]
        doc["max_s"] = _r(worst.time_s)
        doc["max_bracket_s"] = [_r(x) for x in worst.bracket] if worst.bracket else None
        doc["max_last_effect_s"] = _r(worst.last_effect_s)
        doc["median_s"] = _r(order_stat(times, 0.5))
        doc["p90_s"] = _r(order_stat(times, 0.9)) if len(times) >= 30 else \
            f"not estimable at N={len(times)}"
        doc["p99_s"] = _r(order_stat(times, 0.99)) if len(times) >= 100 else \
            f"not estimable at N={len(times)}"
    bad = sum(1 for o in counted if o.ok is False)   # every failed trial: late, revived, ...
    if n and bad == 0:
        doc["exceedance"] = (f"0 of {n} trials exceeded the bound: the chance of a trial "
                             f"exceeding it is at most 3/{n} = {3 / n:.3f} at 95% confidence "
                             f"(rule of three)")
    elif n:
        doc["exceedance"] = f"{bad} of {n} trials exceeded the bound (the count is the finding)"
    if T is None and times:
        doc["effective_bound_s"] = _r(times[-1])
    doc["trials"] = [o.to_doc() for o in outcomes]
    return doc


PERCENTILE_N = {"p90": 30, "p95": 60, "p99": 300}
"""Trials needed before a stated percentile is checked at that percentile."""


def percentile_check(statistic: str, outcomes: Sequence[TrialOutcome], T: Optional[float]
                     ) -> Optional[str]:
    """For a bound stated as a percentile: whether it can be checked at this trial count, and,
    if so, whether it held. A bound with no statistic, or "typically", is graded as a maximum,
    which `aggregate` already does; this returns None for it."""
    if not T or statistic in (None, "", "max", "typically"):
        return None
    need = PERCENTILE_N.get(statistic)
    counted = [o for o in outcomes if o.ok is not None]
    if need is None:
        return f"statistic {statistic!r} is not one the kit checks; graded as a maximum"
    if len(counted) < need:
        return (f"a {statistic} bound cannot be checked at N={len(counted)} (needs about "
                f"{need}); the maximum is reported and graded")
    times = sorted(o.time_s if o.time_s is not None else float("inf") for o in counted)
    q = float(statistic[1:]) / 100.0
    v = order_stat(times, q)
    return f"{statistic} = {v:.2f} s against T = {T:g} s: {'held' if v <= T else 'exceeded'}"
