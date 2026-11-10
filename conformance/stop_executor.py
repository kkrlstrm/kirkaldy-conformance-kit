"""The kit's executor and recorder for KRK-28 (P28, the stop's answer names what landed).

The target (a runtime, a durable engine or a tool-calling harness) dispatches an action to the
kit's executor, `StubExecutor`, as it would call a tool. The executor does nothing on its own: the
probe decides when the call starts, when each of its items lands, how the executor answers a stop,
and when the result goes back. Every step is written to the `Recorder` with a time from the run's
one clock, and the recorder is the only source of truth for what landed (design: "the kit's
recorder as the only source of truth").

**The recorder counts every attempt** (KRK-M223). An effect is one event per item per attempt; a
call the target sends twice is two ``received`` events, and nothing is merged. What landed is
read from those events, never from the target or from the executor's own answers.

**What the target sees.** Three calls, the same for a toy and, through an adapter, for a real
target:

- ``call(call_id, items, reply)``: the dispatch. It returns at once (the call is in flight). The
  target's ``reply`` is called later with the result message ``{"call_id", "result", "items",
  "partial"}`` or an error message ``{"call_id", "error"}``. A ``reply`` that raises (the target
  closed its channel) is recorded as ``delivery_refused``: the result was offered and the target
  did not take it.
- ``cancel(call_id)``: the target's stop, passed on to the executor. It returns the executor's
  answer ``{"answer": ...}`` (``too_late``, ``stopped``, ``partial``, ``already_answered``), or
  ``None`` when the executor gives no answer; it raises `CancelUnsupported` when the executor has
  no cancel channel and ``ConnectionError`` when the executor cannot be reached. The executor's
  answer is an input to the target, never graded.
- nothing else. The executor never reports to the target outside these two channels.

The result of each call carries a fresh random token (`secrets`, never the seed), so the probe
can tell a result the target kept from one it wrote itself (KRK-M226).

Standard library only; it shares no code with any target.
"""
from __future__ import annotations

import itertools
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

ANSWERS = ("too_late", "stopped", "partial", "already_answered", None, "unsupported",
           "unreachable")
"""How the executor answers a stop: a stated answer, ``None`` (no answer at all), or no channel
to answer on (``unsupported``: no cancel channel; ``unreachable``: the executor is cut off)."""


class CancelUnsupported(Exception):
    """The executor has no cancel channel: the target's stop cannot reach it."""


@dataclass
class Plan:
    """How the executor behaves for one call. Set by the probe before the target dispatches."""

    call_id: str
    items: List[str]
    cancel_answer: Optional[str] = "too_late"
    token: str = field(default_factory=lambda: "res-" + secrets.token_hex(12))
    unreachable: bool = False
    attempts: int = 0
    reply: Optional[Callable[[Dict[str, Any]], Any]] = None
    sent: Optional[Dict[str, Any]] = None
    """A result marked sent and not yet delivered (the result and the stop cross)."""


class Recorder:
    """Append-only events for every call, with times from the run's one clock."""

    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self.events: List[Dict[str, Any]] = []
        self._seq = itertools.count(1)

    def note(self, call_id: str, kind: str, **kw: Any) -> Dict[str, Any]:
        e = {"seq": next(self._seq), "call_id": call_id, "kind": kind, "at": self.clock.now(),
             **kw}
        self.events.append(e)
        return e

    def commit(self, call_id: str, item: str, attempt: int) -> None:
        self.note(call_id, "effect", item=item, attempt=attempt)

    def of(self, call_id: str, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["call_id"] == call_id
                and (kind is None or e["kind"] == kind)]

    def first(self, call_id: str, kind: str) -> Optional[float]:
        hits = self.of(call_id, kind)
        return hits[0]["at"] if hits else None

    def effects(self, call_id: str) -> List[Dict[str, Any]]:
        """Every effect event of the call, one per item per attempt; nothing merged."""
        return self.of(call_id, "effect")

    def landed(self, call_id: str) -> List[str]:
        """The items that landed at least once, in the order they first landed."""
        out: List[str] = []
        for e in self.effects(call_id):
            if e["item"] not in out:
                out.append(e["item"])
        return out

    def offered(self, call_id: str) -> Optional[Dict[str, Any]]:
        """The result the executor sent on the target's reply channel, or None. Offered means
        sent, whether or not the target took it."""
        hits = self.of(call_id, "result_sent")
        return hits[-1]["message"] if hits else None


class StubExecutor:
    """The tool the target calls. The probe drives every step; see the module docstring."""

    def __init__(self, clock: Any, recorder: Optional[Recorder] = None) -> None:
        self.clock = clock
        self.recorder = recorder or Recorder(clock)
        self.plans: Dict[str, Plan] = {}

    # ------------------------------------------------------------------ the target's side

    def call(self, call_id: str, items: Sequence[str],
             reply: Callable[[Dict[str, Any]], Any]) -> Dict[str, Any]:
        p = self.plans.get(call_id)
        if p is None:
            self.recorder.note(call_id, "received_unplanned", items=list(items))
            return {"accepted": False, "error": "unknown call"}
        if p.unreachable:
            self.recorder.note(call_id, "unreachable_call")
            raise ConnectionError("executor unreachable")
        p.attempts += 1
        p.reply = reply
        self.recorder.note(call_id, "received", attempt=p.attempts, items=list(items))
        return {"accepted": True}

    def cancel(self, call_id: str) -> Optional[Dict[str, Any]]:
        p = self.plans.get(call_id)
        if p is None:
            self.recorder.note(call_id, "cancel_unplanned")
            return {"answer": "unknown_call"}
        ans = "unreachable" if p.unreachable else p.cancel_answer
        self.recorder.note(call_id, "cancel_received", answer=ans)
        if ans == "unreachable":
            raise ConnectionError("executor unreachable")
        if ans == "unsupported":
            raise CancelUnsupported("the executor has no cancel channel")
        if ans is None:
            return None
        out: Dict[str, Any] = {"answer": ans}
        if ans == "partial":
            out["items"] = self.recorder.landed(call_id)
        return out

    # ------------------------------------------------------------------ the probe's side

    def expect(self, call_id: str, items: Sequence[str], *,
               cancel_answer: Optional[str] = "too_late") -> Plan:
        if cancel_answer not in ANSWERS:
            raise ValueError(f"unknown cancel answer {cancel_answer!r}")
        p = Plan(call_id, list(items), cancel_answer)
        self.plans[call_id] = p
        return p

    def received(self, call_id: str) -> bool:
        return bool(self.recorder.of(call_id, "received"))

    def start(self, call_id: str) -> None:
        self.recorder.note(call_id, "started", attempt=self.plans[call_id].attempts)

    def land(self, call_id: str, items: Optional[Sequence[str]] = None) -> None:
        p = self.plans[call_id]
        for it in (p.items if items is None else items):
            self.recorder.commit(call_id, it, p.attempts)

    def cut_off(self, call_id: str) -> None:
        """The executor can no longer be reached: no cancel, no result."""
        self.plans[call_id].unreachable = True
        self.recorder.note(call_id, "cut_off")

    def _message(self, call_id: str, items: Optional[Sequence[str]], partial: bool
                 ) -> Dict[str, Any]:
        p = self.plans[call_id]
        return {"call_id": call_id, "result": p.token,
                "items": list(p.items if items is None else items), "partial": bool(partial)}

    def mark_sent(self, call_id: str, items: Optional[Sequence[str]] = None,
                  partial: bool = False) -> None:
        """The result leaves the executor now and reaches the target at `deliver`: a stop sent
        in between crosses it on the wire."""
        p = self.plans[call_id]
        p.sent = self._message(call_id, items, partial)
        self.recorder.note(call_id, "result_sent", message=dict(p.sent))

    def deliver(self, call_id: str) -> bool:
        p = self.plans[call_id]
        msg = p.sent
        if msg is None:
            raise RuntimeError("nothing marked sent")
        p.sent = None
        return self._hand(call_id, msg)

    def respond(self, call_id: str, items: Optional[Sequence[str]] = None,
                partial: bool = False) -> bool:
        """Send the result and hand it to the target's reply channel at once. Returns whether
        the target took it."""
        msg = self._message(call_id, items, partial)
        self.recorder.note(call_id, "result_sent", message=dict(msg))
        return self._hand(call_id, msg)

    def fail(self, call_id: str, error: str) -> bool:
        """Answer the call with an error (``connection reset`` for a crash, ``cancelled`` when
        the executor stopped before any effect)."""
        msg = {"call_id": call_id, "error": error}
        self.recorder.note(call_id, "error_sent", message=dict(msg))
        return self._hand(call_id, msg)

    def _hand(self, call_id: str, msg: Dict[str, Any]) -> bool:
        p = self.plans[call_id]
        if p.reply is None:
            self.recorder.note(call_id, "delivery_refused", why="no reply channel")
            return False
        try:
            p.reply(dict(msg))
        except Exception as e:  # noqa: BLE001 - a closed channel is the target's state
            self.recorder.note(call_id, "delivery_refused", why=f"{type(e).__name__}: {e}")
            return False
        self.recorder.note(call_id, "delivered", kind_of="result" if "result" in msg else "error")
        return True
