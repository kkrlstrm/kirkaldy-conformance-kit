"""In-process toy targets, one per property, each in three variants:

- ``bad``      — deliberately broken; the probe MUST report fail.
- ``good``     — correct; the probe MUST report pass. Proves the probe can pass at all.
- ``no-control`` — the control cannot hold; the probe MUST report inconclusive, never a verdict.

A probe that cannot fail is the self-consistent failure this project exists to catch, so these
run in CI on every change (tests/test_known_bad.py). They need no Docker and no network beyond
loopback.

Each toy models the *mechanism* the property is about in a few lines. They are not
simulations of any vendor.
"""
from __future__ import annotations

import base64
import socket
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from conformance.mockserver import MockServer


class _Toy:
    config = "default"

    def __init__(self, variant: str) -> None:
        assert variant in ("bad", "good", "no-control"), variant
        self.variant = variant
        self.config = variant

    def version(self) -> str:
        return f"toy-{self.variant}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


# --------------------------------------------------------------------------- P1


class ToyGateway(_Toy):
    """A gateway that asks a policy decider. ``bad`` forwards when the decider is down, but
    only after the first request has timed out and marked the decider unavailable (KRK-M1).
    A probe that sends one denied request per outage
    passes this toy; that is why P1 repeats."""

    name = "toy-gateway"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.decider_up = True
        self.noticed_outage = False
        self.upstream: List[str] = []

    def implements(self):
        return ["P1"]

    def failure_modes(self) -> List[str]:
        return ["decider-stopped", "decider-timeout"]

    def send(self, kind: str, marker: str) -> str:
        if self.variant == "no-control":  # policy never wired up: everything is forwarded
            self.upstream.append(marker)
            return "200"
        if self.decider_up:
            if kind == "denied":
                return "403 denied by policy"
            self.upstream.append(marker)
            return "200"
        if getattr(self, "hold_and_release", False):
            self.held = getattr(self, "held", []) + [marker]
            return "timeout (request held)"
        if self.variant == "bad":  # fail open, once the outage has been noticed
            if not self.noticed_outage:
                self.noticed_outage = True
                return "503 policy unavailable (timed out)"
            self.upstream.append(marker)
            return "200 (decider unreachable, allowed)"
        return "503 policy unavailable"

    def upstream_received(self, marker: str) -> bool:
        return marker in self.upstream

    def induce(self, mode: str) -> None:
        if getattr(self, "induce_does_nothing", False):  # the stop command failed quietly
            return
        self.decider_up = False

    def restore(self, mode: str) -> None:
        self.decider_up = True
        self.noticed_outage = False
        # "held" variant: requests parked during the outage are released when it ends
        self.upstream.extend(getattr(self, "held", []))
        self.held = []

    def decider_reachable(self) -> bool:
        return self.decider_up


# --------------------------------------------------------------------------- P2


class ToyVault(_Toy):
    """A credential broker. ``bad`` masks the plain value in tool output but returns a debug
    header carrying it base64-encoded, which a string-match redactor never sees."""

    name = "toy-vault"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.secret = ""
        self.upstream_auth: List[str] = []

    def implements(self):
        return ["P2"]

    def store_credential(self, value: str) -> None:
        self.secret = value

    def exercise_credential(self) -> str:
        if self.variant != "no-control":
            self.upstream_auth.append(f"Bearer {self.secret}")
        return "called upstream"

    def upstream_saw(self, value: str) -> bool:
        return any(value in h for h in self.upstream_auth)

    def agent_observations(self, value: str) -> Dict[str, str]:
        tool_out = "result: ok, token=" + "*" * 8
        obs = {"env": "PATH=/usr/bin\nHOME=/home/agent", "tool_output": tool_out}
        if self.variant == "bad":
            obs["response_headers"] = "x-debug-auth: " + base64.b64encode(self.secret.encode()).decode()
        else:
            obs["response_headers"] = "content-type: application/json"
        return obs


# --------------------------------------------------------------------------- P3 / P4


class ToyApprovals(_Toy):
    """An approval engine. P3 ``bad`` keeps pending approvals in memory, so a restart loses
    them. P4 ``bad`` lets anyone holding the run id resume."""

    name = "toy-approvals"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.pending: Dict[str, str] = {}
        self.effects: Dict[str, int] = {}
        self.approver = "human:approver"
        self.wake_after_restart_s = 0.0  # KRK-M11: a restarted wait that wakes on a slow poll
        self.late: Dict[str, float] = {}

    def implements(self):
        return ["P3", "P4"]

    def restart_kinds(self) -> List[str]:
        return ["engine-process"]

    def request(self, action_id: str) -> None:
        self.pending[action_id] = "pending"

    def is_pending(self, action_id: str) -> bool:
        return self.pending.get(action_id) == "pending"

    def restart(self, kind: str) -> None:
        if self.variant == "bad":
            self.pending.clear()
        for aid, st in self.pending.items():
            if st == "pending" and self.wake_after_restart_s:
                self.late[aid] = self.wake_after_restart_s

    def _execute(self, action_id: str) -> None:
        if self.variant == "no-control":
            return  # approval path does nothing
        self.effects[action_id] = self.effects.get(action_id, 0) + 1

    def approve(self, action_id: str) -> str:
        return self.approve_as("designated", action_id)

    def impostors(self) -> Dict[str, str]:
        return {"other_user": "a user who is not the approver",
                "replayed_run_id": "anyone presenting the run id"}

    def approve_as(self, who: str, action_id: str) -> str:
        if self.pending.get(action_id) != "pending":
            return "unknown action"
        if who != "designated" and self.variant == "good":
            return "403 not an approver"
        self.pending[action_id] = "done"
        self._execute(action_id)
        return "approved"

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        if wait_s < self.late.get(action_id, 0.0):
            return 0  # it will run, but not within the window the caller waited
        return self.effects.get(action_id, 0)


# --------------------------------------------------------------------------- P5


class ToyKeys(_Toy):
    """A key service. ``bad`` lets any key mint keys, including broader ones."""

    name = "toy-keys"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.grants = {"agent": {"models": ["small"], "budget": 1}}

    def implements(self):
        return ["P5"]

    def widening_operations(self) -> List[str]:
        return ["mint_broader_key", "raise_own_budget"]

    def as_admin(self, op: str) -> Tuple[bool, str]:
        if self.variant == "no-control":
            return False, "admin API not present on this build"
        return True, f"admin performed {op} on a throwaway principal"

    def as_agent(self, op: str) -> Tuple[bool, str]:
        if self.variant != "bad":
            return False, "403"
        if op == "raise_own_budget":
            self.grants["agent"]["budget"] = 1000
        return True, "200 ok"

    def agent_grant(self) -> Dict[str, Any]:
        return {k: dict(v) for k, v in self.grants.items()}["agent"]


# --------------------------------------------------------------------------- P6


class ToySandbox(_Toy):
    """``bad`` is no sandbox at all: commands connect from the host. ``good`` refuses every
    connection. Public attempts are simulated (CI must not depend on the internet)."""

    name = "toy-sandbox"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.listener: Optional[MockServer] = None

    def implements(self):
        return ["P6"]

    def start(self) -> None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        tcp_port = s.getsockname()[1]
        s.close()
        self.listener = MockServer(tcp_port=tcp_port)

    def stop(self) -> None:
        if self.listener:
            self.listener.close()

    def listener_reachable_from_host(self) -> Tuple[bool, str]:
        if self.variant == "no-control":
            return False, "listener bound to an address the host cannot reach"
        assert self.listener
        try:
            urllib.request.urlopen(f"{self.listener.url}/host-check", timeout=3).read()
            return True, self.listener.url
        except Exception as e:
            return False, str(e)

    def create_default_sandbox(self) -> None:
        pass

    def egress_attempts(self) -> Dict[str, str]:
        return {"http_listener": "curl listener", "tcp_listener": "nc listener",
                "dns_public": "getent hosts example.com", "https_public": "curl https://example.com"}

    shared_tag_baseline = False
    """When True, the baseline really connects to the listener with the same tag the sandbox
    attempt uses, and nothing clears the listener: the KRK-M16 adapter defect."""

    def baseline(self, attempt: str) -> Tuple[bool, str]:
        if self.shared_tag_baseline and attempt == "http_listener":
            assert self.listener
            urllib.request.urlopen(f"{self.listener.url}/egress/{attempt}", timeout=3).read()
        return True, "reference environment reached it"

    def run_inside(self, attempt: str) -> Tuple[int, str]:
        assert self.listener
        if self.variant != "bad":
            return 7, "connection refused"
        if attempt == "http_listener":
            urllib.request.urlopen(f"{self.listener.url}/egress/{attempt}", timeout=3).read()
            return 0, "ok"
        if attempt == "tcp_listener":
            with socket.create_connection(("127.0.0.1", self.listener.tcp_port), timeout=3) as c:
                c.sendall(f"egress {attempt}\n".encode())
                return 0, c.recv(64).decode()
        return 0, "simulated success"

    def listener_saw(self, attempt: str) -> bool:
        assert self.listener
        recs = self.listener.records()
        return (any(attempt in r["path"] for r in recs["http"])
                or any(attempt in r["first_bytes"] for r in recs["tcp"]))

    def destroy_sandbox(self) -> None:
        pass


# --------------------------------------------------------------------------- P7


class ToyAudit(_Toy):
    """``bad`` records the session's user and nothing else, so an agent acting in the human's
    session looks exactly like the human. ``good`` records the acting principal and the
    session it acted through as separate fields."""

    name = "toy-audit"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.log: Dict[str, Dict[str, Any]] = {}
        self.done: set = set()
        self._t = 1000

    def implements(self):
        return ["P7"]

    def actors(self) -> List[str]:
        return ["human", "agent", "agent_in_human_session"]

    def act(self, actor: str, marker: str) -> None:
        if self.variant == "no-control":
            return
        self.done.add(marker)
        self._t += 1
        session_user = {"human": "alice", "agent": "svc-agent", "agent_in_human_session": "alice"}[actor]
        rec: Dict[str, Any] = {"event": "record.update", "ts": self._t, "request": marker,
                               "user": session_user}
        if getattr(self, "coarse_clock", False):
            # a one-"second" timestamp that ticks every third action: equal for two actions in a
            # row, different across the tick
            rec["second"] = self._t // 3
        if self.variant == "good":
            rec["actor"] = "agent:copilot" if actor.startswith("agent") else "human:alice"
        self.log[marker] = rec

    def happened(self, marker: str) -> bool:
        return marker in self.done

    def audit_record(self, marker: str) -> Optional[Dict[str, Any]]:
        return self.log.get(marker)


# --------------------------------------------------------------------------- P8


class ToyWaits(_Toy):
    """``bad`` parks a real thread on every pending approval, the shape of an engine that holds
    the request inline. ``good`` keeps a row. ``no-control``'s waits die during the hold."""

    name = "toy-waits"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        import threading
        self._threading = threading
        self.pending: Dict[str, Any] = {}
        self.effects: Dict[str, int] = {}

    def implements(self):
        return ["P8"]

    def stop(self) -> None:
        for ev in [*self.pending.values(), *getattr(self, "_leaked", [])]:
            if hasattr(ev, "set"):
                ev.set()

    def request(self, action_id: str) -> None:
        if getattr(self, "warming_pool", 0) and len(getattr(self, "_pool", [])) < self.warming_pool:
            # KRK-M14: a pool that starts a thread on demand and keeps it, up to a cap
            ev = self._threading.Event()
            self._threading.Thread(target=ev.wait, daemon=True).start()
            self._pool = getattr(self, "_pool", []) + [ev]
            self._leaked = getattr(self, "_leaked", []) + [ev]
        if self.variant == "bad":
            ev = self._threading.Event()
            self._threading.Thread(target=ev.wait, daemon=True).start()
            self.pending[action_id] = ev
        else:
            self.pending[action_id] = "row"

    def is_pending(self, action_id: str) -> bool:
        if getattr(self, "warming_status_pool", 0) and len(getattr(self, "_spool", [])) < self.warming_status_pool:
            ev = self._threading.Event()  # KRK-M14: a status path that opens a fixed pool, then stops
            self._threading.Thread(target=ev.wait, daemon=True).start()
            self._spool = getattr(self, "_spool", []) + [ev]
            self._leaked = getattr(self, "_leaked", []) + [ev]
        if getattr(self, "leaky_client", False):  # a status call that leaves a thread behind
            ev = self._threading.Event()
            self._threading.Thread(target=ev.wait, daemon=True).start()
            self._leaked = getattr(self, "_leaked", []) + [ev]
        if self.variant == "no-control" and getattr(self, "_sampled_after", False):
            return False
        return action_id in self.pending

    def approve(self, action_id: str) -> str:
        ev = self.pending.pop(action_id, None)
        if hasattr(ev, "set"):
            ev.set()
        self.effects[action_id] = self.effects.get(action_id, 0) + 1
        return "approved"

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)

    def resource_sample(self) -> Dict[str, float]:
        if self.pending:
            self._sampled_after = True
        return {"processes": 1, "threads": self._threading.active_count(), "connections": 0}


# --------------------------------------------------------------------------- P9


class ToyGrants(_Toy):
    """An approval engine that separates approving from running, on a clock the probe moves.

    ``bad`` re-derives its grant on every execute pass from the stored decision. The first pass
    after the time limit refuses (the stored envelope has expired) and stores a fresh envelope
    minted from the same old decision, so the next pass runs it. That is why P9 runs the
    execute path more than once. ``bad`` also ignores a retraction and never re-reads who has
    standing. ``good`` measures the limit from the decision, honours a retraction, and checks
    standing when it runs. ``no-control``'s execute path does nothing.

    ``reply_clock_s`` makes the toy identify a reply by its timestamp rounded to that many
    seconds, so a retraction in the same interval as the approval reads as the same reply and
    is dropped (KRK-M15)."""

    name = "toy-grants"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.now = 1000.0
        self.ttl = 60.0
        self.approvers = {"alice"}
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, int] = {}

    def implements(self):
        return ["P9"]

    def grant_variants(self) -> Dict[str, str]:
        return {"expired": "the clock passes the limit", "revoked": "the approver retracts",
                "standing_withdrawn": "the approver is removed from the approver list"}

    def hold(self, action_id: str, params: Optional[Dict[str, Any]] = None) -> None:
        self.actions[action_id] = {"state": "pending", "revoked": False}

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    def decide(self, action_id: str) -> str:
        self.actions[action_id].update(state="approved", by="alice", decided_at=self.now,
                                       envelope_expires=self.now + self.ttl)
        return "approval recorded"

    def attempt(self, action_id: str) -> str:
        a = self.actions.get(action_id)
        if not a or a["state"] != "approved":
            return "nothing to run"
        if self.variant == "no-control":
            return "ran (the executor is not wired to anything)"
        if self.variant == "good":
            if self.now >= a["decided_at"] + self.ttl:
                return "refused: the approval expired"
            if a["revoked"]:
                return "refused: the approval was revoked"
            if a["by"] not in self.approvers:
                return "refused: the approver no longer has standing"
        elif self.now >= a["envelope_expires"]:
            a["envelope_expires"] = self.now + self.ttl  # re-derived from the same decision
            return "refused: the stored envelope expired"
        a["state"] = "done"
        self.effects[action_id] = self.effects.get(action_id, 0) + 1
        return "ran"

    def grant_ttl_s(self) -> float:
        return self.ttl

    def invalidate(self, variant: str, action_id: str) -> str:
        if variant == "revoked":
            a = self.actions[action_id]
            clock = getattr(self, "reply_clock_s", 0)
            if clock and int(self.now // clock) == int(a["decided_at"] // clock):
                return "the approver retracted (read as the same reply as the approval)"
            a["revoked"] = True
            return "the approver retracted"
        self.approvers.discard("alice")
        return "alice removed from the approvers"

    def restore_variant(self, variant: str) -> None:
        self.approvers = {"alice"}

    def elapse(self, seconds: float) -> None:
        self.now += seconds

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)


# --------------------------------------------------------------------------- P10


class ToyBinding(_Toy):
    """``bad`` keys an approval on the action id and runs whatever parameters the action holds
    when it executes. ``good`` binds the approval to a hash of the parameters approved and
    refuses anything else. ``no-control``'s executor records nothing.

    ``rejects_extra_items`` makes the toy refuse any call carrying an extra item, approved or
    not, as a schema error. A refusal of that variant is then not about binding (KRK-M10)."""

    name = "toy-binding"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.ran: Dict[str, List[Dict[str, Any]]] = {}
        self.rejects_extra_items = False

    def implements(self):
        return ["P10"]

    def binding_variants(self) -> Dict[str, str]:
        return {"substituted": "the agent presents other arguments",
                "changed_after_approval": "the stored parameters are rewritten",
                "extra_item": "an item is appended"}

    @staticmethod
    def _h(params: Dict[str, Any]) -> str:
        import hashlib
        import json
        return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()

    def hold(self, action_id: str, params: Optional[Dict[str, Any]] = None) -> None:
        import copy
        self.actions[action_id] = {"params": copy.deepcopy(params or {}), "state": "pending"}

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    def decide(self, action_id: str) -> str:
        a = self.actions[action_id]
        a.update(state="approved", approved=self._h(a["params"]))
        return "approved"

    def change(self, variant: str, action_id: str, params: Dict[str, Any]) -> str:
        import copy
        self.actions[action_id]["params"] = copy.deepcopy(params)
        return f"{variant}: the call now carries {params}"

    def attempt(self, action_id: str) -> str:
        a = self.actions.get(action_id)
        if not a or a["state"] != "approved":
            return "nothing to run"
        if self.rejects_extra_items and "extra-item" in a["params"].get("items", []):
            return "400 unknown item"
        if self.variant == "good" and self._h(a["params"]) != a["approved"]:
            return "refused: these parameters were not approved"
        a["state"] = "done"
        if self.variant != "no-control":
            self.ran.setdefault(action_id, []).append(dict(a["params"]))
        return "ran"

    def executed_params(self, action_id: str) -> List[Dict[str, Any]]:
        return list(self.ran.get(action_id, []))


# --------------------------------------------------------------------------- P11


class ToyExecutors(_Toy):
    """``bad`` reads the action's status, performs the side effect, then marks it done, with no
    claim, so every executor that reads the status before the first one marks it runs it.
    ``good`` takes an atomic claim before the side effect. ``no-control``'s executor never
    runs anything.

    ``serial`` makes the adapter run its executors one at a time. A probe that does not check
    they overlapped would read the result as "exactly once"."""

    name = "toy-executors"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        import threading
        self.lock = threading.Lock()
        self.serial_lock = threading.Lock()
        self.serial = False
        self.actions: Dict[str, str] = {}
        self.effects: Dict[str, int] = {}

    def implements(self):
        return ["P11"]

    def executor_kinds(self) -> Dict[str, str]:
        return {"worker": "one worker thread calling execute"}

    def hold(self, action_id: str, params: Any = None) -> None:
        self.actions[action_id] = "pending"

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id) == "pending"

    def decide(self, action_id: str) -> str:
        self.actions[action_id] = "approved"
        return "approved"

    def _effect(self, action_id: str) -> None:
        with self.lock:
            self.effects[action_id] = self.effects.get(action_id, 0) + 1

    def _attempt(self, action_id: str) -> Tuple[float, float, str]:
        import time
        began = time.time()
        if self.variant == "no-control":
            time.sleep(0.05)
            return began, time.time(), "nothing ran"
        if self.variant == "good":
            with self.lock:
                if self.actions.get(action_id) != "approved":
                    return began, time.time(), "claimed by another executor"
                self.actions[action_id] = "running"
        elif self.actions.get(action_id) != "approved":
            return began, time.time(), "already done"
        time.sleep(0.05)  # the side effect takes time
        self._effect(action_id)
        self.actions[action_id] = "done"
        return began, time.time(), "ran"

    def attempt_as(self, kind: str, action_id: str,
                   start_at: float = 0.0) -> Tuple[float, float, str]:
        if self.serial:
            with self.serial_lock:
                return self._attempt(action_id)
        return self._attempt(action_id)

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)


# --------------------------------------------------------------------------- P12


class ToyReceipts(_Toy):
    """``bad`` performs the side effect and then writes its record. A crash between the two
    leaves an approved action that looks unrun, and the next pass runs it again. ``good``
    writes an intent record before the side effect; a pass that finds an intent with no
    completion does not run it again and raises it for reconciliation. ``no-control``'s crash
    lands before the side effect.

    ``forgets_crashed`` makes ``bad`` stop considering an action once a run of it crashed:
    no second run, no record, nothing said to anyone."""

    name = "toy-receipts"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, int] = {}
        self.forgets_crashed = False

    def implements(self):
        return ["P12"]

    def crash_kinds(self) -> Dict[str, str]:
        return {"process-killed": "the executor process dies after the call returns"}

    def hold(self, action_id: str, params: Any = None) -> None:
        self.actions[action_id] = {"state": "pending"}

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    def decide(self, action_id: str) -> str:
        self.actions[action_id]["state"] = "approved"
        return "approved"

    def _effect(self, action_id: str) -> None:
        self.effects[action_id] = self.effects.get(action_id, 0) + 1

    def attempt(self, action_id: str) -> str:
        a = self.actions.get(action_id, {})
        if a.get("state") != "approved":
            return f"nothing to run ({a.get('state')})"
        if self.variant == "good" and a.get("intent"):
            a.update(state="needs-reconciliation",
                     flag="started before a crash and never recorded; check upstream")
            return "held for reconciliation"
        if self.forgets_crashed and a.get("crashed"):
            return "not considered"
        if self.variant == "good":
            a["intent"] = True
        self._effect(action_id)
        a["state"] = "done"
        return "ran"

    def attempt_crashing(self, kind: str, action_id: str) -> str:
        a = self.actions[action_id]
        a["crashed"] = True
        if self.variant == "no-control":
            return "process died before the call"
        if self.variant == "good":
            a["intent"] = True
        self._effect(action_id)
        return "process died after the call returned"

    def recover(self, kind: str) -> str:
        return "restarted"

    def recovery_wait_s(self, kind: str) -> float:
        return 0.0

    def completion_recorded(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "done"

    def flagged(self, action_id: str) -> Tuple[bool, str]:
        f = self.actions.get(action_id, {}).get("flag", "")
        return bool(f), f

    def elapse(self, seconds: float) -> None:
        pass

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)


# --------------------------------------------------------------------------- P13


class ToyWorld(_Toy):
    """An approval engine acting on outside state it does not own. ``bad`` runs an approved
    action whatever has happened to that state since. ``good`` records the state when the
    approval is given and, if it differs at execution, puts the action back in front of the
    approver. ``no-control``'s executor records nothing.

    ``refuses_suppressed`` blocks any action whose recipient is suppressed, approved or not, so
    a refusal of that variant is not about re-reading (KRK-M10). ``refuse_not_reask`` makes
    ``good`` refuse outright instead of asking again."""

    name = "toy-world"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.worlds: Dict[str, Dict[str, Any]] = {}
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, int] = {}
        self.refuses_suppressed = False
        self.refuse_not_reask = False

    def implements(self):
        return ["P13"]

    def world_variants(self) -> Dict[str, str]:
        return {"target_changed": "another writer updates the record",
                "precondition_false": "the recipient is added to the suppression list"}

    def prepare_world(self, action_id: str) -> str:
        self.worlds[action_id] = {"version": 1, "suppressed": False}
        return "record v1, recipient not suppressed"

    def change_world(self, variant: str, action_id: str) -> str:
        w = self.worlds[action_id]
        if variant == "target_changed":
            w["version"] += 1
            return f"record updated to v{w['version']} by another writer"
        w["suppressed"] = True
        return "recipient added to the suppression list"

    def hold(self, action_id: str, params: Any = None) -> None:
        self.actions[action_id] = {"state": "pending"}

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    def decide(self, action_id: str) -> str:
        self.actions[action_id].update(state="approved", seen=dict(self.worlds[action_id]))
        return "approved"

    def attempt(self, action_id: str) -> str:
        a = self.actions.get(action_id, {})
        if a.get("state") != "approved":
            return f"nothing to run ({a.get('state')})"
        w = self.worlds[action_id]
        if self.refuses_suppressed and w["suppressed"]:
            return "refused: recipient is suppressed"
        if self.variant == "no-control":
            return "ran (the executor is not wired to anything)"
        if self.variant == "good" and w != a["seen"]:
            if self.refuse_not_reask:
                a["state"] = "refused"
                return "refused: the world changed since the approval"
            a["state"] = "pending"
            return "the world changed since the approval; asking again"
        a["state"] = "done"
        self.effects[action_id] = self.effects.get(action_id, 0) + 1
        return "ran"

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)


# --------------------------------------------------------------------------- P14


class ToyForgery(_Toy):
    """An approval engine whose decisions sit in a store the application can write. ``bad``
    runs any action whose stored decision, or last history entry, says approved. ``good`` runs
    only on a decision signed by its approval path, for this action id, and flags any other
    decision it finds. ``no-control``'s executor records nothing.

    ``malformed_forgery`` makes every forgery a record the product would never write, so its
    refusal is not evidence (KRK-M10)."""

    name = "toy-forgery"
    _KEY = b"approval-service-only"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.now = 1000
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.store: Dict[str, Dict[str, Any]] = {}
        self.history: Dict[str, List[Dict[str, Any]]] = {}
        self.effects: Dict[str, int] = {}
        self.flags: Dict[str, str] = {}
        self.malformed_forgery = False

    def implements(self):
        return ["P14"]

    def forgery_paths(self) -> Dict[str, str]:
        return {"store_write": "write the decision row with the app's own store access",
                "history_injection": "append an approval to the run history",
                "replayed_decision": "copy another action's real decision row"}

    def _sig(self, action_id: str, by: str, at: int) -> str:
        import hashlib
        import hmac
        return hmac.new(self._KEY, f"{action_id}|{by}|{at}".encode(), hashlib.sha256).hexdigest()

    def hold(self, action_id: str, params: Any = None) -> None:
        self.actions[action_id] = {"state": "pending"}
        self.history[action_id] = []

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    def decide(self, action_id: str) -> str:
        self.now += 1
        self.store[action_id] = {"action": action_id, "approved": True, "by": "alice",
                                 "at": self.now, "sig": self._sig(action_id, "alice", self.now)}
        return "approved"

    def forge(self, variant: str, action_id: str, genuine_from: str) -> str:
        self.now += 1
        fake = ({"ok": 1} if self.malformed_forgery else
                {"action": action_id, "approved": True, "by": "alice", "at": self.now,
                 "sig": "0" * 64})
        if variant == "store_write":
            self.store[action_id] = fake
            return "wrote an approved decision row"
        if variant == "history_injection":
            self.history[action_id].append(fake)
            return "appended an approval to the history"
        self.store[action_id] = dict(self.store[genuine_from])
        return f"copied {genuine_from}'s decision row"

    def decision_record(self, action_id: str, variant: str = "") -> Optional[Dict[str, Any]]:
        if variant == "history_injection":
            h = self.history.get(action_id) or []
            return h[-1] if h else None
        return self.store.get(action_id)

    def attempt(self, action_id: str) -> str:
        a = self.actions.get(action_id, {})
        if a.get("state") != "pending":
            return f"nothing to run ({a.get('state')})"
        rec = self.store.get(action_id) or (self.history.get(action_id) or [None])[-1]
        if not rec or not rec.get("approved"):
            return "not approved"
        if self.variant == "good":
            stored = self.store.get(action_id) or {}
            genuine = (stored.get("action") == action_id and
                       stored.get("sig") == self._sig(action_id, stored.get("by", ""),
                                                      stored.get("at", 0)))
            if not genuine:
                self.flags[action_id] = "a decision not issued by the approval path was found"
                return "refused: decision not issued by the approval path"
        if self.variant == "no-control":
            return "ran (the executor is not wired to anything)"
        a["state"] = "done"
        self.effects[action_id] = self.effects.get(action_id, 0) + 1
        return "ran"

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        return self.effects.get(action_id, 0)

    def flagged(self, action_id: str) -> Tuple[bool, str]:
        f = self.flags.get(action_id, "")
        return bool(f), f


# --------------------------------------------------------------------------- P15


class ToyDisplay(_Toy):
    """An approval card. ``bad`` shows the fields it knows (recipients, subject, note), lists at
    most three recipients then "and N more", and prints values as they are. ``good`` shows every
    field, nested ones included, every list item, and escapes characters outside ASCII.
    ``no-control`` shows nothing the probe can read.

    ``clock_in_card`` adds a counter to every card, so two identical calls are shown
    differently and the lookalike comparison cannot be made. ``digest_in_card`` adds a hash of
    the call, which changes with a lookalike while nothing a person reads does."""

    name = "toy-display"

    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.ran: Dict[str, List[Dict[str, Any]]] = {}
        self.clock_in_card = False
        self.digest_in_card = False
        self._tick = 0

    def implements(self):
        return ["P15"]

    def hold(self, action_id: str, params: Dict[str, Any]) -> None:
        import copy
        self.actions[action_id] = {"params": copy.deepcopy(params), "state": "pending"}

    def is_pending(self, action_id: str) -> bool:
        return self.actions.get(action_id, {}).get("state") == "pending"

    @staticmethod
    def _flat(prefix: str, v: Any) -> List[str]:
        if isinstance(v, dict):
            return [s for k in sorted(v) for s in ToyDisplay._flat(f"{prefix}.{k}" if prefix else k, v[k])]
        if isinstance(v, list):
            return [s for i, x in enumerate(v) for s in ToyDisplay._flat(f"{prefix}[{i}]", x)]
        return [f"{prefix}: {str(v).encode('ascii', 'backslashreplace').decode()}"]

    def shown_to_approver(self, action_id: str) -> str:
        if self.variant == "no-control":
            return "(card rendered in a client the probe cannot read)"
        p = self.actions[action_id]["params"]
        head = f"Approve {action_id}?"
        if self.clock_in_card:
            self._tick += 1
            head += f" (#{self._tick})"
        if self.digest_in_card:
            import hashlib
            import json
            head += "\nsha256: " + hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()
        if self.variant == "good":
            return "\n".join([head] + self._flat("", p))
        to = p.get("to", [])
        shown_to = ", ".join(to[:3]) + (f" and {len(to) - 3} more" if len(to) > 3 else "")
        return f"{head}\nTo: {shown_to}\nSubject: {p.get('subject', '')}\nNote: {p.get('note', '')}"

    def decide(self, action_id: str) -> str:
        self.actions[action_id]["state"] = "approved"
        return "approved"

    def attempt(self, action_id: str) -> str:
        import copy
        a = self.actions.get(action_id, {})
        if a.get("state") != "approved":
            return "nothing to run"
        a["state"] = "done"
        self.ran.setdefault(action_id, []).append(copy.deepcopy(a["params"]))
        return "ran"

    def executed_params(self, action_id: str) -> List[Dict[str, Any]]:
        return list(self.ran.get(action_id, []))


TOYS = {"P1": ToyGateway, "P2": ToyVault, "P3": ToyApprovals, "P4": ToyApprovals,
        "P5": ToyKeys, "P6": ToySandbox, "P7": ToyAudit, "P8": ToyWaits,
        "P9": ToyGrants, "P10": ToyBinding, "P11": ToyExecutors, "P12": ToyReceipts,
        "P13": ToyWorld, "P14": ToyForgery, "P15": ToyDisplay}


def _effect_receipts(variant: str):
    """P16's toys live in known_bad/receipts_toys.py (they need `cryptography`); this keeps TOYS
    the one catalogue that tests/test_known_bad.py checks against the property list."""
    from .receipts_toys import ToyEffectReceipts
    return ToyEffectReceipts(variant)


TOYS["P16"] = _effect_receipts


def _records(variant: str):
    """P17's toys live in known_bad/records_toys.py, for the same reason as P16's."""
    from .records_toys import ToyRecords
    return ToyRecords(variant)


TOYS["P17"] = _records


def _binding(variant: str):
    """P18's toys live in known_bad/binding_toys.py, for the same reason as P16's."""
    from .binding_toys import ToyBinding
    return ToyBinding(variant)


TOYS["P18"] = _binding


def _withdrawal(config: str):
    """P19's toys live in known_bad/withdrawal_toys.py, for the same reason as P16's."""
    from known_bad.withdrawal_toys import ToyWithdrawal
    return ToyWithdrawal(config)


TOYS["P19"] = _withdrawal
