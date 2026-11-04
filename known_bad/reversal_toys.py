"""Known-bad and known-good toy B's for P23 (KRK-23, reversibility as declared).

One toy B with a real executor bound to the kit's world (`X10-REVERSIBILITY-DESIGN.md` §4.7): a
claim catalogue it states before the run, a forward path that verifies A's authorisation 0.2 and
acts on the world, a reversal path, a status read, a record read through its own path, a store
that can survive a restart, and operator hooks. It evaluates classes with its own code, not the
kit's (`conformance.reversibility` is used only to read the authorisation's signature).

``good``'s catalogue is true of its behaviour:

| Operation | World call | Claim |
|---|---|---|
| ``crm.contact.create`` | objects:create | reversible within 600 s, restores object, fields, links |
| ``crm.contact.update`` | objects:update | reversible within 600 s, restores fields |
| ``crm.contact.archive`` | objects:delete | reversible within 600 s (soft delete; restore and relink) |
| ``crm.contacts.import`` | objects:create_many | reversible within 600 s |
| ``mail.send`` | mail:deliver | reversible until ``message_read``; irreversible for a recipient outside ``b.example`` |
| ``ledger.transfer`` | ledger:transfer | compensable until ``funds_moved``; counter-effect one refund transfer |
| ``topic.publish`` | topics:publish | compensable, counter-effect retract, residue ``copy_at_subscriber`` |
| ``crm.contact.delete`` | objects:delete | irreversible |
| ``crm.contact.merge`` | objects:update | no claim (``class_absent``) |

It reads the claim in force at commit, evaluates conditions per request, refuses an absent class
under a ceiling, refuses a reversal without standing (A's organisation, an agent with a
``krk.reverse`` grant, B's operator; a withdrawn agent loses the right), keys reversals on the
original authorisation id, stores accepted reversals durably, cancels a held forward call,
completes within R, answers ``pending`` while the world is down and completes within ``rec``
after, and keeps its record in step with the world. ``good-deferred`` holds ``mail.send`` and
``topic.publish`` at B until their window ends (an undo send). ``good-conservative`` declares every
operation with a downstream consequence irreversible and refuses its reversal. ``slow-good`` is
``good`` answering ``accepted`` and completing at 0.6 R. All four must pass.

Flaws behave wrongly; none removes members from what it was sent (KRK-M47):

| Flaw | What it does | Variant it is built to fail |
|---|---|---|
| `slow_reversal` | completes at 1.5 R | `reversal` |
| `marks_only` | answers reversed, calls nothing | `reversal` |
| `async_dropped` | accepts, never runs | `reversal` |
| `partial_items` | reverses the first n - 1 of n items | `reversal` (``multi_item``) |
| `object_only` | restores existence only (no fields, no links) | `reversal` (``object_update``, ``object_delete``) |
| `update_as_delete` | deletes an updated object instead of restoring its fields | `reversal` (``object_update``) |
| `reverses_latest` | reverses the agent's newest action of the operation | `reversal` |
| `notifies_undeclared` | sends a notice to a party for every reversal | `reversal` |
| `refund_as_transfer` | declares the transfer reversible and pays back with a new transfer | `reversal` (``transfer``) |
| `recreates_new_id` | restores an archived object under a new id | `reversal` (``object_delete``) |
| `claims_unconditional` | declares no ``until`` and no residue; recalls what it can and answers done | `downstream_consequence` |
| `refuses_inside_window` | measures the window from the forward request's arrival | `window` |
| `accepts_then_drops` | queues the reversal, drops it once the window has passed, says done | `window` |
| `done_on_world_error` | answers reversed when the world errors, never retries | `partition` |
| `forgets_queued` | accepts, drops the job when the world errors | `partition` |
| `reports_done_on_partial` | skips an item the world refused and answers reversed | `partition` (``refuse_one_item``) |
| `memory_only` | keeps accepted reversals in memory, lost on restart | `partition` (``b_restart``) |
| `lets_held_action_land` | marks a held action reversed; its retry then commits it | `overtake` |
| `compensates_wrong` | refunds one minor unit less than the transfer | `compensation_effect` |
| `compensates_with_notice` | sends the payee a notice with each compensation | `compensation_effect` |
| `double_compensation` | refunds again on a repeat | `duplicate` |
| `keyed_on_request_id` | treats a new request id as a new reversal | `duplicate` (``new_request_id``) |
| `keyed_on_object` | finds the action by the object's email, so a repeat removes X′ | `duplicate` (``after_reapply``) |
| `any_requester` | reverses for any authenticated caller | `no_standing` |
| `agent_grant_ignored` | checks the organisation, not the agent's grant | `no_standing` (``agent_without_reversal``) |
| `ignores_class` | executes any class (``bad`` is this with `marks_only`) | `class_ceiling` |
| `compensable_as_reversible` | orders compensable at or below reversible | `class_ceiling` (``compensable_op``) |
| `absent_means_reversible` | reads an operation with no claim as reversible | `class_ceiling` (``class_absent``) |
| `class_from_request` | takes the class the request states | `class_ceiling` (``class_claimed_in_request``) |
| `class_at_bind` | reads its catalogue once, at bind | `class_downgrade` (``catalogue_changed``) |
| `class_per_operation` | ignores conditions | `class_downgrade` (``condition_in_request``) |
| `checks_class_at_arrival` | checks the class on arrival only, not at commit | `class_downgrade` (``changed_between_arrival_and_commit``) |
| `applies_new_window_to_old` | judges executed actions by the current window | `class_downgrade` (``window_shortened_after_execution``) |
| `operator_silent` | an operator reversal runs; its record still reads done | `b_initiated` |

``no-control``: the executor never reaches the world.
"""
from __future__ import annotations

import copy
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

FLAWS = ("slow_reversal", "marks_only", "async_dropped", "partial_items", "object_only",
         "update_as_delete", "reverses_latest", "notifies_undeclared", "refund_as_transfer",
         "recreates_new_id", "claims_unconditional", "refuses_inside_window",
         "accepts_then_drops", "done_on_world_error", "forgets_queued", "reports_done_on_partial",
         "memory_only", "lets_held_action_land", "compensates_wrong", "compensates_with_notice",
         "double_compensation", "keyed_on_request_id", "keyed_on_object", "any_requester",
         "agent_grant_ignored", "ignores_class", "compensable_as_reversible",
         "absent_means_reversible", "class_from_request", "class_at_bind", "class_per_operation",
         "checks_class_at_arrival", "applies_new_window_to_old", "operator_silent")
FAILS = {"slow_reversal": "reversal", "marks_only": "reversal", "async_dropped": "reversal",
         "partial_items": "reversal", "object_only": "reversal", "update_as_delete": "reversal",
         "reverses_latest": "reversal", "notifies_undeclared": "reversal",
         "refund_as_transfer": "reversal", "recreates_new_id": "reversal",
         "claims_unconditional": "downstream_consequence",
         "refuses_inside_window": "window", "accepts_then_drops": "window",
         "done_on_world_error": "partition", "forgets_queued": "partition",
         "reports_done_on_partial": "partition", "memory_only": "partition",
         "lets_held_action_land": "overtake", "compensates_wrong": "compensation_effect",
         "compensates_with_notice": "compensation_effect",
         "double_compensation": "duplicate", "keyed_on_request_id": "duplicate",
         "keyed_on_object": "duplicate", "any_requester": "no_standing",
         "agent_grant_ignored": "no_standing", "ignores_class": "class_ceiling",
         "compensable_as_reversible": "class_ceiling", "absent_means_reversible": "class_ceiling",
         "class_from_request": "class_ceiling", "class_at_bind": "class_downgrade",
         "class_per_operation": "class_downgrade", "checks_class_at_arrival": "class_downgrade",
         "applies_new_window_to_old": "class_downgrade", "operator_silent": "b_initiated"}
PARTY = "did:web:b.example"
MEANS = "krk.reverse"
WINDOW_S = 600
R_S = 10.0
FORWARD_DELAY_S = 2.0
"""B's forward path: the time from a request's arrival to its commit at the world."""
DEFERRED_S = 30.0
CLASSES = ("reversible", "compensable", "irreversible")
QUOTE = "toy: 'every action states whether and how it can be undone'"


def _claim(op: str, cls: str, *, restores: Optional[List[str]] = None,
           until: Optional[List[str]] = None, residues: Optional[List[Dict[str, Any]]] = None,
           counter: Optional[Dict[str, Any]] = None, conditions: Optional[List[Dict[str, Any]]] = None,
           seconds: Optional[int] = WINDOW_S) -> Dict[str, Any]:
    c: Dict[str, Any] = {"operation": op, "class": cls, "source": "documented", "quote": QUOTE,
                         "url": "toy://catalogue"}
    if cls != "irreversible":
        c.update({"means": {"operation": MEANS, "by": ["requester", "operator"]},
                  "window": {"seconds": seconds, "until": list(until or [])},
                  "completion_bound_s": R_S, "restores": list(restores or ["object"]),
                  "residues": list(residues if residues is not None else [{"kind": "history_entry"}]),
                  "counter_effect": counter, "conditions": list(conditions or []),
                  "executed_claims_may_change": False})
    return c


def catalogue(config: str, flaw: Optional[str]) -> List[Dict[str, Any]]:
    """The claims the toy states before the run."""
    mail_cond = [{"when": {"member": "to", "domain_not_in": ["b.example"]},
                  "class": "irreversible"}]
    cat = [_claim("crm.contact.create", "reversible", restores=["object", "fields", "links"]),
           _claim("crm.contact.update", "reversible", restores=["fields"]),
           _claim("crm.contact.archive", "reversible", restores=["object", "fields", "links"]),
           _claim("crm.contacts.import", "reversible", restores=["object", "fields", "links"]),
           _claim("mail.send", "reversible", restores=["delivery"], until=["message_read"],
                  conditions=mail_cond),
           _claim("ledger.transfer", "compensable", restores=["balance"], until=["funds_moved"],
                  counter={"kind": "transfer", "direction": "back", "amount": "same"}),
           _claim("topic.publish", "compensable", restores=["delivery"],
                  residues=[{"kind": "history_entry"}, {"kind": "copy_at_subscriber"}],
                  counter={"kind": "retract"}),
           _claim("crm.contact.delete", "irreversible")]
    if config == "good-deferred":
        for c in cat:
            if c["operation"] in ("mail.send", "topic.publish"):
                c["window"] = {"seconds": DEFERRED_S, "until": []}
    if config == "good-conservative":
        cat = [c if c["operation"] not in ("mail.send", "ledger.transfer", "topic.publish")
               else _claim(c["operation"], "irreversible") for c in cat]
    if flaw == "refund_as_transfer":
        cat = [c if c["operation"] != "ledger.transfer" else
               _claim("ledger.transfer", "reversible", restores=["balance"], until=["funds_moved"])
               for c in cat]
    if flaw == "claims_unconditional":
        out = []
        for c in cat:
            if c["operation"] in ("mail.send", "ledger.transfer", "topic.publish"):
                c = {**c, "window": {"seconds": WINDOW_S, "until": []}, "conditions": [],
                     "residues": [{"kind": "history_entry"}]}
                if c["operation"] == "topic.publish":
                    c.update({"class": "reversible", "counter_effect": None})
            out.append(c)
        cat = out
    return cat


WORLD_PROFILE = {"crm.contact.create": ["objects:create"], "crm.contact.update": ["objects:update"],
                 "crm.contact.archive": ["objects:delete"],
                 "crm.contacts.import": ["objects:create_many"], "mail.send": ["mail:deliver"],
                 "ledger.transfer": ["ledger:transfer"], "topic.publish": ["topics:publish"],
                 "crm.contact.delete": ["objects:delete"], "crm.contact.merge": ["objects:update"]}


class ToyReversal:
    """A B that performs and reverses actions on the kit's world (P23's role-B adapter)."""

    name = "toy-reversal"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *,
                 clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "ignores_class"
        if flaw is not None and flaw not in FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.config = config if flaw is None or config == "bad" else f"bad:{flaw}"
        self.flaw = flaw
        self.flaws = {flaw, "marks_only"} if config == "bad" else {flaw}
        self.kind = "good" if config == "bad" or flaw else config
        self.clock = clock
        self._clock: Any = None
        self.no_control = config == "no-control"
        self.cat = catalogue(self.kind if self.kind != "good" else "good", flaw)
        self._cat_at_bind: List[Dict[str, Any]] = copy.deepcopy(self.cat)
        self.orgs: Dict[str, Dict[str, bytes]] = {}
        self.home = ""
        self.w: Any = None
        self.boot = secrets.token_hex(4)
        # the durable store (survives restart) and the memory one (does not)
        self.store: Dict[str, Any] = {"actions": {}, "order": [], "reversals": {},
                                      "by_request": {}, "queue": []}
        self.mem_queue: List[Dict[str, Any]] = []
        self.withdrawn: set = set()
        self._tick: Optional[int] = None
        self._rev_lock = threading.Lock()

    # kit plumbing ---------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-reversal {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P23": QUOTE}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        if self._clock is not None and self._tick is not None:
            self._clock.cancel(self._tick)
        self._tick = None

    def role(self) -> str:
        return "B"

    def set_clock(self, c: Any) -> None:
        self._clock = c

    def now(self) -> float:
        return self._clock.now() if self._clock is not None else time.monotonic()

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": PARTY, "endpoints": ["/actions"], "tenants": [None],
                "clock_tolerance_s": 0.0, "timestamp_resolution_s": 0.0}

    def evidence_grade(self) -> str:
        return "world"

    def ceiling_profile(self) -> str:
        return "kirkaldy.request-authorisation/0.2"

    def bind_requester(self, anchor: Dict[str, Any], *, receiver: Any = None) -> str:
        self.home = anchor["issuer"]
        self.orgs[anchor["issuer"]] = dict(anchor["keys"])
        return "pinned A's keys"

    def bind_peer(self, anchor: Dict[str, Any]) -> str:
        self.orgs[anchor["issuer"]] = dict(anchor["keys"])
        return "pinned A′'s keys"

    def bind_world(self, url: str, credential: str) -> str:
        from conformance import world
        if not self.no_control:
            self.w = world.connect(url, credential)
        self._cat_at_bind = copy.deepcopy(self.cat)
        return "connected to the world with B's credential"

    # statements -----------------------------------------------------------------------------

    def reversibility(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.cat)

    def reversal_means(self) -> Dict[str, Any]:
        return {"kind": "kit", "operation": MEANS}

    def reversal_standing(self) -> Dict[str, Any]:
        return {"parties": ["requesting_org", "operator"], "agents": "reverse-grant",
                "withdrawn_agent": "loses", "quote": "toy: 'the requesting organisation, an "
                "agent it granted krk.reverse, or our operator; a withdrawn agent cannot'"}

    def reversal_modes(self) -> List[Dict[str, Any]]:
        if self.kind == "good-deferred":
            return [{"mode": "deferred", "operations": ["mail.send", "topic.publish"],
                     "commit_delay_s": DEFERRED_S}, {"mode": "immediate", "operations": "*"}]
        return [{"mode": "immediate", "operations": "*"}]

    def recovery_bound(self) -> Dict[str, Any]:
        return {"rec_s": R_S}

    def executed_claims_may_change(self) -> Dict[str, Any]:
        return {"applies": False, "quote": "toy: 'an action is governed by the claim in force "
                                           "when it ran'"}

    def reversal_statements(self) -> None:
        return None

    def record_path(self) -> str:
        return "toy.store"

    def world_profile(self) -> Dict[str, List[str]]:
        return dict(WORLD_PROFILE)

    def variants_not_applicable(self) -> Dict[str, str]:
        return {}

    def remote(self) -> bool:
        return False

    # reading what A sent --------------------------------------------------------------------

    def _read(self, p: Any) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], str]:
        import json
        from conformance import authz, reversibility as rv
        claims = authz.claims_of(p.authorisation) or {}
        keys = self.orgs.get(claims.get("issuer"), {})
        v = rv.verify_v2(p.authorisation, keys)
        if not v.ok:
            return None, {}, f"authorisation {v.reason}"
        if authz.binding_digest(p.request) != v.claims["binding"]["request_digest"]:
            return None, {}, "request does not match its authorisation"
        return v.claims, json.loads(p.request), ""

    # classes, the toy's own code -------------------------------------------------------------

    def _catalogue(self) -> List[Dict[str, Any]]:
        return self._cat_at_bind if "class_at_bind" in self.flaws else self.cat

    def _claim(self, op: str, cat: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        return next((c for c in (cat if cat is not None else self._catalogue())
                     if c["operation"] == op), None)

    def _class(self, op: str, values: Dict[str, Any]) -> str:
        if "class_from_request" in self.flaws and values.get("class") in CLASSES:
            return values["class"]
        c = self._claim(op)
        if c is None:
            return "reversible" if "absent_means_reversible" in self.flaws else "irreversible"
        if "class_per_operation" not in self.flaws:
            for cond in c.get("conditions") or []:
                w = cond["when"]
                v = str(values.get(w["member"], ""))
                dom = v.rsplit("@", 1)[-1].lower()
                if "domain_not_in" in w and dom not in w["domain_not_in"]:
                    return cond["class"]
                if "domain_in" in w and dom in w["domain_in"]:
                    return cond["class"]
        return c["class"]

    def _admits(self, cls: str, ceiling: str) -> bool:
        if "ignores_class" in self.flaws:
            return True
        order = {"reversible": 0, "compensable": 1, "irreversible": 2}
        if "compensable_as_reversible" in self.flaws:
            order["compensable"] = 0
        return order.get(cls, 3) <= order.get(ceiling, -1)

    # the forward path -------------------------------------------------------------------------

    def present(self, p: Any) -> Dict[str, Any]:
        claims, values, why = self._read(p)
        if claims is None:
            return {"status": 401, "outcome": "refused", "reason": why}
        if claims.get("reverses"):
            return {"status": 400, "outcome": "refused", "reason": "use the reversal endpoint"}
        op = values.get("operation")
        if op not in WORLD_PROFILE:
            return {"status": 400, "outcome": "refused", "reason": f"unknown operation {op}"}
        ceiling = claims["max_class"]
        if not self._admits(self._class(op, values), ceiling):
            return {"status": 403, "outcome": "refused", "reason": "class_above_ceiling"}
        aid = claims["authorisation_id"]
        act = {"id": aid, "op": op, "values": values, "org": claims["issuer"],
               "agent": (claims.get("agent") or {}).get("id"), "ceiling": ceiling,
               "state": "pending", "arrived_at": self.now(), "committed_at": None,
               "claim_at_exec": None, "refs": {}, "prior": {}}
        self.store["actions"][aid] = act
        self.store["order"].append(aid)
        if self._clock is not None:
            self._clock.sleep(FORWARD_DELAY_S)
        delay = DEFERRED_S if (self.kind == "good-deferred" and op in ("mail.send",
                                                                       "topic.publish")) else 0.0
        if delay:
            act["state"] = "deferred"
            act["committed_at"] = self.now()
            act["claim_at_exec"] = copy.deepcopy(self._claim(op, self.cat))
            self._queue({"kind": "commit", "id": aid, "due": self.now() + delay}, durable=True)
            return {"status": 202, "outcome": "accepted", "ref": aid}
        return self._commit(act)

    def _commit(self, act: Dict[str, Any], *, retry: bool = False) -> Dict[str, Any]:
        from conformance import world
        op, v = act["op"], act["values"]
        if retry and "checks_class_at_arrival" not in self.flaws and \
                not self._admits(self._class(op, v), act["ceiling"]):
            act["state"] = "refused"
            return {"status": 403, "outcome": "refused", "reason": "class_above_ceiling"}
        if self.w is None:
            act["state"] = "done"
            return {"status": 200, "outcome": "done", "ref": act["id"]}
        try:
            refs = self._execute(op, v, act)
        except world.Held as e:
            act["state"] = "held"
            self._queue({"kind": "retry", "id": act["id"], "due": self.now() + e.retry_after_s},
                        durable=True)
            return {"status": 202, "outcome": "accepted", "ref": act["id"]}
        except world.WorldError as e:
            act["state"] = "failed"
            return {"status": 503, "outcome": "error", "reason": e.code}
        act["refs"] = refs
        act["state"] = "done"
        act["committed_at"] = self.now()
        act["claim_at_exec"] = copy.deepcopy(self._claim(op, self.cat))
        return {"status": 200, "outcome": "done", "ref": act["id"]}

    def _execute(self, op: str, v: Dict[str, Any], act: Dict[str, Any]) -> Dict[str, Any]:
        w = self.w
        if op == "crm.contact.create":
            oid = w.create(fields=v["fields"], email=v.get("email"), note=v.get("note"),
                           links=v.get("links") or [])["id"]
            return {"objects": [oid], "edges": [[oid, d] for d in v.get("links") or []]}
        if op == "crm.contacts.import":
            return {"objects": w.create_many(items=v["items"], note=v.get("note"))["ids"]}
        if op in ("crm.contact.update", "crm.contact.merge"):
            prior = w.read(kind="object", eid=v["object_id"])
            act["prior"] = {"fields": {k: prior["fields"].get(k) for k in v["fields"]}}
            w.update(object_id=v["object_id"], fields=v["fields"])
            return {"objects": [v["object_id"]]}
        if op in ("crm.contact.archive", "crm.contact.delete"):
            oid = v["object_id"]
            edges = [[e["src"], e["dst"]] for e in w.find(kind="edge", live=True)
                     if oid in (e["src"], e["dst"])]
            prior = w.read(kind="object", eid=oid)
            act["prior"] = {"fields": dict(prior["fields"]), "email": prior.get("email"),
                            "edges": edges}
            w.delete(object_id=oid)
            return {"objects": [oid]}
        if op == "mail.send":
            return {"mail": w.deliver(to=v["to"], subject=v.get("subject", ""),
                                      body=v.get("body", ""))["id"]}
        if op == "ledger.transfer":
            return {"transfer": w.transfer(frm=v["from"], to=v["to"], amount=v["amount"],
                                           memo=v.get("memo"))["id"]}
        if op == "topic.publish":
            return {"item": w.publish(topic=v["topic"], body=v.get("body", ""))["id"]}
        raise ValueError(op)

    def classify(self, ans: Dict[str, Any]) -> str:
        return {"done": "accepted", "accepted": "in-progress", "refused": "refused"}.get(
            (ans or {}).get("outcome"), "error")

    # the queue --------------------------------------------------------------------------------

    def _queue(self, job: Dict[str, Any], *, durable: bool) -> None:
        if "memory_only" in self.flaws and job["kind"] == "reverse":
            self.mem_queue.append(job)
        else:
            self.store["queue"].append(job)
        self._arm()

    def _arm(self) -> None:
        if self._clock is None or self._tick is not None:
            return
        self._tick = self._clock.call_every(lambda: 0.5, self._work)

    def _work(self) -> None:
        jobs = self.store["queue"] + self.mem_queue
        if not jobs:
            if self._tick is not None:
                self._clock.cancel(self._tick)
                self._tick = None
            return
        now = self.now()
        for job in list(jobs):
            if job["due"] > now:
                continue
            q = self.mem_queue if job in self.mem_queue else self.store["queue"]
            if job in q:
                q.remove(job)
            act = self.store["actions"].get(job["id"])
            if act is None:
                continue
            if job["kind"] in ("retry", "commit"):
                if act["state"] in ("cancelled", "reversed") and "lets_held_action_land" not in \
                        self.flaws:
                    continue
                if job["kind"] == "commit":
                    try:
                        act["refs"] = self._execute(act["op"], act["values"], act)
                        if act["state"] == "deferred":
                            act["state"] = "done"
                    except Exception:  # noqa: BLE001
                        job["due"] = now + 1.0
                        self.store["queue"].append(job)
                    continue
                prev = act["state"]
                self._commit(act, retry=True)
                if prev == "reversed":
                    act["state"] = "reversed"          # lets_held_action_land: says reversed
                continue
            self._reverse_job(act, job)

    # the reversal path ------------------------------------------------------------------------

    def _target(self, claims: Dict[str, Any], values: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rv_ = values.get("reverses") or {}
        act = self.store["actions"].get(rv_.get("authorisation_id"))
        if act is None:
            return None
        if "reverses_latest" in self.flaws:
            mine = [self.store["actions"][i] for i in self.store["order"]
                    if self.store["actions"][i]["agent"] == act["agent"]
                    and self.store["actions"][i]["op"] == act["op"]
                    and self.store["actions"][i]["state"] == "done"]
            return mine[-1] if mine else act
        if "keyed_on_object" in self.flaws and act["values"].get("email"):
            same = [self.store["actions"][i] for i in self.store["order"]
                    if self.store["actions"][i]["values"].get("email") == act["values"]["email"]
                    and self.store["actions"][i]["op"] == act["op"]]
            live = [x for x in same if x["state"] == "done"]
            return live[-1] if live else act
        return act

    def _standing(self, claims: Dict[str, Any], act: Dict[str, Any]) -> Optional[str]:
        if "any_requester" in self.flaws:
            return None
        if claims["issuer"] != act["org"]:
            return "no_standing"
        if "agent_grant_ignored" in self.flaws:
            return None
        ag = claims.get("agent") or {}
        if ag.get("id") in self.withdrawn:
            return "agent_withdrawn"
        if MEANS not in (ag.get("grants") or []):
            return "no_reverse_grant"
        return None

    def present_reversal(self, p: Any) -> Dict[str, Any]:
        began = time.monotonic()
        with self._rev_lock:
            out = self._present_reversal(p)
        time.sleep(0.003)
        out.setdefault("began_at", began)
        out["ended_at"] = time.monotonic()
        return out

    def _present_reversal(self, p: Any) -> Dict[str, Any]:
        claims, values, why = self._read(p)
        if claims is None:
            return {"status": 401, "outcome": "refused", "reason": why}
        act = self._target(claims, values)
        if act is None:
            return {"status": 404, "outcome": "refused", "reason": "unknown_action"}
        no = self._standing(claims, act)
        if no:
            return {"status": 403, "outcome": "refused", "reason": no}
        rid = values.get("request_id")
        key = rid if "keyed_on_request_id" in self.flaws else act["id"]
        prior = self.store["reversals"].get(key)
        if prior is not None and not ("double_compensation" in self.flaws and act["op"] ==
                                      "ledger.transfer"):
            self.store["by_request"][rid] = prior
            return {"status": 200, "outcome": prior["state"] if prior["state"] != "done" else
                    "reversed", "reason": "already_reversed", "repeat": True}
        rec = {"id": act["id"], "state": "accepted", "request_id": rid, "t": self.now()}
        self.store["reversals"][key] = rec
        self.store["by_request"][rid] = rec
        return self._reverse_now(act, rec)

    def _claim_for_action(self, act: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if "applies_new_window_to_old" in self.flaws:
            return self._claim(act["op"], self.cat)
        return act.get("claim_at_exec") or self._claim(act["op"], self.cat)

    def _reverse_now(self, act: Dict[str, Any], rec: Dict[str, Any]) -> Dict[str, Any]:
        from conformance import world
        claim = self._claim_for_action(act)
        if claim is None or claim["class"] == "irreversible":
            rec["state"] = "refused"
            return {"status": 409, "outcome": "refused", "reason": "irreversible"}
        start = act["arrived_at"] if "refuses_inside_window" in self.flaws else \
            (act.get("committed_at") or act["arrived_at"])
        secs = (claim.get("window") or {}).get("seconds")
        if secs is not None and self.now() - start > secs:
            rec["state"] = "refused"
            return {"status": 409, "outcome": "refused", "reason": "window_closed"}
        until = (claim.get("window") or {}).get("until") or []
        if self.w is not None and act["state"] == "done":
            try:
                if "message_read" in until and act["refs"].get("mail") and \
                        self.w.read(kind="mail", eid=act["refs"]["mail"]).get("read_at"):
                    rec["state"] = "refused"
                    return {"status": 409, "outcome": "refused", "reason": "already_read"}
                if "funds_moved" in until and act["refs"].get("transfer") and \
                        self.w.read(kind="transfer", eid=act["refs"]["transfer"]).get("moved_on"):
                    rec["state"] = "refused"
                    return {"status": 409, "outcome": "refused", "reason": "funds_moved"}
            except world.WorldError:
                pass
        if act["state"] in ("held", "deferred", "pending"):
            if "lets_held_action_land" not in self.flaws:
                self.store["queue"] = [j for j in self.store["queue"] if j["id"] != act["id"]]
            act["state"] = "reversed"
            rec["state"] = "reversed"
            return {"status": 200, "outcome": "reversed", "reason": "cancelled_before_commit"}
        if "marks_only" in self.flaws:
            act["state"] = rec["state"] = "reversed"
            return {"status": 200, "outcome": "reversed"}
        if "async_dropped" in self.flaws:
            return {"status": 202, "outcome": "accepted"}
        if "slow_reversal" in self.flaws or self.kind == "slow-good" or \
                "accepts_then_drops" in self.flaws:
            delay = {"slow_reversal": 1.5 * R_S, "accepts_then_drops": 1.0}.get(
                self.flaw or "", 0.6 * R_S)
            self._queue({"kind": "reverse", "id": act["id"], "due": self.now() + delay,
                         "rec": rec["request_id"], "steps_done": []}, durable=True)
            rec["state"] = "pending"
            return {"status": 202, "outcome": "accepted"}
        job = {"kind": "reverse", "id": act["id"], "due": self.now(), "rec": rec["request_id"],
               "steps_done": []}
        return self._run_reverse(act, rec, job, first=True)

    def _reverse_job(self, act: Dict[str, Any], job: Dict[str, Any]) -> None:
        rec = self.store["by_request"].get(job["rec"]) or {}
        if "accepts_then_drops" in self.flaws:
            claim = self._claim_for_action(act) or {}
            secs = (claim.get("window") or {}).get("seconds")
            if secs is not None and self.now() - (act.get("committed_at") or 0) > secs:
                act["state"] = rec["state"] = "reversed"
                return
        self._run_reverse(act, rec, job, first=False)

    def _steps(self, act: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        op, refs, prior = act["op"], act["refs"], act["prior"]
        if op == "crm.contact.create":
            return [("delete", {"object_id": refs["objects"][0]})]
        if op == "crm.contacts.import":
            objs = refs["objects"]
            if "partial_items" in self.flaws:
                objs = objs[:-1]
            return [("delete", {"object_id": o}) for o in objs]
        if op == "crm.contact.update":
            oid = refs["objects"][0]
            if "update_as_delete" in self.flaws:
                return [("delete", {"object_id": oid})]
            if "object_only" in self.flaws:
                return []
            return [("update", {"object_id": oid, "fields": dict(prior["fields"])})]
        if op == "crm.contact.archive":
            oid = refs["objects"][0]
            if "recreates_new_id" in self.flaws:
                return [("recreate", {"oid": oid})]
            steps = [("restore", {"object_id": oid})]
            if "object_only" not in self.flaws:
                steps += [("link", {"src": s, "dst": d}) for s, d in prior.get("edges") or []]
            return steps
        if op == "mail.send":
            return [("recall", {"message_id": refs["mail"]})]
        if op == "ledger.transfer":
            t = self.w.read(kind="transfer", eid=refs["transfer"])
            amount = t["amount"] - 1 if "compensates_wrong" in self.flaws else t["amount"]
            steps = [("transfer", {"frm": t["to"], "to": t["from"], "amount": amount,
                                   "memo": f"refund {refs['transfer']}"})]
            if "compensates_with_notice" in self.flaws:
                steps.append(("deliver", {"to": "billing@d.example", "subject": "refund",
                                          "body": f"refunded {refs['transfer']}"}))
            return steps
        if op == "topic.publish":
            return [("retract", {"item_id": refs["item"]})]
        return []

    def _run_reverse(self, act: Dict[str, Any], rec: Dict[str, Any], job: Dict[str, Any], *,
                     first: bool) -> Dict[str, Any]:
        from conformance import world
        if self.w is None:
            act["state"] = rec["state"] = "reversed"
            return {"status": 200, "outcome": "reversed"}
        steps = self._steps(act)
        for i, (call, kw) in enumerate(steps):
            if i in job["steps_done"]:
                continue
            try:
                if call == "recreate":
                    pr = act["prior"]
                    new = self.w.create(fields=pr["fields"], email=pr.get("email"))["id"]
                    for s, d in pr.get("edges") or []:
                        self.w.link(src=new if s == kw["oid"] else s,
                                    dst=new if d == kw["oid"] else d)
                else:
                    self.w.call(call, **kw)
                job["steps_done"].append(i)
            except world.Refused as e:
                if e.code == "refused_item" and "reports_done_on_partial" in self.flaws:
                    job["steps_done"].append(i)
                    continue
                if e.code == "refused_item":
                    return self._requeue(act, rec, job, first)
                if "claims_unconditional" in self.flaws:
                    job["steps_done"].append(i)
                    continue
                rec["state"] = "refused"
                return {"status": 409, "outcome": "refused", "reason": e.code}
            except world.WorldError:
                if "done_on_world_error" in self.flaws:
                    act["state"] = rec["state"] = "reversed"
                    return {"status": 200, "outcome": "reversed"}
                if "forgets_queued" in self.flaws:
                    rec["state"] = "accepted"
                    return {"status": 202, "outcome": "accepted"}
                return self._requeue(act, rec, job, first)
        if "notifies_undeclared" in self.flaws:
            try:
                self.w.deliver(to="audit@b.example", subject="reversed", body=f"reversed {act['id']}")
            except world.WorldError:
                pass
        act["state"] = rec["state"] = "reversed"
        return {"status": 200, "outcome": "reversed"}

    def _requeue(self, act: Dict[str, Any], rec: Dict[str, Any], job: Dict[str, Any],
                 first: bool) -> Dict[str, Any]:
        rec["state"] = "pending"
        job["due"] = self.now() + 1.0
        self._queue(job, durable=True)
        return {"status": 202, "outcome": "pending"}

    def classify_reversal(self, ans: Dict[str, Any]) -> str:
        o = (ans or {}).get("outcome")
        return o if o in ("reversed", "accepted", "pending", "partial", "refused") else "error"

    def refusal_reason(self, ans: Dict[str, Any]) -> Dict[str, Any]:
        return {"code": (ans or {}).get("reason"), "text": (ans or {}).get("reason")}

    def reversal_status(self, p: Any) -> Dict[str, Any]:
        import json
        rid = json.loads(p.request).get("request_id")
        rec = self.store["by_request"].get(rid)
        if rec is None:
            return {"outcome": "refused", "reason": "unknown"}
        return {"outcome": rec["state"] if rec["state"] in ("reversed", "pending", "refused",
                                                            "accepted") else "pending"}

    def b_record(self, p: Any) -> Dict[str, Any]:
        from conformance import authz
        aid = (authz.claims_of(p.authorisation) or {}).get("authorisation_id")
        act = self.store["actions"].get(aid) or {}
        return {"state": act.get("state"), "authorisation_id": aid}

    # operator hooks ---------------------------------------------------------------------------

    def operator_reverse(self, p: Any) -> Dict[str, Any]:
        from conformance import authz
        aid = (authz.claims_of(p.authorisation) or {}).get("authorisation_id")
        act = self.store["actions"][aid]
        rec = {"id": aid, "state": "accepted", "request_id": f"op-{secrets.token_hex(4)}",
               "t": self.now()}
        self.store["reversals"][aid] = rec
        self.store["by_request"][rec["request_id"]] = rec
        job = {"kind": "reverse", "id": aid, "due": self.now(), "rec": rec["request_id"],
               "steps_done": []}
        state = act["state"]
        out = self._run_reverse(act, rec, job, first=True)
        if "operator_silent" in self.flaws:
            act["state"] = state
        return out

    def operator_set_claim(self, op: str, claim: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        self.cat = [c for c in self.cat if c["operation"] != op] + ([copy.deepcopy(claim)]
                                                                     if claim else [])
        return {"operation": op, "set": bool(claim)}

    def read_claims(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.cat)

    def present_withdrawal(self, token: str) -> Dict[str, Any]:
        import json
        from conformance import receipts
        claims = json.loads(receipts._b64d(token.split(".")[1]))
        if claims.get("issuer") == self.home:
            self.withdrawn.add(claims.get("agent"))
        return {"status": 200}

    def agent_withdrawn(self, agent: str) -> bool:
        return agent in self.withdrawn

    def restart(self) -> Dict[str, Any]:
        before = self.boot
        self.boot = secrets.token_hex(4)
        self.mem_queue = []
        self.stop()
        self._arm()
        return {"before": before, "after": self.boot, "how": "in-process re-initialisation; the "
                "store survives, memory does not"}


def make(flaw: str) -> ToyReversal:
    return ToyReversal("good", flaw)


def toy(config: str) -> ToyReversal:
    if config.startswith("bad:"):
        return make(config[4:])
    return ToyReversal(config)
