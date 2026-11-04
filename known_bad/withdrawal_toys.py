"""Known-bad and known-good toy B's for P19 (KRK-19, withdrawal within T).

One toy B with a real recorder path and a status fetcher (design §4.7). It verifies A's grant and
the per-request authorisation (signed by the agent's key under the grant, or by A itself), then
checks the grant chain's status against the snapshots it fetched from the stub A's source, then
performs the effect by POSTing the request's values to the kit's recorder. Its status poller runs
on the probe's clock (`timing.VirtualClock` in the known-bad gate, so a run at T = 60 s takes
seconds; `timing.RealClock` in the real-time smoke test, where it fetches over HTTP).

``good`` polls every T/4 and refuses once its status is older than T/2 (age from the earlier of
the snapshot's issue time and the moment it fetched it, so a fast issuer clock never makes a
snapshot younger, and a stale one served late never looks fresh); fails closed with no status;
recovers when the source returns; checks every hop and every principal's standing; enforces a
narrowed ceiling; re-checks before retrying a held effect; checks status for requests A signed
itself; keys status per grant; never takes an older snapshot version than one it has seen; keeps
its status in a store that survives a restart; reads a grant absent from its snapshot as
`status.chain_state` does: not yet listed, so accepted until its next fetch, when
A signed the snapshot before the grant, and unknown, so refused, when A signed it after; and
reads a principal missing from a snapshot that lists its grant as unknown. It must
pass.

One flaw per row of design §3.1, each failing its variant (`FAILS`); some fail more than one, as
X3's did, and the tests say which:

| Flaw | What it does | Variant it fails |
|---|---|---|
| `caches_decision` | caches an accepted grant's verdict for 3T from its first acceptance | `withdrawn` |
| `long_tail_poll` | polls at a mean of T/2 with a long gap (four of T/10, one of 2.1T), no age limit | `withdrawn` (the maximum over trials; KRK-M53) |
| `checks_at_session_start` | checks status when a session opens, not on each request in it | `same_session` |
| `fails_open` | on a fetch error keeps its last list however old, or accepts with none | `source_unreachable` |
| `stuck_closed` | refuses everything after any fetch error, for good | `recovery` |
| `leaf_only` | checks the presented grant's status, never its parents' | `parent_withdrawn` |
| `grant_status_only` | ignores the principal's standing (reads every principal as standing) | `standing_withdrawn` |
| `binary_status` | knows only revoked or not: a narrowed grant reads as valid | `narrowed` |
| `checks_on_arrival_only` | retries a held effect without checking again | `in_flight` |
| `signature_and_expiry_only` | for a request A signed itself, checks only signature and expiry | `presigned_after_withdrawal` |
| `status_by_subject` | keys status on the agent acting for a principal, so a newer grant's status stands for the older one | `regrant` |
| `trusts_snapshot_signature` | takes any snapshot A signed, stapled or served, whatever its age | `stale_signed_snapshot` |
| `accepts_rollback` | takes an older snapshot version than one it has seen | `stale_signed_snapshot` (``rollback``) |
| `trusts_issuer_time` | judges age, and when to fetch, by A's issue time alone | `skewed_issuer_clock` |
| `forgets_on_restart` | keeps status in memory only, and accepts until its first fetch after a restart | `restart_after_refusal` |
| `flaps` | two pollers write one cache, one through a mirror T/2 behind | `flapped` (``withdrawn``) |
| `no_check` | never checks status at all (also ``bad``) | `withdrawn` |
| `slow_and_late` | acts on a withdrawal only 1.2 T after it learns of it, and answers slowly (accepted 0.4 T, refused 0.1 T) | `withdrawn` (through the boundary presentation; KRK-M48) |
| `recovers_late` | after an outage, refuses for 0.75 T more once the source is back | `recovery` (``recovered_late``) |

``no-control``: the executor posts to a path that is not the recorder's, so the control cannot
hold.

``slow-good`` is the correct toy answering slowly, as a receiver on a slow host does: every
decision, and its effect, is made when the request arrives, and the answer comes 0.6 T later for
an acceptance and 0.1 T later for a refusal. It must pass. A probe that waited for each answer
before sending the next would space its presentations by the answer time, and its brackets
would cross T (KRK-M48).

Every toy states a recovery bound of T/2 (`withdrawal_bound`); the correct one recovers at its
next poll, within T/4.

**Slow answers on a virtual clock.** `present_deferred` decides at once and hands the answer to
the kit's `deliver` after the toy's answer delay, through the clock's own scheduler, so the kit
reads the answer time from its clock as it would from a real B. On the real clock `present`
sleeps for the delay instead.
"""
from __future__ import annotations

import http.client
import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

FLAWS = ("caches_decision", "long_tail_poll", "checks_at_session_start", "fails_open",
         "stuck_closed", "leaf_only", "grant_status_only", "binary_status",
         "checks_on_arrival_only", "signature_and_expiry_only", "status_by_subject",
         "trusts_snapshot_signature", "accepts_rollback", "trusts_issuer_time",
         "forgets_on_restart", "flaps", "no_check", "slow_and_late", "recovers_late")
FAILS = {"caches_decision": "withdrawn", "long_tail_poll": "withdrawn",
         "checks_at_session_start": "same_session", "fails_open": "source_unreachable",
         "stuck_closed": "recovery", "leaf_only": "parent_withdrawn",
         "grant_status_only": "standing_withdrawn", "binary_status": "narrowed",
         "checks_on_arrival_only": "in_flight",
         "signature_and_expiry_only": "presigned_after_withdrawal",
         "status_by_subject": "regrant", "trusts_snapshot_signature": "stale_signed_snapshot",
         "accepts_rollback": "stale_signed_snapshot", "trusts_issuer_time": "skewed_issuer_clock",
         "forgets_on_restart": "restart_after_refusal", "flaps": "withdrawn",
         "no_check": "withdrawn", "slow_and_late": "withdrawn", "recovers_late": "recovery"}
"""The variant each flaw is built to fail (it may fail others too)."""
PARTY = "did:web:b.example"
NO_AGE = ("long_tail_poll", "fails_open", "trusts_snapshot_signature", "flaps")
"""Flaws that apply no age limit to the status they hold."""
SLOW = {"executed": 0.6, "refused": 0.1}
"""``slow-good``: answer delays, as fractions of T, by B's answer code."""
SLOW_LATE = {"executed": 0.4, "refused": 0.1}
"""``slow_and_late``: answer delays, as fractions of T."""
LATE_BY = 1.2
"""``slow_and_late`` acts on a withdrawal only this many T after it first sees it."""
RECOVERY_HOLD = 0.75
"""``recovers_late`` keeps refusing this many T after the source is back."""


class ToyWithdrawal:
    """A B that accepts requests under A's grants (P19's role-B adapter, in process)."""

    name = "toy-withdrawal"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *, T: float = 60.0,
                 clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "no_check"
        if flaw is not None and flaw not in FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.config = config if flaw is None else f"bad:{flaw}"
        self.flaw = flaw
        self.delays = SLOW if config == "slow-good" else SLOW_LATE if flaw == "slow_and_late" \
            else {}
        self.no_control = config == "no-control"
        self.T = float(T)
        self.clock = clock
        self._clock: Any = None
        self.anchor: Dict[str, Any] = {}
        self.source_url = ""
        self.recorder = ""
        self.boot = secrets.token_hex(4)
        self.store: Dict[str, Any] = {"snap": None, "fetched_at": None, "max_version": 0,
                                      "dead": False, "outage": False, "back_at": None}
        """What survives a restart (a real B's database)."""
        self.mem: Dict[str, Any] = {"snap": None, "fetched_at": None}
        self.verdicts: Dict[str, float] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.latest: Dict[Tuple[str, str, str], int] = {}
        self.grants: Dict[str, Dict[str, Any]] = {}
        self._polls: List[int] = []
        self._tail = 0
        self._mirror: List[Tuple[float, Dict[str, Any]]] = []
        self.fetch_errors = 0

    # kit plumbing ---------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-withdrawal {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P19": f"toy: 'a withdrawal takes effect within {self.T:g} seconds'"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        self._stop_polls()

    def role(self) -> str:
        return "B"

    def withdrawal_bound(self) -> Dict[str, Any]:
        return {"T_s": self.T, "statistic": "max", "source": "documented",
                "quote": f"toy: 'a withdrawal takes effect within {self.T:g} seconds'",
                "url": "known_bad/withdrawal_toys.py", "setting": "", "recovery_s": self.T / 2,
                "clock_tolerance_s": 5.0, "resolution_s": 0.001}

    def channels(self) -> List[str]:
        return ["pull-list"]

    def presentation_forms(self) -> List[str]:
        return ["agent", "a-presigned"]

    def status_profile(self) -> Optional[str]:
        return "kirkaldy"

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": PARTY, "endpoints": ["e1", "e2"], "tenants": [],
                "max_validity_s": 3600}

    def evidence_grade(self) -> str:
        return "recorder"

    def set_clock(self, clock: Any) -> None:
        self._clock = clock

    def _c(self) -> Any:
        if self._clock is None:
            from conformance.timing import RealClock
            self._clock = RealClock()
        return self._clock

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        self.anchor = anchor
        self.source_url = source_url
        self._fetch()
        self._start_polls()
        return f"pinned {sorted(anchor.get('keys', {}))}; polling {source_url}"

    def bind_recorder(self, recorder_url: str) -> str:
        self.recorder = recorder_url.rstrip("/")
        return f"effects to {self.recorder}/effect/<id>"

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "accepted", "queued": "in-progress",
                "refused": "refused"}.get(code, "error")

    def reached_guarantee(self, variant: str, answer: Dict[str, Any]) -> bool:
        return True

    def restart(self) -> Dict[str, Any]:
        before = self.boot
        self._stop_polls()
        self.boot = secrets.token_hex(4)
        self.mem = {"snap": None, "fetched_at": None}
        self.verdicts.clear()
        self.sessions.clear()
        self._start_polls(fetch_first=self.flaw != "forgets_on_restart")
        return {"before": before, "after": self.boot, "how": "in-process restart: memory "
                "cleared, the store kept"}

    # the poller -----------------------------------------------------------------------------

    def _interval(self) -> float:
        if self.flaw == "long_tail_poll":
            self._tail += 1
            return 2.1 * self.T if self._tail % 5 == 0 else 0.1 * self.T
        return self.T / 4.0

    def _start_polls(self, fetch_first: bool = False) -> None:
        c = self._c()
        if fetch_first:
            self._fetch()
        if self.flaw == "trusts_issuer_time":
            self._polls.append(c.call_every(lambda: self.T / 8.0, self._maybe_fetch))
        else:
            self._polls.append(c.call_every(self._interval, self._fetch))
        if self.flaw == "flaps":
            first = [True]

            def lagged() -> float:                       # out of step: half a period later
                if first[0]:
                    first[0] = False
                    return self.T / 8.0
                return self.T / 4.0
            self._polls.append(c.call_every(lagged, self._mirror_fetch))

    def _stop_polls(self) -> None:
        c = self._clock
        for h in self._polls:
            if c is not None:
                c.cancel(h)
        self._polls = []

    def _get(self) -> Tuple[int, str]:
        from conformance import requester
        src = requester.local_source(self.source_url)
        if self.clock == "virtual" and src is not None:
            return src.fetch_local("/status/list", client=f"toy-{self.boot}")
        try:
            with urllib.request.urlopen(self.source_url, timeout=max(0.2, self.T / 8)) as r:
                return r.status, r.read().decode("ascii")
        except urllib.error.HTTPError as e:
            return e.code, ""

    def _fetch(self) -> None:
        from conformance import status
        try:
            code, tok = self._get()
        except Exception:  # noqa: BLE001 - refused, hung: a fetch error
            code, tok = 0, ""
        claims = None
        if code == 200:
            v = status.verify(tok, self._pinned(), status.STATUS_TYP)
            claims = v.claims if v.ok else None
        if claims is None:
            self.fetch_errors += 1
            self.store["outage"] = True
            if self.flaw == "stuck_closed":
                self.store["dead"] = True
            return
        if self.store["outage"]:
            self.store.update(outage=False, back_at=self._c().now())
        if self.flaw != "accepts_rollback" and claims["version"] < self.store["max_version"]:
            return                                          # an older version: never taken
        self._take(claims)

    def _take(self, claims: Dict[str, Any]) -> None:
        now = self._c().wall()
        if self.flaw == "slow_and_late":
            seen = self.__dict__.setdefault("seen", {})
            for gid, e in claims["entries"].items():
                if e["state"] != "valid":
                    seen.setdefault(gid, self._c().now())     # when it learned of it
        self.store["max_version"] = max(self.store["max_version"], claims["version"])
        if self.flaw == "forgets_on_restart":
            self.mem.update(snap=claims, fetched_at=now)
        else:
            self.store.update(snap=claims, fetched_at=now)
        if self.flaw == "flaps":
            self._mirror.append((self._c().now(), claims))

    def _mirror_fetch(self) -> None:
        """`flaps`: the second poller reads a mirror half a T behind the source."""
        lag = self.T / 2.0
        old = [c for t, c in self._mirror if t <= self._c().now() - lag]
        if old:
            self.store.update(snap=old[-1], fetched_at=self._c().wall())

    def _maybe_fetch(self) -> None:
        """`trusts_issuer_time`: fetch only when A's issue time says the list is old."""
        snap = self.store["snap"]
        if snap is None or self._issuer_age(snap) > self.T / 4.0:
            self._fetch()

    def _pinned(self) -> Dict[str, bytes]:
        return {k: bytes(v) for k, v in (self.anchor.get("keys") or {}).items()}

    # status -----------------------------------------------------------------------------

    def _snap(self) -> Tuple[Optional[Dict[str, Any]], Optional[float]]:
        if self.flaw == "forgets_on_restart":
            return self.mem["snap"], self.mem["fetched_at"]
        return self.store["snap"], self.store["fetched_at"]

    def _issuer_age(self, snap: Dict[str, Any]) -> float:
        from conformance import status
        return self._c().wall() - status.epoch_of(snap["issued_at"])

    def _age(self, snap: Dict[str, Any], fetched_at: float) -> float:
        from conformance import status
        if self.flaw == "trusts_issuer_time":
            return self._issuer_age(snap)
        if self.flaw == "flaps":
            return self._c().wall() - fetched_at
        return self._c().wall() - min(status.epoch_of(snap["issued_at"]), fetched_at)

    def _status(self, chain: List[Dict[str, Any]], values: Dict[str, Any],
                staple: Optional[str]) -> Optional[str]:
        """None if the chain is in force for these values, else why not."""
        from conformance import status
        if self.flaw == "no_check":
            return None
        if self.store.get("dead"):
            return "status-unavailable"
        back = self.store.get("back_at")
        if self.flaw == "recovers_late" and back is not None \
                and self._c().now() - back < RECOVERY_HOLD * self.T:
            return "status-unavailable"
        snap, fetched_at = self._snap()
        if self.flaw == "trusts_snapshot_signature" and staple:
            v = status.verify(staple, self._pinned(), status.STATUS_TYP)
            if v.ok:
                snap, fetched_at = v.claims, self._c().wall()
        if snap is None:
            if self.flaw in ("forgets_on_restart", "fails_open"):
                return None                                  # nothing known: accept
            return "status-unavailable"
        if self.flaw not in NO_AGE and self._age(snap, fetched_at) > self.T / 2.0:
            return "status-stale"
        # A grant absent from the snapshot is read by `status.chain_state`: not
        # yet listed, so in force until the next fetch, if A signed the snapshot before the
        # grant; unknown, so refused, if A signed it after.
        view = {"issued_at": snap.get("issued_at"), "expires_at": snap.get("expires_at"),
                "entries": dict(snap.get("entries") or {}),
                "standing": dict(snap.get("standing") or {})}
        if self.flaw == "grant_status_only":
            # Every principal reads as standing. Not by dropping the section: under the rule
            # (KRK-M47) a principal missing from a snapshot that lists its grant reads unknown, so an
            # empty section would make this toy refuse everything, not ignore standing
            # (KRK-M47).
            view["standing"] = {**{p: "standing" for p in view["standing"]},
                                **{g["principal"]: "standing" for g in chain}}
        if self.flaw == "status_by_subject":
            g = chain[0]
            key = (g["subject"], g["operation"], g["principal"])
            newest = self.grants.get(self.latest.get(key, ""), g)
            chain = [newest] + chain[1:]
        if self.flaw == "binary_status":
            view["entries"] = {k: ({"state": "valid", "ceiling": None}
                                   if e["state"] == "narrowed" else e)
                               for k, e in view["entries"].items()}
        use = chain[:1] if self.flaw == "leaf_only" else chain
        st = status.chain_state(view, use)
        if st["state"] not in status.IN_FORCE:
            first = self.__dict__.get("seen", {}).get(chain[0]["grant_id"])
            if self.flaw == "slow_and_late" and first is not None \
                    and self._c().now() - first < LATE_BY * self.T:
                return None                                  # not yet acted on
            return f"withdrawn: {st['why']}"
        over = status.within(values, st["ceiling"])
        return f"over-ceiling: {over}" if over else None

    # the entry point ------------------------------------------------------------------------

    def _read(self, p: Any) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]],
                                     Optional[Dict[str, Any]], bool]:
        """(why refused, chain, values, A-signed?) from one presentation's bytes and headers."""
        from conformance import authz, requester, status
        pinned = self._pinned()
        g = status.verify(p.headers.get(requester.GRANT_HEADER), pinned, status.GRANT_TYP)
        if not g.ok:
            return f"grant {g.reason}", None, None, False
        chain = [g.claims]
        for tok in [t for t in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if t]:
            v = status.verify(tok, pinned, status.GRANT_TYP)
            if not v.ok or v.claims["grant_id"] != chain[-1]["parent"]:
                return "grant chain does not verify", None, None, False
            chain.append(v.claims)
        if chain[-1]["parent"] is not None:
            return "grant chain is incomplete", None, None, False
        gc = chain[0]
        claims = authz.claims_of(p.authorisation) or {}
        a_signed = claims.get("issuer") == self.anchor.get("issuer")
        if a_signed:
            v = authz.verify_authorisation(p.authorisation, pinned)
        else:
            ak = gc["agent_key"]
            v = authz.verify_authorisation(p.authorisation, {ak["kid"]: bytes.fromhex(
                ak["public_key"])})
            if v.ok and v.claims["issuer"] != gc["subject"]:
                return "not signed by the grant's agent", None, None, False
        if not v.ok:
            return f"authorisation {v.reason}", None, None, False
        c = v.claims
        if c.get("grant_id") != gc["grant_id"] or c["audience"]["counterparty"] != PARTY \
                or gc["audience"] != PARTY:
            return "not under this grant, or not for this B", None, None, False
        if c["binding"]["request_digest"] != authz.binding_digest(p.request):
            return "payload-mismatch", None, None, False
        now = self._c().wall()
        if not (authz.epoch(c["not_before"]) - 5 <= now <= authz.epoch(c["not_after"]) + 5):
            return "expired", None, None, False
        if not (status.epoch_of(gc["not_before"]) - 5 <= now <= status.epoch_of(
                gc["not_after"]) + 5):
            return "grant expired", None, None, False
        values = json.loads(p.request.decode("utf-8"))
        if values.get("operation") != gc["operation"]:
            return "operation-mismatch", None, None, False
        over = status.within(values, gc["ceiling"])
        if over:
            return f"over-ceiling: {over}", None, None, False
        for x in chain:
            self.grants[x["grant_id"]] = x
        key = (gc["subject"], gc["operation"], gc["principal"])
        if gc["status"]["index"] >= self.grants.get(self.latest.get(key, ""), {}).get(
                "status", {}).get("index", -1):
            self.latest[key] = gc["grant_id"]
        return None, chain, values, a_signed

    def open_session(self, grant_token: str, endpoint: str) -> Optional[str]:
        from conformance import status
        g = status.verify(grant_token, self._pinned(), status.GRANT_TYP)
        if not g.ok:
            return None
        sid = f"s-{secrets.token_hex(4)}"
        chain = [g.claims]
        while chain[-1]["parent"] and chain[-1]["parent"] in self.grants:
            chain.append(self.grants[chain[-1]["parent"]])
        why = self._status(chain, {"amount": 0}, None)
        self.sessions[sid] = {"grant_id": g.claims["grant_id"], "ok": why is None}
        return sid

    def _delay(self, ans: Dict[str, Any]) -> float:
        code = (ans.get("body") or {}).get("code") if isinstance(ans, dict) else None
        return self.delays.get(code, 0.0) * self.T

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        ans = self._decide(p, session)
        if self.delays and self.clock == "real":
            import time
            time.sleep(self._delay(ans))
        return ans

    def present_deferred(self, p: Any, session: Optional[str], deliver: Any) -> None:
        """Decide now (the effect, if any, is committed now) and answer after the toy's delay
        on the virtual clock (see the module docstring)."""
        ans = self.present(p, session=session)
        d = self._delay(ans)
        if d <= 0:
            deliver(ans)
            return
        c = self._c()
        c.call_at(c.now() + d, lambda: deliver(ans))

    def _decide(self, p: Any, session: Optional[str]) -> Dict[str, Any]:
        from conformance import requester
        why, chain, values, a_signed = self._read(p)
        if why:
            return _answer("refused", why)
        gid = chain[0]["grant_id"]
        now = self._c().now()
        skip = False
        if self.flaw == "caches_decision" and gid in self.verdicts \
                and now - self.verdicts[gid] <= 3 * self.T:
            skip = True
        if self.flaw == "checks_at_session_start" and session in self.sessions \
                and self.sessions[session]["grant_id"] == gid and self.sessions[session]["ok"]:
            skip = True
        if self.flaw == "signature_and_expiry_only" and a_signed:
            skip = True
        if not skip:
            why = self._status(chain, values, p.headers.get(requester.STAPLE_HEADER))
            if why:
                return _answer("refused", why)
        if self.flaw == "caches_decision":
            self.verdicts.setdefault(gid, now)
        return self._effect(chain, values)

    def _effect(self, chain: List[Dict[str, Any]], values: Dict[str, Any], *,
                retry: bool = False) -> Dict[str, Any]:
        url = (f"{self.recorder}/effect/{secrets.token_hex(6)}" if not self.no_control
               else f"{self.recorder.rsplit('/p19/', 1)[0]}/elsewhere/{secrets.token_hex(4)}")
        try:
            code, headers = _KEEP.post(url, json.dumps(values).encode("utf-8"))
        except Exception as e:  # noqa: BLE001
            return _answer("refused", f"effect failed: {type(e).__name__}")
        if code == 503:
            wait = float(headers.get("retry-after") or 5)
            c = self._c()
            c.call_at(c.now() + wait, lambda: self._retry(chain, values))
            return _answer("queued", f"held; retry in {wait:g} s")
        if code != 200:
            return _answer("refused", f"effect failed {code}")
        return _answer("executed", "performed")

    def _retry(self, chain: List[Dict[str, Any]], values: Dict[str, Any]) -> None:
        if self.flaw != "checks_on_arrival_only" and self._status(chain, values, None):
            return                                               # withdrawn since: dropped
        self._effect(chain, values, retry=True)


class _KeepAlive:
    """One kept-alive connection per host to the recorder, so a run of thousands of effects is
    not thousands of TCP handshakes. A request is sent again only if the connection failed
    before it was sent (a closed idle connection), never after."""

    def __init__(self) -> None:
        self.conns: Dict[str, http.client.HTTPConnection] = {}
        self.lock = threading.Lock()

    def post(self, url: str, body: bytes) -> Tuple[int, Dict[str, str]]:
        u = urllib.parse.urlsplit(url)
        with self.lock:
            for attempt in (1, 2):
                c = self.conns.get(u.netloc)
                if c is None:
                    c = self.conns[u.netloc] = http.client.HTTPConnection(
                        u.hostname, u.port, timeout=10)
                try:
                    c.request("POST", u.path, body=body,
                              headers={"Content-Type": "application/json"})
                except (ConnectionError, http.client.HTTPException, OSError):
                    c.close()
                    self.conns.pop(u.netloc, None)
                    if attempt == 2:
                        raise
                    continue
                try:
                    r = c.getresponse()
                    r.read()
                except Exception:
                    c.close()
                    self.conns.pop(u.netloc, None)
                    raise
                return r.status, {k.lower(): v for k, v in r.getheaders()}
        raise RuntimeError("unreachable")


_KEEP = _KeepAlive()


def _answer(code: str, reason: str) -> Dict[str, Any]:
    status = {"executed": 200, "queued": 202, "refused": 403}[code]
    return {"status": status, "body": {"code": code, "reason": reason}}


def make(flaw: Optional[str] = None, **kw: Any) -> ToyWithdrawal:
    return ToyWithdrawal("bad" if flaw else "good", flaw, **kw)
