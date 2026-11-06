"""A synthetic receiver B that authorises at dispatch only, for P19 (KRK-19, role B).

No product is tested. The receiver is written for this example and runs in this process on
the kit's real clock (P19 lets only the kit's own toys use a virtual clock). It is loaded from
outside the kit's tree through ``KIRKALDY_TARGETS_PATH``, so nothing is added to ``targets/``,
``conformance/`` or ``known_bad/``.

**What the receiver does with one request** (`present`):

1. Verifies A's grant, its chain and the per-request authorisation, as the kit's toys do (the
   kit's own format readers in `conformance.status` and `conformance.authz`).
2. **The dispatch check.** Fetches the grant's status from A's source (``/status/item/<grant
   id>``) at that moment, verifies the snapshot's signature, and reads the chain with
   `conformance.status.chain_state`. A withdrawn chain is refused. A fetch that fails, hangs past
   `FETCH_TIMEOUT_S` or does not verify is refused too (fail closed).
3. Dispatches the effect: one POST to the recorder.
4. If the recorder answers 503, B answers ``queued`` and retries later, after the recorder's
   ``Retry-After`` or `RETRY_CAP_S`, whichever is sooner, at most `MAX_ATTEMPTS` attempts in
   all. **The retry does not check status again.** Authorisation is decided once, at dispatch,
   and a request accepted for dispatch is carried through to its commit.

So a request presented after the withdrawal is refused at once (its dispatch check reads the
withdrawn status), and a request already accepted for dispatch when the withdrawal arrives
commits after it.

**Why the stated T is 10 s** (configuration ``stated-bound``). The longest an effect can commit
after the dispatch check that allowed it is the status fetch, then every attempt and every wait
between attempts: `FETCH_TIMEOUT_S` + `MAX_ATTEMPTS` x `POST_TIMEOUT_S` + (`MAX_ATTEMPTS` - 1) x
`RETRY_CAP_S` = 1 + 2 x 2 + 1 x 2 = 7 s. A withdrawal served just after the fetch that read
"valid" can therefore be followed by an effect under it for at most 7 s. The receiver states
T = 10 s, which covers that with 3 s to spare.

**The in-flight hold.** P19's ``in_flight`` variant has the recorder answer B's effect for the
request presented just before the withdrawal with 503 and ``Retry-After`` T + 5 s. That hold is
longer than T by construction: a receiver that waited the whole ``Retry-After`` before retrying
without a fresh check would commit after T and fail. This receiver caps its wait at
`RETRY_CAP_S` = 2 s, so the request is held in flight for about 2 s, and T = 10 s is longer than
that hold.

**The configurations** differ only in the bound the receiver states. Its mechanism, constants
and code path are the same in each, so the three runs see the same receiver.

| Configuration | Stated T | What it states |
|---|---|---|
| ``stated-bound`` | 10 s | no effect under a withdrawn authorisation later than 10 s after the withdrawal is served |
| ``valid-at-commit-zero`` | 0 s | no effect commits under an authorisation that is not valid at the moment of commit |
| ``valid-at-commit`` | 0.001 s | the same, written as the smallest positive bound at the receiver's stated timestamp resolution (1 ms) |

Evidence grade: ``recorder`` (spec §3.8, the highest of KRK-19's four grades): every effect is
the recorder's commit, timed on the kit's clock.

This adapter states no claim basis (`not_claimed`, `claim_basis`): the runs are development
runs of one variant, and the bound the probe grades is the one `withdrawal_bound` states.
"""
from __future__ import annotations

import json
import secrets
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

CONFIGS = ["stated-bound", "valid-at-commit-zero", "valid-at-commit"]
PARTY = "did:web:b.example"
"""B's own id in the agreement (the kit's stub A addresses its grants to it)."""

FETCH_TIMEOUT_S = 1.0
"""The dispatch check's status fetch; a fetch that takes longer is a refusal."""
POST_TIMEOUT_S = 2.0
"""One attempt to commit an effect at the recorder."""
RETRY_CAP_S = 2.0
"""The longest B waits before retrying a held effect, whatever ``Retry-After`` asks."""
MAX_ATTEMPTS = 2
"""Attempts per effect, the first included; after the last, the effect is dropped."""
MAX_LAG_S = FETCH_TIMEOUT_S + MAX_ATTEMPTS * POST_TIMEOUT_S + (MAX_ATTEMPTS - 1) * RETRY_CAP_S
"""The longest an effect can commit after the dispatch check that allowed it: 7 s."""

BOUNDS: Dict[str, Tuple[float, str]] = {
    "stated-bound": (10.0, "B commits no effect under a withdrawn authorisation later than 10 s "
                           "after the withdrawal is served by A's status source."),
    "valid-at-commit-zero": (0.0, "B commits no effect under an authorisation that is not valid "
                                  "at the moment the effect commits."),
    "valid-at-commit": (0.001, "B commits no effect under an authorisation that is not valid at "
                               "the moment the effect commits (stated as 0.001 s, the smallest "
                               "bound at B's timestamp resolution)."),
}
LOCATION = "examples/krk19-dispatch-only/adapters/dispatch_only/adapter.py (BOUNDS)"


class DispatchOnly:
    """Role B for P19, in process, on the real clock."""

    name = "dispatch-only"
    clock = "real"

    def __init__(self, config: str) -> None:
        self.config = config
        self.T, self.quote = BOUNDS[config]
        self.anchor: Dict[str, Any] = {}
        self.item_base = ""
        self.recorder = ""
        self.timers: List[threading.Timer] = []
        self.lock = threading.Lock()

    # lifecycle and statements ---------------------------------------------------------------

    def start(self) -> None:
        pass

    def stop(self) -> None:
        with self.lock:
            timers, self.timers = self.timers, []
        for t in timers:
            t.cancel()

    def version(self) -> str:
        return f"dispatch-only receiver (example), {self.config}"

    def implements(self) -> List[str]:
        return ["P19"]

    def vendor_claims(self) -> Dict[str, str]:
        return {"P19": self.quote}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    # P19's adapter protocol -----------------------------------------------------------------

    def role(self) -> str:
        return "B"

    def withdrawal_bound(self) -> Dict[str, Any]:
        return {"T_s": self.T, "statistic": "max", "source": "documented", "quote": self.quote,
                "url": LOCATION, "setting": "", "recovery_s": 2.0, "clock_tolerance_s": 5.0,
                "resolution_s": 0.001}

    def channels(self) -> List[str]:
        return ["pull-item"]

    def presentation_forms(self) -> List[str]:
        return ["agent"]

    def status_profile(self) -> Optional[str]:
        return "kirkaldy"

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": PARTY, "endpoints": ["e1"], "tenants": [],
                "max_validity_s": 3600}

    def evidence_grade(self) -> str:
        return "recorder"

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        self.anchor = anchor
        self.item_base = source_url.rsplit("/status/list", 1)[0] + "/status/item/"
        return f"pinned {sorted(anchor.get('keys', {}))}; status read at dispatch from " \
               f"{self.item_base}<grant id>"

    def bind_recorder(self, recorder_url: str) -> str:
        self.recorder = recorder_url.rstrip("/")
        return f"effects to {self.recorder}/effect/<id>"

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "accepted", "queued": "in-progress",
                "refused": "refused"}.get(code, "error")

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        why, chain, values = self._read(p)
        if why:
            return _answer("refused", why)
        why = self._dispatch_check(chain, values)
        if why:
            return _answer("refused", why)
        return self._commit(values, attempt=1)

    # the receiver -------------------------------------------------------------------------

    def _pinned(self) -> Dict[str, bytes]:
        return {k: bytes(v) for k, v in (self.anchor.get("keys") or {}).items()}

    def _read(self, p: Any) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]],
                                     Optional[Dict[str, Any]]]:
        """(why refused, chain, values) from one presentation's bytes and headers."""
        from conformance import authz, requester, status
        pinned = self._pinned()
        g = status.verify(p.headers.get(requester.GRANT_HEADER), pinned, status.GRANT_TYP)
        if not g.ok:
            return f"grant {g.reason}", None, None
        chain = [g.claims]
        for tok in [t for t in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if t]:
            v = status.verify(tok, pinned, status.GRANT_TYP)
            if not v.ok or v.claims["grant_id"] != chain[-1]["parent"]:
                return "grant chain does not verify", None, None
            chain.append(v.claims)
        if chain[-1]["parent"] is not None:
            return "grant chain is incomplete", None, None
        gc = chain[0]
        ak = gc["agent_key"]
        v = authz.verify_authorisation(p.authorisation,
                                       {ak["kid"]: bytes.fromhex(ak["public_key"])})
        if not v.ok:
            return f"authorisation {v.reason}", None, None
        c = v.claims
        if c["issuer"] != gc["subject"]:
            return "not signed by the grant's agent", None, None
        if c.get("grant_id") != gc["grant_id"] or c["audience"]["counterparty"] != PARTY \
                or gc["audience"] != PARTY:
            return "not under this grant, or not for this B", None, None
        if c["binding"]["request_digest"] != authz.binding_digest(p.request):
            return "payload-mismatch", None, None
        values = json.loads(p.request.decode("utf-8"))
        if values.get("operation") != gc["operation"]:
            return "operation-mismatch", None, None
        over = status.within(values, gc["ceiling"])
        if over:
            return f"over-ceiling: {over}", None, None
        return None, chain, values

    def _dispatch_check(self, chain: List[Dict[str, Any]], values: Dict[str, Any]
                        ) -> Optional[str]:
        """The one status check: a fresh read of A's source when the request is accepted for
        dispatch. None if the chain is in force for these values, else why not."""
        from conformance import status
        try:
            with urllib.request.urlopen(self.item_base + chain[0]["grant_id"],
                                        timeout=FETCH_TIMEOUT_S) as r:
                tok = r.read().decode("ascii")
        except (urllib.error.URLError, OSError, ValueError) as e:
            return f"status-unavailable: {type(e).__name__}"
        v = status.verify(tok, self._pinned(), status.STATUS_TYP)
        if not v.ok:
            return f"status {v.reason}"
        st = status.chain_state(v.claims, chain)
        if st["state"] not in status.IN_FORCE:
            return f"withdrawn: {st['why']}"
        over = status.within(values, st["ceiling"])
        return f"over-ceiling: {over}" if over else None

    def _commit(self, values: Dict[str, Any], *, attempt: int) -> Dict[str, Any]:
        """One attempt to commit the effect at the recorder. No status check here."""
        req = urllib.request.Request(f"{self.recorder}/effect/{secrets.token_hex(6)}",
                                     data=json.dumps(values).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=POST_TIMEOUT_S) as r:
                code, retry_after = r.status, None
        except urllib.error.HTTPError as e:
            code, retry_after = e.code, e.headers.get("Retry-After")
        except (urllib.error.URLError, OSError) as e:
            return _answer("refused", f"effect failed: {type(e).__name__}")
        if code == 503 and attempt < MAX_ATTEMPTS:
            try:
                asked = float(retry_after) if retry_after is not None else RETRY_CAP_S
            except ValueError:
                asked = RETRY_CAP_S
            wait = min(asked, RETRY_CAP_S)
            t = threading.Timer(wait, self._commit, args=(values,),
                                kwargs={"attempt": attempt + 1})
            t.daemon = True
            with self.lock:
                self.timers.append(t)
            t.start()
            return _answer("queued", f"held by the recorder; retry in {wait:g} s without a "
                                     f"new status check")
        if code != 200:
            return _answer("refused", f"effect failed {code}")
        return _answer("executed", "performed")


def _answer(code: str, reason: str) -> Dict[str, Any]:
    http = {"executed": 200, "queued": 202, "refused": 403}[code]
    return {"status": http, "body": {"code": code, "reason": reason}}


def make(config: str = "stated-bound") -> DispatchOnly:
    if config not in CONFIGS:
        raise ValueError(f"unknown configuration {config!r}; one of {CONFIGS}")
    return DispatchOnly(config)
