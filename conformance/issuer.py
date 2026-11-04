"""The stub A for KRK-20 (P20) and KRK-21 (P21): X4's `requester.StubRequester`, extended.

`X1-STANDING-OFFLINE-DESIGN.md` §6.3 and `X5-NO-WIDENING-DESIGN.md` §6.3. `StubIssuer` subclasses
the X3/X4 stub, so every method P18 and P19 use is unchanged and `requester.py` is not edited. What it adds:

- **An anchor and a key statement** (`standing.KEYSET_SCHEMA`). The anchor is the one key B pins
  at bind and signs key statements only. The statement names A's operational keys and their
  purposes: the X3/X4 key (``self.key``) for ``grant``, ``status`` and ``request``, a
  standing key for ``standing``, and each of its agents' keys for ``request``, so a B that attributes a holder-signed hop by the key statement that lists its signing
  key finds C's agents at C. A new agent's key is published in a new statement
  version when it is first used (`agent`). `add_key`, `retire_key` and `revoke_key` publish a new statement
  version and return a `KeyChange` whose ``t_commit`` is the kit-clock moment the source serves
  it (``t_k``). `signing_with(kid)` makes later standing assertions use that key, retired or not, and `status_signing_with(kid)` the same for status snapshots.
- **Standing assertions** (`standing.STANDING_SCHEMA`): `assert_standing` signs one and makes it
  the principal's current assertion; the source re-signs a current assertion on a fetch that
  finds it older than ``ttl_s/10``, as X4's source re-issues its list. Every signing is in
  `standing_log` with its kit-clock time, and with ``broken`` naming the link a fixture breaks
  (None for valid evidence). `latest_delivered` derives ``t_f`` from that log joined to the fetch
  log and the staple log, never from the claims (KRK-M67, M68, M74).
- **Sources**: ``/keys`` and ``/standing/<principal>`` beside X4's ``/status/list`` and
  ``/status/item/<gid>``, with the baseline client on ``/__baseline/...`` paths B is never given.
  X4's outage modes (``down``, ``hang``, ``error``) apply to every path; ``partition`` fails only
  B's paths (the agent and the baseline still reach A); `serve_standing_to_b` serves B one older
  assertion's original bytes while the baseline reads the current one (``stale``, per principal).
- **Other organisations** (`peer`): A′, A2 or C, each with its own anchor, keys and source, on the
  same clock, sharing one registry of 0.2 grants with A so chains across organisations resolve.
- **Grant 0.2** (`attenuation.GRANT_V2_SCHEMA`): `issue_v2` (A-signed), `delegate_holder` (signed
  by the parent's agent key, with its status at the holder organisation's source), `delegate_v2`
  (never wider), `delegate_wider` (genuinely wider in one dimension), `cycle` (ids
  chosen before signing), `with_member` (a member written as a fixture needs). And grant 0.1
  fixtures X4's `issue` cannot build: `issue_v1` (chosen ids and parents, members left out).
- **Presentations** `under_v2` and `under_raw`: a fresh request signed by the leaf's agent key,
  the chain in X4's headers, and staples in `standing.STANDING_HEADER` / `KEYSET_HEADER`; a
  second chain in `GRANT2_HEADER` / `CHAIN2_HEADER` (X5 ``combined``).

**Never forge.** Everything is signed by the stub's own keys, its peers' or its agents'. Nothing
is re-signed, altered or backdated after signing; an older assertion is served as the bytes it
was signed as; a wider or malformed grant is one its signer genuinely issued. Every kit-clock time comes from ``clock``; `now()` (A's wall clock with its offset) is used
only for what it signs.
"""
from __future__ import annotations

import json
import secrets
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from . import attenuation, authz, receipts, requester, standing, status
from .authz import Presentation
from .receipts import Keypair
from .requester import ISSUER, OPERATION, StubRequester

GRANT2_HEADER = "KRK-Grant-2"
CHAIN2_HEADER = "KRK-Grant-Chain-2"
KEYS_PATH = "/keys"
STANDING_PATH = "/standing/"
BASELINE = "/__baseline"
CURRENCY = "EUR"
MINOR = 2
LIFETIME_S = 12 * 3600


@dataclass(frozen=True)
class Standing:
    """One standing assertion the stub (or, for ``self_attested``, an agent) signed."""

    serial: int
    principal: str
    classes: Dict[str, Any]
    token: str
    kid: str
    t_signed: float
    """Kit clock: when it was signed (the reference for ``t_f``, KRK-M74)."""
    claims: Dict[str, Any]
    org: str
    """The organisation whose source holds it (whose stub signed or relayed it)."""
    broken: Optional[str] = None
    """The link this evidence breaks, for a fixture; None for valid evidence."""


@dataclass
class KeyChange:
    """A change to A's key statement (mirrors `requester.Withdrawal`)."""

    kid: str
    kind: str
    """``added`` | ``retired`` | ``revoked``."""
    since: float
    """A's clock, as written in the statement."""
    t_commit: float
    """Kit clock: the source serves the new statement from here (``t_k``)."""
    version: int
    t_landed: Optional[float] = None


@dataclass(frozen=True)
class Grant2:
    """One grant 0.2 (or a 0.1 fixture `issue_v1` built) the stub or an agent signed."""

    id: str
    token: str
    subject: str
    principal: str
    constraints: Dict[str, Any]
    parent: Any
    claims: Dict[str, Any]
    signer: str
    """``org:<issuer>`` or ``holder:<subject>``: who signed it (KRK-M79)."""
    holder: Any = field(default=None, compare=False, repr=False)
    """The stub organisation holding `subject`'s key (signs the next hop, signs requests)."""
    version: str = "0.2"


class StubIssuer(StubRequester):
    """Org A for X1 and X5: X4's stub with an anchor, a key statement, standing assertions, peers
    and grant 0.2 (module docstring)."""

    def __init__(self, issuer: str = ISSUER, *, clock: Any = None,
                 status_profile: str = "kirkaldy", ttl_s: int = 30,
                 audience: str = "did:web:b.example", registry: Optional[Dict[str, Any]] = None,
                 standing_purpose: str = "standing") -> None:
        super().__init__(issuer, clock=clock, status_profile=status_profile, ttl_s=ttl_s,
                         audience=audience)
        tag = secrets.token_hex(3)
        self.anchor = Keypair.generate(f"anchor-{tag}")
        self.std_key = Keypair.generate(f"standing-{tag}")
        self.standing_purpose = standing_purpose
        self._keys: Dict[str, Dict[str, Any]] = {
            self.key.kid: {"pair": self.key, "purposes": ["grant", "request", "status"],
                           "state": "active", "since": None},
            self.std_key.kid: {"pair": self.std_key, "purposes": [standing_purpose],
                               "state": "active", "since": None}}
        self._keysets: List[Dict[str, Any]] = []
        self.key_changes: List[KeyChange] = []
        self._current: Dict[str, Standing] = {}
        self._params: Dict[str, Dict[str, Any]] = {}
        self._slog: List[Standing] = []
        self._b_override: Dict[str, Standing] = {}
        self._signer_kid: Optional[str] = None
        self._status_kid: Optional[str] = None
        self._status_broken: Optional[str] = None
        self._status_pair: Optional[Keypair] = None
        self._staples: List[Dict[str, Any]] = []
        self._partition = False
        self._serial = 0
        self._omitted: set = set()
        self.registry: Dict[str, Grant2] = registry if registry is not None else {}
        self.peers: List["StubIssuer"] = []
        self._agent_kids: set = set()

    # keys ------------------------------------------------------------------------------------

    def keypair(self, kid: str) -> Keypair:
        return self._keys[kid]["pair"]

    def agent(self, subject: str) -> Keypair:
        """X4's agent key, and, the first time it is used, an entry in this organisation's key
        statement for purpose ``request``, published as a new version. The
        signer of a holder hop is then attributable to the organisation holding the agent."""
        with self._slock:
            new = subject not in self.agents
            pair = super().agent(subject)
            if new and hasattr(self, "_agent_kids"):
                self._keys[pair.kid] = {"pair": pair, "purposes": ["request"],
                                        "state": "active", "since": None}
                self._agent_kids.add(pair.kid)
                self._publish_keyset()
            return pair

    def agent_kids(self) -> List[str]:
        """The kids of the agents' keys this organisation's statement lists."""
        with self._slock:
            return sorted(self._agent_kids)

    def _keyset_claims(self) -> Dict[str, Any]:
        entries = [standing.key_entry(kid, k["pair"].public_bytes(), k["purposes"], k["state"],
                                      k["since"]) for kid, k in self._keys.items()]
        return standing.keyset_claims(issuer=self.issuer, version=len(self._keysets) + 1,
                                      issued_at=self.now(), ttl_s=self.ttl_s, keys=entries)

    def _publish_keyset(self) -> Dict[str, Any]:
        with self._slock:
            claims = self._keyset_claims()
            tok = standing.sign(claims, self.anchor, standing.KEYSET_TYP)
            rec = {"version": claims["version"], "token": tok, "claims": claims,
                   "t_signed": self.clock.now()}
            self._keysets.append(rec)
            return rec

    def keyset(self) -> Dict[str, Any]:
        """The current key statement record: version, token, claims, t_signed (kit clock)."""
        with self._slock:
            if not self._keysets:
                return self._publish_keyset()
            return self._keysets[-1]

    def keysets(self) -> List[Dict[str, Any]]:
        with self._slock:
            return list(self._keysets)

    def add_key(self, purposes: Sequence[str], *, state: str = "active",
                since_offset_s: Optional[float] = None) -> Tuple[Keypair, KeyChange]:
        """A new key for `purposes`. With ``state`` ``retired`` or ``revoked`` and
        `since_offset_s`, it is in the statement already retired from that long before now
        (``retired_before_bind``)."""
        pair = Keypair.generate(f"k-{secrets.token_hex(4)}")
        since = None if state == "active" else self.now() + float(since_offset_s or 0.0)
        with self._slock:
            self._keys[pair.kid] = {"pair": pair, "purposes": sorted(purposes), "state": state,
                                    "since": since}
            rec = self._publish_keyset()
        ch = KeyChange(pair.kid, "added" if state == "active" else state,
                       since if since is not None else self.now(), rec["t_signed"],
                       rec["version"])
        self.key_changes.append(ch)
        return pair, ch

    def _set_key_state(self, kid: str, state: str) -> KeyChange:
        with self._slock:
            since = self.now()
            self._keys[kid].update(state=state, since=since)
            rec = self._publish_keyset()
        ch = KeyChange(kid, state, since, rec["t_signed"], rec["version"])
        self.key_changes.append(ch)
        return ch

    def retire_key(self, kid: str) -> KeyChange:
        return self._set_key_state(kid, "retired")

    def revoke_key(self, kid: str) -> KeyChange:
        return self._set_key_state(kid, "revoked")

    def key_is_valid(self, kid: str, purpose: str, at_wall: float) -> bool:
        """The stub's own view: whether `kid` is A's for `purpose` for a signature at A's wall
        time `at_wall` (to mark what it signs as broken or not; never B's verdict)."""
        k = self._keys.get(kid)
        if k is None or purpose not in k["purposes"]:
            return False
        return k["state"] == "active" or (k["since"] is not None and at_wall < k["since"])

    @contextmanager
    def signing_with(self, kid: Optional[str]) -> Iterator[None]:
        """Standing assertions signed inside use `kid`, retired or not."""
        old, self._signer_kid = self._signer_kid, kid
        try:
            yield
        finally:
            self._signer_kid = old

    def set_standing_signer(self, kid: Optional[str]) -> None:
        self._signer_kid = kid

    def status_signing_with(self, kid: Any, broken: Optional[str] = None) -> None:
        """Status snapshots signed from now on use `kid` (one of A's kids, or another
        organisation's `Keypair`, which A's statement never lists; None: A's status key), each
        recorded with `broken` (the link it breaks for B, if any)."""
        with self._slock:
            if isinstance(kid, Keypair):
                self._status_pair, self._status_kid = kid, None
            else:
                self._status_pair, self._status_kid = None, kid
            self._status_broken = broken

    def trust_anchor_x1(self) -> Dict[str, Any]:
        """What B pins for A in X1 and X5: the issuer, its anchor, the current key statement (bytes
        and claims), and its sources. ``keys`` lists every operational key for a B that pins keys
        by configuration once, at bind (KRK-M71); agents' keys are not the organisation's own and
        are not among them."""
        ks = self.keyset()
        return {"issuer": self.issuer, "anchor": {self.anchor.kid: self.anchor.public_bytes()},
                "keyset": ks["token"], "keyset_claims": ks["claims"],
                "keys": {kid: k["pair"].public_bytes() for kid, k in self._keys.items()
                         if kid not in self._agent_kids},
                "status_source": self.source_url, "status_profile": self.status_profile,
                "base_url": self.base_url}

    # standing -------------------------------------------------------------------------------

    def _sign_standing(self, principal: str, classes: Dict[str, Any], *,
                       audience: Optional[List[str]], kid: Optional[str],
                       not_after: Optional[float], issuer_claim: Optional[str],
                       signer: Optional[Keypair], broken: Optional[str]) -> Standing:
        now = self.now()
        claims = standing.standing_claims(
            issuer=issuer_claim or self.issuer, principal=principal, classes=classes,
            issued_at=now, not_after=not_after or (now + LIFETIME_S), audience=audience)
        pair = signer or self.keypair(kid or self._signer_kid or self.std_key.kid)
        tok = standing.sign(claims, pair, standing.STANDING_TYP)
        if broken is None and signer is None and not self.key_is_valid(
                pair.kid, "standing", now):
            broken = "key"
        with self._slock:
            self._serial += 1
            serial = self._serial
            s = Standing(serial, principal, dict(classes), tok, pair.kid, self.clock.now(),
                         claims, self.issuer, broken)
            self._slog.append(s)
        return s

    def assert_standing(self, principal: str, classes: Dict[str, Any], *,
                        audience: Optional[List[str]] = None, kid: Optional[str] = None,
                        not_after: Optional[float] = None, issuer_claim: Optional[str] = None,
                        signer: Optional[Keypair] = None, broken: Optional[str] = None,
                        publish: bool = True, renew: bool = True) -> Standing:
        """Sign a standing assertion for `principal` covering `classes` (``{operation: limit or
        None}``). With `publish`, it becomes the principal's current assertion on A's source and,
        with `renew`, is re-signed with the same parameters when a fetch finds it older than
        ``reissue_s``. `signer` signs instead of A's keys (the agent, ``self_attested``; another
        org's relayed bytes are `relay_standing`). `broken` names the link the fixture breaks."""
        s = self._sign_standing(principal, classes, audience=audience, kid=kid,
                                not_after=not_after, issuer_claim=issuer_claim, signer=signer,
                                broken=broken)
        if publish:
            with self._slock:
                self._current[principal] = s
                self._params[principal] = {
                    "classes": dict(classes), "audience": audience, "kid": kid,
                    "issuer_claim": issuer_claim, "signer": signer, "broken": broken,
                    "renew": renew, "not_after": not_after}
        return s

    def relay_standing(self, principal: str, s: Standing) -> None:
        """A's source serves `s` (signed by someone else: a peer, an agent) as `principal`'s
        current assertion, its bytes untouched, never renewed (``key_of_other_org``)."""
        with self._slock:
            self._current[principal] = s
            self._params[principal] = {"renew": False}

    def withhold_standing(self, principal: str) -> None:
        """No assertion for `principal` on A's source (``omitted``). Recorded in the log as a
        change to the stub's own records (KRK-M35)."""
        with self._slock:
            self._current.pop(principal, None)
            self._params.pop(principal, None)
            self.offsets.append({"t": self.clock.now(), "withheld_standing": principal})

    def omit_from_snapshots(self, principal: str) -> None:
        """Snapshots signed from now on leave `principal` out of ``standing`` (the X4 status
        profile's ``omitted``). A separate path, recorded (KRK-M35)."""
        with self._slock:
            self._standing.pop(principal, None)
            self._omitted.add(principal)
            self.offsets.append({"t": self.clock.now(), "omitted_from_snapshots": principal})

    def serve_standing_to_b(self, principal: str, s: Optional[Standing]) -> None:
        """B's fetches of `principal`'s assertion get `s`'s original bytes (None: the current
        one again); the baseline reads the current one (``stale_signed``/``served``)."""
        with self._slock:
            if s is None:
                self._b_override.pop(principal, None)
            else:
                self._b_override[principal] = s

    def standing_log(self) -> List[Standing]:
        with self._slock:
            return list(self._slog)

    def current_standing(self, principal: str) -> Optional[Standing]:
        with self._slock:
            return self._current.get(principal)

    def note_staple(self, s: Standing, t: float) -> None:
        """An assertion stapled to a presentation sent at kit time `t` (KRK-M68)."""
        with self._slock:
            self._staples.append({"serial": s.serial, "t": t, "principal": s.principal})

    def _renew(self, principal: str) -> Optional[Standing]:
        cur = self._current.get(principal)
        p = self._params.get(principal) or {}
        if cur is None or not p.get("renew", False):
            return cur
        if status.epoch_of(cur.claims["issued_at"]) + self.reissue_s <= self.now():
            return self.assert_standing(principal, p["classes"], audience=p.get("audience"),
                                        kid=p.get("kid"), issuer_claim=p.get("issuer_claim"),
                                        signer=p.get("signer"), broken=p.get("broken"),
                                        not_after=None, renew=True)
        return cur

    def latest_delivered(self, principal: str, before: float = float("inf"), *,
                         valid_only: bool = True) -> Optional[float]:
        """``t_f``: the newest kit-clock signing time of an assertion for `principal` that reached
        B before kit time `before`, by a fetch (the fetch log, joined by serial) or a staple
        (the staple log); with `valid_only`, only evidence no fixture broke. Never the claims'
        ``issued_at`` (KRK-M74)."""
        with self._slock:
            by_serial = {s.serial: s for s in self._slog}
            served = [e.get("serial") for e in self._fetch_log
                      if e.get("outcome") in ("ok", "stale") and e.get("serial")
                      and e.get("t_start", 0) < before]
            stapled = [e["serial"] for e in self._staples if e["t"] < before]
        cands = [by_serial[n] for n in served + stapled if n in by_serial]
        cands = [s for s in cands if s.principal == principal
                 and (not valid_only or s.broken is None)]
        return max((s.t_signed for s in cands), default=None)

    def latest_snapshot_delivered(self, principal: str, before: float = float("inf")
                                  ) -> Optional[float]:
        """The X4-status profile's ``t_f``: the newest kit-clock signing time of a snapshot that
        reached B before `before`, signed by a key that was A's, listing `principal` as
        standing."""
        with self._slock:
            versions = {e.get("version") for e in self._fetch_log
                        if e.get("outcome") in ("ok", "stale") and e.get("version")
                        and str(e.get("path", "")).startswith("/status/")
                        and e.get("t_start", 0) < before}
            recs = [r for r in self._snapshots if r["version"] in versions
                    and not r.get("broken")
                    and (r["claims"].get("standing") or {}).get(principal) == "standing"]
        return max((r["t_signed"] for r in recs), default=None)

    # status snapshots (signing key chosen per fixture) ---------------------------------------

    def _publish(self, changes: Dict[str, str]) -> Dict[str, Any]:
        """X4's `_publish`, signing with the key `status_signing_with` chose and recording which
        key signed each snapshot and whether a fixture broke it. Otherwise unchanged."""
        with self._slock:
            for p in self._omitted:
                self._standing.pop(p, None)
            claims = self._claims_now()
            kid = self._status_kid or self.key.kid
            pair = self._status_pair or (self.keypair(kid) if kid in self._keys else self.key)
            tok = status.sign(claims, pair, status.STATUS_TYP)
            if self.status_profile == status.BITSTRING:
                ptok = status.sign(status.bitstring_claims(
                    claims, {g: gr.index for g, gr in self.grants.items()}), pair,
                    status.BITSTRING_TYP)
            else:
                ptok = tok
            broken = self._status_broken
            if broken is None and not self.key_is_valid(pair.kid, "status", self.now()):
                broken = "key"
            rec = {"version": claims["version"], "issued_at": claims["issued_at"],
                   "t_signed": self.clock.now(), "token": tok, "profile_token": ptok,
                   "claims": claims, "changes": dict(changes),
                   "clock_offset_s": self.clock_offset_s, "kid": pair.kid, "broken": broken}
            self._snapshots.append(rec)
        if changes:
            self._notify(rec, changes)
        return rec

    def issue(self, subject: str, operation: str = OPERATION,
              ceiling: Optional[Dict[str, Any]] = None, *, principal: str,
              parent: Any = None, not_after: Optional[float] = None,
              publish: bool = True) -> Any:
        g = super().issue(subject, operation, ceiling, principal=principal, parent=parent,
                          not_after=not_after, publish=False)
        if principal in self._omitted:
            with self._slock:
                self._standing.pop(principal, None)
        if publish:
            self._publish({g.id: "issued"})
        return g

    def read_back(self, expect: Dict[str, str]) -> Dict[str, bool]:
        """X4's read-back, verifying under every key the stub holds (a fixture may have signed
        the current snapshot with another of A's keys)."""
        ok, tok, _ = self.baseline_read()
        out = {k: False for k in expect}
        if not ok or tok is None:
            return out
        pinned = {kid: k["pair"].public_bytes() for kid, k in self._keys.items()}
        claims, _why = status.read_profile(tok, pinned, self.status_profile)
        if claims is None:
            return out
        for k, want in expect.items():
            if k.startswith("principal:"):
                std = claims.get("standing")
                p = k[len("principal:"):]
                out[k] = isinstance(std, dict) and (std.get(p) == want if want != "absent"
                                                    else p not in std)
                continue
            g = self.grants.get(k) or self.registry.get(k)
            if g is None:
                continue
            got = status.revoked_in(claims, self.status_profile, g.claims)
            out[k] = got == want
            if want == "narrowed" and got == "narrowed":
                out[k] = claims["entries"][k]["ceiling"] == self._states[k].get("ceiling")
        return out

    # the sources ----------------------------------------------------------------------------

    def set_partition(self, on: bool) -> None:
        """Only B's paths fail (``down``); the agent and the kit's baseline still reach A."""
        with self._slock:
            self._partition = bool(on)

    def _serve(self, path: str, client: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        if self._partition and not path.startswith(BASELINE):
            return "down", None
        return super()._serve(path, client)

    def _serve_x1(self, path: str) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """(outcome, token, log fields) for a ``/keys`` or ``/standing/<p>`` fetch."""
        baseline = path.startswith(BASELINE)
        p = path[len(BASELINE):] if baseline else path
        with self._slock:
            mode = self._mode
            part = self._partition
        if mode in ("down", "hang", "error") or (part and not baseline):
            return ("down" if part and not baseline and mode not in ("hang", "error") else mode,
                    None, {})
        if p == KEYS_PATH:
            cur = self.keyset()
            if status.epoch_of(cur["claims"]["issued_at"]) + self.reissue_s <= self.now():
                cur = self._publish_keyset()
            return "ok", cur["token"], {"keyset_version": cur["version"]}
        if p.startswith(STANDING_PATH):
            principal = urllib.parse.unquote(p[len(STANDING_PATH):])
            with self._slock:
                over = None if baseline else self._b_override.get(principal)
            if over is not None:
                return "stale", over.token, {"serial": over.serial, "principal": principal}
            s = self._renew(principal)
            if s is None:
                return "not-found", None, {"principal": principal}
            return "ok", s.token, {"serial": s.serial, "principal": principal}
        return "not-found", None, {}

    def wait_fetched(self, path: str, after: float, limit_s: float, *,
                     outcomes: Sequence[str] = ("ok", "stale")) -> Optional[float]:
        """When B's first fetch of `path` that started after kit time `after` and ended with one of
        `outcomes` ended, waiting up to `limit_s` for it; None if there was none (KRK-M95)."""
        deadline = self.clock.now() + limit_s
        while True:
            with self._slock:
                done = [e["t_end"] for e in self._fetch_log if e.get("path") == path
                        and e.get("t_end") is not None and e["t_start"] > after
                        and e.get("outcome") in outcomes]
            if done:
                return min(done)
            if self.clock.now() > deadline:
                return None
            self.clock.sleep(0.05)

    def _x1_path(self, path: str) -> bool:
        p = path[len(BASELINE):] if path.startswith(BASELINE) else path
        return p == KEYS_PATH or p.startswith(STANDING_PATH)

    def fetch_local(self, path: str = "/status/list", client: str = "b") -> Tuple[int, str]:
        if not self._x1_path(path):
            return super().fetch_local(path, client)
        t0 = self.clock.now()
        outcome, tok, fields = self._serve_x1(path)
        e = {"client": client, "path": path, "t_start": t0, "outcome": outcome,
             "version": None, "t_end": None, **fields}
        if not path.startswith(BASELINE):
            with self._slock:
                self._fetch_log.append(e)
        try:
            if outcome == "down":
                raise ConnectionRefusedError("source refused the connection")
            if outcome == "hang":
                raise TimeoutError("source did not answer")
            if outcome == "error":
                return 503, ""
            if outcome == "not-found":
                return 404, ""
            return 200, tok or ""
        finally:
            e["t_end"] = self.clock.now()

    def _http_fetch(self, h: Any) -> None:
        path = h.path.split("?")[0]
        if not self._x1_path(path):
            return super()._http_fetch(h)
        t0 = self.clock.now()
        outcome, tok, fields = self._serve_x1(path)
        e = {"client": h.client_address[0], "path": path, "t_start": t0, "outcome": outcome,
             "version": None, "t_end": None, **fields}
        if not path.startswith(BASELINE):
            with self._slock:
                self._fetch_log.append(e)
        try:
            if outcome == "down":
                h.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                        struct.pack("ii", 1, 0))
                h.close_connection = True
                return
            if outcome == "hang":
                end = time.monotonic() + self.hang_s
                while time.monotonic() < end and self._mode == "hang":
                    time.sleep(0.05)
                h.close_connection = True
                return
            code = {"error": 503, "not-found": 404}.get(outcome, 200)
            body = (tok or "").encode("ascii") if code == 200 else b""
            h.send_response(code)
            h.send_header("Content-Type", "application/jose" if body else "text/plain")
            h.send_header("Cache-Control", "no-store")
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)
        finally:
            e["t_end"] = self.clock.now()

    def keys_url(self) -> str:
        return f"{self.base_url}{KEYS_PATH}"

    def standing_url(self, principal: str) -> str:
        return f"{self.base_url}{STANDING_PATH}{urllib.parse.quote(principal, safe='')}"

    def baseline_get(self, path: str) -> Tuple[bool, Optional[str], str]:
        """The kit's own client on ``/__baseline<path>`` (spec §5.1 rule 3): (reached, token,
        detail). Outages apply to it; ``partition`` and per-principal staleness do not."""
        if self._httpd is not None and getattr(self.clock, "kind", "real") == "real":
            try:
                with urllib.request.urlopen(f"{self.base_url}{BASELINE}{path}", timeout=2) as r:
                    return True, r.read().decode("ascii"), f"HTTP {r.status}"
            except urllib.error.HTTPError as e:
                return False, None, f"HTTP {e.code}"
            except Exception as e:  # noqa: BLE001
                return False, None, f"{type(e).__name__}: {e}"[:200]
        try:
            code, tok = self.fetch_local(f"{BASELINE}{path}", "kit-baseline")
        except Exception as e:  # noqa: BLE001
            return False, None, f"{type(e).__name__}: {e}"
        return code == 200, tok if code == 200 else None, f"status {code}"

    def read_back_x1(self, expect: Dict[str, Any]) -> Dict[str, bool]:
        """X1's read-back through the baseline client (KRK-M26): ``"key:<kid>"`` -> the state A's
        current statement must give it; ``"standing:<principal>"`` -> the `Standing` whose bytes
        the source must serve as current, or None for none."""
        out: Dict[str, bool] = {}
        for k, want in expect.items():
            if k.startswith("key:"):
                ok, tok, _ = self.baseline_get(KEYS_PATH)
                v = standing.verify(tok, {self.anchor.kid: self.anchor.public_bytes()},
                                    standing.KEYSET_TYP) if ok else None
                st = None
                if v is not None and v.ok:
                    st = next((x["state"] for x in v.claims["keys"]
                               if x["kid"] == k[len("key:"):]), None)
                out[k] = st == want
            elif k.startswith("standing:"):
                p = k[len("standing:"):]
                ok, tok, _ = self.baseline_get(STANDING_PATH + urllib.parse.quote(p, safe=""))
                out[k] = (not ok) if want is None else (ok and tok == want.token)
        return out

    # other organisations ----------------------------------------------------------------------

    def peer(self, issuer: Optional[str] = None, **kw: Any) -> "StubIssuer":
        """Another organisation (A′, A2 or C): its own anchor, keys and source, on this clock,
        sharing the registry of 0.2 grants. Served the way this stub is."""
        o = StubIssuer(issuer or requester.new_issuer(), clock=self.clock,
                       status_profile=kw.pop("status_profile", self.status_profile),
                       ttl_s=kw.pop("ttl_s", self.ttl_s),
                       audience=kw.pop("audience", self.audience), registry=self.registry,
                       standing_purpose=kw.pop("standing_purpose", self.standing_purpose))
        o.hang_s = self.hang_s
        if self._httpd is not None:
            o.serve()
        else:
            o.serve_local()
        self.peers.append(o)
        return o

    def close(self) -> None:
        for o in self.peers:
            o.close()
        super().close()

    # grant 0.2 --------------------------------------------------------------------------------

    def _v2_claims(self, *, issuer: str, subject: str, agent: Keypair, principal: str,
                   constraints: Dict[str, Any], parent: Any, not_before: float,
                   not_after: Optional[float], source: str, index: int,
                   grant_id: Optional[str], crit: Optional[List[str]],
                   audience_claim: Optional[str], omit: Sequence[str]) -> Dict[str, Any]:
        now = self.now()
        c: Dict[str, Any] = {
            "schema": attenuation.GRANT_V2_SCHEMA, "grant_id": grant_id or status.new_grant_id(),
            "issuer": issuer, "subject": subject,
            "agent_key": {"kid": agent.kid, "public_key": agent.public_bytes().hex()},
            "principal": principal, "constraints": constraints,
            "parent": parent, "issued_at": status.utc_ms(now),
            "not_before": status.utc_s(not_before),
            "not_after": status.utc_s(not_after) if not_after is not None else None,
            "status": {"source": source, "index": int(index)}}
        if crit is not None:
            c["crit"] = list(crit)
        if audience_claim is not None:
            c["audience"] = audience_claim
        for m in omit:
            c.pop(m, None)
        if c.get("not_after", 0) is None:
            c.pop("not_after")
        return c

    def _record_v2(self, claims: Dict[str, Any], tok: str, signer: str, holder: Any) -> Grant2:
        g = Grant2(claims["grant_id"], tok, claims["subject"], claims["principal"],
                   dict(claims.get("constraints") or {}), claims.get("parent"), claims, signer,
                   holder)
        with self._slock:
            self.registry[g.id] = g
            self._states[g.id] = {"state": "valid", "ceiling": None}
            if claims["principal"] not in self._omitted:
                self._standing.setdefault(claims["principal"], "standing")
        return g

    def _next_index(self) -> int:
        with self._slock:
            i = self._index
            self._index += 1
            return i

    def issue_v2(self, subject: str, constraints: Dict[str, Any], *, principal: str,
                 parent: Any = None, not_before: Optional[float] = None,
                 not_after: Optional[float] = None, grant_id: Optional[str] = None,
                 crit: Optional[List[str]] = None, raw: bool = False,
                 audience_claim: Optional[str] = None, omit: Sequence[str] = (),
                 publish: bool = True, holder: Optional["StubIssuer"] = None) -> Grant2:
        """A grant 0.2 signed by A's grant key, for `subject` (an agent whose key `holder`, A by
        default, holds). `parent` is a `Grant2`, a grant id, a list (``two_parents``) or None.
        The window defaults to an hour back and twelve hours on; ``omit=("not_after",)`` leaves it
        out. ``raw`` signs a payload the canonical form refuses (numeric fixtures)."""
        holder = holder or self
        agent = holder.agent(subject)
        now = self.now()
        par = parent.id if isinstance(parent, Grant2) else parent
        claims = self._v2_claims(
            issuer=self.issuer, subject=subject, agent=agent, principal=principal,
            constraints=constraints, parent=par,
            not_before=not_before if not_before is not None else now - 3600,
            not_after=not_after if not_after is not None else now + LIFETIME_S,
            source=self.source_url, index=self._next_index(), grant_id=grant_id, crit=crit,
            audience_claim=audience_claim, omit=omit)
        tok = standing.sign(claims, self.key, standing.GRANT_TYP, raw=raw)
        g = self._record_v2(claims, tok, f"org:{self.issuer}", holder)
        if publish:
            self._publish({g.id: "issued"})
        return g

    def delegate_holder(self, parent: Grant2, subject: str,
                        constraints: Optional[Dict[str, Any]] = None, *,
                        org: Optional["StubIssuer"] = None, principal: Optional[str] = None,
                        not_before: Optional[float] = None, not_after: Optional[float] = None,
                        grant_id: Optional[str] = None, parent_id: Any = None,
                        crit: Optional[List[str]] = None, raw: bool = False,
                        omit: Sequence[str] = (), check: bool = True) -> Grant2:
        """A hop signed by the holder of `parent` (its subject's key, held by `parent.holder`),
        for `subject`, whose key `org` (the holder's organisation by default) holds. The hop's
        status is at the signing holder's organisation's source. Never wider with `check`."""
        signer_org: StubIssuer = parent.holder or self
        agent_key = signer_org.agent(parent.subject)
        new_holder = org or signer_org
        sub_key = new_holder.agent(subject)
        now = signer_org.now()
        c = dict(parent.constraints if constraints is None else constraints)
        pnb = attenuation._epoch_s(parent.claims.get("not_before")) or now - 3600
        pna = attenuation._epoch_s(parent.claims.get("not_after")) or now + LIFETIME_S
        claims = self._v2_claims(
            issuer=parent.subject, subject=subject, agent=sub_key,
            principal=principal or parent.principal, constraints=c,
            parent=parent.id if parent_id is None else parent_id,
            not_before=pnb if not_before is None else not_before,
            not_after=pna if not_after is None else not_after,
            source=signer_org.source_url, index=signer_org._next_index(), grant_id=grant_id,
            crit=crit, audience_claim=None, omit=omit)
        if check and attenuation.wider(claims, parent.claims):
            raise ValueError(f"a delegated grant is never wider than its parent: "
                             f"{attenuation.wider(claims, parent.claims)}")
        tok = standing.sign(claims, agent_key, standing.GRANT_TYP, raw=raw)
        g = signer_org._record_v2(claims, tok, f"holder:{parent.subject}", new_holder)
        signer_org._publish({g.id: "issued"})
        return g

    def delegate_v2(self, parent: Grant2, subject: str, constraints: Dict[str, Any], *,
                    signer: str = "a", org: Optional["StubIssuer"] = None,
                    principal: Optional[str] = None) -> Grant2:
        """A child never wider than its parent (raises otherwise)."""
        if signer == "holder":
            return self.delegate_holder(parent, subject, constraints, org=org,
                                        principal=principal)
        probe = {**parent.claims, "constraints": constraints}
        if attenuation.wider(probe, parent.claims):
            raise ValueError("a delegated grant is never wider than its parent")
        return self.issue_v2(subject, constraints, principal=principal or parent.principal,
                             parent=parent,
                             not_before=attenuation._epoch_s(parent.claims["not_before"]),
                             not_after=attenuation._epoch_s(parent.claims["not_after"]))

    def delegate_wider(self, parent: Grant2, subject: str, *, dimension: str, value: Any,
                       signer: str = "a", org: Optional["StubIssuer"] = None,
                       principal: Optional[str] = None, window: Optional[Tuple[float, float]] = None
                       ) -> Grant2:
        """A child genuinely wider than `parent` in `dimension` (a constraints member set to
        `value`, or ``window`` with `window`), signed by A or by the holder.
        Raises unless the child really is wider there, so a fixture cannot be mislabelled."""
        c = dict(parent.constraints)
        nb = attenuation._epoch_s(parent.claims["not_before"])
        na = attenuation._epoch_s(parent.claims["not_after"])
        if dimension == "window":
            nb, na = window  # type: ignore[misc]
        else:
            c[dimension] = value
        probe = {**parent.claims, "constraints": c, "not_before": status.utc_s(nb),
                 "not_after": status.utc_s(na)}
        if dimension not in attenuation.wider(probe, parent.claims):
            raise ValueError(f"the child is not wider than its parent in {dimension}")
        if signer == "holder":
            return self.delegate_holder(parent, subject, c, org=org, principal=principal,
                                        not_before=nb, not_after=na, check=False)
        return self.issue_v2(subject, c, principal=principal or parent.principal,
                             parent=parent, not_before=nb, not_after=na)

    def cycle(self, subjects: Sequence[str], *, kind: str = "id", principal: str,
              constraints: Dict[str, Any], signer: str = "a",
              org: Optional["StubIssuer"] = None) -> List[Grant2]:
        """``id``: grants whose ids are chosen before signing, each naming the next as its parent
        and the last naming the first; ``self``: one grant naming its own id. Signed by A, or with
        ``signer="holder"`` each by the agent key of the grant it names as parent."""
        if kind == "self":
            gid = status.new_grant_id()
            return [self.issue_v2(subjects[0], constraints, principal=principal, parent=gid,
                                  grant_id=gid)]
        ids = [status.new_grant_id() for _ in subjects]
        out = []
        for i, s in enumerate(subjects):
            par = ids[(i + 1) % len(ids)]
            if signer == "holder":
                # Signed by the agent of the grant it names as parent (that grant's subject).
                holder_subject = subjects[(i + 1) % len(subjects)]
                fake_parent = Grant2(par, "", holder_subject, principal, dict(constraints), None,
                                     {"not_before": status.utc_s(self.now() - 3600),
                                      "not_after": status.utc_s(self.now() + LIFETIME_S),
                                      "constraints": constraints},
                                     "", org or self)
                out.append(self.delegate_holder(fake_parent, s, constraints, org=org or self,
                                                principal=principal, grant_id=ids[i],
                                                parent_id=par, check=False))
            else:
                out.append(self.issue_v2(s, constraints, principal=principal, parent=par,
                                         grant_id=ids[i]))
        return out

    def with_member(self, like: Grant2, member: str, value: Any, *,
                    where: str = "constraints", crit: Optional[List[str]] = None,
                    omit: Sequence[str] = ()) -> Grant2:
        """A new grant like `like` (same subject, principal, parent and window, a fresh id) with
        ``constraints[member]`` set to `value` (``"__absent__"`` removes it), signed as written:
        null, ``[]``, ``"*"``, an unknown or near-name member. `like` must be A-signed."""
        c = dict(like.constraints)
        if value == "__absent__":
            c.pop(member, None)
        else:
            c[member] = value
        nb = attenuation._epoch_s(like.claims["not_before"])
        na = attenuation._epoch_s(like.claims.get("not_after") or "") if "not_after" in \
            like.claims else None
        return self.issue_v2(like.subject, c, principal=like.principal, parent=like.parent,
                             not_before=nb, not_after=na, crit=crit, omit=omit,
                             holder=like.holder)

    def chain_v2(self, g: Grant2) -> List[Grant2]:
        """`g`, then each parent up to the root, across organisations (the shared registry).
        Stops at a repeat or an unknown or listed parent (fixtures build those by hand)."""
        out, seen = [g], {g.id}
        while isinstance(out[-1].parent, str) and out[-1].parent in self.registry \
                and out[-1].parent not in seen:
            nxt = self.registry[out[-1].parent]
            out.append(nxt)
            seen.add(nxt.id)
        return out

    # grant 0.1 fixtures ------------------------------------------------------------------------

    def issue_v1(self, subject: str, operation: str, ceiling: Dict[str, Any], *,
                 principal: str, parent_id: Any = None, grant_id: Optional[str] = None,
                 not_before: Optional[float] = None, not_after: Optional[float] = None,
                 omit: Sequence[str] = (), raw: bool = False) -> Any:
        """A grant 0.1 X4's `issue` cannot build (an id chosen first, a parent named by id or as
        a list, a member left out), signed by A's key as written. Registered in ``grants`` so
        A's source lists it; never followed by `chain` (fixtures build their headers)."""
        ak = self.agent(subject)
        now = self.now()
        idx = self._next_index()
        claims = status.grant_claims(
            issuer=self.issuer, audience=self.audience, subject=subject, agent_kid=ak.kid,
            agent_public=ak.public_bytes(), principal=principal, operation=operation,
            ceiling=dict(ceiling), parent=None, issued_at=now,
            not_before=not_before if not_before is not None else now - 3600,
            not_after=not_after if not_after is not None else now + LIFETIME_S,
            source=self.source_url, index=idx, grant_id=grant_id)
        claims["parent"] = parent_id
        for m in omit:
            claims.pop(m, None)
        tok = standing.sign(claims, self.key, status.GRANT_TYP, raw=raw)
        g = requester.Grant(claims["grant_id"], tok, subject, principal, operation,
                            dict(ceiling), parent_id if isinstance(parent_id, str) else None,
                            int(status.epoch_of(claims.get("not_after") or status.utc_s(now))),
                            idx, claims)
        with self._slock:
            self.grants[g.id] = g
            self._states[g.id] = {"state": "valid", "ceiling": None}
            self._standing.setdefault(principal, "standing")
        self._publish({g.id: "issued"})
        return g

    # presentations ----------------------------------------------------------------------------

    def _authz(self, raw: bytes, values: Dict[str, Any], *, subject: str, key: Keypair,
               operation: str, grant_id: str, audience: Dict[str, Any], loose: bool,
               window_s: Tuple[float, float]) -> str:
        t = self.clock.wall()
        basis = authz.RAW if loose else authz.CANONICAL
        claims = authz.authorisation_claims(
            issuer=subject, audience=audience, operation=operation,
            binding=authz.exact_binding(raw, basis=basis), max_uses=1,
            not_before=authz.utc(t + window_s[0]), not_after=authz.utc(t + window_s[1]),
            decision_digest=None, extra={"grant_id": grant_id})
        tok = authz.sign_authorisation(claims, key)
        self.issued.append({**claims, "token": tok, "signer": "agent"})
        return tok

    def request_raw(self, values: Dict[str, Any], *, loose: bool = False) -> bytes:
        if loose:
            return json.dumps(values, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        return requester.request_bytes(values)

    def under_v2(self, grant: Grant2, values: Dict[str, Any], *, audience: Dict[str, Any],
                 chain: Optional[List[Any]] = None, loose: bool = False,
                 staple: Optional[Standing] = None, staple_keyset: Optional[str] = None,
                 second: Optional[List[Any]] = None,
                 window_s: Tuple[float, float] = (-900.0, 900.0)) -> Presentation:
        """A fresh request under `grant`, signed by its agent's key (held by `grant.holder`),
        with the chain (default: `chain_v2`) in X4's headers, a second chain in
        `GRANT2_HEADER`/`CHAIN2_HEADER`, and staples. Each staple is logged (KRK-M68)."""
        raw = self.request_raw(values, loose=loose)
        holder = grant.holder or self
        key = holder.agent(grant.subject)
        op = values.get("operation", OPERATION)
        tok = self._authz(raw, values, subject=grant.subject, key=key, operation=op,
                          grant_id=grant.id, audience=audience, loose=loose, window_s=window_s)
        ch = chain if chain is not None else self.chain_v2(grant)
        h: Dict[str, str] = {requester.GRANT_HEADER: ch[0].token}
        if len(ch) > 1:
            h[requester.CHAIN_HEADER] = ",".join(g.token for g in ch[1:])
        if second:
            h[GRANT2_HEADER] = second[0].token
            if len(second) > 1:
                h[CHAIN2_HEADER] = ",".join(g.token for g in second[1:])
        if staple is not None:
            h[standing.STANDING_HEADER] = staple.token
            self.note_staple(staple, self.clock.now())
        if staple_keyset:
            h[standing.KEYSET_HEADER] = staple_keyset
        return Presentation(pid=f"w{secrets.token_hex(6)}",
                            endpoint=audience.get("endpoint") or "default",
                            tenant=audience.get("tenant"), request=raw, authorisation=tok,
                            headers=h)

    def under_raw(self, tokens: Sequence[str], values: Dict[str, Any], *,
                  audience: Dict[str, Any], subject: str, holder: Optional["StubIssuer"],
                  grant_id: str, operation: str, loose: bool = False,
                  window_s: Tuple[float, float] = (-900.0, 900.0)) -> Presentation:
        """A fresh request with `tokens` as the chain headers in this order, as written (cycles,
        grant 0.1 fixtures), signed by `subject`'s agent key."""
        raw = self.request_raw(values, loose=loose)
        key = (holder or self).agent(subject)
        tok = self._authz(raw, values, subject=subject, key=key, operation=operation,
                          grant_id=grant_id, audience=audience, loose=loose, window_s=window_s)
        h = {requester.GRANT_HEADER: tokens[0]}
        if len(tokens) > 1:
            h[requester.CHAIN_HEADER] = ",".join(tokens[1:])
        return Presentation(pid=f"w{secrets.token_hex(6)}",
                            endpoint=audience.get("endpoint") or "default",
                            tenant=audience.get("tenant"), request=raw, authorisation=tok,
                            headers=h)


def amount(value: Any, currency: str = CURRENCY, minor_units: int = MINOR) -> Dict[str, Any]:
    """An amount in the kit's X5 vocabulary."""
    return {"value": value, "currency": currency, "minor_units": minor_units}
