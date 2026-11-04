"""Known-bad and known-good toy B's for P20 (KRK-20, standing verifiable offline).

One toy B with a real recorder path (`X1-STANDING-OFFLINE-DESIGN.md` §4.6), in the kit's own
profile: it pins each organisation's anchor, fetches its key statement (``/keys``) and the
standing assertion of each root principal it meets (``/standing/<principal>``), reads stapled
assertions, verifies grant 0.2 chains with holder-signed hops (`standing.verify_holder_chain`,
`attenuation.allowed`), verifies the agent's per-request authorisation, then performs the effect
by POSTing the request's values to the kit's recorder. Its pollers run on the probe's clock
(`timing.VirtualClock` in the known-bad gate, `timing.RealClock` in the real-time smoke test).

``good`` checks every link at receive and again before a held retry: the assertion's key is in
the root organisation's newest key statement, designated for standing and not retired or revoked
at its claimed issue time (`standing.key_state`); the assertion is the root organisation's, for
the chain's root principal, covering the request's operation, addressed to B or to any; and its
age, from the earlier of A's issue time and B's receipt, is no more than T/2 (so A's clock running
ahead never makes evidence younger, and evidence served late never looks fresh). It polls key
statements and known principals every T/4, accepts offline until the bound, keeps evidence and its
age in a store that survives a restart, and never takes an older key statement than one it holds.
It must pass.

One flaw per row of design §3.1 (`FAILS`), each reading the evidence wrongly rather than removing
members from it (KRK-M47):

| Flaw | What it does | Variant it fails |
|---|---|---|
| `trusts_expiry` | judges age by the assertion's own ``not_after`` | `stale_signed` |
| `age_from_fetch` | measures age from its own receipt | `stale_signed` (``aged_at_fetch``) |
| `fails_open_offline` | once a fetch fails, keeps its last evidence however old | `a_unreachable` |
| `online_only` | refuses as soon as a fetch fails | `a_unreachable` (``online_only``) |
| `checks_on_arrival_only` | retries a held effect without checking again | `aged_in_queue` |
| `ignores_key_state` | takes any key A ever listed, whatever its state | `retired_key` |
| `pinned_once` | reads A's key statement once, at bind | `retired_key` (``revoked_key``) |
| `any_pinned_key` | verifies under any organisation's keys it pins | `key_of_other_org` |
| `issuer_unchecked` | takes standing from any pinned issuer | `other_organisation` (``other_issuer``) |
| `audience_unchecked` | ignores the assertion's audience | `other_organisation` (``other_audience``) |
| `leaf_org_standing` | takes a staple from the leaf's organisation as the root's standing | `other_organisation` (``c_standing``) |
| `agent_key_only` | verifies the agent's key and the grant, and no standing | `agent_not_principal` |
| `principal_unchecked` | does not compare the assertion's principal with the root's | `agent_not_principal` (``other_principal``) |
| `class_unchecked` | does not check the operation is among the classes | `agent_not_principal` (``other_action_class``) |
| `trusts_agent_assertion` | takes an assertion signed by the agent's own key | `agent_not_principal` (``self_attested``) |
| `purpose_unchecked` | takes any of A's keys for standing, whatever its purpose | `agent_not_principal` (``undesignated_key``) |
| `leaf_standing_only` | checks the presented grant's principal at the leaf's organisation | `deep_chain` |
| `trusts_issuer_time` | judges age, and when to fetch, by A's issue time alone | `clock_skew` |
| `accepts_on_boot` | keeps evidence in memory and accepts until its first fetch after a restart | `restart_offline` |
| `flaps` | its second endpoint reads a replica that never ages evidence out | `a_unreachable` (``flapped``) |
| `no_check` | never checks standing (also ``bad``) | `agent_not_principal` |
| `chain_before_fetch` | reads standing only by fetching (as ``pull-good``), and acts on the chain alone for a principal it has not yet fetched anything for | `agent_not_principal` (``before_first_fetch``) |

``no-control``: the executor posts to a path that is not the recorder's. ``slow-good`` is the
correct toy answering 0.6 T after an acceptance and 0.1 T after a refusal; it must
pass.

**Pull only** (KRK-M95, M95b). ``pull-good`` is the correct toy reading standing as the reference
implementation does: only by fetching, on its own poll, for the principals A's status list names;
never a staple, and never a fetch made because a request arrived. It must pass. Before its first
fetch for a principal it holds nothing, and refuses. ``bad:chain_before_fetch`` reads the same
way, and for a principal it has not yet had any answer about it acts on the chain alone; with the
KRK-M95 wait every other form presents after its fetch, so only ``before_first_fetch`` sees it.

**The X4-status profile.** ``x4-good`` is a correct B in P20's other profile, the one the reference implementation
is read in: it takes grant 0.1 chains, reads standing only from each organisation's X4 status
snapshot (per principal, with `status.chain_state`), and verifies each snapshot under a key A's
own key statement designates for ``status`` at the snapshot's issue time, so it learns of a key
A revokes. It must pass every form that profile can express; the rest are format gaps.
``x4-bad:pinned_once`` reads A's key statement once, at bind, as a B with keys in its own
configuration does, and must fail ``retired_key`` (``revoked_key``) as P20's design says.
"""
from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from known_bad.withdrawal_toys import _KEEP, _answer

FLAWS = ("trusts_expiry", "age_from_fetch", "fails_open_offline", "online_only",
         "checks_on_arrival_only", "ignores_key_state", "pinned_once", "any_pinned_key",
         "issuer_unchecked", "audience_unchecked", "leaf_org_standing", "agent_key_only",
         "principal_unchecked", "class_unchecked", "trusts_agent_assertion",
         "purpose_unchecked", "leaf_standing_only", "trusts_issuer_time", "accepts_on_boot",
         "flaps", "no_check", "chain_before_fetch")
PULL_ONLY_FLAWS = ("chain_before_fetch",)
"""Flaws whose toy reads standing only by fetching, as ``pull-good`` does."""
FAILS = {"trusts_expiry": "stale_signed", "age_from_fetch": "stale_signed",
         "fails_open_offline": "a_unreachable", "online_only": "a_unreachable",
         "checks_on_arrival_only": "aged_in_queue", "ignores_key_state": "retired_key",
         "pinned_once": "retired_key", "any_pinned_key": "key_of_other_org",
         "issuer_unchecked": "other_organisation", "audience_unchecked": "other_organisation",
         "leaf_org_standing": "other_organisation", "agent_key_only": "agent_not_principal",
         "principal_unchecked": "agent_not_principal", "class_unchecked": "agent_not_principal",
         "trusts_agent_assertion": "agent_not_principal",
         "purpose_unchecked": "agent_not_principal", "leaf_standing_only": "deep_chain",
         "trusts_issuer_time": "clock_skew", "accepts_on_boot": "restart_offline",
         "flaps": "a_unreachable", "no_check": "agent_not_principal",
         "chain_before_fetch": "agent_not_principal"}
"""The variant each flaw is built to fail (it may fail others too)."""
FORM = {"age_from_fetch": "aged_at_fetch", "online_only": None, "pinned_once": "revoked_key",
        "issuer_unchecked": "other_issuer", "audience_unchecked": "other_audience",
        "leaf_org_standing": "c_standing", "principal_unchecked": "other_principal",
        "class_unchecked": "other_action_class", "trusts_agent_assertion": "self_attested",
        "purpose_unchecked": "undesignated_key", "chain_before_fetch": "before_first_fetch"}
"""Where a flaw is built for one form of its variant."""
PARTY = "did:web:b.example"
SLOW = {"executed": 0.6, "refused": 0.1}


class ToyStanding:
    """A B that acts for other organisations' agents on standing evidence (P20's role-B adapter,
    in process)."""

    name = "toy-standing"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *, T: float = 60.0,
                 clock: str = "virtual") -> None:
        self.x4 = config.startswith("x4-")
        if self.x4:
            config = config[3:]
        if config == "bad" and flaw is None:
            flaw = "no_check"
        if flaw is not None and flaw not in FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.config = (("x4-" if self.x4 else "") + config) if flaw is None else \
            f"{'x4-' if self.x4 else ''}bad:{flaw}"
        self.flaw = flaw
        self.no_control = config == "no-control"
        self.pull_only = not self.x4 and (config == "pull-good" or flaw in PULL_ONLY_FLAWS)
        """Standing only by fetching, on the poll, for the principals A's status list names."""
        self._polling = False
        self.answered: Dict[Tuple[str, str], float] = {}
        """(issuer, principal) -> when A first answered a fetch for it (200 or 404): survives a
        restart, as `store` does."""
        self.delays = SLOW if config == "slow-good" else {}
        self.snaps: Dict[str, Dict[str, Any]] = {}
        """X4-status profile: issuer -> {claims, received} of the newest snapshot taken."""
        self.T = float(T)
        self.clock = clock
        self._clock: Any = None
        self.recorder = ""
        self.boot = secrets.token_hex(4)
        self.orgs: Dict[str, Dict[str, Any]] = {}
        """issuer -> {anchor, base, keyset (claims), versions, ever (kid -> entry)}."""
        self.store: Dict[Tuple[str, str], Dict[str, Any]] = {}
        """(issuer, principal) -> {token, received}: survives a restart (a real B's database)."""
        self.mem: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.fetch_ok: Dict[str, bool] = {}
        self.boot_fetched = True
        self.known: Dict[Tuple[str, str], float] = {}
        """(issuer, principal) -> when a request last needed it; polled while used in the last
        3 T, as a real B drops principals it no longer acts for."""
        self._polls: List[int] = []

    # kit plumbing ---------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-standing {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P20": f"toy: 'acts only on standing evidence no older than {self.T:g} s'"}

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
                "quote": f"toy: 'evidence no older than {self.T:g} seconds'",
                "url": "known_bad/standing_toys.py", "setting": "", "recovery_s": self.T / 2,
                "clock_tolerance_s": 5.0, "resolution_s": 0.001}

    def channels(self) -> List[str]:
        return ["pull-list"] if self.x4 else []

    def standing_profile(self) -> Optional[str]:
        return "x4-status" if self.x4 else None

    def standing_channels(self) -> List[str]:
        return ["pull"] if self.x4 or self.pull_only else ["pull", "stapled"]

    def keys_from(self) -> str:
        return "statement"

    def issuers(self) -> int:
        return 4

    def accepts_holder_hops(self) -> bool:
        return not self.x4

    def max_depth(self) -> Optional[int]:
        return 6

    def documents_standing(self) -> bool:
        return True

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

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "accepted", "queued": "in-progress",
                "refused": "refused"}.get(code, "error")

    def reached_guarantee(self, variant: str, answer: Dict[str, Any]) -> bool:
        return True

    # binding --------------------------------------------------------------------------------

    def _bind(self, anchor: Dict[str, Any]) -> str:
        iss = anchor["issuer"]
        self.orgs[iss] = {"anchor": {k: bytes(v) for k, v in anchor["anchor"].items()},
                          "base": anchor["base_url"], "keyset": None, "ever": {}}
        self._fetch_keys(iss)
        return iss

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        iss = self._bind(anchor)
        self._start_polls()
        return f"pinned {iss}'s anchor; polling its key statement and principals' standing"

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        return f"pinned {self._bind(anchor)}'s anchor"

    def bind_recorder(self, recorder_url: str) -> str:
        self.recorder = recorder_url.rstrip("/")
        return f"effects to {self.recorder}/effect/<id>"

    def restart(self) -> Dict[str, Any]:
        before = self.boot
        self._stop_polls()
        self.boot = secrets.token_hex(4)
        self.mem = {}
        self.boot_fetched = False
        self._start_polls()
        return {"before": before, "after": self.boot,
                "how": "in-process restart: memory cleared, the store kept"}

    # fetching -------------------------------------------------------------------------------

    def _get(self, url: str) -> Tuple[int, str]:
        from conformance import requester
        base = next((o["base"] for o in self.orgs.values() if url.startswith(o["base"] + "/")),
                    None)
        src = requester.local_source(base + "/status/list") if base else None
        if self.clock == "virtual" and src is not None:
            return src.fetch_local(url[len(base):], client=f"toy-{self.boot}")
        try:
            with urllib.request.urlopen(url, timeout=max(0.2, self.T / 8)) as r:
                return r.status, r.read().decode("ascii")
        except urllib.error.HTTPError as e:
            return e.code, ""

    def _fetch_keys(self, iss: str) -> None:
        from conformance import standing as st
        o = self.orgs[iss]
        if self.flaw == "pinned_once" and o["keyset"] is not None:
            return
        try:
            code, tok = self._get(o["base"] + "/keys")
        except Exception:  # noqa: BLE001
            code, tok = 0, ""
        if code != 200:
            self.fetch_ok[iss] = False
            return
        v = st.verify(tok, o["anchor"], st.KEYSET_TYP)
        if not v.ok:
            return
        if o["keyset"] is None or v.claims["version"] > o["keyset"]["version"]:
            o["keyset"] = v.claims
            for k in v.claims["keys"]:
                o["ever"][k["kid"]] = k

    def _fetch_standing(self, iss: str, principal: str) -> None:
        o = self.orgs.get(iss)
        if o is None or (self.pull_only and not self._polling):
            return
        try:
            code, tok = self._get(o["base"] + "/standing/" + urllib.parse.quote(principal,
                                                                               safe=""))
        except Exception:  # noqa: BLE001 - refused, hung: a fetch error
            code, tok = 0, ""
        if code in (200, 404):
            self.answered.setdefault((iss, principal), self._c().wall())
        if code != 200:
            self.fetch_ok[iss] = code == 404 and self.fetch_ok.get(iss, True)
            return
        self.fetch_ok[iss] = True
        self.boot_fetched = True
        entry = {"token": tok, "received": self._c().wall()}
        self._where()[(iss, principal)] = entry
        if self.flaw == "flaps":
            self.__dict__.setdefault("replica", {})[(iss, principal)] = entry

    def _fetch_snapshot(self, iss: str) -> None:
        """X4-status profile: the newest snapshot, verified under a key A's statement designates
        for status at the snapshot's issue time; never an older version."""
        from conformance import standing as st, status
        o = self.orgs[iss]
        try:
            code, tok = self._get(o["base"] + "/status/list")
        except Exception:  # noqa: BLE001
            code, tok = 0, ""
        if code != 200:
            self.fetch_ok[iss] = False
            return
        ks = o["keyset"] or {}
        kid = st.header_of(tok).get("kid", "")
        v = status.verify(tok, st.keys_of(ks), status.STATUS_TYP)
        if not v.ok or v.claims["issuer"] != iss:
            return
        state, _why = st.key_state(ks, kid, "status", st.epoch_of(v.claims["issued_at"]))
        if state != "a-key":
            return
        cur = self.snaps.get(iss)
        if cur is not None and v.claims["version"] < cur["claims"]["version"]:
            return
        self.fetch_ok[iss] = True
        self.snaps[iss] = {"claims": v.claims, "received": self._c().wall()}

    def _where(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        return self.mem if self.flaw == "accepts_on_boot" else self.store

    def _poll(self) -> None:
        if self.pull_only:
            self._polling = True
            try:
                self._poll_listed()
                self._poll_all()
            finally:
                self._polling = False
            return
        self._poll_all()

    def _poll_listed(self) -> None:
        """Pull only: each principal A's status list names becomes one to fetch for."""
        from conformance import standing as st
        now = self._c().wall()
        for iss, o in list(self.orgs.items()):
            try:
                code, tok = self._get(o["base"] + "/status/list")
            except Exception:  # noqa: BLE001 - the source is down: nothing new is listed
                continue
            if code == 200 and tok:
                for p in (st.peek(tok).get("standing") or {}):
                    self.known.setdefault((iss, p), now)

    def _poll_all(self) -> None:
        for iss in list(self.orgs):
            self._fetch_keys(iss)
            if self.x4:
                self._fetch_snapshot(iss)
        now = self._c().wall()
        for (iss, p), used in list(self.known.items()):
            if now - used <= 3 * self.T:
                self._fetch_standing(iss, p)
            else:
                self.known.pop((iss, p), None)

    def _start_polls(self) -> None:
        c = self._c()
        self._polls.append(c.call_every(lambda: self.T / 4.0, self._poll))

    def _stop_polls(self) -> None:
        c = self._clock
        for h in self._polls:
            if c is not None:
                c.cancel(h)
        self._polls = []

    # the standing check ---------------------------------------------------------------------

    def _keyset(self, iss: str) -> Optional[Dict[str, Any]]:
        o = self.orgs.get(iss)
        return o["keyset"] if o else None

    def _verify_assertion(self, tok: str, root_iss: str, agent_key: Dict[str, Any]
                          ) -> Tuple[Optional[Dict[str, Any]], str]:
        """(claims, '') when the assertion's signature is acceptable to this toy, for a chain
        rooted at `root_iss`."""
        from conformance import standing as st
        kid = st.header_of(tok).get("kid", "")
        claimed = st.peek(tok)
        if self.flaw == "trusts_agent_assertion" and kid == agent_key.get("kid"):
            v = st.verify(tok, {kid: bytes.fromhex(agent_key["public_key"])}, st.STANDING_TYP)
            return (v.claims, "") if v.ok else (None, "bad signature")
        if self.flaw == "any_pinned_key":
            for iss, o in self.orgs.items():
                ks = o["keyset"] or {}
                if any(k["kid"] == kid for k in ks.get("keys") or ()):
                    v = st.verify(tok, st.keys_of(ks), st.STANDING_TYP)
                    if v.ok:
                        s, why = st.key_state(ks, kid, "standing", st.epoch_of(
                            v.claims.get("issued_at")))
                        return (v.claims, "") if s == "a-key" else (None, why)
            return None, "no pinned key"
        iss = claimed.get("issuer") if self.flaw in ("issuer_unchecked",) else root_iss
        if self.flaw == "leaf_org_standing" and getattr(self, "_leaf_org", None) \
                and claimed.get("issuer") == self._leaf_org:
            iss = self._leaf_org
        ks = self._keyset(str(iss))
        if ks is None:
            return None, f"no key statement for {iss}"
        if self.flaw == "ignores_key_state":
            keys = {k: bytes.fromhex(e["public_key"]) for k, e in self.orgs[iss]["ever"].items()
                    if "standing" in e["purposes"]}
            v = st.verify(tok, keys, st.STANDING_TYP)
            return (v.claims, "") if v.ok else (None, v.reason or "")
        v = st.verify(tok, st.keys_of(ks), st.STANDING_TYP)
        if not v.ok:
            return None, f"{v.reason}"
        purpose = "standing"
        if self.flaw == "purpose_unchecked":
            purposes = next((k["purposes"] for k in ks["keys"] if k["kid"] == kid), [])
            purpose = purposes[0] if purposes else "standing"
        s, why = st.key_state(ks, kid, purpose, st.epoch_of(v.claims.get("issued_at")))
        if s != "a-key":
            return None, why
        if self.flaw not in ("issuer_unchecked", "leaf_org_standing") and \
                v.claims.get("issuer") != root_iss:
            return None, "another organisation's evidence"
        return v.claims, ""

    def _age_ok(self, claims: Dict[str, Any], received: float, iss: str) -> bool:
        from conformance import standing as st
        now = self._c().wall()
        issued = st.epoch_of(claims.get("issued_at")) or 0.0
        na = st.epoch_of(claims.get("not_after")) or 0.0
        if now > na:
            return False
        if self.flaw == "trusts_expiry":
            return True
        if self.flaw == "fails_open_offline" and self.fetch_ok.get(iss) is False:
            return True
        if self.flaw == "age_from_fetch":
            age = now - received
        elif self.flaw == "trusts_issuer_time":
            age = now - issued
        else:
            age = now - min(issued, received)
        return age <= self.T / 2.0

    def _standing(self, chain: List[Dict[str, Any]], values: Dict[str, Any],
                  staple: Optional[str], endpoint: str = "") -> Optional[str]:
        """None if the chain's root principal has current standing for this operation."""
        from conformance import standing as st
        if self.x4:
            return self._standing_x4(chain, values)
        if self.flaw in ("no_check", "agent_key_only"):
            return None
        if self.pull_only:
            staple = None                      # never read: standing only by fetching
        root, leaf = chain[-1], chain[0]
        root_iss, principal = root["issuer"], root["principal"]
        op = values.get("operation")
        leaf_org = self._org_of_source(leaf["status"]["source"])
        self._leaf_org = leaf_org
        if self.flaw == "leaf_standing_only":
            root_iss, principal = leaf_org or root_iss, leaf["principal"]
        self.known[(root_iss, principal)] = self._c().wall()
        if self.flaw == "online_only" and self.fetch_ok.get(root_iss) is False:
            return "standing-unavailable: a fetch failed"
        ent = self._where().get((root_iss, principal))
        if self.flaw == "flaps" and endpoint == "e2":
            ent = self.__dict__.get("replica", {}).get((root_iss, principal), ent)
        stale = ent is None or (self._c().wall() - ent["received"] > self.T / 4.0)
        if self.flaw == "trusts_issuer_time" and ent is not None:
            c = st.peek(ent["token"])
            stale = self._c().wall() - (st.epoch_of(c.get("issued_at")) or 0) > self.T / 4.0
        if stale or ent is None:
            self._fetch_standing(root_iss, principal)
            ent = self._where().get((root_iss, principal), ent)
        if self.flaw == "accepts_on_boot" and ent is None and not self.boot_fetched:
            return None                                  # nothing known since boot: accept
        if self.flaw == "chain_before_fetch" and ent is None and \
                (root_iss, principal) not in self.answered:
            return None                                  # nothing fetched yet: the chain alone
        cands: List[Tuple[str, float]] = []
        if ent is not None:
            cands.append((ent["token"], ent["received"]))
        if staple:
            cands.append((staple, self._c().wall()))
        why = "no standing evidence for the root principal"
        for tok, received in cands:
            claims, problem = self._verify_assertion(tok, root_iss, leaf["agent_key"])
            if claims is None:
                why = f"standing evidence refused: {problem}"
                continue
            leaf_staple = self.flaw == "leaf_org_standing" and claims.get("issuer") == \
                self._leaf_org and claims.get("issuer") != root_iss
            if self.flaw != "principal_unchecked" and not leaf_staple and \
                    claims.get("principal") != principal:
                why = "the evidence names another principal"
                continue
            if self.flaw != "class_unchecked" and op not in (claims.get("classes") or {}):
                why = "the evidence does not cover this operation"
                continue
            au = claims.get("audience")
            if self.flaw != "audience_unchecked" and au is not None and PARTY not in au:
                why = "the evidence is addressed to another relying party"
                continue
            flap_e2 = self.flaw == "flaps" and endpoint == "e2"
            if not flap_e2 and not self._age_ok(claims, received, root_iss):
                why = "standing-stale"
                continue
            return None
        return why

    def _org_of_source(self, source: str) -> Optional[str]:
        for iss, o in self.orgs.items():
            if source.startswith(o["base"]):
                return iss
        return None

    # the entry point ------------------------------------------------------------------------

    def _anchors(self) -> Dict[str, Dict[str, Any]]:
        return {iss: o["keyset"] for iss, o in self.orgs.items() if o["keyset"]}

    def _read_x4(self, p: Any) -> Tuple[Optional[str], Any, Any]:
        """A grant 0.1 chain, every grant signed by its issuer's grant key (by A's statement)."""
        from conformance import authz, requester, standing as st, status
        toks = [p.headers.get(requester.GRANT_HEADER) or ""] + [
            t for t in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if t]
        chain = []
        for tok in toks:
            iss = str(st.peek(tok).get("issuer"))
            ks = self._keyset(iss) or {}
            kid = st.header_of(tok).get("kid", "")
            v = status.verify(tok, st.keys_of(ks), status.GRANT_TYP)
            if not v.ok:
                return f"grant {v.reason}", None, None
            if st.key_state(ks, kid, "grant", st.epoch_of(v.claims["issued_at"]))[0] != "a-key":
                return "grant signed by a key that is not A's for grants", None, None
            if chain and v.claims["grant_id"] != chain[-1]["parent"]:
                return "grant chain does not link", None, None
            if chain and (v.claims["issuer"] != chain[-1]["issuer"]
                          or chain[-1]["ceiling"]["max_amount"] > v.claims["ceiling"]["max_amount"]
                          or v.claims["operation"] != chain[-1]["operation"]):
                return "grant chain widens or crosses organisations", None, None
            chain.append(v.claims)
        if not chain or chain[-1]["parent"] is not None:
            return "grant chain is incomplete", None, None
        leaf = chain[0]
        ak = leaf["agent_key"]
        v = authz.verify_authorisation(p.authorisation,
                                       {ak["kid"]: bytes.fromhex(ak["public_key"])})
        if not v.ok or v.claims["issuer"] != leaf["subject"] or \
                v.claims.get("grant_id") != leaf["grant_id"] or leaf["audience"] != PARTY:
            return "authorisation does not verify under the grant", None, None
        if v.claims["binding"]["request_digest"] != authz.binding_digest(p.request):
            return "payload-mismatch", None, None
        values = json.loads(p.request.decode("utf-8"))
        if status.within(values, leaf["ceiling"]):
            return "over-ceiling", None, None
        return None, chain, values

    def _standing_x4(self, chain: List[Dict[str, Any]], values: Dict[str, Any]) -> Optional[str]:
        from conformance import status
        if self.flaw == "no_check":
            return None
        root = chain[-1]
        snap = self.snaps.get(root["issuer"])
        if snap is None:
            return "standing-unavailable"
        c = snap["claims"]
        now = self._c().wall()
        if self.flaw != "fails_open_offline" or self.fetch_ok.get(root["issuer"]) is not False:
            if now - min(status.epoch_of(c["issued_at"]), snap["received"]) > self.T / 2.0:
                return "standing-stale"
        st = status.chain_state(c, chain)
        if st["state"] not in status.IN_FORCE:
            return f"standing: {st['why']}"
        return None

    def _read(self, p: Any) -> Tuple[Optional[str], Any, Any]:
        if self.x4:
            return self._read_x4(p)
        from conformance import attenuation, authz, requester, standing as st
        toks = [p.headers.get(requester.GRANT_HEADER) or ""] + [
            t for t in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if t]
        if not toks[0]:
            return "no grant", None, None
        hops, problem = st.verify_holder_chain(toks, self._anchors())
        if problem:
            return f"grant chain: {problem}", None, None
        chain = [h.claims for h in hops]
        if len(chain) > (self.max_depth() or 99):
            return "chain deeper than stated", None, None
        al = attenuation.allowed(chain)
        if isinstance(al, attenuation.Refusal):
            return f"grant chain: {al.reason}", None, None
        leaf = chain[0]
        ak = leaf["agent_key"]
        v = authz.verify_authorisation(p.authorisation,
                                       {ak["kid"]: bytes.fromhex(ak["public_key"])})
        if not v.ok:
            return f"authorisation {v.reason}", None, None
        c = v.claims
        if c["issuer"] != leaf["subject"] or c.get("grant_id") != leaf["grant_id"] \
                or c["audience"]["counterparty"] != PARTY:
            return "not under this grant, or not for this B", None, None
        if c["binding"]["request_digest"] != authz.binding_digest(p.request,
                                                                  c["binding"]["basis"]):
            return "payload-mismatch", None, None
        now = self._c().wall()
        if not (authz.epoch(c["not_before"]) - 5 <= now <= authz.epoch(c["not_after"]) + 5):
            return "expired", None, None
        values = json.loads(p.request.decode("utf-8"))
        if values.get("operation") != c["operation"]:
            return "operation-mismatch", None, None
        out = attenuation.inside(values, al, at=now, tolerance_s=5.0, party=PARTY)
        if out:
            return f"outside the grant: {out}", None, None
        return None, chain, values

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        from conformance import standing as st
        why, chain, values = self._read(p)
        if why:
            ans = _answer("refused", why)
        else:
            why = self._standing(chain, values, p.headers.get(st.STANDING_HEADER), p.endpoint)
            ans = _answer("refused", why) if why else self._effect(chain, values)
        if self.delays and self.clock == "real":
            import time
            time.sleep(self._delay(ans))
        return ans

    def _delay(self, ans: Dict[str, Any]) -> float:
        code = (ans.get("body") or {}).get("code") if isinstance(ans, dict) else None
        return self.delays.get(code, 0.0) * self.T

    def present_deferred(self, p: Any, session: Optional[str], deliver: Any) -> None:
        delays, self.delays = self.delays, {}
        try:
            ans = self.present(p, session=session)
        finally:
            self.delays = delays
        d = self._delay(ans)
        if d <= 0:
            deliver(ans)
            return
        c = self._c()
        c.call_at(c.now() + d, lambda: deliver(ans))

    def _effect(self, chain: List[Dict[str, Any]], values: Dict[str, Any]) -> Dict[str, Any]:
        url = (f"{self.recorder}/effect/{secrets.token_hex(6)}" if not self.no_control
               else f"{self.recorder.rsplit('/p20/', 1)[0]}/elsewhere/{secrets.token_hex(4)}")
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
        if self.flaw != "checks_on_arrival_only" and self._standing(chain, values, None):
            return                                   # aged since: dropped
        self._effect(chain, values)


def make(flaw: Optional[str] = None, *, x4: bool = False, **kw: Any) -> ToyStanding:
    return ToyStanding(("x4-" if x4 else "") + ("bad" if flaw else "good"), flaw, **kw)


def toy(config: str) -> ToyStanding:
    """The toy for a known-bad configuration name (``good``, ``bad:<flaw>``, ``x4-good``,
    ``x4-bad:<flaw>``, ``no-control``, ``slow-good``, ``pull-good``)."""
    x4 = config.startswith("x4-")
    rest = config[3:] if x4 else config
    if rest.startswith("bad:"):
        return make(rest[4:], x4=x4)
    return ToyStanding(("x4-" if x4 else "") + rest)
