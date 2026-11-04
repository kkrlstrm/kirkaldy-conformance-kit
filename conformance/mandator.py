"""The stub principal for KRK-24 (P24): X1's `issuer.StubIssuer`, extended in a subclass.

`X2-MANDATE-BOUND-DESIGN.md` §6.3. `issuer.py` is imported and never edited, because P20 and P21
import it. What the subclass adds:

- **Grant 0.4** (`terms.GRANT_V4_SCHEMA`): `issue_v4` signs grant 0.2's members and ``terms``
  with A's grant key; `restate` signs a holder hop (the parent's agent key, X1's
  `delegate_holder` shape) whose terms restate the parent's with whatever change it is given.
- **Goals** (`goal`): a drawn ``goal_id`` and terms, with members the principal seals at signing.
  A sealed member's disclosure is kept by the principal and handed to the agent; whether the agent
  presents it is the fixture (`present`).
- **Linked authorisations** (`linked`): a second grant 0.4 whose terms carry ``serves``.
- **Confirmations** (`confirm`): ``kirkaldy.confirmation/0.1``, signed by the principal's key (the
  key B pins for A's grants) or, for ``agent_confirmed``, by the agent's own key. Either way it is
  that party's genuine signature over the real action's digest.
- **Presentations** (`present`): X3's request under the presented chain, with the linked
  authorisation in `LINKED_HEADER`, a confirmation in `CONFIRMATION_HEADER`, disclosures in
  `DISCLOSURES_HEADER`, and the agent's own statements in `PURPOSE_HEADER` and `GOAL_HEADER`.

**Never forge.** Every mandate is the principal's genuine statement, signed by its own key; every
wrong action is the agent's real action under it; nothing is altered after signing (design
§3.2).
"""
from __future__ import annotations

import dataclasses
import json
import secrets
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import attenuation, authz, requester, standing, terms as tm
from .authz import Presentation
from .issuer import Grant2, StubIssuer, LIFETIME_S

LINKED_HEADER = "KRK-Grant-Linked"
CONFIRMATION_HEADER = "KRK-Confirmation"
DISCLOSURES_HEADER = "KRK-Disclosures"
PURPOSE_HEADER = "KRK-Purpose"
GOAL_HEADER = "KRK-Goal"
HEADERS = (requester.GRANT_HEADER, requester.CHAIN_HEADER, LINKED_HEADER, CONFIRMATION_HEADER,
           DISCLOSURES_HEADER, PURPOSE_HEADER, GOAL_HEADER)
"""Every header P24 writes: what a landing check compares (KRK-M154, M156)."""
CONFIRMATION_TTL_MS = 15 * 60 * 1000


class Seal:
    """A term member the principal seals at signing (`goal`, `seal_terms`)."""

    def __init__(self, value: Any) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"Seal({self.value!r})"


def seal_terms(t: Any) -> Tuple[Any, List[List[Any]]]:
    """`t` with every `Seal` replaced by its sealed form under a fresh salt (from the operating
    system), and the disclosures ``[salt, path, value]`` that open them, in document order."""
    disc: List[List[Any]] = []

    def walk(x: Any, path: str) -> Any:
        if isinstance(x, Seal):
            salt = secrets.token_urlsafe(16)
            disc.append([salt, path, x.value])
            return tm.seal(x.value, salt)
        if isinstance(x, dict):
            return {k: walk(v, f"{path}/{k}" if path else str(k)) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v, f"{path}/{i}" if path else str(i)) for i, v in enumerate(x)]
        return x
    return walk(t, ""), disc


def plain_terms(t: Any) -> Any:
    """`t` with every `Seal` replaced by its value: the terms as the principal approved them."""
    if isinstance(t, Seal):
        return t.value
    if isinstance(t, dict):
        return {k: plain_terms(v) for k, v in t.items()}
    if isinstance(t, list):
        return [plain_terms(v) for v in t]
    return t


@dataclasses.dataclass(frozen=True)
class Mandate:
    """One signed grant 0.4 and what the principal keeps beside it."""

    grant: Grant2
    terms: Dict[str, Any]
    """As approved, every sealed member open."""
    disclosures: Tuple[Tuple[str, str, Any], ...] = ()

    @property
    def id(self) -> str:
        return self.grant.id

    @property
    def token(self) -> str:
        return self.grant.token

    @property
    def goal_id(self) -> Optional[str]:
        return self.terms.get("goal_id")


class StubMandator(StubIssuer):
    """The principal's organisation for X2 (module docstring)."""

    def goal(self, *, slots: Any = None, fixed: Any = None, floor: Any = None,
             purpose: Any = None, confirm: Any = None, text: Any = None,
             sealed: Sequence[str] = (), goal_id: Optional[str] = None) -> tm.Goal:
        """A goal: a fresh ``goal_id`` and the terms given, with the top-level members named in
        `sealed` marked to be sealed at signing."""
        t: Dict[str, Any] = {"goal_id": goal_id or tm.new_goal_id()}
        for k, v in (("purpose", purpose), ("slots", slots), ("fixed", fixed),
                     ("floor", floor), ("confirm", confirm), ("text", text)):
            if v is not None:
                t[k] = Seal(v) if k in sealed else v
        return tm.Goal(t["goal_id"], t)

    def issue_v4(self, subject: str, constraints: Dict[str, Any], terms: Dict[str, Any], *,
                 principal: str, parent: Any = None, not_before: Optional[float] = None,
                 not_after: Optional[float] = None, grant_id: Optional[str] = None,
                 raw: bool = False, holder: Optional[StubIssuer] = None) -> Mandate:
        """A grant 0.4 signed by A's grant key for `subject` (an agent `holder`, A by default,
        holds). `terms` may hold `Seal` members, sealed here."""
        holder = holder or self
        agent = holder.agent(subject)
        now = self.now()
        par = parent.id if isinstance(parent, (Grant2, Mandate)) else parent
        claims = self._v2_claims(
            issuer=self.issuer, subject=subject, agent=agent, principal=principal,
            constraints=constraints, parent=par,
            not_before=not_before if not_before is not None else now - 3600,
            not_after=not_after if not_after is not None else now + LIFETIME_S,
            source=self.source_url, index=self._next_index(), grant_id=grant_id, crit=None,
            audience_claim=None, omit=())
        sealed, disc = seal_terms(terms)
        claims["schema"] = tm.GRANT_V4_SCHEMA
        claims["terms"] = sealed
        tok = standing.sign(claims, self.key, standing.GRANT_TYP, raw=raw)
        g = self._record_v2(claims, tok, f"org:{self.issuer}", holder)
        g = dataclasses.replace(g, version="0.4")
        with self._slock:
            self.registry[g.id] = g
        self._publish({g.id: "issued"})
        return Mandate(g, plain_terms(terms), tuple(tuple(d) for d in disc))

    def restate(self, parent: Mandate, subject: str, terms: Dict[str, Any], *,
                constraints: Optional[Dict[str, Any]] = None, org: Optional[StubIssuer] = None,
                principal: Optional[str] = None) -> Mandate:
        """A hop signed by the holder of `parent` (its subject's key), for `subject`, whose key
        `org` holds, restating the terms as `terms` (design §3.1 ``restated_terms``). The
        constraints are the parent's unless given; never wider (raises)."""
        pg = parent.grant
        signer_org: StubIssuer = pg.holder or self
        agent_key = signer_org.agent(pg.subject)
        new_holder = org or signer_org
        sub_key = new_holder.agent(subject)
        c = dict(pg.constraints if constraints is None else constraints)
        claims = signer_org._v2_claims(
            issuer=pg.subject, subject=subject, agent=sub_key,
            principal=principal or pg.principal, constraints=c, parent=pg.id,
            not_before=attenuation._epoch_s(pg.claims.get("not_before")),
            not_after=attenuation._epoch_s(pg.claims.get("not_after")),
            source=signer_org.source_url, index=signer_org._next_index(), grant_id=None,
            crit=None, audience_claim=None, omit=())
        if attenuation.wider(tm.without_terms({**claims, "schema": tm.GRANT_V4_SCHEMA}),
                             tm.without_terms(pg.claims)):
            raise ValueError("a restated hop is never wider than its parent in a limit")
        sealed, disc = seal_terms(terms)
        claims["schema"] = tm.GRANT_V4_SCHEMA
        claims["terms"] = sealed
        tok = standing.sign(claims, agent_key, standing.GRANT_TYP)
        g = signer_org._record_v2(claims, tok, f"holder:{pg.subject}", new_holder)
        g = dataclasses.replace(g, version="0.4")
        with signer_org._slock:
            signer_org.registry[g.id] = g
        signer_org._publish({g.id: "issued"})
        return Mandate(g, plain_terms(terms), tuple(tuple(d) for d in disc))

    def linked(self, goal_id: Optional[str], constraints: Dict[str, Any], *, principal: str,
               subject: Optional[str] = None, holder: Optional[StubIssuer] = None) -> Mandate:
        """A linked authorisation (a payment authority): a grant 0.4 whose terms carry
        ``serves`` (`goal_id`), or name no goal when `goal_id` is None (``unbound``)."""
        t: Dict[str, Any] = {"goal_id": tm.new_goal_id()}
        if goal_id is not None:
            t["serves"] = goal_id
        return self.issue_v4(subject or f"pay-{secrets.token_hex(3)}", constraints, t,
                             principal=principal, holder=holder)

    def confirm(self, m: Mandate, values: Dict[str, Any], *, by: str = "principal",
                loose: bool = False) -> str:
        """A confirmation of the action `values` under mandate `m`: the principal's (signed with
        A's grant key, the key B pins for A) or, with ``by="agent"``, the agent's own (signed with
        the mandate subject's key). The digest is X3's binding digest of the request bytes
        `present` sends for `values`."""
        raw = self.request_raw(values, loose=loose)
        basis = authz.RAW if loose else authz.CANONICAL
        now_ms = int(self.now() * 1000)
        claims = {"schema": tm.CONFIRMATION_SCHEMA,
                  "confirmation_id": "cf-" + secrets.token_hex(8),
                  "goal_id": m.goal_id, "grant_id": m.id,
                  "request_digest": authz.binding_digest(raw, basis),
                  "issued_at": now_ms, "not_after": now_ms + CONFIRMATION_TTL_MS}
        if by == "principal":
            key = self.key
        elif by == "agent":
            key = (m.grant.holder or self).agent(m.grant.subject)
        else:
            raise ValueError(f"by is 'principal' or 'agent', not {by!r}")
        return standing.sign(claims, key, tm.CONFIRMATION_TYP)

    def present(self, chain: Sequence[Mandate], values: Dict[str, Any], *,
                audience: Dict[str, Any], linked: Optional[Mandate] = None,
                confirmation: Optional[str] = None,
                disclosures: Optional[Sequence[Sequence[Any]]] = None,
                asserted_purpose: Optional[str] = None, named_goal: Optional[str] = None,
                loose: bool = False, window_s: Tuple[float, float] = (-900.0, 900.0)
                ) -> Presentation:
        """A fresh request `values` under `chain` (presented grant first), signed by the
        presented grant's agent, with the optional headers (module docstring)."""
        leaf = chain[0].grant
        p = self.under_raw([m.token for m in chain], values, audience=audience,
                           subject=leaf.subject, holder=leaf.holder or self, grant_id=leaf.id,
                           operation=values["operation"], loose=loose, window_s=window_s)
        h = dict(p.headers)
        if linked is not None:
            h[LINKED_HEADER] = linked.token
        if confirmation is not None:
            h[CONFIRMATION_HEADER] = confirmation
        if disclosures:
            h[DISCLOSURES_HEADER] = json.dumps([list(d) for d in disclosures],
                                               separators=(",", ":"), ensure_ascii=False)
        if asserted_purpose is not None:
            h[PURPOSE_HEADER] = asserted_purpose
        if named_goal is not None:
            h[GOAL_HEADER] = named_goal
        return dataclasses.replace(p, headers=h)


def principal_keys(keyset: Dict[str, Any]) -> Dict[str, bytes]:
    """The keys a B that pinned A's key statement reads a principal's confirmation under: A's
    keys for purpose ``grant`` (the principal signs the mandate and its confirmations)."""
    out = {}
    for e in keyset.get("keys") or []:
        if "grant" in (e.get("purposes") or []) and e.get("state") == "active":
            out[e["kid"]] = bytes.fromhex(e["public_key"])
    return out


def headers_digest(headers: Dict[str, str], request: bytes) -> str:
    """KRK-M156, M162: every P24 header and the request bytes, digested: what left the kit, to
    compare with what B says it received."""
    import hashlib
    h = hashlib.sha256()
    for k in HEADERS:
        h.update(f"{k}\0{headers.get(k, '')}\n".encode("utf-8"))
    h.update(b"request\0" + bytes(request))
    return "sha256:" + h.hexdigest()
