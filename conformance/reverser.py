"""The stub A for KRK-23 (P23): X3/X4's `StubRequester`, extended with authorisation 0.2,
reversal requests and a second organisation A′ (`X10-REVERSIBILITY-DESIGN.md` §2.5, §6.3).

Nothing in `requester.py` changes; this subclass adds:

- `authorise_v2`: an authorisation 0.2 (`reversibility.AUTHZ_V2_SCHEMA`), exact over the request
  bytes, carrying ``max_class``, the agent and its grants as A signs them, and, for a reversal,
  the original it reverses;
- `forward`: one forward request as a `Presentation`, values drawn by the caller;
- `request_reversal`: a reversal request in the kit's format, signed by this organisation. A
  reversal from A′ is A′'s own genuine request about an action that is not A′'s: nothing claims to
  be A (§3.2);
- `peer`: A′, a second organisation with its own key, on the same clock (X1's pattern);
- `claim_in_request`: the request values with a class the agent states for its own action
  (``class_claimed_in_request``), a genuine statement of a wrong class;
- `withdraw_agent`: a notice, signed by A, that one of its agents no longer acts for it.

**Never forge.** Every token is signed with this organisation's own key, generated from the
operating system (KRK-M36). Request bytes travel as built, never re-serialised (KRK-M37).
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from . import authz, receipts, reversibility as rv
from .authz import Presentation
from .requester import StubRequester, new_issuer, request_bytes

AGENT_HEADER = "KRK-Agent"
WITHDRAWAL_SCHEMA = "kirkaldy.agent-withdrawal/0.1"
REQ_WINDOW_S = (-900, 3000)
"""Validity of every authorisation the stub signs, around its issue: wide enough for the window
trials, which reverse up to the claim's window after the action."""


class ReversalRequester(StubRequester):
    """Org A (or A′), played by the kit, for X10."""

    def __init__(self, issuer: Optional[str] = None, *, clock: Any = None,
                 audience: str = "did:web:b.example", tenant: Optional[str] = None,
                 name: str = "a") -> None:
        super().__init__(issuer or new_issuer(), clock=clock, audience=audience)
        self.name = name
        self.tenant = tenant
        self.presented: List[Dict[str, Any]] = []
        """Every presentation built, with its claims: the kit's ground truth for judging."""

    # authorisations ------------------------------------------------------------------------

    def authorise_v2(self, request: bytes, *, operation: str, max_class: str,
                     endpoint: Optional[str], agent: Optional[str] = None,
                     grants: Optional[List[str]] = None,
                     reverses: Optional[Dict[str, str]] = None) -> str:
        now = self.now()
        claims = rv.authorise_v2_claims(
            issuer=self.issuer,
            audience={"counterparty": self.audience, "endpoint": endpoint, "tenant": self.tenant},
            operation=operation, request=request, max_class=max_class,
            agent={"id": agent, "grants": list(grants or [operation])} if agent else None,
            not_before=authz.utc(now + REQ_WINDOW_S[0]),
            not_after=authz.utc(now + REQ_WINDOW_S[1]), reverses=reverses)
        tok = rv.sign_v2(claims, self.key)
        self.issued.append({**claims, "token": tok})
        return tok

    def forward(self, values: Dict[str, Any], *, operation: str, max_class: str,
                endpoint: str, agent: str, grants: Optional[List[str]] = None,
                label: str = "") -> Presentation:
        """One forward request: the values as raw bytes and an authorisation 0.2 over them."""
        body = request_bytes({**values, "operation": operation, "agent": agent})
        tok = self.authorise_v2(body, operation=operation, max_class=max_class,
                                endpoint=endpoint, agent=agent, grants=grants)
        p = Presentation(pid=f"{label or 'p'}-{secrets.token_hex(4)}", endpoint=endpoint,
                         tenant=self.tenant, request=body, authorisation=tok,
                         headers={AGENT_HEADER: agent})
        self.presented.append({"pid": p.pid, "label": label, "operation": operation,
                               "max_class": max_class, "agent": agent,
                               "authorisation_id": authz.claims_of(tok)["authorisation_id"]})
        return p

    def request_reversal(self, original: Presentation, *, means: Dict[str, Any], agent: str,
                         grants: Optional[List[str]] = None, endpoint: Optional[str] = None,
                         request_id: Optional[str] = None, label: str = "") -> Presentation:
        """A reversal of `original`, signed by this organisation. `request_id` repeats a
        reversal's id (``new_request_id`` passes a fresh one); the id is fresh by default."""
        oc = authz.claims_of(original.authorisation) or {}
        op = means.get("operation") or "krk.reverse"
        vals = rv.reversal_values(oc, original.request, means_operation=op,
                                  request_id=request_id or f"rq-{secrets.token_hex(8)}",
                                  agent=agent)
        body = request_bytes(vals)
        ep = endpoint or means.get("endpoint") or original.endpoint
        tok = self.authorise_v2(body, operation=op, max_class="irreversible", endpoint=ep,
                                agent=agent, grants=grants if grants is not None else [op],
                                reverses=vals["reverses"])
        p = Presentation(pid=f"{label or 'rev'}-{secrets.token_hex(4)}", endpoint=ep,
                         tenant=self.tenant, request=body, authorisation=tok,
                         headers={AGENT_HEADER: agent})
        self.presented.append({"pid": p.pid, "label": label, "operation": op,
                               "reverses": vals["reverses"], "request_id": vals["request_id"],
                               "agent": agent, "org": self.name})
        return p

    def repeat(self, p: Presentation, label: str = "") -> Presentation:
        """The same bytes and the same authorisation again, under a new kit id (the kit's
        own id is never sent to B)."""
        return Presentation(pid=f"{label or 'again'}-{secrets.token_hex(4)}", endpoint=p.endpoint,
                            tenant=p.tenant, request=p.request, authorisation=p.authorisation,
                            headers=dict(p.headers))

    # A′ and the agent's own statements -------------------------------------------------------

    def peer(self, name: str = "a_prime") -> "ReversalRequester":
        return ReversalRequester(new_issuer(), clock=self.clock, audience=self.audience,
                                 tenant=self.tenant, name=name)

    @staticmethod
    def claim_in_request(values: Dict[str, Any], cls: str) -> Dict[str, Any]:
        """The values with the class the agent states for its own action. B never decides on it
        (decision 3); the stub states it genuinely."""
        return {**values, "class": cls, "reversibility": {"class": cls, "by": "agent"}}

    def withdraw_agent(self, agent: str) -> str:
        """A's signed notice that `agent` no longer acts for it."""
        claims = {"schema": WITHDRAWAL_SCHEMA, "issuer": self.issuer, "agent": agent,
                  "issued_at": authz.utc(self.now())}
        return receipts.sign_payload(receipts.canonical_json(claims), self.key,
                                     {"alg": "EdDSA", "kid": self.key.kid,
                                      "typ": "krk-withdrawal+jws"})


def presentation_claims(p: Presentation) -> Dict[str, Any]:
    return authz.claims_of(p.authorisation) or {}
