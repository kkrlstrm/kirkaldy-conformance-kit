"""The stub A for KRK-25 (P25): X1's `issuer.StubIssuer`, extended with principals, disclosures and
the presentations that carry them.

`X6-COUNTERPARTY-DISCLOSURE-DESIGN.md` §2.1, §2.3 and §6.3. `StubDiscloser` subclasses the X1 and
X5 stub, so `issuer.py`, `requester.py` and `standing.py` are not edited. What it
adds:

- **Principals** (`principal`): fresh test identities from the operating system, never from the
  seed (KRK-M186). Mixed case, so a B that folds case is seen doing it (KRK-M187).
- **The person's own credential** (`person`): a key the principal holds for B's direct path, never
  listed in A's key statement, so a direct request carries no agent credential (KRK-M178).
- **Pseudonyms and commitments** (`pseudonym`, `commit`): A's pairwise secret and per-principal
  salts are kept here and never leave A.
- **Disclosures** (`disclose`): A's statement for one request, signed under A's ``standing`` key, or genuinely by the agent's own key (``self_asserted/agent_signed``), unsigned
  (``unsigned``), or by another organisation's ``standing`` key (A′, ``other_issuer``). Every one is
  in `disclosure_log` with its kit-clock time and the link a fixture breaks.
- **Presentations** (`presentation`, `chain_presentation`): the agent's own X3 authorisation over
  the request bytes, the disclosure in `disclosure.HEADER`, and any asserted member a fixture adds
  (a header, a query parameter in a ``?``-key, or a body member already in the bytes).
- **Reads** (`read_request`): an agent's own signed request to read one of B's operations, for
  the answers clause (d) searches.
- **The second wire format** (`act_token`): an RFC 8693-shaped delegated token, for a B that reads
  that form. Version 1 of the probe presents only the kit's own statement (design §2.3 note;
  build note 13.4).

**Never forge.** Every statement is signed by the key of the party it names as its signer, or by
nothing. A foreign disclosure is a real statement for another request, agent or organisation,
presented as its signer made it. Nothing is altered or re-signed after signing.
"""
from __future__ import annotations

import dataclasses
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import authz, disclosure as dz, receipts, requester
from .authz import Presentation
from .issuer import Grant2, StubIssuer
from .receipts import Keypair

LIFETIME_S = 600
"""How long a disclosure is valid by its own ``not_after``: far beyond a trial."""
READ_OPERATION = "krk.read"


@dataclass(frozen=True)
class Disclosure:
    """One statement the stub, an agent, or another organisation made."""

    token: str
    claims: Dict[str, Any]
    signer: str
    """``a`` (the issuer's standing key), ``agent`` (the agent's own key), ``none`` (unsigned)."""
    org: str
    """The organisation whose stub made it (the issuer's for ``a``, the agent's holder's for
    ``agent`` and ``none``)."""
    request_digest: Optional[str]
    t_signed: float
    """Kit clock."""
    broken: Optional[str] = None
    """The link this statement breaks for the request it is presented with, for a fixture."""


class StubDiscloser(StubIssuer):
    """Org A for X6: X1's stub with principals, pairwise pseudonyms, commitments and
    disclosures (module docstring)."""

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.pair_secret = secrets.token_bytes(32)
        self._salts: Dict[str, bytes] = {}
        self._persons: Dict[str, Keypair] = {}
        self._dlog: List[Disclosure] = []
        self._dlock = threading.Lock()

    # principals ------------------------------------------------------------------------------

    @property
    def host(self) -> str:
        return self.issuer.rsplit(":", 1)[-1]

    def principal(self) -> str:
        """A fresh principal of this organisation, from the operating system (KRK-M186). Mixed
        case on purpose (KRK-M187)."""
        return f"Pr-{secrets.token_hex(5).upper()}x{secrets.token_hex(3)}@{self.host}"

    def person(self, principal: str) -> Keypair:
        """The principal's own credential for B's direct path. Never in A's key statement."""
        with self._dlock:
            if principal not in self._persons:
                self._persons[principal] = Keypair.generate(f"person-{secrets.token_hex(4)}")
            return self._persons[principal]

    def person_kids(self) -> List[str]:
        with self._dlock:
            return sorted(k.kid for k in self._persons.values())

    def pseudonym(self, principal: str, audience: str) -> str:
        return dz.pairwise(self.pair_secret, principal, audience)

    def commit(self, principal: str) -> str:
        with self._dlock:
            salt = self._salts.setdefault(principal, secrets.token_bytes(16))
        return dz.commitment(principal, salt)

    def principal_claim(self, principal: str, level: str, audience: str) -> Dict[str, Any]:
        if level == "named":
            return dz.principal_named(principal)
        if level == "pairwise":
            return dz.principal_pairwise(self.pseudonym(principal, audience))
        if level == "organisation":
            return dz.principal_organisation(self.commit(principal))
        raise ValueError(f"level {level!r} has no principal claim")

    def needles(self, principal: str, audience: str) -> Dict[str, Tuple[str, str]]:
        """Every identifier the kit drew for `principal`, with its kind (`disclosure.NEEDLE_KINDS`):
        the named id, the pairwise pseudonym for `audience`, the commitment, and the kit's own
        plain SHA-256 of the named id (KRK-M184)."""
        return {"named": ("named", principal),
                "pairwise": ("pairwise", self.pseudonym(principal, audience)),
                "commitment": ("commitment", self.commit(principal)),
                "hash": ("hash", dz.plain_hash(principal))}

    # disclosures -----------------------------------------------------------------------------

    def disclose(self, request: bytes, *, agent: str, principal: str, level: str,
                 audience: str, authorisation_id: Optional[str] = None, signer: str = "a",
                 holder: Optional[StubIssuer] = None, agent_org: Optional[str] = None,
                 broken: Optional[str] = None, lifetime_s: float = LIFETIME_S) -> Disclosure:
        """A statement that `request` is made by `agent` for `principal` at `level`, for
        `audience`. `holder` is the organisation holding the agent's key (this one by default; C
        for a chain into C), and `agent_org` the organisation the statement names for the agent
        (the holder's by default). `signer`: ``a`` (this organisation's standing key), ``agent``
        (the agent's own key), ``none`` (unsigned)."""
        holder = holder or self
        key = holder.agent(agent)
        now = self.now()
        claims = dz.disclosure_claims(
            issuer=self.issuer, audience=audience,
            actor={"kind": "agent", "id": agent, "org": agent_org or holder.issuer},
            principal=self.principal_claim(principal, level, audience),
            request_digest=authz.binding_digest(request), authorisation_id=authorisation_id,
            agent_key=key.kid, issued_at=now, not_after=now + lifetime_s)
        if signer == "a":
            tok, org = dz.sign(claims, self.std_key), self.issuer
        elif signer == "agent":
            tok, org = dz.sign(claims, key), holder.issuer
        elif signer == "none":
            tok, org = dz.unsigned(claims), holder.issuer
        else:
            raise ValueError(f"unknown signer {signer!r}")
        d = Disclosure(tok, claims, signer, org, claims["request_digest"], self.clock.now(),
                       broken)
        with self._dlock:
            self._dlog.append(d)
        return d

    def disclosure_log(self) -> List[Disclosure]:
        with self._dlock:
            return list(self._dlog)

    def act_token(self, *, agent: str, principal: str, audience: str,
                  holder: Optional[StubIssuer] = None) -> str:
        """An RFC 8693-shaped delegated token signed under A's standing key: ``sub`` the
        principal, ``act.sub`` the agent, ``aud`` B. It binds to no request."""
        holder = holder or self
        now = int(self.now())
        claims = {"iss": self.issuer, "sub": principal, "aud": audience,
                  "act": {"sub": agent, "org": holder.issuer}, "iat": now, "exp": now + 600,
                  "jti": f"act-{secrets.token_hex(8)}"}
        return receipts.sign_payload(receipts.canonical_json(claims), self.std_key,
                                     {"alg": "EdDSA", "kid": self.std_key.kid,
                                      "typ": dz.ACT_TYP})

    # presentations ---------------------------------------------------------------------------

    def authorise(self, raw: bytes, *, subject: str, audience: Dict[str, Any],
                  operation: str, holder: Optional[StubIssuer] = None,
                  grant_id: Optional[str] = None, key: Optional[Keypair] = None,
                  window_s: Tuple[float, float] = (-900.0, 900.0)) -> Tuple[str, Dict[str, Any]]:
        """The agent's own X3 authorisation over `raw` (exact, canonical basis), signed by its key
        (held by `holder`), or by `key` for the person's direct request."""
        holder = holder or self
        k = key or holder.agent(subject)
        t = self.clock.wall()
        claims = authz.authorisation_claims(
            issuer=subject, audience=audience, operation=operation,
            binding=authz.exact_binding(raw), max_uses=1,
            not_before=authz.utc(t + window_s[0]), not_after=authz.utc(t + window_s[1]),
            decision_digest=None, extra={"grant_id": grant_id} if grant_id else None)
        tok = authz.sign_authorisation(claims, k)
        self.issued.append({**claims, "token": tok, "signer": "person" if key else "agent"})
        return tok, claims

    def presentation(self, raw: bytes, *, subject: str, audience: Dict[str, Any],
                     operation: str, disclosure: Optional[Disclosure] = None,
                     extra_headers: Optional[Dict[str, str]] = None,
                     holder: Optional[StubIssuer] = None) -> Tuple[Presentation, Dict[str, Any]]:
        """One fresh request `raw` by agent `subject`: its own authorisation, `disclosure` in
        `disclosure.HEADER`, and `extra_headers` (an asserted member) beside it. Returns the
        presentation and the authorisation's claims."""
        tok, claims = self.authorise(raw, subject=subject, audience=audience,
                                     operation=operation, holder=holder)
        h: Dict[str, str] = {}
        if disclosure is not None:
            h[dz.HEADER] = disclosure.token
        h.update(extra_headers or {})
        return (Presentation(pid=f"d{secrets.token_hex(6)}",
                             endpoint=audience.get("endpoint") or "default",
                             tenant=audience.get("tenant"), request=raw, authorisation=tok,
                             headers=h), claims)

    def chain_presentation(self, grant: Grant2, values: Dict[str, Any], *,
                           audience: Dict[str, Any], disclosure: Disclosure) -> Presentation:
        """X5's presentation under a holder chain (`issuer.StubIssuer.under_v2`), with the
        disclosure added beside it. The disclosure must name the bytes `under_v2` sends."""
        p = self.under_v2(grant, values, audience=audience)
        if authz.binding_digest(p.request) != disclosure.request_digest:
            raise ValueError("the disclosure names other bytes than the chain presentation sends")
        return dataclasses.replace(p, headers={**p.headers, dz.HEADER: disclosure.token})

    def read_request(self, subject: str, op_id: str, *, audience: Dict[str, Any],
                     holder: Optional[StubIssuer] = None) -> Presentation:
        """Agent `subject`'s own signed request to read B's operation `op_id`."""
        raw = requester.request_bytes({"operation": READ_OPERATION, "op_id": op_id,
                                       "ref": secrets.token_hex(8)})
        p, _c = self.presentation(raw, subject=subject, audience=audience,
                                  operation=READ_OPERATION, holder=holder)
        return p
