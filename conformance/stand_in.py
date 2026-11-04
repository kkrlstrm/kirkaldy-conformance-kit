"""The stand-in agent A and the person at B's page, for B-issuer modules (design §2.2, §2.3).

The generic part lives here and fixes what a driver may do; the product-specific part is the
adapter's (``targets/<product>/``, or a toy in ``known_bad/``):

- **Identities** are fresh per pair: a client id and keys from the operating system
  (`AgentIdentity.fresh`, KRK-M36).
- **One consent per pair**, made through the hook at the start of the pair and recorded. Every
  further consent or per-object approval is a step the probe asks for; a driver never consents,
  refreshes or re-polls on its own (KRK-M139). The probe checks it: the hook's own log
  (`PersonHook.log`) must hold exactly the records the probe asked for.
- **Every presentation** that can cause an effect is built by the stand-in as a
  `authz.Presentation` and sent by the kit's `requester.Transport`, as raw bytes, once. Protocol
  proofs that must be fresh per request (a DPoP proof, a client assertion) are built by the
  stand-in per presentation, travel in ``headers``, and are outside the exact layer (rule 4).
- **The hook** supplies only what a person would supply, through one of `bissuer.HOOKS`. It never
  writes B's store, calls B's code in process, or uses a route that issues the credential or
  marks a consent approved by itself (KRK-M133).

The design's ``AgentKeySource`` (the kit's server for agent key metadata) belongs to P20B's link 2
and is not built in phase 1a; P18B does not read agent keys at B. It will go in a new module, so
this file need not change.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from .bissuer import HOOKS, BObject

DECISIONS = ("approved", "declined")


@dataclass
class AgentIdentity:
    """One stand-in identity: its own client id and key, fresh per pair (KRK-M36)."""

    client_id: str
    kid: str
    private: Any = field(repr=False)
    """An Ed25519 private key from the operating system (`cryptography`)."""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def fresh(cls, base: str = "https://agent.kirkaldy.test/clients") -> "AgentIdentity":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        cid = f"{base}/{secrets.token_hex(8)}"
        return cls(client_id=cid, kid=f"agent-{secrets.token_hex(4)}",
                   private=Ed25519PrivateKey.generate())

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self.private.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)

    def jwk(self) -> Dict[str, Any]:
        from .bissuer import b64e
        return {"kty": "OKP", "crv": "Ed25519", "x": b64e(self.public_bytes()), "kid": self.kid}

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


@dataclass
class ConsentRecord:
    """What the hook did at B's page for one decision (design §6.3)."""

    pair: str
    identity: str
    hook: str
    person: str
    """The test person the hook played: fictitious data the target ships, or a test account
    made through B's documented flow. Never a real person's account."""
    decision: str
    """``approved`` | ``declined``."""
    handle: Dict[str, Any] = field(default_factory=dict)
    """What was decided on: the pair's consent, or one of B's objects by id."""
    shown: Optional[Dict[str, Any]] = None
    """The terms as B's page rendered them, where it shows them (information, KRK-15)."""
    steps: List[Dict[str, Any]] = field(default_factory=list)
    """Each request the hook made, with route and status."""
    credential: Optional[BObject] = None
    """What B issued after the decision, if anything (for the decline check)."""
    at: float = 0.0
    asked_by: str = "probe"
    """``probe`` when the probe asked for this decision; anything else is a driver acting on its
    own (KRK-M139)."""

    def doc(self) -> Dict[str, Any]:
        return {"pair": self.pair, "identity": self.identity, "hook": self.hook,
                "person": self.person, "decision": self.decision, "handle": self.handle,
                "shown": self.shown, "steps": self.steps, "at": self.at,
                "asked_by": self.asked_by,
                "credential": self.credential.doc() if self.credential else None}


class PersonHook(Protocol):
    """The person at B's page. ``kind`` is one of `bissuer.HOOKS`."""

    kind: str
    log: List[ConsentRecord]
    """Every record the hook made, in order, whoever asked for it."""

    def approve(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord: ...

    def decline(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord: ...


class StandInAgent(Protocol):
    """A, as one agent identity at one B. Every method that returns a `Presentation` only builds
    it; the kit sends it. The stand-in decides nothing about binding (KRK-M24, M25): it names B's
    objects as B sent them and writes the body the kit gives it."""

    def identity(self) -> AgentIdentity: ...

    def consent(self, hook: PersonHook, *, tenant: Optional[str], pair: str,
                decision: str = "approve") -> ConsentRecord:
        """The pair's one consent at B's page for this identity at `tenant`; the class
        credential B issues on it is kept by the stand-in and returned in the record."""
        ...

    def request(self, raw: bytes, *, pid: str, tenant: Optional[str],
                endpoint: str) -> Any:
        """Ask B for its exact object for the request whose bytes are `raw`."""
        ...

    def counter(self, obj: BObject, raw: bytes, *, pid: str, tenant: Optional[str],
                endpoint: str) -> Any:
        """``revision`` shape: propose changed terms on `obj` (the request bytes `raw`)."""
        ...

    def read(self, answer: Dict[str, Any], *, endpoint: str) -> List[BObject]:
        """B's objects in one answer, each with the raw bytes B sent."""
        ...

    def person_needed(self, obj: BObject) -> Optional[Dict[str, Any]]:
        """The handle for the hook when `obj` waits for the person's decision at B's page."""
        ...

    def complete(self, obj: BObject, *, pid: str, tenant: Optional[str],
                 endpoint: str) -> Optional[Any]:
        """``rar-token``: redeem an approved request for the token that carries its details.
        None for the other shapes."""
        ...

    def acceptance_body(self, obj: BObject, *, approval: str = "person") -> Dict[str, Any]:
        """The body an honest acceptance of `obj` carries, as a dict the kit serialises:
        ``revision`` names the revision and how it was approved; ``consent-id`` names the consent
        and repeats its terms; ``rar-token`` is the request the token's details describe."""
        ...

    def accept(self, obj: BObject, body: bytes, *, pid: str, tenant: Optional[str],
               endpoint: str, headers: Optional[Dict[str, str]] = None,
               credential_tenant: Optional[str] = None) -> Any:
        """Present `body` as the acceptance of `obj`, under this identity's own credential for
        `credential_tenant` (default `tenant`) and with its own proof."""
        ...

    def class_body(self, values: Dict[str, Any]) -> Dict[str, Any]:
        """The body of the shape's class route for `values` (design §3.1, ``class_for_exact``)."""
        ...

    def class_use(self, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
                  headers: Optional[Dict[str, str]] = None) -> Any:
        """Present `body` on the shape's class route, under the pair's class credential only."""
        ...


def hook_problem(hook: Any, declared: Optional[str]) -> Optional[str]:
    """Why `hook` may not be used, or None (design §2.3)."""
    kind = getattr(hook, "kind", None)
    if kind not in HOOKS:
        return f"the hook's kind is {kind!r}, not one of {HOOKS}"
    if declared and kind != declared:
        return f"the hook's kind {kind!r} is not the one the agreement declares ({declared!r})"
    if not isinstance(getattr(hook, "log", None), list):
        return "the hook keeps no log of the decisions it made (KRK-M139)"
    return None
