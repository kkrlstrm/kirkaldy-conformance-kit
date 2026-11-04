"""The kit's parties for KRK-26 (P26): A's stand-in, the stub translator T′, the faithful receiver
R′, the source receiver S′ and the recorder.

`X11-TRANSLATION-DESIGN.md` §2.5 and §6.3.

- **`StandInA`** issues originals in ``kirkaldy.authority/0.1`` with its own key, generated from
  the operating system. It signs each original once and never changes, re-signs or backdates one
  (spec §3.9, KRK-M209); `issued` keeps every original's bytes.
- **`StubTranslator`** (T′, topology R) signs translated forms with its own key. Its faithful path
  (`translate`) writes the kit's image; its widening path (`translate_wider`) and its unbound path
  (`unbound`) are separate named calls, so a wider form is never made by accident. Every form it
  signs is one it really issued: it is out of scope, never forged.
- **`FaithfulReceiver`** (R′, topology T) enacts a request under a translated form exactly as the
  target documents its members (`semantics`, quoted by the target): an enforced member constrains,
  an informational member or an ignorable extension does not, and absence means what the target
  says it means (KRK-M197, M203). A member it has no documented semantics for, or one the decoder
  could not read, is a gap: R′ commits nothing under that form and says why.
- **`SourceReceiver`** (S′) enacts a request under a source-format form a translator wrote back
  (`retranslation/round_trip`).
- **`Recorder`** keeps every committed effect with its currency, minor units and unit, so every
  comparison goes through the original's own terms (KRK-M200).
"""
from __future__ import annotations

import copy
import secrets
import threading
from typing import Any, Dict, List, Optional

from . import translation as tr
from . import translation_formats as fmt
from .receipts import Keypair


def fresh(prefix: str, n: int = 8) -> str:
    """A fresh identifier from the operating system, never from the seed (KRK-M36)."""
    return f"{prefix}-{secrets.token_hex(n)}"


class Recorder:
    """The kit's recorder: every committed effect, by request id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.effects: List[Dict[str, Any]] = []

    def commit(self, effect: Dict[str, Any], *, by: str) -> None:
        with self._lock:
            self.effects.append({**copy.deepcopy(effect), "committed_by": by})

    def for_request(self, request_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.effects if e.get("request_id") == request_id]


class StandInA:
    """Organisation A's stand-in: issues originals honestly under its own key."""

    def __init__(self) -> None:
        self.issuer = f"did:web:a-{secrets.token_hex(4)}.example"
        self.key = Keypair.generate(fresh("a-key", 4))
        self.issued: List[Dict[str, Any]] = []

    def public(self) -> Dict[str, bytes]:
        return {self.key.kid: self.key.public_bytes()}

    def issue(self, claims: Dict[str, Any]) -> bytes:
        body = {"issuer": self.issuer, "authority_id": fresh("au"), **claims}
        raw = fmt.write_authority(body, self.key)
        self.issued.append({"authority_id": body["authority_id"], "raw": raw})
        return raw


class StubTranslator:
    """T′: the kit's translator in topology R."""

    def __init__(self) -> None:
        self.id = f"did:web:t-{secrets.token_hex(4)}.example"
        self.key = Keypair.generate(fresh("t-key", 4))
        self.signed: List[Dict[str, Any]] = []

    def public(self) -> Dict[str, bytes]:
        return {self.key.kid: self.key.public_bytes()}

    def _write(self, members: Dict[str, Any], *, sub: str, orig: Optional[str], iat: int,
               path: str) -> bytes:
        raw = fmt.write_translated(members, self.key, issuer=self.id, sub=sub, orig=orig,
                                   iat=iat, token_id=fresh("tx"))
        self.signed.append({"path": path, "raw": raw, "members": copy.deepcopy(members)})
        return raw

    def translate(self, original: Dict[str, Any], raw: bytes, profile: Dict[str, Any],
                  sem: Dict[str, Any], *, iat: int) -> Any:
        """The faithful image, signed; a `translation.Refusal` when there is none."""
        members = tr.image(original, profile, sem)
        if isinstance(members, tr.Refusal):
            return members
        return self._write(members, sub=original.get("subject", ""), orig=fmt.digest(raw),
                           iat=iat, path="translate")

    def translate_wider(self, original: Dict[str, Any], raw: bytes, members: Dict[str, Any], *,
                        iat: int) -> bytes:
        """A translated form T′ genuinely signs with the given (wider) members, bound to the
        original. The caller states the members; nothing is altered after signing."""
        return self._write(members, sub=original.get("subject", ""), orig=fmt.digest(raw),
                           iat=iat, path="translate_wider")

    def unbound(self, members: Dict[str, Any], *, sub: str, iat: int) -> bytes:
        """A translated form that names no original."""
        return self._write(members, sub=sub, orig=None, iat=iat, path="unbound")


def admits(members: Dict[str, Any], request: Dict[str, Any], profile: Dict[str, Any],
           sem: Dict[str, Any], *, tolerance: int = 0) -> Optional[str]:
    """Why the translated `members`, read by the target's documented semantics, do not admit
    `request`; None when they do. The kind of each member is the source member the profile maps it
    to; only enforced members constrain."""
    fields = profile["fields"]
    kinds: Dict[str, str] = {m: fields[m] for m in sem if m in fields}
    for m, d in sem.items():
        if d.get("semantics") != "enforced":
            continue
        kind = kinds.get(m)
        if kind is None:
            continue
        if m not in members:
            if d.get("absent") == "nothing":
                return f"{m} absent: the target documents that absence admits nothing"
            continue
        v = members[m]
        if kind in ("max_amount", "min_amount"):
            a = request.get("amount")
            if a is None or a.get("currency") != v["currency"] or \
                    a.get("minor_units") != v["minor_units"]:
                return f"{m}: the request's amount is not in {v['currency']}/{v['minor_units']}"
            if kind == "max_amount" and tr.int_value(a["value"]) > v["value"]:
                return f"{m}: amount above the translated limit"
            if kind == "min_amount" and tr.int_value(a["value"]) < v["value"]:
                return f"{m}: amount below the translated floor"
        elif kind == "max_count":
            c = request.get("count")
            if c is None or c.get("unit") != v["unit"] or c["value"] > v["value"]:
                return f"{m}: count outside the translated quota"
        elif kind in tr.SET_MEMBERS:
            key = {"operations": "operation", "audience": "audience", "categories": "category",
                   "regions": "region", "channels": "channel"}[kind]
            if request.get(key) not in v:
                return f"{m}: {key} {request.get(key)!r} is not in the translated set"
        elif kind == "resources":
            if not any(tr.covers(p, str(request.get("resource"))) for p in v):
                return f"{m}: resource not covered"
        elif kind == "payee":
            if request.get("payee") != v:
                return f"{m}: payee differs"
        elif kind == "not_after":
            if request["at"] > v + tolerance:
                return f"{m}: after the translated end"
        elif kind == "not_before":
            if request["at"] < v - tolerance:
                return f"{m}: before the translated start"
    return None


class FaithfulReceiver:
    """R′: enacts a translated form by the target's documented semantics (topology T)."""

    def __init__(self, profile: Dict[str, Any], sem: Dict[str, Any], recorder: Recorder, *,
                 receiver: str, tolerance: int = 0) -> None:
        self.profile, self.sem, self.recorder = profile, sem, recorder
        self.receiver, self.tolerance = receiver, tolerance

    def enact(self, decoded: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
        if decoded.get("unreadable"):
            return {"accepted": False, "gap": "unreadable",
                    "reason": f"members the decoder could not read: {decoded['unreadable']}"}
        unknown = sorted(m for m in decoded["members"] if m not in self.sem)
        if unknown:
            return {"accepted": False, "gap": "no_semantics",
                    "reason": f"members with no documented semantics: {unknown}"}
        why = admits(decoded["members"], request, self.profile, self.sem,
                     tolerance=self.tolerance)
        if why:
            return {"accepted": False, "reason": why}
        self.recorder.commit(request, by="R′")
        return {"accepted": True, "reason": ""}


class SourceReceiver:
    """S′: enacts a request under a source-format form (a round trip's O′), source semantics."""

    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder

    def enact(self, claims: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
        c = claims.get("constraints") or {}
        a = request.get("amount")
        if "max_amount" in c:
            m = c["max_amount"]
            if a is None or a["currency"] != m["currency"] or \
                    a["minor_units"] != m["minor_units"] or \
                    tr.int_value(a["value"]) > tr.int_value(m["value"]):
                return {"accepted": False, "reason": "amount outside O′"}
        if "operations" in c and request.get("operation") not in c["operations"]:
            return {"accepted": False, "reason": "operation outside O′"}
        na = claims.get("not_after")
        if na is not None and request["at"] * tr.TIME_UNITS[claims.get("time_unit", "s")] > na:
            return {"accepted": False, "reason": "after O′'s end"}
        self.recorder.commit(request, by="S′")
        return {"accepted": True, "reason": ""}
