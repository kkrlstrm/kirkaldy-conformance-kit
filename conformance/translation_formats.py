"""Source and translated formats for KRK-26 (P26): writers and decoders, imported only by P26.

`X11-TRANSLATION-DESIGN.md` §6.3, built as a format module that only its property
imports, so no other probe's version moves (design §13 item 3).

**Source format** ``kirkaldy.authority/0.1`` (`SOURCE`): a compact JWS (EdDSA, typ
``krk-authority+jws``) signed by A's stand-in with its own key. It uses grant 0.2's constraint
vocabulary (`attenuation`) plus the members translation needs: ``payee``, ``min_amount``,
``max_count`` (``{value, unit}``), ``categories``, ``regions`` and ``channels``; the window as
``not_before`` (optional) and ``not_after`` in ``time_unit`` (``s`` or ``ms``); and ``crit``.
An amount's ``value`` is a JSON integer or a string of decimal digits: both are the source
format's, so a translator whose parser takes only one of them meets ``partial/error_fallback``.
It is not grant 0.2 itself, which has none of the added members (design §13, as built).

**Translated format** ``kirkaldy.translated/0.1`` (`TARGET`): the kit's own target format, used by
the known-bad toys and by the kit's translator T′ in topology R. A compact JWS (typ
``krk-translated+jws``) whose payload names the translator (``iss``), the subject (``sub``), the
issue time (``iat``), the original it was made from (``orig``, the SHA-256 of the original's bytes;
absent in an unbound form) and the members in the target's vocabulary. An amount is
``{value: "<digits>", asset, decimals}``; a count ``{value, unit}``; times are integers in the
profile's time unit; ``ext`` is an ignorable extension object and ``regions_hint`` an
informational member (the target's documentation says so, `TOY_SEMANTICS`).

**A decoder decodes; it never judges** (KRK-M191). `read_translated` returns every member it
could decode and names every one it could not (``unreadable``); it drops nothing silently.
Neither format is a published standard; an outside target's formats get their own modules
(design §6.3), none of which is built in version 1.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .receipts import Keypair, canonical_json, sign_payload

SOURCE = "kirkaldy.authority/0.1"
SOURCE_TYP = "krk-authority+jws"
TARGET = "kirkaldy.translated/0.1"
TARGET_TYP = "krk-translated+jws"
AMOUNT_MEMBERS_T = ("limit", "floor")
COUNT_MEMBERS_T = ("quota",)
TIME_MEMBERS_T = ("nbf", "exp")
LIST_MEMBERS_T = ("scope", "paths", "aud")
STRING_MEMBERS_T = ("pay_to",)
INFO_MEMBERS_T = ("regions_hint",)
ENVELOPE_T = ("schema", "iss", "sub", "iat", "orig", "id")
EXT = "ext"


class BadToken(ValueError):
    """A token that is not a well-formed, correctly signed token of the format."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise BadToken(f"not base64url: {e}")


def digest(raw: bytes) -> str:
    """The binding a translated form names its original by."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _sign(claims: Dict[str, Any], key: Keypair, typ: str) -> bytes:
    return sign_payload(canonical_json(claims), key,
                        {"alg": "EdDSA", "kid": key.kid, "typ": typ}).encode("ascii")


def verify(raw: bytes, pinned: Dict[str, bytes], typ: str) -> Tuple[str, Dict[str, Any]]:
    """(kid, payload) of a compact JWS signed by a pinned key, or `BadToken`."""
    try:
        h, p, s = raw.decode("ascii").split(".")
    except (UnicodeDecodeError, ValueError):
        raise BadToken("not a compact JWS")
    try:
        header = json.loads(_b64d(h))
        payload = json.loads(_b64d(p))
    except ValueError as e:
        raise BadToken(f"not JSON: {e}")
    if not isinstance(header, dict) or header.get("alg") != "EdDSA" or header.get("typ") != typ:
        raise BadToken(f"header is not EdDSA {typ}")
    kid = header.get("kid")
    if kid not in pinned:
        raise BadToken(f"key {kid!r} is not pinned")
    try:
        Ed25519PublicKey.from_public_bytes(pinned[kid]).verify(_b64d(s), f"{h}.{p}".encode())
    except InvalidSignature:
        raise BadToken("signature does not verify")
    if not isinstance(payload, dict):
        raise BadToken("payload is not an object")
    return kid, payload


# --------------------------------------------------------------------------- source


def write_authority(claims: Dict[str, Any], key: Keypair) -> bytes:
    """A's stand-in signs `claims` as they are. Nothing is changed after signing (spec §3.9)."""
    return _sign({"schema": SOURCE, **claims}, key, SOURCE_TYP)


def read_authority(raw: bytes, pinned: Dict[str, bytes]) -> Dict[str, Any]:
    _kid, payload = verify(raw, pinned, SOURCE_TYP)
    if payload.get("schema") != SOURCE:
        raise BadToken(f"schema is not {SOURCE}")
    return payload


# --------------------------------------------------------------------------- translated


def _amount_out(a: Dict[str, Any]) -> Dict[str, Any]:
    return {"value": str(a["value"]), "asset": a["currency"], "decimals": a["minor_units"]}


def write_translated(members: Dict[str, Any], key: Keypair, *, issuer: str, sub: str,
                     orig: Optional[str], iat: int, token_id: str) -> bytes:
    """A translated form in `TARGET`, signed by `key`. `members` are in the target's vocabulary
    with amounts as ``{value, currency, minor_units}``; `orig` None writes an unbound form."""
    payload: Dict[str, Any] = {"schema": TARGET, "iss": issuer, "sub": sub, "iat": iat,
                               "id": token_id}
    if orig is not None:
        payload["orig"] = orig
    for m, v in members.items():
        payload[m] = _amount_out(v) if m in AMOUNT_MEMBERS_T else v
    return _sign(payload, key, TARGET_TYP)


def _amount_in(v: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(v, dict) or set(v) != {"value", "asset", "decimals"}:
        return None
    if not isinstance(v["value"], str) or not v["value"].isdigit() or \
            (len(v["value"]) > 1 and v["value"][0] == "0"):
        return None
    if not isinstance(v["asset"], str) or not isinstance(v["decimals"], int) or \
            isinstance(v["decimals"], bool) or v["decimals"] < 0:
        return None
    return {"value": int(v["value"]), "currency": v["asset"], "minor_units": v["decimals"]}


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def read_translated(raw: bytes, pinned: Dict[str, bytes]) -> Dict[str, Any]:
    """Decode a `TARGET` form. Returns ``{"members", "unreadable", "signed_by", "orig", "sub",
    "iat", "envelope"}``. A member that cannot be decoded is named in ``unreadable`` and left out
    of ``members``; the caller must never read it as absent (KRK-M191)."""
    kid, p = verify(raw, pinned, TARGET_TYP)
    if p.get("schema") != TARGET:
        raise BadToken(f"schema is not {TARGET}")
    members: Dict[str, Any] = {}
    unreadable: List[str] = []
    for m, v in p.items():
        if m in ENVELOPE_T:
            continue
        ok: Any = None
        if m in AMOUNT_MEMBERS_T:
            ok = _amount_in(v)
        elif m in COUNT_MEMBERS_T:
            ok = v if isinstance(v, dict) and set(v) == {"value", "unit"} and \
                _int(v["value"]) and isinstance(v["unit"], str) else None
        elif m in TIME_MEMBERS_T:
            ok = v if _int(v) else None
        elif m in LIST_MEMBERS_T or m in INFO_MEMBERS_T:
            ok = list(v) if isinstance(v, list) and all(isinstance(x, str) for x in v) else None
        elif m in STRING_MEMBERS_T:
            ok = v if isinstance(v, str) else None
        elif m == EXT:
            ok = dict(v) if isinstance(v, dict) else None
        if ok is None:
            unreadable.append(m)
        else:
            members[m] = ok
    return {"members": members, "unreadable": sorted(unreadable), "signed_by": kid,
            "orig": p.get("orig"), "sub": p.get("sub"), "iat": p.get("iat"),
            "envelope": {k: p.get(k) for k in ENVELOPE_T if k in p}}


def write_round_trip(claims: Dict[str, Any], key: Keypair) -> bytes:
    """O′ in the source format, signed by the translator that made it (`retranslation/round_trip`).
    The kit's source receiver pins the translator's key for it, never A's."""
    return _sign({"schema": SOURCE, **claims}, key, SOURCE_TYP)
