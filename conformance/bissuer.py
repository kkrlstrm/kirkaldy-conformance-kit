"""The B-issuer profile (`b-issuer/0.1`): shared parts of the modules that judge a receiver B which
issues the authority it honours.

Under this profile B issues the credential and the exact-binding object the property
judges, holds the consent, and the kit holds none of B's keys. The kit's stand-in agent obtains
every object through B's own flow, and the kit judges B against B's own signed objects, B's store
and the kit's own record of what it asked for and accepted (design §1, §5).

This module holds what every B-issuer property module needs and nothing property-specific:

- the agreement's ``authority`` block, read with the default ``{"issuer": "A"}`` (`authority_of`);
- the log of B's objects, kept as the bytes B sent (`BObject`, `BObjectLog`);
- the kit's own JOSE verifier for B's compact JWS objects, EdDSA (Ed25519) and ES256, written on
  `cryptography` and sharing no code with any target (KRK-M140, `verify_b_object`);
- RFC 7638 key thumbprints, to tell two instances' keys apart (KRK-M142, `thumbprint`);
- RFC 8785 JSON Canonicalization Scheme, for B's stated terms digests (`jcs`, `terms_digest`),
  checked against the vectors in ``tests/vectors/bissuer/jcs.json`` by ``tests/test_bissuer.py``;
- the restatement comparison of rule 8 (`restatement`);
- the labels of §5.3 (`SUMMARY_SENTENCE`, `label`).

`receipts.canonical_json` is not reused for the digest: it is not JCS (it refuses floats and
non-ASCII keys, which JCS serialises), and it is in the closure of P16 to P21, so it must not be
changed to fit (design §4.3).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROFILE = "b-issuer/0.1"
SHAPES = ("revision", "consent-id", "rar-token")
HOOKS = ("documented-automation", "declared-test-route", "driven-page")
ISSUERS = ("A", "B")
BASES = ("jcs", "json-values")
"""How restated terms are compared with a request: ``jcs`` (the JSON values, compared as JCS
would serialise them) and ``json-values`` (the parsed JSON values). For the values the kit sends
the two agree; a B states which one it uses."""

SUMMARY_SENTENCE = ("Authority held at B: judged against B's own signed objects and B's store, "
                    "with approvals given by the tester at B's page; not comparable with KRK-18 "
                    "results where the requesting organisation issues the authorisation.")
"""The fixed first sentence of every P18B summary (design §5.3). The B-issuer
modules for KRK-16, -19 and -20 will state their own, naming their property."""

FORBIDDEN_WORDS = ("person's consent",)
"""Words a B-issuer verdict never uses (KRK-M131): the kit played the person through a hook, so
what B honoured is the tester's approval, not a person's consent."""


# --------------------------------------------------------------------------- the authority block


@dataclass(frozen=True)
class Authority:
    """The agreement's ``authority`` block as the kit read it (design §6.8)."""

    issuer: str
    shape: Optional[str] = None
    objects: Dict[str, Any] = field(default_factory=dict)
    """``class_credential``, ``exact_object`` and ``acceptance``, as the agreement states them."""
    hook: Dict[str, Any] = field(default_factory=dict)
    revocation: List[Dict[str, Any]] = field(default_factory=list)
    agent_keys_from: Optional[str] = None
    keys: Dict[str, Any] = field(default_factory=dict)
    quotes: Dict[str, Any] = field(default_factory=dict)
    source: str = "default"
    """Where it was read from: ``authority()``, ``agreement()`` or ``default``."""

    def problem(self) -> Optional[str]:
        """Why this block cannot drive a B-issuer probe, or None."""
        if self.issuer not in ISSUERS:
            return f"authority.issuer is {self.issuer!r}, not one of {ISSUERS}"
        if self.issuer != "B":
            return None
        if self.shape not in SHAPES:
            return f"authority.shape is {self.shape!r}, not one of {SHAPES}"
        kind = (self.hook or {}).get("kind")
        if kind not in HOOKS:
            return f"authority.hook.kind is {kind!r}, not one of {HOOKS} (design §2.3)"
        return None


def _block(raw: Any, source: str) -> Authority:
    if not isinstance(raw, dict):
        return Authority(issuer="A", source="default")
    objects = {k: raw[k] for k in ("class_credential", "exact_object", "acceptance") if k in raw}
    return Authority(issuer=str(raw.get("issuer", "A")), shape=raw.get("shape"),
                     objects=objects, hook=dict(raw.get("hook") or {}),
                     revocation=list(raw.get("revocation") or []),
                     agent_keys_from=raw.get("agent_keys_from"), keys=dict(raw.get("keys") or {}),
                     quotes=dict(raw.get("quotes") or {}), source=source)


def declared_authority(adapter: Any) -> Authority:
    """The adapter's own ``authority()`` method only, or the default. The runner uses this one:
    it never calls an adapter's ``agreement()``, which on some targets starts a process."""
    fn = getattr(adapter, "authority", None)
    if callable(fn):
        try:
            return _block(fn(), "authority()")
        except Exception:  # noqa: BLE001 - an unreadable block is the default, never B
            return Authority(issuer="A", source="default")
    return Authority(issuer="A", source="default")


def authority_of(adapter: Any) -> Authority:
    """``adapter.authority()``, then ``adapter.agreement()["authority"]``, then ``{"issuer":
    "A"}`` (design §6.8). Every existing adapter declares nothing and reads as A."""
    a = declared_authority(adapter)
    if a.source != "default":
        return a
    fn = getattr(adapter, "agreement", None)
    if callable(fn):
        try:
            ag = fn() or {}
        except Exception:  # noqa: BLE001
            return a
        if isinstance(ag, dict) and isinstance(ag.get("authority"), dict):
            return _block(ag["authority"], "agreement()")
    return a


# --------------------------------------------------------------------------- B's objects


@dataclass
class BObject:
    """One object B sent, kept as the bytes B sent (design §6.2)."""

    kind: str
    """``credential`` | ``exact`` | ``pending`` | ``statement`` | ``revocation-ack``."""
    id: str
    raw: bytes
    signed: bool
    kid: Optional[str] = None
    alg: Optional[str] = None
    terms: Optional[Dict[str, Any]] = None
    terms_digest: Optional[str] = None
    issued_to: Optional[str] = None
    tenant: Optional[str] = None
    endpoint: Optional[str] = None
    instance: Optional[str] = None
    expires_at: Optional[float] = None
    issued_at: Optional[float] = None
    supersedes: Optional[str] = None
    counter_proposal: bool = False
    """B labelled these terms a counter-proposal (rule 8)."""
    claims: Dict[str, Any] = field(default_factory=dict)
    """Every member B signed, decoded, for the evidence."""
    received_at: float = 0.0
    """Kit clock."""
    pair: str = ""
    """The kit's pair id; never sent to B."""
    verified: Optional[bool] = None
    """Set by the kit's own verifier (`verify_b_object`); None until checked."""
    why: str = ""

    def doc(self) -> Dict[str, Any]:
        out = {k: getattr(self, k) for k in ("kind", "id", "signed", "kid", "alg", "terms",
                                               "terms_digest", "issued_to", "tenant", "endpoint",
                                               "instance", "expires_at", "issued_at", "supersedes",
                                               "counter_proposal", "received_at", "pair",
                                               "verified", "why")}
        out["raw"] = self.raw.decode("utf-8", "replace") if len(self.raw) < 4096 else \
            f"<{len(self.raw)} bytes, sha256 {hashlib.sha256(self.raw).hexdigest()}>"
        return out


class BObjectLog:
    """Every object B sent in one run, append-only (design §2.2)."""

    def __init__(self) -> None:
        self._objs: List[BObject] = []

    def add(self, obj: BObject) -> BObject:
        self._objs.append(obj)
        return obj

    def get(self, oid: str) -> Optional[BObject]:
        hits = [o for o in self._objs if o.id == oid]
        return hits[-1] if hits else None

    def all(self) -> List[BObject]:
        return list(self._objs)

    def superseded(self, oid: str) -> Optional[BObject]:
        """B's own later signed object that supersedes `oid`, verified by the kit, or None
        (KRK-M141: the supersession is read from B's object, not assumed from the kit's
        counter-proposal)."""
        for o in self._objs:
            if o.supersedes == oid and o.signed and o.verified:
                return o
        return None

    def docs(self) -> List[Dict[str, Any]]:
        return [o.doc() for o in self._objs]


# --------------------------------------------------------------------------- the kit's JOSE

_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(seg: str) -> bytes:
    """Strict base64url: no padding, only the alphabet, the one canonical spelling."""
    if not isinstance(seg, str) or not _B64URL.fullmatch(seg):
        raise ValueError("not base64url")
    try:
        data = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"not base64url: {e}") from None
    if b64e(data) != seg:
        raise ValueError("non-canonical base64url")
    return data


def _strict_json(data: bytes) -> Any:
    def pairs(ps: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in ps:
            if k in out:
                raise ValueError(f"duplicate member {k!r}")
            out[k] = v
        return out

    def const(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=const)


@dataclass(frozen=True)
class Verified:
    ok: bool
    reason: Optional[str]
    """None when ok; else ``malformed`` | ``unsigned`` | ``alg`` | ``unknown-key`` |
    ``bad-signature``."""
    header: Optional[Dict[str, Any]] = None
    claims: Optional[Dict[str, Any]] = None
    kid: Optional[str] = None
    alg: Optional[str] = None
    thumbprint: Optional[str] = None
    detail: str = ""
    payload: Optional[bytes] = None
    """The signed payload bytes, as B sent them."""


ALGS = {"EdDSA": ("OKP", "Ed25519"), "ES256": ("EC", "P-256")}


def _public_key(jwk: Dict[str, Any]):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        x = b64d(jwk["x"])
        if len(x) != 32:
            raise ValueError("Ed25519 x is not 32 bytes")
        return Ed25519PublicKey.from_public_bytes(x)
    if kty == "EC" and crv == "P-256":
        x, y = b64d(jwk["x"]), b64d(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise ValueError("P-256 coordinates are not 32 bytes")
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                             ec.SECP256R1()).public_key()
    raise ValueError(f"unsupported key kty={kty!r} crv={crv!r}")


def key_set(published: Any) -> List[Dict[str, Any]]:
    """The keys of a JWKS document (``{"keys": [...]}``) or a list of JWKs."""
    if isinstance(published, dict) and isinstance(published.get("keys"), list):
        return [k for k in published["keys"] if isinstance(k, dict)]
    if isinstance(published, list):
        return [k for k in published if isinstance(k, dict)]
    return []


def verify_signature(raw: Any, published: Any) -> Verified:
    """Verify one compact JWS against B's published keys (a JWKS read through the kit's baseline
    path) and return its payload bytes; the payload need not be JSON. The kit's own code on
    `cryptography`; never the target's verifier and never a key the kit holds (KRK-M140).
    ``alg: none`` and every algorithm outside `ALGS` are refused; a key must match the header's
    ``kid`` (when the header names one) and the algorithm's key type."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    token = raw.decode("ascii", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    if not isinstance(token, str) or token.count(".") != 2:
        return Verified(False, "malformed", detail="not a compact JWS")
    h64, p64, s64 = token.split(".")
    try:
        header = _strict_json(b64d(h64))
        payload = b64d(p64)
        sig = b64d(s64)
    except (ValueError, UnicodeDecodeError) as e:
        return Verified(False, "malformed", detail=str(e))
    if not isinstance(header, dict):
        return Verified(False, "malformed", detail="the header is not an object")
    alg, kid = header.get("alg"), header.get("kid")
    if alg in (None, "none") or not sig:
        return Verified(False, "unsigned", header, None, kid, alg, detail="no signature",
                        payload=payload)
    if alg not in ALGS:
        return Verified(False, "alg", header, None, kid, alg, detail=f"alg {alg!r} refused",
                        payload=payload)
    if header.get("crit"):
        return Verified(False, "malformed", header, None, kid, alg,
                        detail="a crit header the kit does not understand", payload=payload)
    kty, crv = ALGS[alg]
    cands = [k for k in key_set(published) if k.get("kty") == kty and k.get("crv") == crv
             and (kid is None or k.get("kid") == kid)]
    if not cands:
        return Verified(False, "unknown-key", header, None, kid, alg,
                        detail=f"no published {kty}/{crv} key with kid {kid!r}", payload=payload)
    signing_input = f"{h64}.{p64}".encode("ascii")
    for jwk in cands:
        try:
            pub = _public_key(jwk)
            if alg == "EdDSA":
                pub.verify(sig, signing_input)
            else:
                if len(sig) != 64:
                    raise InvalidSignature()
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                           int.from_bytes(sig[32:], "big"))
                pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return Verified(True, None, header, None, kid, alg, thumbprint(jwk), payload=payload)
        except (InvalidSignature, ValueError, KeyError):
            continue
    return Verified(False, "bad-signature", header, None, kid, alg,
                    detail="the signature does not verify under the published key",
                    payload=payload)


def verify_b_object(raw: Any, published: Any) -> Verified:
    """`verify_signature`, then the payload read as one strict JSON object (no duplicate
    member, no NaN): B's objects are JSON claims."""
    v = verify_signature(raw, published)
    if v.payload is None:
        return v
    try:
        claims = _strict_json(v.payload)
    except (ValueError, UnicodeDecodeError) as e:
        return Verified(False, "malformed", v.header, None, v.kid, v.alg, v.thumbprint,
                        f"the payload is not strict JSON: {e}", v.payload)
    if not isinstance(claims, dict):
        return Verified(False, "malformed", v.header, None, v.kid, v.alg, v.thumbprint,
                        "the payload is not a JSON object", v.payload)
    return Verified(v.ok, v.reason, v.header, claims, v.kid, v.alg, v.thumbprint, v.detail,
                    v.payload)


def thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace,
    base64url."""
    kty = jwk.get("kty")
    req = {"OKP": ("crv", "kty", "x"), "EC": ("crv", "kty", "x", "y"),
           "RSA": ("e", "kty", "n")}.get(kty)
    if req is None:
        raise ValueError(f"no thumbprint members for kty {kty!r}")
    body = "{" + ",".join(f"{json.dumps(k)}:{json.dumps(jwk[k])}" for k in req) + "}"
    return b64e(hashlib.sha256(body.encode("utf-8")).digest())


def thumbprints(published: Any) -> List[str]:
    out = []
    for k in key_set(published):
        try:
            out.append(thumbprint(k))
        except (ValueError, KeyError):
            continue
    return sorted(out)


# --------------------------------------------------------------------------- JCS (RFC 8785)


class NotIJSON(ValueError):
    """A value JCS cannot serialise: not I-JSON (RFC 7493), such as an integer beyond what a
    double holds exactly, a non-finite number, or a lone surrogate."""


SAFE = 2 ** 53


def _jcs_number(x: Any) -> str:
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > SAFE:
            raise NotIJSON(f"integer {x} is beyond 2^53 (I-JSON)")
        x = float(x)
    if not math.isfinite(x):
        raise NotIJSON(f"{x!r} is not a finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    d = Decimal(repr(abs(x)))
    _, digits, exp = d.as_tuple()
    s = "".join(map(str, digits)).rstrip("0") or "0"
    k = len(s)
    n = exp + len(digits)            # x = 0.s * 10^n with s's leading digit nonzero
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        e = n - 1
        mant = s if k == 1 else s[0] + "." + s[1:]
        out = f"{mant}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + out


_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"',
          0x5C: "\\\\"}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _SHORT:
            out.append(_SHORT[c])
        elif c < 0x20:
            out.append(f"\\u{c:04x}")
        elif 0xD800 <= c <= 0xDFFF:
            raise NotIJSON("a lone surrogate is not I-JSON")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> List[int]:
    return list(k.encode("utf-16-be"))


def _jcs(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise NotIJSON(f"member name {k!r} is not a string")
        return "{" + ",".join(f"{_jcs_string(k)}:{_jcs(v[k])}"
                              for k in sorted(v, key=_utf16_key)) + "}"
    raise NotIJSON(f"{type(v).__name__} is not JSON")


def jcs(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme: members sorted by their UTF-16 code units, numbers
    as ECMAScript writes a double, strings with only the escapes JSON requires, UTF-8."""
    return _jcs(obj).encode("utf-8")


def terms_digest(terms: Dict[str, Any], basis: str = "jcs") -> str:
    """The kit's own digest of B's terms: ``sha256:`` and the hex SHA-256 of their JCS bytes.
    Raises `NotIJSON` where JCS has no serialisation (the digest is then not recomputable)."""
    if basis != "jcs":
        raise ValueError(f"no digest basis {basis!r}")
    return "sha256:" + hashlib.sha256(jcs(terms)).hexdigest()


def digest_matches(stated: Optional[str], terms: Optional[Dict[str, Any]],
                   basis: str = "jcs") -> Optional[bool]:
    """Does B's stated digest equal the kit's own over B's signed terms? None when B states
    none, or the terms are not I-JSON so the kit cannot recompute it."""
    if not stated or terms is None:
        return None
    try:
        mine = terms_digest(terms, basis)
    except (NotIJSON, ValueError):
        return None
    alg, _, hexd = str(stated).partition(":")
    if alg.lower().replace("-", "") != "sha256":
        return None
    return mine.split(":", 1)[1] == hexd.lower()


# --------------------------------------------------------------------------- restatement (rule 8)


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b                # exact: Python compares an int and a float without rounding
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def restatement(requested: Dict[str, Any], terms: Optional[Dict[str, Any]], *,
                basis: str = "jcs", mapping: Optional[Dict[str, str]] = None,
                members: Optional[Iterable[str]] = None) -> Optional[Dict[str, Any]]:
    """Rule 8. None when B's signed terms state the request: every member the kit asked for is
    in the terms with the same value, read under `basis`. Else the members that differ, as
    ``{member: {"asked": ..., "signed": ...}}``. Members B adds that the kit did not ask for
    (B's own ids, an expiry) are not a restatement. `mapping` names B's member for each of the
    kit's (``{kit_member: b_member}``) where B states one; `members` limits the comparison."""
    if basis not in BASES:
        raise ValueError(f"no restatement basis {basis!r}")
    if terms is None:
        return {"*": {"asked": requested, "signed": None}}
    names = list(members) if members is not None else list(requested)
    out: Dict[str, Any] = {}
    for k in names:
        b = (mapping or {}).get(k, k)
        if k not in requested:
            continue
        if b not in terms:
            out[k] = {"asked": requested[k], "signed": "<absent>"}
            continue
        if basis == "jcs":
            try:
                same = jcs(requested[k]) == jcs(terms[b])
            except NotIJSON:
                same = _same(requested[k], terms[b])
        else:
            same = _same(requested[k], terms[b])
        if not same:
            out[k] = {"asked": requested[k], "signed": terms[b]}
    return out or None


# --------------------------------------------------------------------------- labels (§5.3)


def grade_label(grade: str) -> str:
    return f"{grade}, authority at B"


def label(authority: Authority, *, extra_links: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """``extra.authority`` for a B-issuer result (design §5.3)."""
    out = {"issuer": "B", "profile": PROFILE, "shape": authority.shape,
           "hook": (authority.hook or {}).get("kind")}
    if extra_links:
        out["links"] = dict(extra_links)
    return out


def hook_sentence(kind: Optional[str]) -> str:
    return (f"Approvals at B's page were given by the tester through a {kind or 'undeclared'} "
            f"hook (design §2.3), so no result here speaks for a real person.")


def now() -> float:
    """The kit's clock for B-issuer modules (spec §3.7: one clock)."""
    return time.time()
