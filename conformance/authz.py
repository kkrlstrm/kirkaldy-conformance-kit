"""Per-request authorisations for KRK-18 (P18): the format the kit's stub A issues, binding
digests, and the test for input that two parsers read differently.

An authorisation is A's signed statement that one request (or, where the agreement allows it, a
class of requests) may be performed by one counterparty, endpoint and tenant, inside a window, a
stated number of times. It is a compact JWS (RFC 7515) with header
``{"alg": "EdDSA", "kid": ..., "typ": "krk-authz+jws"}`` and the canonical JSON of the claims
(`receipts.canonical_json`) as its payload, the same construction as KRK-16's receipts. The format is the kit's own terms, not one a target must use: a wire profile in
`requester.py` translates the same claims into another format.

Claims (`SCHEMA`):

- ``authorisation_id``: drawn from the operating system per authorisation, never from the run's
  seed (KRK-M36, KRK-M36);
- ``issuer``, ``audience`` (``counterparty``, ``endpoint``, ``tenant``), ``operation``;
- ``binding``: ``kind`` (``exact`` or ``class``), ``basis`` (`BASES`), ``request_digest``
  (exact only), ``parts`` (a list of per-part digests, or null), ``mapping`` (the name of a
  mapping profile the agreement declares, or null), ``summary`` (what the approver was shown, in
  A's terms, or null; never the binding), ``ceiling`` (class only);
- ``max_uses``, ``not_before``, ``not_after`` (RFC 3339 UTC), ``decision_digest``.

**Binding bases.** ``raw-bytes``: the digest is SHA-256 over the exact bytes sent.
``kirkaldy.canonical-json/0.1``: the bytes are parsed by a parser that refuses ambiguous input
(`ambiguous`), re-serialised as canonical JSON, and hashed. Either way the request travels
beside the authorisation as raw bytes; nothing here re-serialises a request on the way to a
target (KRK-M37, KRK-M37).

**Ambiguous input.** Bytes that two conforming JSON parsers read differently have no single
meaning to bind: an object with a member twice (one parser keeps the first, another the last),
an integer beyond +/-(2**53 - 1) (a float parser rounds it), and a number with a fraction or an
exponent (float formatting differs between languages). `ambiguous` names the first of these it
finds, in that order of priority, and `binding_digest` refuses all of them under the canonical
basis. ``not-json`` covers bytes that are not UTF-8 JSON at all.

`lenient_digest` is the digest an A computes when it canonicalises with an ordinary lenient
parser (the last duplicate wins, any integer is kept). The stub A uses it only to play that A in
the ``duplicate_key`` and ``number_precision`` fixtures, where it genuinely signs that digest.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import receipts
from .receipts import Keypair, Verified

SCHEMA = "kirkaldy.request-authorisation/0.1"
TYP = "krk-authz+jws"
ALG = "EdDSA"
CANONICAL = "kirkaldy.canonical-json/0.1"
RAW = "raw-bytes"
BASES = (CANONICAL, RAW)
KINDS = ("exact", "class")
AMBIGUITIES = ("not-json", "duplicate-key", "unsafe-integer", "float")
"""What `ambiguous` can answer, besides None. Priority order: the first that applies is named."""

MAX_SAFE_INT = 2 ** 53 - 1
REQUIRED_CLAIMS = ("schema", "authorisation_id", "issuer", "audience", "operation", "binding",
                   "max_uses", "not_before", "not_after", "decision_digest")
BASE_MEMBERS = frozenset(REQUIRED_CLAIMS)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_AZ_ID = re.compile(r"az-[0-9a-f]{16,64}")


class NotBindable(ValueError):
    """The request has no single reading to bind under the canonical basis."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


# --------------------------------------------------------------------------- reading the bytes


class _Found(Exception):
    pass


def _scan(request: bytes) -> Dict[str, str]:
    """Every ambiguity in `request`, as {kind: where}. Parses with hooks that note, and never
    coerce: duplicate members, integers outside the safe range, numbers with a fraction or an
    exponent, and the constants NaN and Infinity (which are not JSON)."""
    found: Dict[str, str] = {}
    try:
        text = request.decode("utf-8")
    except (UnicodeDecodeError, AttributeError) as e:
        return {"not-json": f"not UTF-8: {e}"}

    def pairs(items):
        seen = set()
        for k, _ in items:
            if k in seen:
                found.setdefault("duplicate-key", f"member {k!r} appears more than once")
            seen.add(k)
        return dict(items)

    def num_int(s: str):
        if abs(int(s)) > MAX_SAFE_INT:
            found.setdefault("unsafe-integer", f"integer {s} is outside +/-(2**53 - 1)")
        return int(s)

    def num_float(s: str):
        found.setdefault("float", f"number {s} has a fraction or an exponent")
        return float(s)

    def constant(s: str):
        found.setdefault("not-json", f"{s} is not a JSON value")
        return None

    try:
        json.loads(text, object_pairs_hook=pairs, parse_int=num_int, parse_float=num_float,
                   parse_constant=constant)
    except ValueError as e:
        return {"not-json": str(e)}
    return found


def ambiguous(request: bytes) -> Optional[str]:
    """``"not-json"`` | ``"duplicate-key"`` | ``"unsafe-integer"`` | ``"float"`` | None: the
    first reason, in that priority, why two conforming parsers could read `request` differently,
    or None if they cannot."""
    found = _scan(request)
    for kind in AMBIGUITIES:
        if kind in found:
            return kind
    return None


def explain_ambiguity(request: bytes) -> Dict[str, str]:
    """Every ambiguity found, with where, for the evidence."""
    return _scan(request)


def parse(request: bytes) -> Any:
    """The one reading of `request`, or `NotBindable` if it has more than one."""
    found = _scan(request)
    for kind in AMBIGUITIES:
        if kind in found:
            raise NotBindable(kind, found[kind])
    return json.loads(request.decode("utf-8"))


def canonical_bytes(request: bytes) -> bytes:
    """The canonical form of `request` (`receipts.canonical_json` of its one reading)."""
    obj = parse(request)
    try:
        return receipts.canonical_json(obj)
    except (ValueError, TypeError) as e:
        raise NotBindable("not-canonical", str(e)) from None


def binding_digest(request: bytes, basis: str = CANONICAL) -> str:
    """The digest an exact authorisation binds, under `basis`. Raw: SHA-256 of the bytes as
    sent. Canonical: refuses ambiguous input (`NotBindable`), then hashes the canonical form."""
    if not isinstance(request, (bytes, bytearray)):
        raise TypeError("a request is bytes, exactly as sent")
    if basis == RAW:
        return receipts.sha256_ref(bytes(request))
    if basis == CANONICAL:
        return receipts.sha256_ref(canonical_bytes(bytes(request)))
    raise ValueError(f"unknown binding basis {basis!r}; one of {BASES}")


def lenient_digest(request: bytes) -> str:
    """The digest an A computes with a lenient parser: the last duplicate wins, any integer is
    kept, sorted keys and no whitespace, no checks. Only for playing that A (module docstring)."""
    obj = json.loads(bytes(request).decode("utf-8"))
    return receipts.sha256_ref(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8"))


# --------------------------------------------------------------------------- claims


def utc(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(rfc3339: str) -> int:
    return int(datetime.strptime(rfc3339, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc).timestamp())


def new_authorisation_id() -> str:
    """From the operating system's random source, never from a run's seed (KRK-M36)."""
    return f"az-{secrets.token_hex(8)}"


def exact_binding(request: bytes, *, basis: str = CANONICAL,
                  parts: Optional[List[bytes]] = None, mapping: Optional[str] = None,
                  summary: Optional[Dict[str, Any]] = None,
                  digest: Optional[str] = None) -> Dict[str, Any]:
    """The binding of an exact authorisation for `request`. `digest` overrides the computed one
    (the stub A playing a lenient A); `parts` are the declared parts' raw bytes."""
    return {"kind": "exact", "basis": basis,
            "request_digest": digest or binding_digest(request, basis),
            "parts": [binding_digest(p, basis) for p in parts] if parts else None,
            "mapping": mapping, "summary": summary, "ceiling": None}


def class_binding(ceiling: Dict[str, Any], *, basis: str = CANONICAL) -> Dict[str, Any]:
    """The binding of a class authorisation: an operation and a ceiling, no request digest."""
    return {"kind": "class", "basis": basis, "request_digest": None, "parts": None,
            "mapping": None, "summary": None, "ceiling": dict(ceiling)}


def authorisation_claims(*, issuer: str, audience: Dict[str, Any], operation: str,
                         binding: Dict[str, Any], max_uses: int, not_before: str,
                         not_after: str, decision_digest: Optional[str],
                         authorisation_id: Optional[str] = None,
                         extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The claims of one authorisation. `extra` holds members a later property adds (X4's
    ``grant_id``); it may not set a base member."""
    claims = {"schema": SCHEMA, "authorisation_id": authorisation_id or new_authorisation_id(),
              "issuer": issuer,
              "audience": {"counterparty": audience.get("counterparty"),
                           "endpoint": audience.get("endpoint"),
                           "tenant": audience.get("tenant")},
              "operation": operation, "binding": dict(binding), "max_uses": int(max_uses),
              "not_before": not_before, "not_after": not_after,
              "decision_digest": decision_digest}
    clash = sorted(set(extra or {}) & BASE_MEMBERS)
    if clash:
        raise ValueError(f"extra members may not set base members {clash}")
    claims.update(extra or {})
    return claims


def claims_problem(claims: Any) -> Optional[str]:
    """Why these claims are not a well-formed authorisation, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in REQUIRED_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    if claims["schema"] != SCHEMA:
        return f"schema must be {SCHEMA!r}"
    if not isinstance(claims["authorisation_id"], str) or not _AZ_ID.fullmatch(
            claims["authorisation_id"]):
        return "authorisation_id must be 'az-' and 16 to 64 hex digits"
    for c in ("issuer", "operation"):
        if not isinstance(claims[c], str) or not claims[c]:
            return f"{c} must be a non-empty string"
    aud = claims["audience"]
    if not isinstance(aud, dict) or set(aud) != {"counterparty", "endpoint", "tenant"}:
        return "audience must have exactly counterparty, endpoint and tenant"
    if not isinstance(aud["counterparty"], str) or not aud["counterparty"]:
        return "audience.counterparty must be a non-empty string"
    for c in ("endpoint", "tenant"):
        if aud[c] is not None and (not isinstance(aud[c], str) or not aud[c]):
            return f"audience.{c} must be a non-empty string or null"
    b = claims["binding"]
    if not isinstance(b, dict) or set(b) != {"kind", "basis", "request_digest", "parts",
                                              "mapping", "summary", "ceiling"}:
        return "binding must have exactly kind, basis, request_digest, parts, mapping, summary, " \
               "ceiling"
    if b["kind"] not in KINDS:
        return f"binding.kind must be one of {KINDS}"
    if b["basis"] not in BASES:
        return f"binding.basis must be one of {BASES}"
    if b["kind"] == "exact":
        if not isinstance(b["request_digest"], str) or not _DIGEST.fullmatch(b["request_digest"]):
            return "an exact binding needs request_digest 'sha256:<64 hex>'"
        if b["ceiling"] is not None:
            return "an exact binding has no ceiling"
    else:
        if b["request_digest"] is not None or b["parts"] is not None:
            return "a class binding has no request_digest and no parts"
        if not isinstance(b["ceiling"], dict):
            return "a class binding needs a ceiling"
    if b["parts"] is not None:
        if (not isinstance(b["parts"], list) or not b["parts"]
                or not all(isinstance(p, str) and _DIGEST.fullmatch(p) for p in b["parts"])
                or len(set(b["parts"])) != len(b["parts"])):
            return "binding.parts must be a non-empty list of distinct digests"
    if b["mapping"] is not None and (not isinstance(b["mapping"], str) or not b["mapping"]):
        return "binding.mapping must be a profile name or null"
    if b["summary"] is not None and not isinstance(b["summary"], dict):
        return "binding.summary must be an object or null"
    mu = claims["max_uses"]
    if isinstance(mu, bool) or not isinstance(mu, int) or mu < 1:
        return "max_uses must be a positive integer"
    if b["parts"] is not None and mu != len(b["parts"]):
        return "with declared parts, max_uses is the number of parts"
    for c in ("not_before", "not_after"):
        if not isinstance(claims[c], str) or not _RFC3339_UTC.fullmatch(claims[c]):
            return f"{c} must be RFC 3339 UTC, whole seconds, ending in Z"
    if epoch(claims["not_after"]) <= epoch(claims["not_before"]):
        return "not_after must be later than not_before"
    dd = claims["decision_digest"]
    if dd is not None and (not isinstance(dd, str) or not _DIGEST.fullmatch(dd)):
        return "decision_digest must be 'sha256:<64 hex>' or null"
    return None


# --------------------------------------------------------------------------- JWS


def header(kid: str) -> Dict[str, str]:
    return {"alg": ALG, "kid": kid, "typ": TYP}


def sign_authorisation(claims: Dict[str, Any], key: Keypair) -> str:
    """Compact JWS, alg EdDSA, typ krk-authz+jws, over the canonical JSON of `claims`. Signs what
    it is given; the shape is the verifier's check."""
    return receipts.sign_payload(receipts.canonical_json(claims), key, header(key.kid))


def unsigned_authorisation(claims: Dict[str, Any]) -> str:
    """alg none and an empty signature. For X1; P18 never presents one (§3.4 of the design)."""
    h = receipts._b64e(receipts.canonical_json({"alg": "none", "typ": TYP}))
    return f"{h}.{receipts._b64e(receipts.canonical_json(claims))}."


def claims_of(token: Any) -> Optional[Dict[str, Any]]:
    """The payload of a compact JWS, read without checking anything (for evidence only)."""
    try:
        out = json.loads(receipts._b64d(str(token).split(".")[1]))
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def verify_authorisation(token: str, pinned: Dict[str, bytes]) -> Verified:
    """The kit's own reader of an authorisation: form, then a signature, then a pinned key, then
    the signature itself, in the order and with the reasons of `receipts.verify_receipt`
    (``malformed``, ``unsigned``, ``unpinned-key``, ``bad-signature``). Only EdDSA is verified;
    keys in the header are never read."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    for k, v in pinned.items():
        if not isinstance(k, str) or not isinstance(v, (bytes, bytearray)) or len(v) != 32:
            raise ValueError(f"pinned[{k!r}] must be a raw 32-byte Ed25519 public key")

    def bad(reason: str, detail: str, kid: Optional[str] = None) -> Verified:
        return Verified(ok=False, reason=reason, claims=None, kid=kid, detail=detail)

    if not isinstance(token, str):
        return bad("malformed", f"token is {type(token).__name__}, not a string")
    if len(token) > (1 << 20):
        return bad("malformed", "token is larger than 1 MiB")
    parts = token.split(".")
    if len(parts) != 3:
        return bad("malformed", f"compact JWS has 3 segments, this has {len(parts)}")
    h_seg, p_seg, s_seg = parts
    try:
        hdr = receipts._strict_json(receipts._b64d(h_seg))
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", f"header: {e}")
    if not isinstance(hdr, dict):
        return bad("malformed", "header is not a JSON object")
    kid = hdr.get("kid") if isinstance(hdr.get("kid"), str) else None
    try:
        payload = receipts._b64d(p_seg)
        claims = receipts._strict_json(payload)
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", f"payload: {e}", kid)
    try:
        canonical = receipts.canonical_json(claims)
    except (ValueError, TypeError) as e:
        return bad("malformed", f"payload is not canonical JSON: {e}", kid)
    if canonical != payload:
        return bad("malformed", "payload bytes are not the canonical form of its claims", kid)
    problem = claims_problem(claims)
    if problem:
        return bad("malformed", problem, kid)
    alg = hdr.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return bad("unsigned", f"alg is {alg!r}", kid)
    if alg != ALG:
        return bad("malformed", f"alg {alg!r} is not {ALG}; no other algorithm is verified", kid)
    if hdr.get("typ") != TYP:
        return bad("malformed", f"typ {hdr.get('typ')!r} is not {TYP!r}", kid)
    if "crit" in hdr or "b64" in hdr:
        return bad("malformed", "header uses crit or b64, which this format does not", kid)
    if not kid:
        return bad("malformed", "header has no kid", None)
    try:
        sig = receipts._b64d(s_seg)
    except ValueError as e:
        return bad("malformed", f"signature: {e}", kid)
    if not sig:
        return bad("unsigned", "alg is EdDSA but the signature is empty", kid)
    if kid not in pinned:
        return bad("unpinned-key", f"kid {kid!r} is not pinned", kid)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pinned[kid])).verify(
            sig, f"{h_seg}.{p_seg}".encode("ascii"))
    except InvalidSignature:
        return bad("bad-signature", f"signature does not verify under pinned key {kid!r}", kid)
    return Verified(ok=True, reason=None, claims=claims, kid=kid, detail="verified")


# --------------------------------------------------------------------------- a presentation


@dataclass(frozen=True)
class Presentation:
    """One request presented to B, exactly as it leaves the kit."""

    pid: str
    """The kit's id for this presentation. Never sent to B."""
    endpoint: str
    tenant: Optional[str]
    request: bytes
    """Raw, exactly as sent."""
    authorisation: Optional[str]
    headers: Dict[str, str] = field(default_factory=dict)
    """Members outside the binding (headers, query parameters)."""

    def __post_init__(self) -> None:
        if not isinstance(self.request, (bytes, bytearray)):
            raise TypeError("Presentation.request is raw bytes")
        object.__setattr__(self, "request", bytes(self.request))
        object.__setattr__(self, "headers", dict(self.headers))
