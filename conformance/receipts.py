"""Effect receipts for KRK-16 (P16): canonical bytes, digests, Ed25519 JWS, and the kit's judge.

A receipt is B's signed statement of what it did for one request. It is a compact JWS
(RFC 7515) with header ``{"alg": "EdDSA", "kid": ..., "typ": "krk-receipt+jws"}`` and the
canonical JSON of the claims as its payload. A verifies it against keys it pinned beforehand,
and compares it with the request it built and the effect it recorded as expected.

`judge` is the kit's own ground truth for what A should conclude about one receipt. The
property compares a target's status with it. A target's verifier must not call it (the
checker shares no code with the producer); it may use `verify_receipt` and the digest helpers,
which are the shared specification, and the test vectors in ``tests/vectors/krk16/`` pin them.

Canonical JSON is ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`` as
UTF-8, restricted so that it matches RFC 8785 (JCS) for the values allowed: no floats, integers
within +/-(2**53 - 1), string keys in ASCII. A value outside that is refused, not coerced.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TYP = "krk-receipt+jws"
ALG = "EdDSA"

VERBS = frozenset({"create", "update", "upsert", "delete", "none"})
VERDICTS = ("executed", "refused", "no-record")
"""`no-record`: B's signed statement that it never received this request. It
counts only with the claim ``"refuses_permanently": true`` (B commits to refuse that correlation
id for good) and must report no effect; without the claim it is malformed."""
OUTCOME_FIELDS = ("created", "updated", "deleted", "failed")

GRADES = ("signed-by-B", "B-record-read-back", "person", "executor-report")
"""Evidence grades, strongest first. An executor report alone never completes an effect."""

STATUSES = ("done", "refused", "not-executed", "awaiting-receipt", "blocked")

VERIFY_REASONS = ("malformed", "unsigned", "unpinned-key", "bad-signature")

# The outcome fields a verb may produce. Anything nonzero outside these is a mismatch.
_VERB_OUTCOMES = {
    "create": {"created"},
    "update": {"updated"},
    "upsert": {"created", "updated"},
    "delete": {"deleted"},
    "none": set(),
}

_MAX_SAFE_INT = 2 ** 53 - 1
_MAX_TOKEN = 1 << 20
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z")
_MIN_SALT = 16

REQUIRED_CLAIMS = ("receipt_id", "correlation_id", "request_digest", "expected_effect_digest",
                   "verdict", "refusal_reason", "outcome", "items_digest", "counterparty",
                   "executed_at", "log_seq")


# --------------------------------------------------------------------------- canonical bytes


def _check_canonical(obj: Any, path: str = "$") -> None:
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, int):
        if abs(obj) > _MAX_SAFE_INT:
            raise ValueError(f"{path}: integer {obj} is outside +/-(2**53 - 1); JCS cannot "
                             f"represent it exactly")
        return
    if isinstance(obj, float):
        raise ValueError(f"{path}: floats are not allowed in canonical JSON (got {obj!r}); "
                         f"float formatting differs across languages")
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check_canonical(v, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: object key {k!r} is not a string")
            if not k.isascii():
                raise ValueError(f"{path}: object key {k!r} is not ASCII; code-point and "
                                 f"UTF-16 key order differ outside ASCII")
            _check_canonical(v, f"{path}.{k}")
        return
    raise TypeError(f"{path}: {type(obj).__name__} is not a JSON value")


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8, no ASCII escaping. Refuses NaN and infinity (and every
    other float), integers beyond 2**53 - 1, non-string or non-ASCII keys, and non-JSON types."""
    _check_canonical(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_ref(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sha256_ref takes bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def request_digest(envelope: dict) -> str:
    if not isinstance(envelope, dict):
        raise TypeError("the request envelope must be a JSON object")
    return sha256_ref(canonical_json(envelope))


def item_key_hash(salt: bytes, key: str) -> str:
    """sha256(salt || key) for one item key. The salt is fixed per agreement and known to A and
    B only; a plain hash of an email address can be reversed by trying known addresses."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < _MIN_SALT:
        raise ValueError(f"the salt must be at least {_MIN_SALT} bytes")
    if not isinstance(key, str):
        raise TypeError("item keys are strings")
    return sha256_ref(bytes(salt) + key.encode("utf-8"))


def items_digest(salt: bytes, keys: List[str]) -> str:
    """Digest of an item set: the sorted salted hashes as canonical JSON. Order-independent.
    A key listed twice is refused, because the count is the number of distinct items."""
    hashes = [item_key_hash(salt, k) for k in keys]
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate item keys")
    return digest_of_hashes(hashes)


def digest_of_hashes(hashes: List[str]) -> str:
    """`items_digest` for a side that holds only the hashes (B's store holds no plain keys)."""
    return sha256_ref(canonical_json(sorted(hashes)))


# --------------------------------------------------------------------------- expected effect


@dataclass(frozen=True)
class ExpectedEffect:
    """What A records, before execution, as the effect it expects. Verbs are stored sorted and
    de-duplicated, so the same set always gives the same digest."""

    operation: str
    counterparty: str
    container: str
    verbs: Tuple[str, ...]
    count: int
    items_digest: str

    def __post_init__(self) -> None:
        for name in ("operation", "counterparty", "container", "items_digest"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"ExpectedEffect.{name} must be a non-empty string")
        if not _DIGEST.fullmatch(self.items_digest):
            raise ValueError("ExpectedEffect.items_digest must be 'sha256:<64 hex>'")
        if isinstance(self.verbs, str):
            raise TypeError("ExpectedEffect.verbs is a sequence of verbs, not one string")
        verbs = tuple(sorted(set(self.verbs)))
        if not verbs or not set(verbs) <= VERBS:
            raise ValueError(f"ExpectedEffect.verbs must be a non-empty subset of {sorted(VERBS)}")
        object.__setattr__(self, "verbs", verbs)
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 0:
            raise ValueError("ExpectedEffect.count must be a non-negative integer")

    def to_doc(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_ref(canonical_json(asdict(self)))


# --------------------------------------------------------------------------- keys and JWS


@dataclass(frozen=True)
class Keypair:
    kid: str
    private: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, kid: str) -> "Keypair":
        return cls(kid=kid, private=Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, kid: str, seed: bytes) -> "Keypair":
        """A fixed key from a 32-byte seed, for test vectors only."""
        return cls(kid=kid, private=Ed25519PrivateKey.from_private_bytes(seed))

    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(seg: str) -> bytes:
    """Strict base64url: no padding, no characters outside the alphabet, and only the one
    canonical encoding of the bytes, so a token cannot be re-spelled with the same meaning."""
    if not _B64URL.fullmatch(seg):
        raise ValueError("not base64url")
    try:
        data = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"not base64url: {e}")
    if _b64e(data) != seg:
        raise ValueError("non-canonical base64url")
    return data


def _header(kid: str) -> Dict[str, str]:
    return {"alg": ALG, "kid": kid, "typ": TYP}


def sign_payload(payload: bytes, key: Keypair, header: Optional[Dict[str, Any]] = None) -> str:
    """Compact JWS over raw payload bytes. `sign_receipt` is the normal entry point; this one
    exists so test vectors can sign payloads the verifier must refuse as malformed."""
    h = _b64e(canonical_json(header if header is not None else _header(key.kid)))
    p = _b64e(payload)
    sig = key.private.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{_b64e(sig)}"


def sign_receipt(claims: dict, key: Keypair) -> str:
    """Compact JWS, alg EdDSA, over the canonical JSON of `claims`. Signs what it is given; the
    claim schema is the verifier's check, so tests can sign deliberately malformed claims."""
    return sign_payload(canonical_json(claims), key)


def unsigned_receipt(claims: dict) -> str:
    """A JWS with alg "none" and an empty signature. For the `unsigned` variant only."""
    h = _b64e(canonical_json({"alg": "none", "typ": TYP}))
    return f"{h}.{_b64e(canonical_json(claims))}."


@dataclass(frozen=True)
class Verified:
    ok: bool
    reason: Optional[str]
    claims: Optional[dict]
    kid: Optional[str]
    detail: str = ""
    """Why, in words, for the evidence. Not part of the contract; compare `reason`."""


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _strict_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                      parse_constant=_reject_constant)


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_SAFE_INT


def claims_problem(claims: Any) -> Optional[str]:
    """Why these claims are not a well-formed receipt, or None. Shape only; no comparison."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in REQUIRED_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    for c in ("receipt_id", "correlation_id", "counterparty"):
        if not isinstance(claims[c], str) or not claims[c]:
            return f"{c} must be a non-empty string"
    for c in ("request_digest", "expected_effect_digest", "items_digest"):
        if not isinstance(claims[c], str) or not _DIGEST.fullmatch(claims[c]):
            return f"{c} must be 'sha256:<64 hex>'"
    if claims["verdict"] not in VERDICTS:
        return f"verdict must be one of {VERDICTS}"
    rr = claims["refusal_reason"]
    if claims["verdict"] == "refused" and (not isinstance(rr, str) or not rr):
        return "a refused receipt must carry a refusal_reason"
    if claims["verdict"] == "executed" and rr is not None:
        return "an executed receipt must have refusal_reason null"
    out = claims["outcome"]
    if not isinstance(out, dict) or set(out) != set(OUTCOME_FIELDS):
        return f"outcome must have exactly {OUTCOME_FIELDS}"
    if not all(_is_count(out[f]) for f in OUTCOME_FIELDS):
        return "outcome counts must be non-negative integers"
    if claims["verdict"] == "no-record":
        if claims.get("refuses_permanently") is not True:
            return ("a no-record receipt counts only with refuses_permanently: true (B commits "
                    "to refuse this request id for good)")
        if any(out[f] for f in OUTCOME_FIELDS):
            return "a no-record receipt must report no effect"
    if not isinstance(claims["executed_at"], str) or not _RFC3339_UTC.fullmatch(claims["executed_at"]):
        return "executed_at must be RFC 3339 in UTC (ending in Z)"
    if not _is_count(claims["log_seq"]):
        return "log_seq must be a non-negative integer"
    return None


def verify_receipt(token: str, pinned: Dict[str, bytes]) -> Verified:
    """Check one receipt's form and signature against the keys A pinned. Ordered: structure and
    claims (`malformed`), then a signature present (`unsigned`), then a pinned key
    (`unpinned-key`), then the signature (`bad-signature`).

    Only alg EdDSA is ever verified. Any other alg is `malformed` (or `unsigned` for "none" in
    any case), so a token cannot pick the algorithm the verifier uses. Keys embedded in the
    header (jwk, x5c, jku) are never read: only `pinned` decides which key verifies.
    `pinned` is caller configuration; a wrong-length key there raises instead of failing a token.
    """
    for k, v in pinned.items():
        if not isinstance(k, str) or not isinstance(v, (bytes, bytearray)) or len(v) != 32:
            raise ValueError(f"pinned[{k!r}] must be a raw 32-byte Ed25519 public key")

    def bad(reason: str, detail: str, kid: Optional[str] = None) -> Verified:
        return Verified(ok=False, reason=reason, claims=None, kid=kid, detail=detail)

    if not isinstance(token, str):
        return bad("malformed", f"token is {type(token).__name__}, not a string")
    if len(token) > _MAX_TOKEN:
        return bad("malformed", "token is larger than 1 MiB")
    parts = token.split(".")
    if len(parts) != 3:
        return bad("malformed", f"compact JWS has 3 segments, this has {len(parts)}")
    h_seg, p_seg, s_seg = parts
    try:
        header = _strict_json(_b64d(h_seg))
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", f"header: {e}")
    if not isinstance(header, dict):
        return bad("malformed", "header is not a JSON object")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    try:
        payload = _b64d(p_seg)
        claims = _strict_json(payload)
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", f"payload: {e}", kid)
    try:
        canonical = canonical_json(claims)
    except (ValueError, TypeError) as e:
        return bad("malformed", f"payload is not canonical JSON: {e}", kid)
    if canonical != payload:
        return bad("malformed", "payload bytes are not the canonical form of its claims", kid)
    problem = claims_problem(claims)
    if problem:
        return bad("malformed", problem, kid)

    alg = header.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return bad("unsigned", f"alg is {alg!r}", kid)
    if alg != ALG:
        return bad("malformed", f"alg {alg!r} is not {ALG}; no other algorithm is verified", kid)
    if header.get("typ") != TYP:
        return bad("malformed", f"typ {header.get('typ')!r} is not {TYP!r}", kid)
    if "crit" in header or "b64" in header:
        return bad("malformed", "header uses crit or b64, which this format does not", kid)
    if kid is None or not kid:
        return bad("malformed", "header has no kid", None)
    try:
        sig = _b64d(s_seg)
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


# --------------------------------------------------------------------------- judge


@dataclass(frozen=True)
class Judgement:
    """The kit's own ground truth for what A should conclude about one receipt."""

    accept: bool
    status: str
    grade: Optional[str]
    reason: Optional[str]
    detail: str = ""
    """Why, in words, for the evidence. Not part of the contract; compare `reason`."""


_SUCCESS_WORDS = {"done", "success", "succeeded", "ok", "completed", "executed"}


def report_claims_success(report: Optional[dict]) -> bool:
    """Does an executor report claim the effect happened? Only used to choose between the two
    no-receipt reasons; neither completes the effect."""
    if not isinstance(report, dict):
        return False
    if report.get("success") is True or report.get("ok") is True:
        return True
    status = report.get("status")
    return isinstance(status, str) and status.lower() in _SUCCESS_WORDS


def report_claims_sent(report: Optional[dict]) -> bool:
    """Does an executor report say the request went out to B? A claim of success says so, and
    so does ``"sent": true``. ``"sent": false`` or no report is no such claim. Decides what a
    signed no-record means."""
    if report_claims_success(report):
        return True
    return isinstance(report, dict) and report.get("sent") is True


def _blocked(reason: str, detail: str) -> Judgement:
    return Judgement(accept=False, status="blocked", grade=None, reason=reason, detail=detail)


def judge(receipt: Optional[str], *, pinned: Dict[str, bytes], envelope: dict,
          expected: ExpectedEffect, executor_report: Optional[dict]) -> Judgement:
    """What A may conclude from this receipt (or its absence). Only a verified receipt for this
    request and this expectation, with exactly the expected effect, is `done`. An executor
    report is never enough, and once a receipt exists it is read for one thing only: whether
    the executor claims it sent the request, which decides what a signed no-record means."""
    if receipt is None:
        if report_claims_success(executor_report):
            return Judgement(accept=False, status="awaiting-receipt", grade=None,
                             reason="executor-report-only",
                             detail="the executor reports success; B has issued no receipt")
        return Judgement(accept=False, status="awaiting-receipt", grade=None, reason="no-receipt",
                         detail="no receipt from B")

    v = verify_receipt(receipt, pinned)
    if not v.ok:
        return _blocked(v.reason or "malformed", v.detail)
    c = v.claims or {}

    # 1. the request this receipt answers
    want_req = request_digest(envelope)
    if c["request_digest"] != want_req:
        return _blocked("wrong-request", f"receipt answers {c['request_digest']}, A sent {want_req}")
    cid = envelope.get("correlation_id")
    if cid is not None and c["correlation_id"] != cid:
        return _blocked("wrong-request",
                        f"receipt names correlation id {c['correlation_id']!r}, A sent {cid!r}")

    # 2. the expectation it was issued against
    want_exp = expected.digest()
    if c["expected_effect_digest"] != want_exp:
        return _blocked("expected-mismatch",
                        f"receipt names expectation {c['expected_effect_digest']}, A recorded {want_exp}")
    if c["counterparty"] != expected.counterparty:
        return _blocked("expected-mismatch",
                        f"receipt names counterparty {c['counterparty']!r}, A expected "
                        f"{expected.counterparty!r}")

    # 3. a refusal closes the attempt as not executed
    if c["verdict"] == "refused":
        return Judgement(accept=False, status="refused", grade=None, reason="refused",
                         detail=f"B refused: {c['refusal_reason']}")

    # 3b. a permanent no-record closes it without a person only if the executor does not claim
    #     to have sent the request; otherwise the two sides disagree and a person decides
    if c["verdict"] == "no-record":
        if report_claims_sent(executor_report):
            return _blocked("no-record-disputed",
                            "B signed that it has no record of this request; the executor "
                            "reports it sent it")
        return Judgement(accept=False, status="not-executed", grade=None, reason="no-record",
                         detail="B signed that it has no record of this request and will "
                                "refuse it permanently")

    # 4. counts, per verb
    o = c["outcome"]
    done_n = o["created"] + o["updated"] + o["deleted"]
    if o["failed"] or done_n != expected.count:
        if o["failed"] > 0 and done_n + o["failed"] == expected.count:
            return _blocked("partial", f"{done_n} of {expected.count} done, {o['failed']} failed")
        return _blocked("count-mismatch", f"receipt covers {done_n} done and {o['failed']} failed; "
                                          f"A expected {expected.count}")
    allowed = set().union(*(_VERB_OUTCOMES[vb] for vb in expected.verbs))
    stray = [f for f in ("created", "updated", "deleted") if o[f] and f not in allowed]
    if stray:
        return _blocked("count-mismatch", f"receipt reports {', '.join(stray)} but A expected only "
                                          f"{', '.join(expected.verbs)}")

    # 5. the item set
    if c["items_digest"] != expected.items_digest:
        return _blocked("items-mismatch", "receipt's item digest differs from A's expectation")

    # 6. everything matches
    return Judgement(accept=True, status="done", grade="signed-by-B", reason=None,
                     detail=f"verified under {v.kid}")
