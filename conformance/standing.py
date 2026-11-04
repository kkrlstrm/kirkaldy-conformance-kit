"""Key statements, standing assertions and holder-signed chains for KRK-20 (P20, standing
verifiable offline), shared with KRK-21 (P21).

`X1-STANDING-OFFLINE-DESIGN.md` §2.4 and §6.2. Two formats, each a compact JWS (EdDSA) over the
canonical JSON of its claims, as every kit format is (`receipts.canonical_json`):

- **Key statement** (`KEYSET_SCHEMA`, typ `KEYSET_TYP`), signed by A's **anchor**, the one key B
  pins at bind; the anchor signs nothing else: ``issuer``, ``version`` (grows), ``issued_at``
  (ms), ``ttl_s``, ``expires_at``, ``keys`` (``[{kid, public_key, purposes, state, since}]``).
  ``purposes`` from `PURPOSES`; ``state`` ``active``, ``retired`` (a signature made at or after
  ``since`` is not A's) or ``revoked`` (the same, and A says the key may be in other hands);
  ``since`` is RFC 3339 UTC with milliseconds on A's clock, or null for an active key.
- **Standing assertion** (`STANDING_SCHEMA`, typ `STANDING_TYP`), signed by a key the statement
  designates for ``standing``: ``issuer``, ``principal``, ``classes`` (``{operation: limit or
  null}``, a limit in X5's constraint vocabulary, `attenuation`), ``issued_at`` (ms),
  ``not_after`` (ms), ``audience`` (a list of relying parties, or null for any).

**When a signature was made.** A JWS carries no signing time of its own. B reads a token's
``issued_at`` as the claimed signing time against a key's ``since`` (`key_state`). A leaked key
can claim an earlier time, so the claim alone never makes evidence fresh: its age is bounded by
T from the earlier of ``issued_at`` and B's receipt, whatever it claims. The kit's own reference
instants never come from claims: `t_f` is the stub's kit-clock signing log (KRK-M74).

**What makes standing current** (§2.2, the kit's rule for its own format): B holds an assertion
naming the principal and covering the class, signed under a key designated for standing, and the
newer of its ``issued_at`` and the ``issued_at`` of the newest snapshot that lists the principal
as standing is no more than T before the commit. ``not_after`` can end it earlier and never
extends it. A snapshot alone shows standing for something, not the class.

**Holder-signed hops** (grant 0.2, `attenuation.GRANT_V2_SCHEMA`): `verify_holder_chain` checks
each hop's signature: the root under a key the root organisation's statement designates for
``grant``, every other hop under its parent's ``agent_key``, with the hop's ``issuer`` the
parent's ``subject``. Meaning (scope, depth, cycles) is `attenuation`'s.

Nothing here imports a target, and P16 to P19 do not import this module.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import attenuation, receipts
from .receipts import Keypair, Verified

ALG = "EdDSA"
KEYSET_SCHEMA, KEYSET_TYP = "kirkaldy.keyset/0.1", "krk-keyset+jws"
STANDING_SCHEMA, STANDING_TYP = "kirkaldy.standing/0.1", "krk-standing+jws"
GRANT_TYP = attenuation.GRANT_TYP
PURPOSES = ("grant", "status", "standing", "request")
KEY_STATES = ("active", "retired", "revoked")
KEYSET_CLAIMS = ("schema", "issuer", "version", "issued_at", "ttl_s", "expires_at", "keys")
STANDING_CLAIMS = ("schema", "issuer", "principal", "classes", "issued_at", "not_after",
                   "audience")
STANDING_HEADER = "KRK-Standing"
KEYSET_HEADER = "KRK-Keyset"
"""Headers the agent staples a standing assertion and a key statement in, outside the binding."""
LIFETIME_S = 12 * 3600
"""Every assertion the stub signs is valid by its own ``not_after`` for twelve hours, far beyond
any T, so a B that reads expiry as freshness cannot pass a stale fixture by accident
(KRK-M78)."""

_UTC_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")

STATES = ("current", "stale", "wrong-key", "wrong-org", "wrong-principal", "wrong-class",
          "wrong-audience", "missing")
"""`standing_state` readings; only ``current`` lets B act."""


def utc_ms(epoch: float) -> str:
    from .status import utc_ms as f
    return f(epoch)


def epoch_of(s: Any) -> Optional[float]:
    from .status import epoch_of as f
    try:
        return f(s)
    except ValueError:
        return None


# --------------------------------------------------------------------------- claims


def keyset_claims(*, issuer: str, version: int, issued_at: float, ttl_s: int,
                  keys: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"schema": KEYSET_SCHEMA, "issuer": issuer, "version": int(version),
            "issued_at": utc_ms(issued_at), "ttl_s": int(ttl_s),
            "expires_at": utc_ms(issued_at + int(ttl_s)),
            "keys": [dict(k) for k in sorted(keys, key=lambda k: k["kid"])]}


def key_entry(kid: str, public: bytes, purposes: Sequence[str], state: str = "active",
              since: Optional[float] = None) -> Dict[str, Any]:
    return {"kid": kid, "public_key": bytes(public).hex(), "purposes": sorted(purposes),
            "state": state, "since": None if since is None else utc_ms(since)}


def standing_claims(*, issuer: str, principal: str, classes: Dict[str, Any], issued_at: float,
                    not_after: float, audience: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"schema": STANDING_SCHEMA, "issuer": issuer, "principal": principal,
            "classes": dict(classes), "issued_at": utc_ms(issued_at),
            "not_after": utc_ms(not_after),
            "audience": None if audience is None else list(audience)}


def _is_int(v: Any, lo: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= 2 ** 53 - 1


def keyset_problem(claims: Any) -> Optional[str]:
    """Why these claims are not a well-formed key statement, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    if set(claims) != set(KEYSET_CLAIMS):
        return f"a key statement has exactly {KEYSET_CLAIMS}"
    if claims["schema"] != KEYSET_SCHEMA:
        return f"schema must be {KEYSET_SCHEMA!r}"
    if not isinstance(claims["issuer"], str) or not claims["issuer"]:
        return "issuer must be a non-empty string"
    if not _is_int(claims["version"], 1) or not _is_int(claims["ttl_s"], 1):
        return "version and ttl_s are positive integers"
    for c in ("issued_at", "expires_at"):
        if not isinstance(claims[c], str) or not _UTC_MS.fullmatch(claims[c]):
            return f"{c} must be RFC 3339 UTC with milliseconds"
    keys = claims["keys"]
    if not isinstance(keys, list) or not keys:
        return "keys is a non-empty list"
    seen = set()
    for k in keys:
        if not isinstance(k, dict) or set(k) != {"kid", "public_key", "purposes", "state",
                                                 "since"}:
            return "each key is {kid, public_key, purposes, state, since}"
        if not isinstance(k["kid"], str) or not k["kid"] or k["kid"] in seen:
            return "each kid is a non-empty string, once"
        seen.add(k["kid"])
        if not isinstance(k["public_key"], str) or not _HEX64.fullmatch(k["public_key"]):
            return f"key {k['kid']}: public_key is 64 hex digits"
        if not isinstance(k["purposes"], list) or not k["purposes"] \
                or any(p not in PURPOSES for p in k["purposes"]):
            return f"key {k['kid']}: purposes are from {PURPOSES}"
        if k["state"] not in KEY_STATES:
            return f"key {k['kid']}: state is one of {KEY_STATES}"
        if (k["state"] == "active") != (k["since"] is None):
            return f"key {k['kid']}: since is null exactly when the key is active"
        if k["since"] is not None and (not isinstance(k["since"], str)
                                       or not _UTC_MS.fullmatch(k["since"])):
            return f"key {k['kid']}: since must be RFC 3339 UTC with milliseconds"
    return None


def standing_problem(claims: Any) -> Optional[str]:
    """Why these claims are not a well-formed standing assertion, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    if set(claims) != set(STANDING_CLAIMS):
        return f"a standing assertion has exactly {STANDING_CLAIMS}"
    if claims["schema"] != STANDING_SCHEMA:
        return f"schema must be {STANDING_SCHEMA!r}"
    for c in ("issuer", "principal"):
        if not isinstance(claims[c], str) or not claims[c]:
            return f"{c} must be a non-empty string"
    cl = claims["classes"]
    if not isinstance(cl, dict) or not cl:
        return "classes is a non-empty object {operation: limit or null}"
    for op, lim in cl.items():
        if not isinstance(op, str) or not op:
            return "each class is an operation name"
        if lim is not None:
            p = attenuation.constraints_problem(lim)
            if p:
                return f"class {op}: {p[1]}"
    for c in ("issued_at", "not_after"):
        if not isinstance(claims[c], str) or not _UTC_MS.fullmatch(claims[c]):
            return f"{c} must be RFC 3339 UTC with milliseconds"
    au = claims["audience"]
    if au is not None and (not isinstance(au, list) or not au
                           or any(not isinstance(x, str) or not x for x in au)):
        return "audience is null or a non-empty list of relying parties"
    return None


def _grant_v2(claims: Any) -> Optional[str]:
    p = attenuation.grant_v2_problem(claims)
    return None if p is None else f"{p[0]}: {p[1]}"


PROBLEMS: Dict[str, Callable[[Any], Optional[str]]] = {
    KEYSET_TYP: keyset_problem, STANDING_TYP: standing_problem}


# --------------------------------------------------------------------------- JWS


def sign(claims: Dict[str, Any], key: Keypair, typ: str, *, raw: bool = False) -> str:
    """Compact JWS, alg EdDSA. Over the canonical JSON of `claims`; with ``raw``, over a plain
    sorted, compact serialisation the canonical form would refuse (a float, an integer beyond
    2^53 - 1), for numeric fixtures a sloppy issuer genuinely signs (X5 ``numeric``). Signs what
    it is given; the shape is the verifier's check."""
    if raw:
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    else:
        payload = receipts.canonical_json(claims)
    return receipts.sign_payload(payload, key, {"alg": ALG, "kid": key.kid, "typ": typ})


def header_of(token: Any) -> Dict[str, Any]:
    try:
        h = receipts._strict_json(receipts._b64d(str(token).split(".")[0]))
        return h if isinstance(h, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def peek(token: Any) -> Dict[str, Any]:
    """Claims read without checking anything (to route a token); never used for a decision."""
    try:
        c = json.loads(receipts._b64d(str(token).split(".")[1]))
        return c if isinstance(c, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def verify(token: Any, pinned: Dict[str, bytes], typ: str, *,
           problem_of: Optional[Callable[[Any], Optional[str]]] = None,
           lenient: bool = False) -> Verified:
    """The kit's reader of these formats (and grant 0.2, `GRANT_TYP` with `problem_of`), with
    `status.verify`'s order and reasons: form, a signature, a pinned key, the signature.
    ``lenient`` skips the canonical-bytes check and parses floats and integers beyond 2^53 - 1,
    as a sloppy reader would; only toys that model that flaw set it."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    problem_of = problem_of or PROBLEMS.get(typ) or (_grant_v2 if typ == GRANT_TYP else None)
    if problem_of is None:
        raise ValueError(f"unknown typ {typ!r}")

    def bad(reason: str, detail: str, kid: Optional[str] = None) -> Verified:
        return Verified(ok=False, reason=reason, claims=None, kid=kid, detail=detail)

    if not isinstance(token, str):
        return bad("malformed", f"token is {type(token).__name__}, not a string")
    parts = token.split(".")
    if len(parts) != 3 or len(token) > (1 << 22):
        return bad("malformed", "not a compact JWS")
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
        if lenient:
            claims = json.loads(payload.decode("utf-8"))
        else:
            claims = receipts._strict_json(payload)
            if receipts.canonical_json(claims) != payload:
                return bad("malformed", "payload bytes are not the canonical form of its "
                                        "claims", kid)
    except (ValueError, UnicodeDecodeError, TypeError) as e:
        return bad("malformed", f"payload: {e}", kid)
    if not lenient:
        problem = problem_of(claims)
        if problem:
            return bad("malformed", problem, kid)
    alg = hdr.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return bad("unsigned", f"alg is {alg!r}", kid)
    if alg != ALG or hdr.get("typ") != typ or "crit" in hdr or "b64" in hdr or not kid:
        return bad("malformed", f"header must be EdDSA, {typ}, a kid", kid)
    try:
        sig = receipts._b64d(s_seg)
    except ValueError as e:
        return bad("malformed", f"signature: {e}", kid)
    if not sig:
        return bad("unsigned", "the signature is empty", kid)
    if kid not in pinned:
        return bad("unpinned-key", f"kid {kid!r} is not pinned", kid)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pinned[kid])).verify(
            sig, f"{h_seg}.{p_seg}".encode("ascii"))
    except InvalidSignature:
        return bad("bad-signature", f"signature does not verify under {kid!r}", kid)
    return Verified(ok=True, reason=None, claims=claims, kid=kid, detail="verified")


# --------------------------------------------------------------------------- keys


def keys_of(keyset: Dict[str, Any]) -> Dict[str, bytes]:
    """Every key a statement lists, by kid, whatever its state (to verify a signature; whether
    the key was A's when it signed is `key_state`'s)."""
    return {k["kid"]: bytes.fromhex(k["public_key"]) for k in keyset.get("keys") or ()}


def key_state(keyset: Dict[str, Any], kid: str, purpose: str,
              signed_at: Optional[float], *, strict_revoked: bool = False) -> Tuple[str, str]:
    """Whether `kid` is A's for `purpose` for a signature made at `signed_at` (A's claimed time),
    by `keyset` (claims): ``("a-key", why)``, or ``"retired"`` / ``"revoked"`` (made at or after
    ``since``, or with no readable time), ``"wrong-purpose"``, ``"not-a-key"``.

    With `strict_revoked`, a revoked key is ``"revoked"`` whatever time the token claims: the
    reading of a B that does not trust a revoked key's claimed time, since whoever holds it can
    backdate what it signs. That reading is conformant too, so the kit
    accepts both (`key_readings`); everything else is the same in both readings."""
    k = next((k for k in keyset.get("keys") or () if k.get("kid") == kid), None)
    if k is None:
        return "not-a-key", f"{kid} is not in key statement version {keyset.get('version')}"
    if purpose not in (k.get("purposes") or ()):
        return "wrong-purpose", f"{kid} is designated for {k.get('purposes')}, not {purpose}"
    if k["state"] == "active":
        return "a-key", f"{kid} is active for {purpose}"
    if strict_revoked and k["state"] == "revoked":
        return "revoked", f"{kid} is revoked from {k.get('since')}; its claimed signing time is " \
                          f"not trusted"
    since = epoch_of(k.get("since"))
    if since is None or signed_at is None or signed_at >= since:
        return k["state"], (f"{kid} is {k['state']} from {k.get('since')}, and the token claims "
                            f"to be signed at {utc_ms(signed_at) if signed_at else 'no time'}")
    return "a-key", f"{kid} is {k['state']} from {k.get('since')}, after this signature"


def key_readings(keyset: Dict[str, Any], kid: str, purpose: str,
                 signed_at: Optional[float]) -> Tuple[str, ...]:
    """Every state a conformant B may read for this signature: one, except
    for a revoked key's signature claimed before ``since``, where both ``"a-key"`` and the
    stricter ``"revoked"`` are conformant."""
    lenient = key_state(keyset, kid, purpose, signed_at)[0]
    strict = key_state(keyset, kid, purpose, signed_at, strict_revoked=True)[0]
    return (lenient,) if lenient == strict else (lenient, strict)


# --------------------------------------------------------------------------- what B should derive


def standing_state(assertion: Optional[Dict[str, Any]], *, kid: Optional[str],
                   keyset: Optional[Dict[str, Any]], issuer: str, principal: str,
                   operation: str, audience: str, at: float, T: float,
                   signed_at: Optional[float] = None,
                   snapshot_at: Optional[float] = None,
                   strict_revoked: bool = False) -> Dict[str, Any]:
    """What a correct B derives for one standing assertion (claims, as verified, and the kid that
    signed it) for the root principal `principal` of a chain issued by `issuer`, for `operation`
    at relying party `audience`, at time `at` (wall seconds), with bound `T`.

    Returns ``{"state", "t_f", "why"}`` with ``state`` from `STATES`. ``t_f`` is the time the
    evidence counts from: `signed_at` when the caller gives one (the kit gives its kit-clock
    signing log, never the claims, KRK-M74; a toy gives the earlier of the claim and its own
    receipt), else the claim's ``issued_at``; the newest snapshot that lists the principal as
    standing (`snapshot_at`) can make it newer (§2.2)."""
    if assertion is None:
        return {"state": "missing", "t_f": None, "why": f"no standing assertion for {principal}"}
    if keyset is None or kid is None:
        return {"state": "wrong-key", "t_f": None, "why": "no key statement to check the signer"}
    claimed = epoch_of(assertion.get("issued_at"))
    ks, why = key_state(keyset, kid, "standing", claimed, strict_revoked=strict_revoked)
    if ks != "a-key":
        return {"state": "wrong-key", "t_f": None, "why": why}
    if assertion.get("issuer") != issuer or keyset.get("issuer") != issuer:
        return {"state": "wrong-org", "t_f": None,
                "why": f"the assertion is {assertion.get('issuer')}'s, the chain roots at "
                       f"{issuer}"}
    if assertion.get("principal") != principal:
        return {"state": "wrong-principal", "t_f": None,
                "why": f"the assertion names {assertion.get('principal')}, the chain's root "
                       f"principal is {principal}"}
    if operation not in (assertion.get("classes") or {}):
        return {"state": "wrong-class", "t_f": None,
                "why": f"the assertion covers {sorted(assertion.get('classes') or {})}, not "
                       f"{operation}"}
    au = assertion.get("audience")
    if au is not None and audience not in au:
        return {"state": "wrong-audience", "t_f": None,
                "why": f"the assertion is addressed to {au}, not {audience}"}
    t_f = signed_at if signed_at is not None else claimed
    if snapshot_at is not None and t_f is not None:
        t_f = max(t_f, snapshot_at)
    na = epoch_of(assertion.get("not_after"))
    if t_f is None or na is None:
        return {"state": "stale", "t_f": t_f, "why": "no readable time"}
    if at > na:
        return {"state": "stale", "t_f": t_f, "why": "past its own not_after"}
    if at - t_f > T:
        return {"state": "stale", "t_f": t_f,
                "why": f"the evidence is {at - t_f:.2f} s old; the bound is {T:g} s"}
    return {"state": "current", "t_f": t_f, "why": f"{at - t_f:.2f} s old, within {T:g} s"}


def standing_readings(assertion: Optional[Dict[str, Any]], **kw: Any) -> Tuple[str, ...]:
    """Every state a conformant B may derive (`standing_state`'s arguments): one, or two where
    the only difference is a revoked key's claimed signing time."""
    lenient = standing_state(assertion, **kw)["state"]
    strict = standing_state(assertion, **kw, strict_revoked=True)["state"]
    return (lenient,) if lenient == strict else (lenient, strict)


@dataclass
class Hop:
    """One verified hop of a grant 0.2 chain, with who signed it."""

    claims: Dict[str, Any]
    signer: str
    """``org:<issuer>:<kid>`` for a root signed by an organisation, ``holder:<subject>:<kid>``
    for a hop signed by its parent's agent key (KRK-M79: the evidence names each signer)."""


def verify_holder_chain(tokens: Sequence[str], anchors: Dict[str, Dict[str, Any]], *,
                        lenient: bool = False,
                        problem_of: Optional[Callable[[Any], Optional[str]]] = None
                        ) -> Tuple[List[Hop], Optional[str]]:
    """Signatures of a grant 0.2 chain (the presented grant first, then each parent): the root
    (the last token) under a key that its issuer's key statement designates for ``grant``
    (`anchors` maps an issuer to its verified key statement claims); every other hop either
    signed the same way by its parent's own organisation (the hop's ``issuer`` is the parent's
    ``issuer``, X4's chains), or held-signed: under its parent's ``agent_key``, with the hop's
    ``issuer`` its parent's ``subject``. Returns the hops
    and None, or ``([], what is wrong)``. Shape is `attenuation.grant_v2_problem` unless
    `problem_of` says otherwise (a toy that ignores unknown members); scope, depth, links and
    cycles are `attenuation.allowed`'s. A chain whose last token is issued by an agent, not an
    organisation (a cycle signed by holders), has no root to verify, and is refused here."""
    shape = (lambda _c: None) if lenient else (problem_of or _grant_v2)
    toks = list(tokens)
    if not toks:
        return [], "no grant was presented"
    decoded = [peek(t) for t in toks]
    out: List[Hop] = []
    for n, tok in enumerate(toks):
        c = decoded[n]
        kid = header_of(tok).get("kid", "")
        if not c:
            return [], f"grant {n}: unreadable"
        if n + 1 == len(toks):
            ks = anchors.get(str(c.get("issuer")))
            if ks is None:
                return [], f"the root's issuer {c.get('issuer')!r} is not an organisation B pins"
            st, why = key_state(ks, kid, "grant", epoch_of(c.get("issued_at")))
            if st != "a-key":
                return [], f"the root: {st}: {why}"
            pinned = {kid: keys_of(ks)[kid]}
            signer = f"org:{c.get('issuer')}:{kid}"
        elif c.get("issuer") == decoded[n + 1].get("issuer") and \
                str(c.get("issuer")) in anchors:
            # A child its parent's own organisation signed (X4's chains: A signs every hop).
            ks = anchors[str(c.get("issuer"))]
            st, why = key_state(ks, kid, "grant", epoch_of(c.get("issued_at")))
            if st != "a-key":
                return [], f"grant {n}: {st}: {why}"
            pinned = {kid: keys_of(ks)[kid]}
            signer = f"org:{c.get('issuer')}:{kid}"
        else:
            parent = decoded[n + 1]
            ak = parent.get("agent_key") if isinstance(parent, dict) else None
            if not isinstance(ak, dict) or c.get("issuer") != parent.get("subject"):
                return [], (f"grant {n} is issued by {c.get('issuer')!r}, not by its parent's "
                            f"holder {parent.get('subject')!r}")
            try:
                pinned = {str(ak["kid"]): bytes.fromhex(str(ak["public_key"]))}
            except (KeyError, ValueError, TypeError):
                return [], f"grant {n + 1} has no readable agent_key"
            signer = f"holder:{c.get('issuer')}:{kid}"
        v = verify(tok, pinned, GRANT_TYP, problem_of=shape, lenient=lenient)
        if not v.ok:
            return [], f"grant {n}: {v.reason}: {v.detail}"
        out.append(Hop(v.claims, signer))
    return out, None
