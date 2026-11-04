"""Grants, status snapshots and notices for KRK-19 (P19, withdrawal within T).

X4 needs something that can be withdrawn. A per-request authorisation (`authz`, KRK-18) covers
one request, and every P19 presentation is a fresh request (design §4.3), so the thing withdrawn
is a **grant**: a longer-lived authority A gives its agent. The agent signs each request under it
(a per-request authorisation in `authz`'s format, with the extra member ``grant_id``), or A signs
the request itself before the withdrawal (``presigned_after_withdrawal``, and the only form a B
that pins A's key alone can take). Either way, the status B has to check is the grant's, and
every parent's above it, and the standing of the principal it rests on.

Three formats, each a compact JWS (RFC 7515) with header ``{"alg": "EdDSA", "kid", "typ"}`` over
the canonical JSON of its claims (`receipts.canonical_json`), the construction of KRK-16 receipts
and KRK-18 authorisations:

- **Grant** (`GRANT_SCHEMA`, typ `GRANT_TYP`), signed by A: ``grant_id`` (``gr-`` and hex, from
  the operating system), ``issuer``, ``audience`` (B's id), ``subject`` (the agent),
  ``agent_key`` (``{"kid", "public_key"}``, hex), ``principal`` (who at A granted it),
  ``operation``, ``ceiling`` (``{"max_amount": n}`` and nothing else in version 1), ``parent``
  (a grant id or null), ``issued_at`` (RFC 3339 UTC with milliseconds, read from A's clock when
  A signs the grant, the same clock as a snapshot's ``issued_at``), ``not_before`` /
  ``not_after`` (RFC 3339 UTC, whole seconds), and ``status`` (``{"source": url, "index": n}``).
  ``issued_at`` is not ``not_before``: A may set ``not_before`` earlier than the issue, to allow
  for clocks that differ (the stub sets it an hour back), so only ``issued_at`` says whether a
  snapshot was signed before the grant existed.
- **Status snapshot** (`STATUS_SCHEMA`, typ `STATUS_TYP`), signed by A: ``issuer``, ``source``,
  ``version`` (a positive integer; every snapshot the source signs has a larger one, so version,
  not time, orders snapshots, KRK-M63), ``issued_at`` (RFC 3339 UTC with milliseconds, read from
  A's clock, which a fixture may offset), ``ttl_s`` and ``expires_at``, ``entries``
  (``{grant_id: {"state", "ceiling"}}``, `GRANT_STATES`; ``ceiling`` set only for
  ``narrowed``), and ``standing`` (``{principal: "standing" | "withdrawn"}``).
- **Notice** (`NOTICE_SCHEMA`, typ `NOTICE_TYP`), pushed by A: ``issuer``, ``source``,
  ``version`` (the snapshot version that first shows the change), ``issued_at``, ``entries`` and
  ``standing`` holding only what changed.

**A grant absent from a snapshot**. A snapshot lists the grants that existed when
A signed it, so what an absent grant means depends on when the grant was issued:

- **Not yet listed.** The grant's ``issued_at`` is at or after the snapshot's ``issued_at``: A
  signed the snapshot before the grant existed, so the snapshot cannot list it. The same instant
  counts here: a correct A lists a grant in every snapshot it signs after issuing it, so a snapshot
  of the grant's own instant that lacks it was signed first, and the reading lasts only until B's
  next fetch, which is the bound the format promises anyway. The grant reads ``not-yet-listed``,
  which is in force (`IN_FORCE`) only until B's next fetch, the one B must make within its bound T.
  It never makes the snapshot usable for longer than B's age limit allows; how old a snapshot may
  get is that limit's question, not this rule's, so a grant issued after the snapshot's
  ``expires_at`` reads the same way. From the next snapshot on, the grant is listed, or it is absent
  from a snapshot issued after it, which is the next case. Index-based status lists work the same
  way: an unset bit means valid.
- **Unknown.** The grant's ``issued_at`` is before the snapshot's ``issued_at``: A signed the
  snapshot after the grant existed and did not list it. The source does not know the grant
  (another source's grant, an entry A lost, a snapshot of a different list), so the snapshot
  cannot say whether the grant was withdrawn. The grant reads ``unknown``, and B refuses: absence
  here fails safe. So does a grant or snapshot with no readable ``issued_at``: absence cannot be
  ordered.

Both times are A's, so the comparison does not depend on B's clock. It does depend on A's clock
not running backwards between the two signatures. If it does, a grant issued after the jump reads
``unknown`` against a snapshot signed before it, until B's next fetch, which fails safe (the
kit's stub does this once, when it resets the offset after `skewed_issuer_clock`). The other
direction, a snapshot signed after the jump that omits a grant issued before it, reads ``not yet
listed`` and fails open; it needs an A that both moves its clock back and drops an entry, and
the kit's stub does neither.

**A principal absent from ``standing``**. A snapshot that lists a grant must state
the standing of the principal that grant rests on. A principal missing from ``standing`` in a
snapshot that lists one of its grants reads ``unknown``, and B refuses: the source has not said
the principal still has standing, so absence fails safe, as for a grant the source does not list.
A grant that is not yet listed is not covered: the snapshot was signed before the grant existed,
so it need not name the grant's principal either, and the reading lasts only until B's next
fetch. The kit's stub lists every principal it issues to, in every snapshot it signs after the
issue.

**The status a B should derive** for a presented grant chain is `chain_state`: the presented
grant and every parent must be ``valid``, ``narrowed`` or not yet listed in the snapshot, every
principal they rest on must have standing, and the effective ceiling is the narrowest of them.
`within` says whether a request's values are inside a ceiling. The kit uses these to state what
each fixture means and to read the published state back (KRK-M26); toys use them as a correct B
would. A target uses whatever it likes.

**One wire profile** besides the kit's own: `BITSTRING`, a binary revocation list in the manner
of the W3C Bitstring Status List (one bit per status index, compressed with zlib and base64url
encoded). It can say only "revoked or not": a narrowing, a suspension and a loss of standing are
format gaps (`bitstring_gaps`, KRK-M62), never silently dropped. In this profile every index
below ``size`` is listed, and an unset bit is valid, whenever the grant was issued: that is the
profile's own rule, and the one KRK-M46 follows. An index at or past ``size`` is absent, and
reads as above by the grant's ``issued_at`` (`revoked_in` returns None for it: the kit reads the
published state back, and an absent grant has none). The OAuth Token Status List and an SSF/CAEP
push profile are not built.
"""
from __future__ import annotations

import base64
import re
import secrets
import zlib
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import receipts
from .receipts import Keypair, Verified

ALG = "EdDSA"
GRANT_SCHEMA = "kirkaldy.grant/0.1"
GRANT_TYP = "krk-grant+jws"
STATUS_SCHEMA = "kirkaldy.status/0.1"
STATUS_TYP = "krk-status+jws"
NOTICE_SCHEMA = "kirkaldy.status-notice/0.1"
NOTICE_TYP = "krk-notice+jws"
BITSTRING = "bitstring-status-list"
BITSTRING_SCHEMA = "kirkaldy.status-bitstring/0.1"
BITSTRING_TYP = "krk-status-bitstring+jws"
PROFILES = ("kirkaldy", BITSTRING)
"""The status wire profiles the stub A can serve. ``kirkaldy`` is the kit's own format."""

GRANT_STATES = ("valid", "revoked", "suspended", "narrowed")
STANDING_STATES = ("standing", "withdrawn")
IN_FORCE = ("valid", "narrowed", "not-yet-listed")
"""The `chain_state` states under which a chain is in force. ``not-yet-listed`` holds only until
B's next fetch."""
CEILING_MEMBERS = ("max_amount",)

GRANT_CLAIMS = ("schema", "grant_id", "issuer", "audience", "subject", "agent_key", "principal",
                "operation", "ceiling", "parent", "issued_at", "not_before", "not_after",
                "status")
STATUS_CLAIMS = ("schema", "issuer", "source", "version", "issued_at", "ttl_s", "expires_at",
                 "entries", "standing")
NOTICE_CLAIMS = ("schema", "issuer", "source", "version", "issued_at", "entries", "standing")
BITSTRING_CLAIMS = ("schema", "issuer", "source", "version", "issued_at", "ttl_s", "expires_at",
                    "purpose", "size", "encoded_list")

_GR_ID = re.compile(r"gr-[0-9a-f]{16,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC_S = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_UTC_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


# --------------------------------------------------------------------------- time


def utc_s(epoch: float) -> str:
    """RFC 3339 UTC, whole seconds (grants), as `authz.utc`."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_ms(epoch: float) -> str:
    """RFC 3339 UTC with milliseconds (snapshots and notices)."""
    ms = int(round(epoch * 1000))
    d = datetime.fromtimestamp(ms // 1000, timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"


def epoch_of(s: str) -> float:
    """Seconds since the epoch for either form; ValueError for anything else."""
    if not isinstance(s, str):
        raise ValueError("not a time string")
    if _UTC_MS.fullmatch(s):
        base, frac = s[:-1].split(".")
        d = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return d.timestamp() + int(frac) / 1000.0
    if _UTC_S.fullmatch(s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    raise ValueError(f"{s!r} is not RFC 3339 UTC")


def new_grant_id() -> str:
    """From the operating system's random source, never from a run's seed (KRK-M36)."""
    return f"gr-{secrets.token_hex(8)}"


# --------------------------------------------------------------------------- claims


def grant_claims(*, issuer: str, audience: str, subject: str, agent_kid: str,
                 agent_public: bytes, principal: str, operation: str, ceiling: Dict[str, Any],
                 parent: Optional[str], issued_at: float, not_before: float,
                 not_after: float, source: str, index: int,
                 grant_id: Optional[str] = None) -> Dict[str, Any]:
    return {"schema": GRANT_SCHEMA, "grant_id": grant_id or new_grant_id(), "issuer": issuer,
            "audience": audience, "subject": subject,
            "agent_key": {"kid": agent_kid, "public_key": bytes(agent_public).hex()},
            "principal": principal, "operation": operation, "ceiling": dict(ceiling),
            "parent": parent, "issued_at": utc_ms(issued_at),
            "not_before": utc_s(not_before), "not_after": utc_s(not_after),
            "status": {"source": source, "index": int(index)}}


def snapshot_claims(*, issuer: str, source: str, version: int, issued_at: float, ttl_s: int,
                    entries: Dict[str, Dict[str, Any]], standing: Dict[str, str]
                    ) -> Dict[str, Any]:
    return {"schema": STATUS_SCHEMA, "issuer": issuer, "source": source, "version": int(version),
            "issued_at": utc_ms(issued_at), "ttl_s": int(ttl_s),
            "expires_at": utc_ms(issued_at + int(ttl_s)),
            "entries": {g: {"state": e["state"], "ceiling": e.get("ceiling")}
                        for g, e in sorted(entries.items())},
            "standing": dict(sorted(standing.items()))}


def notice_claims(*, issuer: str, source: str, version: int, issued_at: float,
                  entries: Dict[str, Dict[str, Any]], standing: Dict[str, str]
                  ) -> Dict[str, Any]:
    return {"schema": NOTICE_SCHEMA, "issuer": issuer, "source": source, "version": int(version),
            "issued_at": utc_ms(issued_at),
            "entries": {g: {"state": e["state"], "ceiling": e.get("ceiling")}
                        for g, e in sorted(entries.items())},
            "standing": dict(sorted(standing.items()))}


def _is_int(v: Any, lo: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= 2 ** 53 - 1


def ceiling_problem(c: Any) -> Optional[str]:
    if not isinstance(c, dict) or not c or set(c) - set(CEILING_MEMBERS):
        return f"a ceiling is an object with members from {CEILING_MEMBERS}"
    if not _is_int(c.get("max_amount", 0)):
        return "ceiling.max_amount must be a non-negative integer"
    return None


def grant_problem(claims: Any) -> Optional[str]:
    """Why these claims are not a well-formed grant, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in GRANT_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    extra = sorted(set(claims) - set(GRANT_CLAIMS))
    if extra:
        return f"unknown claims: {', '.join(extra)}"
    if claims["schema"] != GRANT_SCHEMA:
        return f"schema must be {GRANT_SCHEMA!r}"
    if not isinstance(claims["grant_id"], str) or not _GR_ID.fullmatch(claims["grant_id"]):
        return "grant_id must be 'gr-' and 16 to 64 hex digits"
    for c in ("issuer", "audience", "subject", "principal", "operation"):
        if not isinstance(claims[c], str) or not claims[c]:
            return f"{c} must be a non-empty string"
    ak = claims["agent_key"]
    if (not isinstance(ak, dict) or set(ak) != {"kid", "public_key"}
            or not isinstance(ak["kid"], str) or not ak["kid"]
            or not isinstance(ak["public_key"], str) or not _HEX64.fullmatch(ak["public_key"])):
        return "agent_key must be {kid, public_key: 64 hex}"
    p = ceiling_problem(claims["ceiling"])
    if p:
        return p
    par = claims["parent"]
    if par is not None and (not isinstance(par, str) or not _GR_ID.fullmatch(par)):
        return "parent must be a grant id or null"
    if not isinstance(claims["issued_at"], str) or not _UTC_MS.fullmatch(claims["issued_at"]):
        return "issued_at must be RFC 3339 UTC with milliseconds"
    for c in ("not_before", "not_after"):
        if not isinstance(claims[c], str) or not _UTC_S.fullmatch(claims[c]):
            return f"{c} must be RFC 3339 UTC, whole seconds"
    if epoch_of(claims["not_after"]) <= epoch_of(claims["not_before"]):
        return "not_after must be later than not_before"
    st = claims["status"]
    if (not isinstance(st, dict) or set(st) != {"source", "index"}
            or not isinstance(st["source"], str) or not st["source"] or not _is_int(st["index"])):
        return "status must be {source, index}"
    return None


def _entries_problem(entries: Any) -> Optional[str]:
    if not isinstance(entries, dict):
        return "entries must be an object"
    for g, e in entries.items():
        if not _GR_ID.fullmatch(str(g)):
            return f"entry {g!r} is not a grant id"
        if not isinstance(e, dict) or set(e) != {"state", "ceiling"}:
            return f"entry {g} must be {{state, ceiling}}"
        if e["state"] not in GRANT_STATES:
            return f"entry {g}: state must be one of {GRANT_STATES}"
        if e["state"] == "narrowed":
            p = ceiling_problem(e["ceiling"])
            if p:
                return f"entry {g}: {p}"
        elif e["ceiling"] is not None:
            return f"entry {g}: only a narrowed entry carries a ceiling"
    return None


def _standing_problem(standing: Any) -> Optional[str]:
    if not isinstance(standing, dict):
        return "standing must be an object"
    for p, s in standing.items():
        if not isinstance(p, str) or not p or s not in STANDING_STATES:
            return f"standing[{p!r}] must be one of {STANDING_STATES}"
    return None


def snapshot_problem(claims: Any) -> Optional[str]:
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in STATUS_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    if claims["schema"] != STATUS_SCHEMA:
        return f"schema must be {STATUS_SCHEMA!r}"
    for c in ("issuer", "source"):
        if not isinstance(claims[c], str) or not claims[c]:
            return f"{c} must be a non-empty string"
    if not _is_int(claims["version"], 1):
        return "version must be a positive integer"
    if not _is_int(claims["ttl_s"], 1):
        return "ttl_s must be a positive integer"
    for c in ("issued_at", "expires_at"):
        if not isinstance(claims[c], str) or not _UTC_MS.fullmatch(claims[c]):
            return f"{c} must be RFC 3339 UTC with milliseconds"
    if epoch_of(claims["expires_at"]) <= epoch_of(claims["issued_at"]):
        return "expires_at must be later than issued_at"
    return _entries_problem(claims["entries"]) or _standing_problem(claims["standing"])


def notice_problem(claims: Any) -> Optional[str]:
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in NOTICE_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    if claims["schema"] != NOTICE_SCHEMA:
        return f"schema must be {NOTICE_SCHEMA!r}"
    if not _is_int(claims["version"], 1):
        return "version must be a positive integer"
    if not isinstance(claims["issued_at"], str) or not _UTC_MS.fullmatch(claims["issued_at"]):
        return "issued_at must be RFC 3339 UTC with milliseconds"
    return _entries_problem(claims["entries"]) or _standing_problem(claims["standing"])


def bitstring_problem(claims: Any) -> Optional[str]:
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    missing = [c for c in BITSTRING_CLAIMS if c not in claims]
    if missing:
        return f"missing claims: {', '.join(missing)}"
    if claims["schema"] != BITSTRING_SCHEMA:
        return f"schema must be {BITSTRING_SCHEMA!r}"
    if claims["purpose"] != "revocation":
        return "purpose must be 'revocation'"
    if not _is_int(claims["version"], 1) or not _is_int(claims["size"], 1):
        return "version and size must be positive integers"
    try:
        bits = decode_bits(claims["encoded_list"])
    except ValueError as e:
        return f"encoded_list: {e}"
    if len(bits) * 8 < claims["size"]:
        return "encoded_list is shorter than size"
    return None


PROBLEMS: Dict[str, Callable[[Any], Optional[str]]] = {
    GRANT_TYP: grant_problem, STATUS_TYP: snapshot_problem, NOTICE_TYP: notice_problem,
    BITSTRING_TYP: bitstring_problem}


# --------------------------------------------------------------------------- JWS


def sign(claims: Dict[str, Any], key: Keypair, typ: str) -> str:
    """Compact JWS, alg EdDSA, over the canonical JSON of `claims`. Signs what it is given; the
    shape is the verifier's check."""
    if typ not in PROBLEMS:
        raise ValueError(f"unknown typ {typ!r}")
    return receipts.sign_payload(receipts.canonical_json(claims), key,
                                 {"alg": ALG, "kid": key.kid, "typ": typ})


def verify(token: Any, pinned: Dict[str, bytes], typ: str) -> Verified:
    """The kit's reader of the three formats (and the bitstring profile): form, then a signature,
    then a pinned key, then the signature, with `receipts.verify_receipt`'s reasons
    (``malformed``, ``unsigned``, ``unpinned-key``, ``bad-signature``). The typ must be the one
    asked for, so a snapshot cannot be read as a grant. Only EdDSA is verified."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    problem_of = PROBLEMS.get(typ)
    if problem_of is None:
        raise ValueError(f"unknown typ {typ!r}")

    def bad(reason: str, detail: str, kid: Optional[str] = None) -> Verified:
        return Verified(ok=False, reason=reason, claims=None, kid=kid, detail=detail)

    if not isinstance(token, str):
        return bad("malformed", f"token is {type(token).__name__}, not a string")
    if len(token) > (1 << 22):
        return bad("malformed", "token is larger than 4 MiB")
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
        canonical = receipts.canonical_json(claims)
    except (ValueError, UnicodeDecodeError, TypeError) as e:
        return bad("malformed", f"payload: {e}", kid)
    if canonical != payload:
        return bad("malformed", "payload bytes are not the canonical form of its claims", kid)
    problem = problem_of(claims)
    if problem:
        return bad("malformed", problem, kid)
    alg = hdr.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return bad("unsigned", f"alg is {alg!r}", kid)
    if alg != ALG:
        return bad("malformed", f"alg {alg!r} is not {ALG}", kid)
    if hdr.get("typ") != typ:
        return bad("malformed", f"typ {hdr.get('typ')!r} is not {typ!r}", kid)
    if "crit" in hdr or "b64" in hdr or not kid:
        return bad("malformed", "header uses crit or b64, or has no kid", kid)
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


def typ_of(token: Any) -> Optional[str]:
    """The header's typ, read without checking anything (to route a token to its reader)."""
    try:
        hdr = receipts._strict_json(receipts._b64d(str(token).split(".")[0]))
        return hdr.get("typ") if isinstance(hdr, dict) else None
    except Exception:
        return None


# --------------------------------------------------------------------------- what B should derive


def within(values: Dict[str, Any], ceiling: Optional[Dict[str, Any]]) -> Optional[str]:
    """Why `values` are outside `ceiling`, or None when inside (or when there is no ceiling)."""
    if not ceiling:
        return None
    if "max_amount" in ceiling:
        amt = values.get("amount")
        if not _is_int(amt) or amt > ceiling["max_amount"]:
            return f"amount {amt!r} is above max_amount {ceiling['max_amount']}"
    return None


def narrowest(ceilings: List[Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    cs = [c for c in ceilings if c]
    if not cs:
        return None
    return {"max_amount": min(c.get("max_amount", 2 ** 53 - 1) for c in cs)}


def absent_state(snapshot: Dict[str, Any], grant: Dict[str, Any]) -> Tuple[str, str]:
    """What `grant`, absent from `snapshot`'s entries, reads as: ``not-yet-listed``
    when A signed the snapshot before the grant existed (the grant's ``issued_at`` at or after
    the snapshot's ``issued_at``), else ``unknown``. Returns (state, why)."""
    gid = grant.get("grant_id")
    try:
        g_at = epoch_of(grant["issued_at"])
        s_at = epoch_of(snapshot["issued_at"])
    except (KeyError, TypeError, ValueError):
        return "unknown", (f"{gid} is not in the snapshot, and the grant or the snapshot has no "
                           f"readable issued_at, so absence cannot be read as not yet listed")
    if g_at < s_at:
        return "unknown", (f"{gid} is not in a snapshot A signed after its issue "
                           f"({grant['issued_at']} < {snapshot['issued_at']}): the source does "
                           f"not list it")
    return "not-yet-listed", (f"{gid} was issued after the snapshot ({grant['issued_at']} >= "
                              f"{snapshot['issued_at']}): not yet listed, in force only until "
                              f"B's next fetch")


def chain_state(snapshot: Dict[str, Any], chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What a correct B derives from one snapshot's claims for a presented grant chain (the
    presented grant first, then each parent). Returns ``state``, ``ceiling`` (the narrowest of
    every grant's own ceiling and any narrowing), ``why`` and ``not_yet_listed`` (the grant ids
    read as not yet listed).

    ``state`` is ``revoked`` or ``suspended`` (a grant in the chain is), ``standing-withdrawn`` (a
    principal it rests on has no standing), ``unknown`` (a grant is absent and `absent_state`
    does not read it as not yet listed, or a grant is listed and the snapshot does not state its
    principal's standing), or, with the chain in force (`IN_FORCE`):
    ``not-yet-listed`` when any grant in it is not yet listed, which holds only until B's next
    fetch; ``narrowed`` when a grant is narrowed; ``valid`` otherwise. A narrowing in a chain that
    is also not yet listed still shows in ``ceiling``. A grant not yet listed is still subject to
    its parents' entries and its principal's standing in the same snapshot."""
    entries = snapshot.get("entries") or {}
    standing = snapshot.get("standing") or {}
    ceilings: List[Optional[Dict[str, Any]]] = []
    narrowed = False
    unlisted: List[str] = []
    why_unlisted = ""
    for g in chain:
        gid = g["grant_id"]
        e = entries.get(gid)
        if e is None:
            state, why = absent_state(snapshot, g)
            if state == "unknown":
                return {"state": "unknown", "ceiling": None, "why": why, "not_yet_listed": []}
            unlisted.append(gid)
            why_unlisted = why_unlisted or why
        elif e["state"] in ("revoked", "suspended"):
            return {"state": e["state"], "ceiling": None, "not_yet_listed": [],
                    "why": f"{gid} is {e['state']}" + (" (a parent)" if g is not chain[0]
                                                         else "")}
        if e is not None and g["principal"] not in standing:
            # A snapshot that lists a grant states its principal's standing (KRK-M47).
            return {"state": "unknown", "ceiling": None, "not_yet_listed": [],
                    "why": f"{gid} is listed, and the snapshot does not state the standing of "
                           f"its principal {g['principal']}"}
        if standing.get(g["principal"], "standing") != "standing":
            return {"state": "standing-withdrawn", "ceiling": None, "not_yet_listed": [],
                    "why": f"{g['principal']} has no standing (grant {gid})"}
        ceilings.append(g.get("ceiling"))
        if e is not None and e["state"] == "narrowed":
            narrowed = True
            ceilings.append(e["ceiling"])
    if unlisted:
        return {"state": "not-yet-listed", "ceiling": narrowest(ceilings), "why": why_unlisted,
                "not_yet_listed": unlisted}
    return {"state": "narrowed" if narrowed else "valid", "ceiling": narrowest(ceilings),
            "why": "every grant in the chain is in force", "not_yet_listed": []}


# --------------------------------------------------------------------------- the bitstring profile


def encode_bits(revoked: List[int], size: int) -> str:
    """Bit i (most significant first in each byte) set for each index in `revoked`; zlib, then
    base64url without padding."""
    size = max(size, 8)
    buf = bytearray((size + 7) // 8)
    for i in revoked:
        buf[i // 8] |= 0x80 >> (i % 8)
    return base64.urlsafe_b64encode(zlib.compress(bytes(buf), 9)).rstrip(b"=").decode("ascii")


def decode_bits(encoded: Any) -> bytes:
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise ValueError("not base64url")
    try:
        return zlib.decompress(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (zlib.error, ValueError) as e:
        raise ValueError(f"not a zlib bitstring: {e}")


def bit(encoded: str, index: int) -> bool:
    buf = decode_bits(encoded)
    if index // 8 >= len(buf):
        raise IndexError(index)
    return bool(buf[index // 8] & (0x80 >> (index % 8)))


def bitstring_gaps(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What the bitstring profile cannot say about this snapshot (KRK-M62): a narrowing, a
    suspension, a loss of standing."""
    gaps = [{"grant_id": g, "state": e["state"]} for g, e in snapshot["entries"].items()
            if e["state"] in ("narrowed", "suspended")]
    gaps += [{"principal": p, "state": s} for p, s in snapshot["standing"].items()
             if s != "standing"]
    return gaps


def bitstring_claims(snapshot: Dict[str, Any], index_of: Dict[str, int]) -> Dict[str, Any]:
    """The bitstring form of a kit snapshot: only ``revoked`` sets a bit. Whatever else the
    snapshot says is in `bitstring_gaps`, and is not in these claims."""
    revoked = [index_of[g] for g, e in snapshot["entries"].items() if e["state"] == "revoked"]
    size = max([8] + [i + 1 for i in index_of.values()])
    return {"schema": BITSTRING_SCHEMA, "issuer": snapshot["issuer"],
            "source": snapshot["source"], "version": snapshot["version"],
            "issued_at": snapshot["issued_at"], "ttl_s": snapshot["ttl_s"],
            "expires_at": snapshot["expires_at"], "purpose": "revocation", "size": size,
            "encoded_list": encode_bits(revoked, size)}


def read_profile(token: str, pinned: Dict[str, bytes], profile: str
                 ) -> Tuple[Optional[Dict[str, Any]], str]:
    """A published snapshot read in `profile`: (claims, "") or (None, why)."""
    typ = STATUS_TYP if profile == "kirkaldy" else BITSTRING_TYP
    v = verify(token, pinned, typ)
    return (v.claims, "") if v.ok else (None, f"{v.reason}: {v.detail}")


def revoked_in(claims: Dict[str, Any], profile: str, grant: Dict[str, Any]) -> Optional[str]:
    """The state a reader of `profile` sees for `grant` in these claims: a `GRANT_STATES` value,
    or None when the profile does not list the grant."""
    if profile == "kirkaldy":
        e = (claims.get("entries") or {}).get(grant["grant_id"])
        return e["state"] if e else None
    try:
        return "revoked" if bit(claims["encoded_list"], grant["status"]["index"]) else "valid"
    except (IndexError, ValueError, KeyError):
        return None
