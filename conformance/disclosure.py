"""Counterparty disclosure for KRK-25 (P25): the vocabulary, the kit's disclosure statement, and
the kit's own reading of B's record by value.

Nothing here imports a
target, and no P1 to P23 or P18B module imports this file.

**The statement** (`SCHEMA`, typ `TYP`): A's signed statement that one request was made by one
agent for one principal, at one level, for one audience. A compact JWS (EdDSA) over the canonical
JSON of its claims, as every kit format (`standing.sign`). Claims: ``schema``, ``issuer`` (the
organisation stating the principal), ``audience`` (B), ``actor`` (``{kind, id, org}``),
``principal`` (one of three shapes, below), ``request_digest`` (`authz.binding_digest` of the
request bytes), ``authorisation_id`` (the X3 authorisation it travels with, or null),
``agent_key`` (the kid of the key that signs the request), ``issued_at`` and ``not_after``
(epoch milliseconds). It travels in the `HEADER` header, outside the request's binding, and binds
to the request by ``request_digest``, to the agent by ``agent_key``, and to B by ``audience``.

**Principal shapes**, one per level (`LEVELS`):

- ``{"level": "named", "id"}``: the identifier A uses for the principal;
- ``{"level": "pairwise", "pseudonym"}``: `pairwise`, an HMAC-SHA256 of the principal and the
  audience under A's pairwise secret, so each counterparty gets its own value;
- ``{"level": "organisation", "commitment"}``: `commitment`, a salted SHA-256 A can open on
  dispute; no principal identifier;
- level ``none`` sends no disclosure at all.

**The signing key**: a key A's key statement designates for
``standing``. `standing.PURPOSES` is not edited, because `standing.py` is in the closure of P20 and
P21; a ``disclosure`` purpose is added at P20's next revision.

**Bases**, strongest first (`BASES`): ``a-attested`` (A's statement, verified under A's key
statement), ``b-consent`` (B's own consent record), ``agent-asserted`` (signed by the agent's own
key, or by nothing A designates), ``unattested`` (a request member). B may record a weaker basis;
never a stronger one than its evidence supports.

**Reading B's record by value** (KRK-M176). `flatten` turns whatever B returned
into ``{path: text}``; it decodes JSON held in a string (``#json``) and the payload of a compact
JWS held in a string (``#jws``), so a principal kept only inside a stored token is found and
labelled as such (KRK-M188). `find` searches the flattened B-originated bytes for each identifier
the kit drew, exactly, or under a normalisation B declared (KRK-M187). `infer_fields` is KRK-7's
rule: the fields stable within an actor that differ between actors, never a field the adapter
names. `flatten` is written here and shares no code with P7's module, so a P7 change does not
lapse P25.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import receipts, standing
from .receipts import Keypair, Verified

SCHEMA = "kirkaldy.disclosure/0.1"
TYP = "krk-disclosure+jws"
ACT_TYP = "krk-act+jws"
"""The second wire format (`discloser.StubDiscloser.act_token`): an RFC 8693-shaped delegated
token, ``sub`` the principal and ``act.sub`` the agent. It carries no request digest."""
FORMATS = (SCHEMA, "act-token")
ACTOR_KINDS = ("agent", "person")
LEVELS = ("named", "pairwise", "organisation", "none")
LEVEL_RANK = {"none": 0, "organisation": 1, "pairwise": 2, "named": 3}
BASES = ("a-attested", "b-consent", "agent-asserted", "unattested")
"""Strongest first."""
BASIS_RANK = {b: len(BASES) - i for i, b in enumerate(BASES)}
APPROVALS = ("person", "agent-asserted", "standing-permission")
"""Who an approval came from, as B's record of an approved operation may label it (b-held,
``approval_basis``)."""
CLAUSES = ("actor", "principal", "basis", "level", "requirement")
REQUIREMENTS = ("disclosure-required", "agents-barred")
PSEUDONYM_SCOPES = ("per-counterparty", "global")
HEADER = "KRK-Disclosure"
ASSERT_HEADER = "On-Behalf-Of"
"""The member an asserted principal travels in (``asserted_principal/header``)."""
ASSERT_MEMBER = "on_behalf_of"
"""The body member and the query parameter of ``asserted_principal``."""
QUERY = "?"
"""A key of `authz.Presentation.headers` that starts with this is a query parameter, not a
header (``?on_behalf_of``); the adapter sends it as one."""
CLAIMS = ("schema", "issuer", "audience", "actor", "principal", "request_digest",
          "authorisation_id", "agent_key", "issued_at", "not_after")
TOKEN_MARK = "#jws"
JSON_MARK = "#json"
NEEDLE_KINDS = ("named", "pairwise", "commitment", "hash", "agent", "org", "b-identity")
"""What a drawn identifier is, for `over_level`. ``hash`` is the kit's own SHA-256 of a named
identifier (KRK-M184), ``b-identity`` an identity B minted (``b-held``)."""
KIND_RANK = {"named": 3, "hash": 3, "pairwise": 2, "commitment": 1}

_JWS = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


# --------------------------------------------------------------------------- the statement


def principal_named(pid: str) -> Dict[str, Any]:
    return {"level": "named", "id": pid}


def principal_pairwise(pseudonym: str) -> Dict[str, Any]:
    return {"level": "pairwise", "pseudonym": pseudonym}


def principal_organisation(commit: str) -> Dict[str, Any]:
    return {"level": "organisation", "commitment": commit}


def pairwise(secret: bytes, principal: str, audience: str) -> str:
    """HMAC-SHA256 under `secret` of the principal, a NUL, and the audience; lowercase hex."""
    msg = principal.encode("utf-8") + b"\0" + audience.encode("utf-8")
    return hmac.new(bytes(secret), msg, hashlib.sha256).hexdigest()


def commitment(principal: str, salt: bytes) -> str:
    """``sha256:`` + SHA-256 of the salt, a NUL, and the principal: hiding while the salt is kept
    by A (the composition draft's commitment rule; KRK-M184 is why a plain hash is not one)."""
    return "sha256:" + hashlib.sha256(bytes(salt) + b"\0" + principal.encode("utf-8")).hexdigest()


def plain_hash(identifier: str) -> str:
    """The kit's own SHA-256 of a named identifier, searched for in B's records (KRK-M184)."""
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def disclosure_claims(*, issuer: str, audience: str, actor: Dict[str, Any],
                      principal: Dict[str, Any], request_digest: Optional[str],
                      authorisation_id: Optional[str], agent_key: Optional[str],
                      issued_at: float, not_after: float) -> Dict[str, Any]:
    return {"schema": SCHEMA, "issuer": issuer, "audience": audience, "actor": dict(actor),
            "principal": dict(principal), "request_digest": request_digest,
            "authorisation_id": authorisation_id, "agent_key": agent_key,
            "issued_at": int(issued_at * 1000), "not_after": int(not_after * 1000)}


def _principal_problem(p: Any) -> Optional[str]:
    if not isinstance(p, dict):
        return "principal is not an object"
    level = p.get("level")
    want = {"named": "id", "pairwise": "pseudonym", "organisation": "commitment"}.get(level)
    if want is None:
        return f"principal.level is {level!r}, not one of named, pairwise, organisation"
    if set(p) != {"level", want} or not isinstance(p[want], str) or not p[want]:
        return f"a {level} principal is exactly {{level, {want}}}, with {want} a string"
    if level == "pairwise" and not _HEX64.fullmatch(p[want]):
        return "a pairwise pseudonym is 64 lowercase hex digits"
    if level == "organisation" and not _DIGEST.fullmatch(p[want]):
        return "an organisation-level commitment is sha256:<64 hex>"
    return None


def claims_problem(claims: Any) -> Optional[str]:
    """Why `claims` are not a well-formed disclosure statement, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    if set(claims) != set(CLAIMS):
        missing = sorted(set(CLAIMS) - set(claims))
        extra = sorted(set(claims) - set(CLAIMS))
        return f"members differ from the schema (missing {missing}, extra {extra})"
    if claims["schema"] != SCHEMA:
        return f"schema is {claims['schema']!r}"
    for k in ("issuer", "audience"):
        if not isinstance(claims[k], str) or not claims[k]:
            return f"{k} is not a non-empty string"
    a = claims["actor"]
    if not isinstance(a, dict) or set(a) != {"kind", "id", "org"} or \
            a.get("kind") not in ACTOR_KINDS or not all(isinstance(a.get(x), str) and a.get(x)
                                                         for x in ("id", "org")):
        return "actor is not {kind, id, org} with kind one of agent, person"
    pp = _principal_problem(claims["principal"])
    if pp:
        return pp
    rd = claims["request_digest"]
    if rd is not None and not (isinstance(rd, str) and _DIGEST.fullmatch(rd)):
        return "request_digest is not sha256:<64 hex> or null"
    for k in ("authorisation_id", "agent_key"):
        if claims[k] is not None and not isinstance(claims[k], str):
            return f"{k} is not a string or null"
    for k in ("issued_at", "not_after"):
        if not isinstance(claims[k], int) or isinstance(claims[k], bool) or claims[k] < 0:
            return f"{k} is not a non-negative integer (ms)"
    if claims["not_after"] <= claims["issued_at"]:
        return "not_after is not after issued_at"
    return None


def sign(claims: Dict[str, Any], key: Keypair) -> str:
    return standing.sign(claims, key, TYP)


def unsigned(claims: Dict[str, Any]) -> str:
    """The agent's own unsigned claim (``self_asserted/unsigned``): alg none, empty signature."""
    h = receipts._b64e(receipts.canonical_json({"alg": "none", "typ": TYP}))
    p = receipts._b64e(receipts.canonical_json(claims))
    return f"{h}.{p}."


def verify(token: Any, pinned: Dict[str, bytes]) -> Verified:
    """The kit's reader of the statement: `standing.verify` with this format's shape check."""
    return standing.verify(token, pinned, TYP, problem_of=claims_problem)


def peek(token: Any) -> Dict[str, Any]:
    """Claims read without checking anything; for evidence and routing, never a decision."""
    return standing.peek(token)


def basis_of(claims: Optional[Dict[str, Any]], *, verified_by: Optional[str]) -> str:
    """The basis a statement supports: ``a-attested`` only if it verified under a key the
    principal's organisation designates (``verified_by="a"``); ``b-consent`` for B's own consent
    record; ``agent-asserted`` for a statement signed by the agent or by nothing; ``unattested``
    when there is no statement at all."""
    if verified_by == "b-consent":
        return "b-consent"
    if claims is None:
        return "unattested"
    if verified_by == "a":
        return "a-attested"
    return "agent-asserted"


def stronger(a: str, b: str) -> bool:
    """Whether basis `a` is stronger than basis `b`."""
    return BASIS_RANK.get(a, 0) > BASIS_RANK.get(b, 0)


@dataclass
class Attribution:
    """The kit's own statement of the right answer for one operation (design §2.5)."""

    op_id: str
    actor_kind: str
    agent: Optional[str]
    agent_org: Optional[str]
    principal: Optional[str]
    """The identifier at the level: a named id, a pseudonym, or a commitment; None at ``none``."""
    level: str
    basis: str
    principal_org: Optional[str] = None
    also: List[str] = field(default_factory=list)
    """Other identifiers that name the same agent (B's own minted identity, ``b-held``)."""

    def doc(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def expected(*, op_id: str, actor_kind: str, agent: Optional[str], agent_org: Optional[str],
             principal: Optional[str], level: str, basis: str,
             principal_org: Optional[str] = None,
             also: Sequence[str] = ()) -> Attribution:
    if actor_kind not in ACTOR_KINDS or level not in LEVELS or basis not in BASES + ("person",):
        raise ValueError("expected(): unknown actor kind, level or basis")
    return Attribution(op_id, actor_kind, agent, agent_org, principal if level != "none" else None,
                       level, basis, principal_org, list(also))


# --------------------------------------------------------------------------- reading by value


def _is_jws(s: str) -> bool:
    return bool(_JWS.match(s)) and len(s) < (1 << 20)


def _jws_payload(s: str) -> Optional[Any]:
    try:
        return json.loads(receipts._b64d(s.split(".")[1]).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def flatten(obj: Any, prefix: str = "$") -> Dict[str, str]:
    """Every leaf of `obj` as ``{path: text}``. Bytes are read as UTF-8 and, if they are JSON,
    walked. A string that is a JSON object or array is walked under ``<path>#json``; a string that
    is a compact JWS keeps its own leaf and its payload is walked under ``<path>#jws``. Keys are
    sorted, so two flattenings of equal records are equal."""
    out: Dict[str, str] = {}

    def walk(x: Any, path: str, depth: int) -> None:
        if depth > 12:
            out[path] = json.dumps(x, sort_keys=True, default=str)[:4096]
            return
        if isinstance(x, (bytes, bytearray)):
            try:
                x = bytes(x).decode("utf-8")
            except UnicodeDecodeError:
                out[path] = bytes(x).hex()
                return
            try:
                walk(json.loads(x), path, depth + 1)
                return
            except ValueError:
                out[path] = x
                return
        if isinstance(x, dict):
            if not x:
                out[path] = "{}"
            for k in sorted(x, key=str):
                walk(x[k], f"{path}.{k}", depth + 1)
            return
        if isinstance(x, (list, tuple)):
            if not x:
                out[path] = "[]"
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]", depth + 1)
            return
        if x is None:
            out[path] = "null"
            return
        if isinstance(x, bool):
            out[path] = "true" if x else "false"
            return
        s = str(x)
        out[path] = s
        if isinstance(x, str):
            t = s.strip()
            if t[:1] in ("{", "[") and len(t) > 1:
                try:
                    walk(json.loads(t), path + JSON_MARK, depth + 1)
                except ValueError:
                    pass
            elif _is_jws(t):
                pay = _jws_payload(t)
                if pay is not None:
                    walk(pay, path + TOKEN_MARK, depth + 1)

    walk(obj, prefix, 0)
    return out


def in_token(path: str) -> bool:
    """Whether `path` lies inside a stored token's payload (KRK-M188)."""
    return TOKEN_MARK in path


def normaliser(declared: Optional[Dict[str, Any]]) -> Optional[Callable[[str], str]]:
    """The comparison B declared before the run (``{"case": "fold"}``, ``{"strip": true}``), or
    None for exact comparison (KRK-M187)."""
    if not declared:
        return None
    fold = declared.get("case") == "fold"
    strip = bool(declared.get("strip"))

    def f(s: str) -> str:
        s = s.strip() if strip else s
        return s.casefold() if fold else s
    return f


def find(flat: Dict[str, str], needles: Dict[str, str], *,
         normalise: Optional[Callable[[str], str]] = None) -> Dict[str, List[str]]:
    """Which drawn identifiers appear in `flat`, and at which paths: ``{label: [path, ...]}`` for
    each label found. A value contains a needle if the needle is a substring of it, after
    `normalise` on both where B declared one. Empty needles are never searched for."""
    out: Dict[str, List[str]] = {}
    for label, needle in needles.items():
        if not needle:
            continue
        n = normalise(needle) if normalise else needle
        hits = [p for p, v in flat.items() if n in (normalise(v) if normalise else v)]
        if hits:
            out[label] = sorted(hits)
    return out


def find_folded(flat: Dict[str, str], needles: Dict[str, str]) -> Dict[str, List[str]]:
    """`find` under case-folding and stripping, for identifiers B normalised without declaring it
    (KRK-M187: information, never a pass)."""
    return find(flat, needles, normalise=lambda s: s.strip().casefold())


def echo_paths(flat: Dict[str, str], request_tokens: Iterable[str]) -> List[str]:
    """Fields that hold request content: a value containing any of the request's own drawn
    tokens (its ``ref``, its recipient), and everything walked inside such a value (``#json``,
    ``#jws``). A hit only in these is ``echoed`` (KRK-M171)."""
    toks = [t for t in request_tokens if t]
    roots = [p for p, v in flat.items() if any(t in v for t in toks)]
    out = set(roots)
    for p in flat:
        if any(p.startswith(r + JSON_MARK) or p.startswith(r + TOKEN_MARK) for r in roots):
            out.add(p)
    return sorted(out)


def infer_fields(rows: List[Tuple[str, Dict[str, str]]], *,
                 exclude: Iterable[str] = ()) -> List[str]:
    """KRK-7's rule over interleaved runs: the paths present in every row whose value is the same
    in every row of one actor and differs between actors. `rows` are ``(actor label, flat)``;
    `exclude` names paths that track the transport (KRK-M189)."""
    ex = set(exclude)
    if not rows:
        return []
    labels = sorted({lab for lab, _f in rows})
    if len(labels) < 2:
        return []
    common = set.intersection(*(set(f) for _l, f in rows)) - ex
    out = []
    for path in sorted(common):
        per: Dict[str, set] = {}
        for lab, f in rows:
            per.setdefault(lab, set()).add(f[path])
        if all(len(v) == 1 for v in per.values()) and \
                len({next(iter(v)) for v in per.values()}) == len(per):
            out.append(path)
    return out


def transport_paths(rows: List[Tuple[Dict[str, str], Iterable[str]]]) -> List[str]:
    """Paths whose value on each row is one of that row's transport values (the endpoint, the
    tenant, the source the kit sent from). Excluded from inference (KRK-M189)."""
    if not rows:
        return []
    common = set.intersection(*(set(f) for f, _t in rows))
    out = []
    for path in sorted(common):
        if all(f[path] in set(t) for f, t in rows if f.get(path) not in (None, "null")) and \
                any(f.get(path) not in (None, "null") for f, _t in rows):
            out.append(path)
    return out


def over_level(flat: Dict[str, str], level: str, needles: Dict[str, Tuple[str, str]], *,
               normalise: Optional[Callable[[str], str]] = None) -> List[str]:
    """Labels of the identifiers in `flat` that carry more about the principal than `level`
    allows: `needles` maps a label to ``(kind, value)``; a ``named`` or ``hash`` value is above
    every level but ``named``, a ``pairwise`` value above ``organisation`` and ``none``, a
    ``commitment`` above ``none``. For an answer to another party pass ``"none"``."""
    cap = LEVEL_RANK[level]
    over = {lab: v for lab, (kind, v) in needles.items() if KIND_RANK.get(kind, 0) > cap}
    return sorted(find(flat, over, normalise=normalise))
