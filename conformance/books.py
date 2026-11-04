"""KRK-17 (P17) two-sided records: the kit's reading format, its checks, and its reconciler.

**What this module is.** P17 asks whether organisation A's record of its actions with
organisation B can be joined with B's record, and whether every difference between the two is
found and ends in a stated state, with both original entries kept. The kit reads each side's
record in one format of its own (below), checks each side's numbering and chaining, checks the
signed checkpoints each side holds of the other's record, and runs its own reconciler over both,
as an independent third party. A target meets the property however it likes; its adapter
translates its export into these entries (`docs/KRK17-INTERFACE.md`).

**The reading format** (`SCHEMA`), one JSON object per entry, canonical JSON as in KRK-16
(`receipts.canonical_json`):

    {"schema": "kirkaldy.record-entry/0.1", "side": "A", "party": "did:web:a.example",
     "peer": "did:web:b.example", "pair_seq": 41, "prev_digest": "sha256:<entry 40>",
     "kind": "request-sent", "correlation_id": "...", "request_digest": "sha256:...",
     "answers": null, "body": {...}, "raw_sha256": null, "recorded_at": "2026-11-01T13:02:11Z"}

- ``side`` is A (the requester) or B (the counterparty); ``party`` wrote the entry, ``peer`` is
  the other organisation of the pair.
- ``pair_seq`` numbers one party's entries for one peer 1, 2, 3, ... with no gap; ``prev_digest``
  is the digest of the entry numbered one less (None for entry 1). A side that does not number
  its entries gives None for both, and the chain check reports it (``unnumbered``).
- ``recorded_at`` is information only. Nothing here orders or joins entries by it.
- An entry may carry ``entry_digest``; if it does it must be its own digest.

**The join key** of an action is ``(requester, counterparty, correlation_id, request_digest)``
(`action_key`): the correlation id alone is a string A chose that another requester can choose
too, and the request digest alone is the same for two attempts at one decision.

**Checkpoints** are compact JWS (EdDSA, ``typ`` `CHECKPOINT_TYP`) over
``{schema, issuer, peer, pair_seq, head, issued_at}``: the issuer's signed statement that its
entry ``pair_seq`` for ``peer`` has digest ``head``. Entry n names the digest of entry n-1, so a
checkpoint pins every entry up to n. Each side holds the other's checkpoints; an entry changed
or removed after the other side holds a checkpoint covering it no longer reaches that head.

Digests use `receipts.canonical_json` and `receipts.sha256_ref`, the KRK-16 specification. The
test vectors in ``tests/vectors/krk17/`` pin every digest, chain finding and checkpoint here with
expectations written out by hand.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import receipts
from .receipts import Keypair, canonical_json, sha256_ref

SCHEMA = "kirkaldy.record-entry/0.1"
CHECKPOINT_SCHEMA = "kirkaldy.checkpoint/0.1"
CHECKPOINT_TYP = "krk-checkpoint+jws"

SIDES = ("A", "B")
KINDS = ("request-sent", "request-received", "effect-committed", "receipt-issued",
         "receipt-received", "checkpoint-received", "void", "settlement", "alert")
ACTION_KINDS = ("request-sent", "request-received", "effect-committed", "receipt-issued",
                "receipt-received")
"""Kinds that are about one action, so they carry the correlation id and request digest."""

FIELDS = ("schema", "side", "party", "peer", "pair_seq", "prev_digest", "kind",
          "correlation_id", "request_digest", "answers", "body", "raw_sha256", "recorded_at")

STATES = ("matched", "awaiting", "explained", "break", "settled", "no-basis")
"""The reconciled state of one action (design §2.5)."""

BREAK_KINDS = ("missing-on-a", "missing-on-b", "content-differs", "statement-vs-log",
               "statement-vs-state", "changed-after-ack", "removed-after-ack", "renumbered",
               "repeated", "gap", "forked", "join-ambiguous", "torn", "settlement-contradicted")
"""Break kinds (design §2.5). A break is two readable records that disagree; a statement that
cannot be verified is treated as missing, never as a break."""

EFFECT_KINDS = ("missing-on-a", "missing-on-b", "content-differs", "statement-vs-log",
                "statement-vs-state", "changed-after-ack", "removed-after-ack", "repeated",
                "settlement-contradicted", "join-ambiguous")
"""Breaks about whether, or how much of, an effect happened, or about whose action an entry is.
None of these may close without a person."""

RECORD_FINDINGS = ("unnumbered", "malformed", "unverifiable", "foreign")
"""Findings about a side's record as a whole rather than about one action: entries carry no
per-peer number (R3 not met), an entry is not in the reading format, a held statement does not
verify (it is then treated as absent), an export holds entries of another pair."""

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


# --------------------------------------------------------------------------- entries


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and bool(_DIGEST.fullmatch(v))


def _is_seq(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def entry_digest(entry: Dict[str, Any]) -> str:
    """sha256 over the canonical JSON of the entry, without its own ``entry_digest``."""
    return sha256_ref(canonical_json({k: v for k, v in entry.items() if k != "entry_digest"}))


def entry_problem(entry: Any) -> Optional[str]:
    """Why `entry` is not an entry in the reading format, or None. Shape only."""
    if not isinstance(entry, dict):
        return "an entry is a JSON object"
    missing = [f for f in FIELDS if f not in entry]
    if missing:
        return f"missing members: {', '.join(missing)}"
    extra = sorted(set(entry) - set(FIELDS) - {"entry_digest"})
    if extra:
        return f"members outside the format: {', '.join(extra)}"
    if entry["schema"] != SCHEMA:
        return f"schema is {entry['schema']!r}, not {SCHEMA!r}"
    if entry["side"] not in SIDES:
        return f"side must be one of {SIDES}"
    for f in ("party", "peer", "recorded_at"):
        if not isinstance(entry[f], str) or not entry[f]:
            return f"{f} must be a non-empty string"
    if entry["party"] == entry["peer"]:
        return "party and peer are the same organisation"
    if entry["kind"] not in KINDS:
        return f"kind must be one of {KINDS}"
    seq, prev = entry["pair_seq"], entry["prev_digest"]
    if seq is not None and not _is_seq(seq):
        return "pair_seq must be a positive integer or null"
    if prev is not None and not _is_digest(prev):
        return "prev_digest must be 'sha256:<64 hex>' or null"
    if seq == 1 and prev is not None:
        return "entry 1 names no previous entry"
    if seq is None and prev is not None:
        return "an unnumbered entry cannot name a previous entry"
    for f in ("request_digest", "answers", "raw_sha256"):
        if entry[f] is not None and not _is_digest(entry[f]):
            return f"{f} must be 'sha256:<64 hex>' or null"
    if entry["correlation_id"] is not None and (not isinstance(entry["correlation_id"], str)
                                                or not entry["correlation_id"]):
        return "correlation_id must be a non-empty string or null"
    if entry["kind"] in ACTION_KINDS and (entry["correlation_id"] is None
                                          or entry["request_digest"] is None):
        return f"a {entry['kind']} entry names its action (correlation_id and request_digest)"
    if not isinstance(entry["body"], dict):
        return "body must be a JSON object"
    if entry["kind"] == "void" and not _is_digest(entry["body"].get("voids")):
        return "a void entry names the digest of the entry it voids (body.voids)"
    if entry["kind"] == "settlement":
        if not isinstance(entry["body"].get("outcome"), str):
            return "a settlement names its outcome (body.outcome)"
        if not isinstance(entry["body"].get("by"), str) or not entry["body"]["by"]:
            return "a settlement names who or what settled it (body.by)"
        settles = entry["body"].get("settles", [])
        if not isinstance(settles, list) or not all(_is_digest(d) for d in settles):
            return "body.settles lists entry digests"
    if entry["kind"] == "checkpoint-received":
        b = entry["body"]
        if not _is_seq(b.get("pair_seq")) or not _is_digest(b.get("head")):
            return "a checkpoint-received entry carries the checkpoint's pair_seq and head"
    if "entry_digest" in entry and entry["entry_digest"] != entry_digest(entry):
        return "entry_digest is not the digest of the entry"
    try:
        canonical_json(entry)
    except (TypeError, ValueError) as e:
        return f"not canonical JSON: {e}"
    return None


def requester_of(entry: Dict[str, Any]) -> str:
    return entry["party"] if entry["side"] == "A" else entry["peer"]


def counterparty_of(entry: Dict[str, Any]) -> str:
    return entry["peer"] if entry["side"] == "A" else entry["party"]


def action_key(entry: Dict[str, Any]) -> Tuple[str, str, Optional[str], Optional[str]]:
    """``(requester, counterparty, correlation_id, request_digest)``."""
    return (requester_of(entry), counterparty_of(entry), entry.get("correlation_id"),
            entry.get("request_digest"))


def key_str(key: Sequence[Any]) -> str:
    """A key as one string, for JSON evidence and adapter reports."""
    return "|".join("" if k is None else str(k) for k in key)


def by_person(by: Any) -> bool:
    """Was a settlement made by a person? ``body.by`` is ``person:<id>`` or ``rule:<name>``."""
    return isinstance(by, str) and by.startswith("person:") and len(by) > len("person:")


# --------------------------------------------------------------------------- breaks


@dataclass(frozen=True)
class Break:
    kind: str
    key: Optional[Tuple[Any, ...]]
    """The action's join key, or None for a break in a side's numbering that names no action
    (an entry removed from the middle of a chain has no key left to name)."""
    sides: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    """{"A": (entry digests...), "B": (...)}: the entries the break is about."""
    detail: str = ""
    numbers: Tuple[int, ...] = ()
    """The pair_seq numbers involved, where the break is about a side's numbering."""

    def to_doc(self) -> Dict[str, Any]:
        return {"kind": self.kind, "key": None if self.key is None else key_str(self.key),
                "sides": {k: list(v) for k, v in self.sides.items()}, "detail": self.detail,
                "numbers": list(self.numbers)}


@dataclass(frozen=True)
class Finding:
    """A finding about one side's record as a whole (`RECORD_FINDINGS`)."""
    kind: str
    side: str
    detail: str

    def to_doc(self) -> Dict[str, Any]:
        return {"kind": self.kind, "side": self.side, "detail": self.detail}


def _chains(entries: Iterable[Dict[str, Any]]) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    out: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for e in entries:
        out.setdefault((e["side"], e["party"], e["peer"]), []).append(e)
    return out


def chain_breaks(entries: Sequence[Dict[str, Any]]) -> Tuple[List[Break], List[Finding]]:
    """Check each party's entries for each peer: numbered 1..n with no gap and no number used
    twice, and each entry naming the digest of the entry numbered one less.

    - a missing number is a ``gap`` (no key: the missing entry cannot be named);
    - a number used twice, or a link to an entry that is there but is not the predecessor, is
      ``renumbered``;
    - a link to an entry that is not there at all is ``torn``: an entry before it changed, or the
      side's own record is inconsistent with itself. Links across a gap are not judged: the
      missing entry's digest is unknown, and the gap is already reported;
    - a chain whose entries carry no numbers is the finding ``unnumbered``: R3 is not met, and
      a reader can neither order these entries nor see one removed.

    Entries must already pass `entry_problem`."""
    breaks: List[Break] = []
    findings: List[Finding] = []
    for (side, party, peer), chain in _chains(entries).items():
        numbered = [e for e in chain if e["pair_seq"] is not None]
        if len(numbered) < len(chain):
            findings.append(Finding("unnumbered", side,
                                    f"{len(chain) - len(numbered)} of {len(chain)} entries of "
                                    f"{party} for {peer} carry no pair_seq"))
        if not numbered:
            continue
        digests = {entry_digest(e): e for e in numbered}
        at: Dict[int, List[Dict[str, Any]]] = {}
        for e in numbered:
            at.setdefault(e["pair_seq"], []).append(e)
        top = max(at)
        for n in range(1, top + 1):
            if n not in at:
                breaks.append(Break("gap", None, {side: ()}, f"{party}'s entries for {peer} "
                                    f"have no entry {n} (highest {top})", (n,)))
        for n, here in sorted(at.items()):
            if len(here) > 1:
                breaks.append(Break("renumbered", None,
                                    {side: tuple(entry_digest(e) for e in here)},
                                    f"{party} numbers {len(here)} entries for {peer} as {n}",
                                    (n,)))
            for e in here:
                prev = e["prev_digest"]
                if n == 1 or (n - 1) not in at:
                    continue                       # entry 1, or across a gap: not judged
                want = {entry_digest(p) for p in at[n - 1]}
                if prev in want:
                    continue
                k = action_key(e) if e["kind"] in ACTION_KINDS else None
                if prev in digests:
                    breaks.append(Break("renumbered", k, {side: (entry_digest(e),)},
                                        f"entry {n} of {party} for {peer} names entry "
                                        f"{digests[prev]['pair_seq']} as its predecessor",
                                        (n, digests[prev]["pair_seq"])))
                else:
                    breaks.append(Break("torn", k, {side: (entry_digest(e),)},
                                        f"entry {n} of {party} for {peer} names a predecessor "
                                        f"that is not in the record", (n,)))
    return breaks, findings


def head(entries: Sequence[Dict[str, Any]], party: str, peer: str) -> Tuple[int, Optional[str]]:
    """The highest pair_seq of `party`'s entries for `peer`, and that entry's digest."""
    mine = [e for e in entries if e["party"] == party and e["peer"] == peer
            and e["pair_seq"] is not None]
    if not mine:
        return 0, None
    last = max(mine, key=lambda e: e["pair_seq"])
    return last["pair_seq"], entry_digest(last)


# --------------------------------------------------------------------------- checkpoints


@dataclass(frozen=True)
class CheckpointVerified:
    ok: bool
    reason: Optional[str]
    """None | "malformed" | "unsigned" | "unpinned-key" | "bad-signature" """
    claims: Optional[Dict[str, Any]]
    kid: Optional[str]
    detail: str = ""


def checkpoint_claims(issuer: str, peer: str, pair_seq: int, head_digest: str,
                      issued_at: str) -> Dict[str, Any]:
    return {"schema": CHECKPOINT_SCHEMA, "issuer": issuer, "peer": peer, "pair_seq": pair_seq,
            "head": head_digest, "issued_at": issued_at}


def checkpoint_problem(claims: Any) -> Optional[str]:
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    want = {"schema", "issuer", "peer", "pair_seq", "head", "issued_at"}
    if set(claims) != want:
        return f"a checkpoint has exactly {sorted(want)}"
    if claims["schema"] != CHECKPOINT_SCHEMA:
        return f"schema is not {CHECKPOINT_SCHEMA!r}"
    for f in ("issuer", "peer", "issued_at"):
        if not isinstance(claims[f], str) or not claims[f]:
            return f"{f} must be a non-empty string"
    if not _is_seq(claims["pair_seq"]):
        return "pair_seq must be a positive integer"
    if not _is_digest(claims["head"]):
        return "head must be 'sha256:<64 hex>'"
    return None


def sign_checkpoint(claims: Dict[str, Any], key: Keypair) -> str:
    """Compact JWS over the canonical claims, header {alg EdDSA, kid, typ krk-checkpoint+jws}."""
    return receipts.sign_payload(canonical_json(claims), key,
                                 {"alg": receipts.ALG, "kid": key.kid, "typ": CHECKPOINT_TYP})


def verify_checkpoint(token: Any, pinned: Dict[str, bytes]) -> CheckpointVerified:
    """Form, then signature, against keys pinned beforehand. The same rules as
    `receipts.verify_receipt`: only EdDSA, no key read from the header, canonical bytes only."""
    def bad(reason: str, detail: str, kid: Optional[str] = None) -> CheckpointVerified:
        return CheckpointVerified(False, reason, None, kid, detail)

    if not isinstance(token, str):
        return bad("malformed", f"token is {type(token).__name__}, not a string")
    parts = token.split(".")
    if len(parts) != 3:
        return bad("malformed", f"compact JWS has 3 segments, this has {len(parts)}")
    h_seg, p_seg, s_seg = parts
    try:
        header = receipts._strict_json(receipts._b64d(h_seg))
        payload = receipts._b64d(p_seg)
        claims = receipts._strict_json(payload)
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", str(e))
    if not isinstance(header, dict):
        return bad("malformed", "header is not a JSON object")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    try:
        if canonical_json(claims) != payload:
            return bad("malformed", "payload bytes are not the canonical form of its claims", kid)
    except (ValueError, TypeError) as e:
        return bad("malformed", f"payload is not canonical JSON: {e}", kid)
    problem = checkpoint_problem(claims)
    if problem:
        return bad("malformed", problem, kid)
    alg = header.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return bad("unsigned", f"alg is {alg!r}", kid)
    if alg != receipts.ALG or header.get("typ") != CHECKPOINT_TYP or not kid:
        return bad("malformed", f"header {header!r} is not EdDSA / {CHECKPOINT_TYP} with a kid",
                   kid)
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
    return CheckpointVerified(True, None, claims, kid, "verified")


def checkpoint_covers(entries: Sequence[Dict[str, Any]],
                      claims: Dict[str, Any]) -> List[Break]:
    """Does the issuer's record still reach a checkpoint the other side holds? `claims` are a
    verified checkpoint's. Returns ``removed-after-ack`` for every number up to the checkpoint's
    that is missing, and ``changed-after-ack`` when the entry at the checkpoint's number is not
    the one it pinned, or a link at or below it is broken. Empty when the record reaches it."""
    issuer, peer, n, want = claims["issuer"], claims["peer"], claims["pair_seq"], claims["head"]
    chain = [e for e in entries if e["party"] == issuer and e["peer"] == peer
             and e["pair_seq"] is not None]
    side = chain[0]["side"] if chain else "?"
    at: Dict[int, List[Dict[str, Any]]] = {}
    for e in chain:
        at.setdefault(e["pair_seq"], []).append(e)
    out: List[Break] = []
    missing = [k for k in range(1, n + 1) if k not in at]
    for k in missing:
        out.append(Break("removed-after-ack", None, {side: ()},
                         f"{issuer}'s entry {k} for {peer} is gone, and {peer} holds "
                         f"{issuer}'s checkpoint at {n}", (k,)))
    if missing:
        return out
    if len(at[n]) != 1 or entry_digest(at[n][0]) != want:
        out.append(Break("changed-after-ack", None,
                         {side: tuple(entry_digest(e) for e in at[n])},
                         f"{issuer}'s entry {n} for {peer} is not the one its checkpoint "
                         f"pinned: an entry at or before {n} changed after {peer} held it", (n,)))
        return out
    for k in range(2, n + 1):
        if at[k][0]["prev_digest"] != entry_digest(at[k - 1][0]):
            out.append(Break("changed-after-ack", None, {side: (entry_digest(at[k][0]),)},
                             f"{issuer}'s entry {k} for {peer} no longer links to entry {k - 1}, "
                             f"which {peer}'s checkpoint at {n} covers", (k - 1, k)))
    return out


# --------------------------------------------------------------------------- the reconciler

GRADES = ("witnessed", "cross-held", "own-log", "state-only", "none")
"""Evidence grades of one side's record, strongest first (design §2.6). The kit computes
`cross-held`, `own-log`, `state-only` and `none` from what the side exposes; `witnessed` needs a
third-party transparency service, which the kit does not run, so it is never computed."""

EXPLAINED = ("redelivery", "declared-void", "clock-skew", "mapping")
"""Differences on which both sides agree about the effect, closed by rule:
an identical statement held twice, a declared void that A holds no receipt for, a clock
difference beyond the stated tolerance, a vocabulary difference a declared mapping removes."""


@dataclass
class Reconciled:
    states: Dict[Tuple[Any, ...], str]
    breaks: List[Break]
    findings: List[Finding]
    grade_a: str
    grade_b: str
    explained: Dict[Tuple[Any, ...], List[str]] = field(default_factory=dict)
    settled: List[Break] = field(default_factory=list)
    """Breaks a person's settlement entry names in full. They stay listed in `breaks`."""

    def kinds(self, key: Optional[Tuple[Any, ...]] = None) -> set:
        return {b.kind for b in self.breaks if key is None or b.key == key}

    def to_doc(self) -> Dict[str, Any]:
        return {"states": {key_str(k): v for k, v in self.states.items()},
                "breaks": [b.to_doc() for b in self.breaks],
                "settled": [b.to_doc() for b in self.settled],
                "findings": [f.to_doc() for f in self.findings],
                "explained": {key_str(k): v for k, v in self.explained.items()},
                "grade_a": self.grade_a, "grade_b": self.grade_b}


def _epoch(s: Any) -> Optional[float]:
    from datetime import datetime
    if not isinstance(s, str):
        return None
    try:
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t.timestamp() if t.tzinfo else None


_OUTCOME = ("created", "updated", "deleted", "failed")


def _outcome(body: Dict[str, Any]) -> Tuple[int, ...]:
    return tuple(int(body.get(f) or 0) for f in _OUTCOME)


class Reconciler:
    """The kit's reconciler (design §6.2). One instance per run; `run()` returns `Reconciled`.

    It joins on the full key, walks both sides (never one side looked up in the other),
    compares contents (never totals alone), re-checks every entry against what each side holds
    of the other on every run (it keeps no state between runs), orders by ``pair_seq`` (never by
    ``recorded_at``), and refuses to compare across vocabularies without a declared mapping.
    Each check is its own method, so the self-test (`tests/test_books.py`) can weaken one at a
    time and show that the self-test then fails (KRK-M29). It shares no code with any target.

    Inputs:

    - ``a``, ``b``: A's export and B's record for this pair, in the reading format;
    - ``holdings_a``: B's statements A holds, raw: ``{"type": "receipt"|"checkpoint", "token"}``;
    - ``holdings_b``: A's statements B holds, raw, the same shape (checkpoints);
    - ``receipt_keys``, ``b_checkpoint_keys``, ``a_checkpoint_keys``: pinned public keys;
    - ``mapping``: the vocabulary mapping the agreement declares, ``{"operation": {B term: A
      term}, "container": {...}}``, or None. Only this mapping is used (KRK-M33);
    - ``state_b``: B's read API, ``{correlation_id: {"written": n, ...}}``, or None;
    - ``tolerance_s``: the stated clock tolerance; None checks no clocks;
    - ``window_s`` and ``now`` (epoch seconds, A's clock): an A request younger than the window
      with nothing at B yet is ``awaiting``; with ``now`` None every window has passed.
    """

    def __init__(self, a: Sequence[Dict[str, Any]], b: Sequence[Dict[str, Any]], *,
                 requester: str, counterparty: str,
                 holdings_a: Sequence[Dict[str, Any]] = (),
                 holdings_b: Sequence[Dict[str, Any]] = (),
                 receipt_keys: Optional[Dict[str, bytes]] = None,
                 b_checkpoint_keys: Optional[Dict[str, bytes]] = None,
                 a_checkpoint_keys: Optional[Dict[str, bytes]] = None,
                 mapping: Optional[Dict[str, Dict[str, str]]] = None,
                 state_b: Optional[Dict[str, Dict[str, Any]]] = None,
                 tolerance_s: Optional[float] = None, window_s: float = 0.0,
                 now: Optional[float] = None) -> None:
        self.a_in, self.b_in = list(a), list(b)
        self.requester, self.counterparty = requester, counterparty
        self.holdings_a, self.holdings_b = list(holdings_a), list(holdings_b)
        self.receipt_keys = dict(receipt_keys or {})
        self.b_ck = dict(b_checkpoint_keys or {})
        self.a_ck = dict(a_checkpoint_keys or {})
        self.mapping = mapping
        self.state_b = state_b
        self.tolerance_s, self.window_s, self.now = tolerance_s, window_s, now
        self.breaks: List[Break] = []
        self.findings: List[Finding] = []
        self.explained: Dict[Tuple[Any, ...], List[str]] = {}

    # ------------------------------------------------------------------ steps

    def split(self) -> None:
        """Keep the well-formed entries of this pair. An entry of another pair that shares a
        correlation id with one of this pair's is ``join-ambiguous``: never joined."""
        pair = {"A": (self.requester, self.counterparty), "B": (self.counterparty, self.requester)}
        self.a: List[Dict[str, Any]] = []
        self.b: List[Dict[str, Any]] = []
        foreign: List[Tuple[str, Dict[str, Any]]] = []
        for side, entries, out in (("A", self.a_in, self.a), ("B", self.b_in, self.b)):
            for e in entries:
                p = entry_problem(e)
                if p:
                    self.findings.append(Finding("malformed", side, p))
                elif e["side"] != side:
                    self.findings.append(Finding("malformed", side, f"a side-{e['side']} entry "
                                                 f"in side {side}'s record"))
                elif (e["party"], e["peer"]) != pair[side]:
                    foreign.append((side, e))
                else:
                    out.append(e)
        cids = {e["correlation_id"] for e in self.a + self.b if e["correlation_id"]}
        for side, e in foreign:
            if e["correlation_id"] in cids:
                self.breaks.append(Break(
                    "join-ambiguous", (self.requester, self.counterparty, e["correlation_id"],
                                       e["request_digest"]),
                    {side: (entry_digest(e),)},
                    f"side {side}'s record for this pair holds an entry of {e['party']} for "
                    f"{e['peer']} under correlation id {e['correlation_id']!r}; not joined"))
            else:
                self.findings.append(Finding("foreign", side, f"an entry of {e['party']} for "
                                             f"{e['peer']} in this pair's record"))

    def chains(self) -> None:
        for entries in (self.a, self.b):
            br, fi = chain_breaks(entries)
            self.breaks += br
            self.findings += fi

    def held(self) -> None:
        """Verify what each side holds of the other. A statement that does not verify is treated
        as absent (a finding), never as a break."""
        self.receipts: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
        seen: Dict[str, int] = {}
        self.b_checkpoints: List[Dict[str, Any]] = []
        self.a_checkpoints: List[Dict[str, Any]] = []
        for h in self.holdings_a:
            tok = h.get("token")
            if h.get("type") == "receipt":
                v = receipts.verify_receipt(tok, self.receipt_keys) if isinstance(tok, str) else None
                if v is None or not v.ok:
                    self.findings.append(Finding("unverifiable", "A", f"a receipt A holds does not "
                                                 f"verify ({v.reason if v else 'not a string'})"))
                    continue
                sha = sha256_ref(tok.encode("utf-8"))
                seen[sha] = seen.get(sha, 0) + 1
                if seen[sha] > 1:
                    continue                     # the same bytes again: a redelivery
                c = v.claims
                k = (self.requester, c["counterparty"], c["correlation_id"], c["request_digest"])
                self.receipts.setdefault(k, []).append(dict(c, _sha=sha))
            elif h.get("type") == "checkpoint":
                self._checkpoint(tok, self.b_ck, self.counterparty, self.requester,
                                 self.b_checkpoints, "A")
        for h in self.holdings_b:
            if h.get("type") == "checkpoint":
                self._checkpoint(h.get("token"), self.a_ck, self.requester, self.counterparty,
                                 self.a_checkpoints, "B")
        for sha, n in seen.items():
            if n > 1:
                for k, rs in self.receipts.items():
                    if any(x["_sha"] == sha for x in rs):
                        self.explained.setdefault(k, []).append("redelivery")

    def _checkpoint(self, tok: Any, keys: Dict[str, bytes], issuer: str, peer: str,
                    out: List[Dict[str, Any]], holder: str) -> None:
        v = verify_checkpoint(tok, keys)
        if not v.ok:
            self.findings.append(Finding("unverifiable", holder, f"a checkpoint side {holder} "
                                         f"holds does not verify ({v.reason})"))
            return
        if (v.claims["issuer"], v.claims["peer"]) != (issuer, peer):
            self.findings.append(Finding("foreign", holder, "a checkpoint side "
                                         f"{holder} holds is about another pair"))
            return
        out.append(v.claims)

    def checkpoints(self) -> None:
        """Re-check each side's record against every checkpoint the other side holds, and two
        checkpoints for one number with different heads (a fork)."""
        for cks, entries in ((self.b_checkpoints, self.b), (self.a_checkpoints, self.a)):
            heads: Dict[int, set] = {}
            for c in cks:
                heads.setdefault(c["pair_seq"], set()).add(c["head"])
            for n, hs in heads.items():
                if len(hs) > 1:
                    issuer = cks[0]["issuer"]
                    self.breaks.append(Break("forked", None, {}, f"{issuer} signed {len(hs)} "
                                             f"different heads for entry {n}", (n,)))
            done = set()
            for c in sorted(cks, key=lambda c: -c["pair_seq"]):
                if (c["pair_seq"], c["head"]) in done:
                    continue
                done.add((c["pair_seq"], c["head"]))
                for br in checkpoint_covers(entries, c):
                    if br not in self.breaks:
                        self.breaks.append(br)

    def group(self) -> Dict[Tuple[Any, ...], Dict[str, List[Dict[str, Any]]]]:
        """Entries by action key, on the full key."""
        g: Dict[Tuple[Any, ...], Dict[str, List[Dict[str, Any]]]] = {}
        by_digest = {entry_digest(e): e for e in self.a + self.b}
        for e in self.a + self.b:
            kind = e["kind"]
            if kind in ACTION_KINDS or (kind == "settlement" and e["request_digest"]):
                k = action_key(e)
            elif kind == "void" and e["body"]["voids"] in by_digest:
                k = action_key(by_digest[e["body"]["voids"]])
            else:
                continue
            g.setdefault(k, {}).setdefault(f"{e['side']}:{kind}", []).append(e)
        for k in self.receipts:
            g.setdefault(k, {})
        return g

    def keys(self, g: Dict[Tuple[Any, ...], Any]) -> List[Tuple[Any, ...]]:
        return list(g)

    # ------------------------------------------------------------------ per action

    def _br(self, kind: str, key: Tuple[Any, ...], gk: Dict[str, List[Dict[str, Any]]],
            detail: str, kinds: Sequence[str] = ()) -> Break:
        sides = {"A": tuple(entry_digest(e) for n, es in gk.items() if n.startswith("A:")
                            and (not kinds or n[2:] in kinds) for e in es),
                 "B": tuple(entry_digest(e) for n, es in gk.items() if n.startswith("B:")
                            and (not kinds or n[2:] in kinds) for e in es)}
        return Break(kind, key, sides, detail)

    def missing(self, key, gk) -> List[Break]:
        a_req = gk.get("A:request-sent", [])
        b_any = [e for n in ("B:request-received", "B:effect-committed", "B:receipt-issued")
                 for e in gk.get(n, [])]
        signed = [c for c in self.receipts.get(key, []) if c["verdict"] == "executed"]
        out: List[Break] = []
        if (a_req or signed) and not b_any:
            if signed:
                out.append(self._br("removed-after-ack", key, gk,
                                    "B signed a receipt for this request and B's record holds "
                                    "nothing for it"))
            elif self._awaiting(a_req):
                self.explained.setdefault(key, []).append("awaiting")
            else:
                out.append(self._br("missing-on-b", key, gk, "A sent this request; B's record "
                                    "holds nothing for it"))
        if b_any and not a_req:
            out.append(self._br("missing-on-a", key, gk, "B's record holds this action; A's "
                                "record holds no request for it"))
        return out

    def _awaiting(self, a_req: List[Dict[str, Any]]) -> bool:
        if self.now is None or not a_req:
            return False
        t = _epoch(a_req[0]["recorded_at"])
        return t is not None and self.now - t < self.window_s

    def basis(self, key, gk) -> Tuple[Optional[str], List[Break]]:
        """Compare the request as A sent it with the request as B received it. Returns
        ("no-basis" | None, breaks)."""
        a_req, b_req = gk.get("A:request-sent", []), gk.get("B:request-received", [])
        if not a_req or not b_req:
            return None, []
        ab, bb = a_req[0]["body"], b_req[0]["body"]
        mapped = dict(bb)
        for f in ("operation", "container"):
            if bb.get(f) == ab.get(f):
                continue
            if self.mapping is None:
                return "no-basis", []
            to = (self.mapping.get(f) or {}).get(bb.get(f))
            if to is None:
                return "no-basis", []
            mapped[f] = to
            if "mapping" not in self.explained.get(key, []):
                self.explained.setdefault(key, []).append("mapping")
        diff = [f for f in ("operation", "container", "count", "items_digest",
                            "expected_effect_digest") if f in ab and mapped.get(f) != ab.get(f)]
        if diff:
            return None, [self._br("content-differs", key, gk, f"A sent and B received this "
                                   f"request differently: {', '.join(diff)}",
                                   ("request-sent", "request-received"))]
        return None, []

    def repeated(self, key, gk) -> List[Break]:
        eff = gk.get("B:effect-committed", [])
        if len(eff) > 1:
            return [self._br("repeated", key, gk, f"B committed {len(eff)} effects for one "
                             f"request", ("effect-committed",))]
        return []

    def statement_vs_log(self, key, gk) -> List[Break]:
        eff = gk.get("B:effect-committed", [])
        if not eff and not gk.get("B:request-received"):
            return []                            # nothing at B: `missing` reports it
        out: List[Break] = []
        for c in self.receipts.get(key, []):
            if c["verdict"] != "executed":
                if eff and any(_outcome(e["body"])[:3] != (0, 0, 0) for e in eff):
                    out.append(self._br("statement-vs-log", key, gk, f"B signed {c['verdict']}; "
                                        "B's log shows an effect"))
                continue
            at = [e for e in eff if e["body"].get("log_seq") == c["log_seq"]]
            if not at:
                out.append(self._br("statement-vs-log", key, gk, f"B's receipt names log entry "
                                    f"{c['log_seq']}; B's log has no effect there"))
                continue
            said = tuple(int(c["outcome"].get(f) or 0) for f in _OUTCOME)
            if _outcome(at[0]["body"]) != said or at[0]["body"].get("items_digest") != c["items_digest"]:
                out.append(self._br("statement-vs-log", key, gk, f"B's receipt says {said}; B's "
                                    f"log says {_outcome(at[0]['body'])}"))
        return out

    def voids(self, key, gk) -> List[Break]:
        vs = gk.get("B:void", [])
        if not vs:
            return []
        if any(c["verdict"] == "executed" for c in self.receipts.get(key, [])):
            return [self._br("removed-after-ack", key, gk, "B voids an entry of an action A "
                             "holds B's signed receipt for", ("void", "effect-committed"))]
        if not gk.get("B:effect-committed"):
            self.explained.setdefault(key, []).append("declared-void")
            return []
        return [self._br("statement-vs-log", key, gk, "B voids an entry while its log shows "
                         "the effect committed", ("void", "effect-committed"))]

    def read_state(self, key, gk) -> List[Break]:
        if self.state_b is None or key[2] not in self.state_b:
            return []
        have = int(self.state_b[key[2]].get("written", -1))
        said = [sum(_outcome(e["body"])[:3]) for e in gk.get("B:effect-committed", [])]
        said += [sum(int(c["outcome"].get(f) or 0) for f in _OUTCOME[:3])
                 for c in self.receipts.get(key, []) if c["verdict"] == "executed"]
        if said and any(n != have for n in said):
            return [self._br("statement-vs-state", key, gk, f"B's statements say {said}; B's read "
                             f"API shows {have}")]
        return []

    def settlements(self, key, gk) -> List[Break]:
        """A person's settlement that a later entry contradicts reopens: a not-executed settlement while B's record shows the effect."""
        out: List[Break] = []
        b_done = (any(sum(_outcome(e["body"])[:3]) for e in gk.get("B:effect-committed", []))
                  or any(c["verdict"] == "executed" for c in self.receipts.get(key, [])))
        for s in gk.get("A:settlement", []) + gk.get("B:settlement", []):
            if by_person(s["body"]["by"]) and s["body"]["outcome"] == "not-executed" and b_done:
                out.append(Break("settlement-contradicted", key,
                                 {s["side"]: (entry_digest(s),),
                                  "B": tuple(entry_digest(e)
                                             for e in gk.get("B:effect-committed", []))},
                                 "a person settled this action as not executed; B's record "
                                 "shows the effect"))
        return out

    def clock(self, key, gk) -> None:
        a_req, b_req = gk.get("A:request-sent", []), gk.get("B:request-received", [])
        if self.tolerance_s is None or not a_req or not b_req:
            return
        ta, tb = _epoch(a_req[0]["recorded_at"]), _epoch(b_req[0]["recorded_at"])
        if ta is not None and tb is not None and abs(ta - tb) > self.tolerance_s:
            self.explained.setdefault(key, []).append("clock-skew")

    def settled_by_person(self, br: Break, gk) -> bool:
        named = set()
        for s in gk.get("A:settlement", []) + gk.get("B:settlement", []):
            if by_person(s["body"]["by"]):
                named |= set(s["body"].get("settles", []))
        mine = set(br.sides.get("A", ())) | set(br.sides.get("B", ()))
        return bool(mine) and mine <= named

    def grade(self, side: str, entries: List[Dict[str, Any]], held: List[Dict[str, Any]]) -> str:
        if not entries:
            return "none"
        if any(e["pair_seq"] is None for e in entries):
            return "state-only"
        mine = [b for b in self.breaks if b.kind in ("changed-after-ack", "removed-after-ack")
                and side in b.sides]
        if held and not mine:
            return "cross-held"
        return "own-log"

    # ------------------------------------------------------------------ run

    def run(self) -> Reconciled:
        self.split()
        self.chains()
        self.held()
        self.checkpoints()
        g = self.group()
        states: Dict[Tuple[Any, ...], str] = {}
        settled: List[Break] = []
        for key in self.keys(g):
            gk = g[key]
            mine = self.missing(key, gk)
            basis, br = self.basis(key, gk)
            mine += br
            mine += self.repeated(key, gk)
            mine += self.statement_vs_log(key, gk)
            mine += self.voids(key, gk)
            mine += self.read_state(key, gk)
            mine += self.settlements(key, gk)
            self.clock(key, gk)
            mine += [b for b in self.breaks if b.key == key]
            open_ = [b for b in mine if b.kind == "settlement-contradicted"
                     or not self.settled_by_person(b, gk)]
            settled += [b for b in mine if b not in open_]
            self.breaks += [b for b in mine if b not in self.breaks]
            if open_:
                states[key] = "break"
            elif mine:
                states[key] = "settled"
            elif basis == "no-basis":
                states[key] = "no-basis"
            elif "awaiting" in self.explained.get(key, []):
                states[key] = "awaiting"
            elif self.explained.get(key):
                states[key] = "explained"
            else:
                states[key] = "matched"
        return Reconciled(states=states, breaks=self.breaks, findings=self.findings,
                          grade_a=self.grade("A", self.a, self.a_checkpoints),
                          grade_b=self.grade("B", self.b, self.b_checkpoints),
                          explained=self.explained, settled=settled)


def reconcile(a: Sequence[Dict[str, Any]], b: Sequence[Dict[str, Any]], **kw: Any) -> Reconciled:
    """Run the kit's reconciler (`Reconciler`) once."""
    return Reconciler(a, b, **kw).run()
