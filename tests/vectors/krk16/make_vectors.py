"""Writes the KRK-16 receipt test vectors in this directory. Run from the repo root:

    python tests/vectors/krk16/make_vectors.py

The tokens are built here with fixed keys (Ed25519 signing is deterministic, so they are
byte-stable). Every expected outcome below is written out by hand from the rules in
docs/KRK16-INTERFACE.md; none is computed by `receipts.judge` or `receipts.verify_receipt`,
so a bug in either cannot make its own vector agree with it. The canonical-JSON expectations are
hand-written per RFC 8785 and checked with hashlib alone.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from conformance import receipts as r  # noqa: E402

# RFC 8032 section 7.1, TEST 1 and TEST 2: the secret keys and their public keys.
RFC8032 = [
    {"name": "TEST 1",
     "secret": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "message": "",
     "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33"
                  "bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"name": "TEST 2",
     "secret": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "message": "72",
     "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
                  "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
]

B_KID = "b-receipts-2026-11"
OTHER_KID = "b-receipts-2026-11-unpinned"
B = r.Keypair.from_seed(B_KID, bytes.fromhex(RFC8032[0]["secret"]))
OTHER = r.Keypair.from_seed(OTHER_KID, bytes.fromhex(RFC8032[1]["secret"]))
# The other key under B's kid: a genuine signature by a key that is not the one pinned there.
OTHER_AS_B = r.Keypair.from_seed(B_KID, bytes.fromhex(RFC8032[1]["secret"]))
PINNED = {B_KID: RFC8032[0]["public"]}

SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
ITEMS = ["ada@a.example", "bo@a.example", "cy@a.example", "dé@a.example"]
OTHER_ITEMS = ["ada@a.example", "bo@a.example", "cy@a.example", "eve@a.example"]

EXPECTED = {"operation": "crm.record.push", "counterparty": "did:web:b.example",
            "container": "people", "verbs": ["upsert"], "count": 4,
            "items_digest": r.items_digest(SALT, ITEMS)}
EXP = r.ExpectedEffect(**{**EXPECTED, "verbs": tuple(EXPECTED["verbs"])})

ENVELOPE = {"schema": "kirkaldy.effect-request/0.1", "correlation_id": "case-17:9f2c41d07a3b6e55",
            "operation": "crm.record.push", "counterparty": "did:web:b.example",
            "container": "people", "items": ITEMS, "expected_effect_digest": EXP.digest()}
SIBLING = {**ENVELOPE, "correlation_id": "case-17:9f2c41d07a3b6e55/sibling-0000002a"}


def claims(**over):
    c = {"receipt_id": "rcpt-0000000000000001", "correlation_id": ENVELOPE["correlation_id"],
         "request_digest": r.request_digest(ENVELOPE), "expected_effect_digest": EXP.digest(),
         "verdict": "executed", "refusal_reason": None,
         "outcome": {"created": 4, "updated": 0, "deleted": 0, "failed": 0},
         "items_digest": EXP.items_digest, "counterparty": "did:web:b.example",
         "executed_at": "2026-11-01T13:02:11Z", "log_seq": 40177}
    c.update(over)
    return c


def outcome(created=0, updated=0, deleted=0, failed=0):
    return {"created": created, "updated": updated, "deleted": deleted, "failed": failed}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def seg(obj) -> str:
    return b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def header(**over):
    h = {"alg": "EdDSA", "kid": B_KID, "typ": "krk-receipt+jws"}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


def tamper_payload(token: str, **over) -> str:
    """The signature of `token`, kept, over a payload with one claim changed. Used only as a
    verify vector (a verifier must refuse it); never produced by the stub counterparty."""
    h, _, s = token.split(".")
    return f"{h}.{b64(r.canonical_json(claims(**over)))}.{s}"


GOOD = r.sign_receipt(claims(), B)

VERIFY = [
    ("ok", GOOD, True, None, B_KID),
    ("ok-ignores-embedded-jwk",
     r.sign_payload(r.canonical_json(claims()), B,
                    header(jwk={"kty": "OKP", "crv": "Ed25519", "x": b64(OTHER.public_bytes())})),
     True, None, B_KID),
    ("unsigned-alg-none", r.unsigned_receipt(claims()), False, "unsigned", None),
    ("unsigned-alg-None-capitalised",
     f"{seg({'alg': 'None', 'typ': 'krk-receipt+jws'})}.{b64(r.canonical_json(claims()))}.",
     False, "unsigned", None),
    ("unsigned-eddsa-empty-signature", GOOD.rsplit(".", 1)[0] + ".", False, "unsigned", B_KID),
    ("unpinned-key", r.sign_receipt(claims(), OTHER), False, "unpinned-key", OTHER_KID),
    ("bad-signature-other-key-under-pinned-kid", r.sign_receipt(claims(), OTHER_AS_B), False,
     "bad-signature", B_KID),
    ("bad-signature-embedded-jwk-is-not-trusted",
     r.sign_payload(r.canonical_json(claims()), OTHER_AS_B,
                    header(jwk={"kty": "OKP", "crv": "Ed25519", "x": b64(OTHER.public_bytes())})),
     False, "bad-signature", B_KID),
    ("bad-signature-payload-changed-after-signing",
     tamper_payload(GOOD, outcome=outcome(created=400)), False, "bad-signature", B_KID),
    ("malformed-two-segments", GOOD.rsplit(".", 1)[0], False, "malformed", None),
    ("malformed-four-segments", GOOD + ".x", False, "malformed", None),
    ("malformed-empty", "", False, "malformed", None),
    ("malformed-bad-base64-char", "*" + GOOD[1:], False, "malformed", None),
    ("malformed-padded-base64", GOOD.split(".")[0] + "=." + GOOD.split(".", 1)[1], False,
     "malformed", None),
    ("malformed-header-not-json", f"{b64(b'not json')}.{GOOD.split('.', 1)[1]}", False,
     "malformed", None),
    ("malformed-header-array", f"{b64(b'[1]')}.{GOOD.split('.', 1)[1]}", False, "malformed", None),
    ("malformed-payload-not-canonical",
     r.sign_payload(json.dumps(claims(), sort_keys=True).encode(), B), False, "malformed", B_KID),
    ("malformed-payload-missing-claim",
     r.sign_payload(r.canonical_json({k: v for k, v in claims().items() if k != "log_seq"}), B),
     False, "malformed", B_KID),
    ("malformed-payload-duplicate-member",
     r.sign_payload(r.canonical_json(claims())[:-1] + b',"log_seq":1}', B), False, "malformed",
     B_KID),
    ("malformed-payload-float",
     r.sign_payload(r.canonical_json(claims())[:-1].replace(b'"log_seq":40177', b'"log_seq":1.5')
                    + b"}", B), False, "malformed", B_KID),
    ("malformed-outcome-bool", r.sign_receipt(claims(outcome={**outcome(created=4), "failed": False}), B),
     False, "malformed", B_KID),
    ("malformed-executed-at-not-utc",
     r.sign_receipt(claims(executed_at="2026-11-01T14:02:11+01:00"), B), False, "malformed", B_KID),
    ("malformed-refused-without-reason", r.sign_receipt(claims(verdict="refused"), B), False,
     "malformed", B_KID),
    ("malformed-executed-with-reason", r.sign_receipt(claims(refusal_reason="x"), B), False,
     "malformed", B_KID),
    ("malformed-typ", r.sign_payload(r.canonical_json(claims()), B, header(typ="JWT")), False,
     "malformed", B_KID),
    ("malformed-crit", r.sign_payload(r.canonical_json(claims()), B, header(crit=["exp"])), False,
     "malformed", B_KID),
    ("malformed-no-kid", r.sign_payload(r.canonical_json(claims()), B, header(kid=None)), False,
     "malformed", None),
]


def _hs256_with_public_key() -> str:
    """Algorithm confusion: HS256 keyed with B's public key, which A holds."""
    h = seg(header(alg="HS256"))
    p = b64(r.canonical_json(claims()))
    mac = hmac.new(B.public_bytes(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64(mac)}"


VERIFY.append(("malformed-alg-HS256-keyed-with-public-key", _hs256_with_public_key(), False,
               "malformed", B_KID))
# The no-record verdict: B's signed "no record of this request", valid only
# with refuses_permanently true and no effect.
NO_RECORD = dict(verdict="no-record", outcome=outcome(), refuses_permanently=True)
VERIFY += [
    ("ok-no-record", r.sign_receipt(claims(**NO_RECORD), B), True, None, B_KID),
    ("malformed-no-record-not-permanent",
     r.sign_receipt(claims(verdict="no-record", outcome=outcome()), B), False, "malformed", B_KID),
    ("malformed-no-record-refuses-permanently-false",
     r.sign_receipt(claims(**{**NO_RECORD, "refuses_permanently": False}), B), False, "malformed",
     B_KID),
    ("malformed-no-record-refuses-permanently-string",
     r.sign_receipt(claims(**{**NO_RECORD, "refuses_permanently": "true"}), B), False,
     "malformed", B_KID),
    ("malformed-no-record-with-effect",
     r.sign_receipt(claims(**{**NO_RECORD, "outcome": outcome(created=1)}), B), False,
     "malformed", B_KID),
]

VERIFY.append(("malformed-alg-RS256-over-eddsa-signature",
               r.sign_payload(r.canonical_json(claims()), B, header(alg="RS256")), False,
               "malformed", B_KID))

REFUSED = dict(verdict="refused", refusal_reason="outside-mandate", outcome=outcome())
OK_REPORT = {"by": "executor", "success": True, "status": "done", "count": 4}

# (name, token, executor_report, accept, status, grade, reason)
JUDGE = [
    ("done", GOOD, None, True, "done", "signed-by-B", None),
    ("done-upsert-split", r.sign_receipt(claims(outcome=outcome(created=2, updated=2)), B), None,
     True, "done", "signed-by-B", None),
    ("done-report-ignored-when-receipt-exists", GOOD, {"by": "executor", "success": False}, True,
     "done", "signed-by-B", None),
    ("no-receipt", None, None, False, "awaiting-receipt", None, "no-receipt"),
    ("no-receipt-report-claims-failure", None, {"by": "executor", "success": False}, False,
     "awaiting-receipt", None, "no-receipt"),
    ("executor-report-only", None, OK_REPORT, False, "awaiting-receipt", None,
     "executor-report-only"),
    ("blocked-unsigned", r.unsigned_receipt(claims()), OK_REPORT, False, "blocked", None,
     "unsigned"),
    ("blocked-unpinned-key", r.sign_receipt(claims(), OTHER), None, False, "blocked", None,
     "unpinned-key"),
    ("blocked-bad-signature", r.sign_receipt(claims(), OTHER_AS_B), None, False, "blocked", None,
     "bad-signature"),
    ("blocked-malformed", r.sign_receipt(claims(log_seq=-1), B), None, False, "blocked", None,
     "malformed"),
    ("wrong-request-sibling-digest",
     r.sign_receipt(claims(correlation_id=SIBLING["correlation_id"],
                           request_digest=r.request_digest(SIBLING)), B),
     None, False, "blocked", None, "wrong-request"),
    ("wrong-request-correlation-id-only",
     r.sign_receipt(claims(correlation_id=SIBLING["correlation_id"]), B), None, False, "blocked",
     None, "wrong-request"),
    ("wrong-request-before-refusal",
     r.sign_receipt(claims(request_digest=r.request_digest(SIBLING), **REFUSED), B), None, False,
     "blocked", None, "wrong-request"),
    ("expected-mismatch",
     r.sign_receipt(claims(expected_effect_digest=r.ExpectedEffect(
         **{**EXPECTED, "verbs": ("upsert",), "count": 5}).digest()), B),
     None, False, "blocked", None, "expected-mismatch"),
    ("expected-mismatch-counterparty", r.sign_receipt(claims(counterparty="did:web:c.example"), B),
     None, False, "blocked", None, "expected-mismatch"),
    ("expected-mismatch-before-count",
     r.sign_receipt(claims(expected_effect_digest="sha256:" + "0" * 64,
                           outcome=outcome(created=1)), B),
     None, False, "blocked", None, "expected-mismatch"),
    ("refused", r.sign_receipt(claims(**REFUSED), B), None, False, "refused", None, "refused"),
    ("count-mismatch-short", r.sign_receipt(claims(outcome=outcome(created=3)), B), None, False,
     "blocked", None, "count-mismatch"),
    ("count-mismatch-over", r.sign_receipt(claims(outcome=outcome(created=5)), B), None, False,
     "blocked", None, "count-mismatch"),
    ("count-mismatch-full-plus-failed",
     r.sign_receipt(claims(outcome=outcome(created=4, failed=1)), B), None, False, "blocked",
     None, "count-mismatch"),
    ("count-mismatch-short-and-failed-not-adding-up",
     r.sign_receipt(claims(outcome=outcome(created=2, failed=1)), B), None, False, "blocked",
     None, "count-mismatch"),
    ("count-mismatch-verb-not-expected", r.sign_receipt(claims(outcome=outcome(deleted=4)), B),
     None, False, "blocked", None, "count-mismatch"),
    ("count-mismatch-with-success-report", r.sign_receipt(claims(outcome=outcome(created=3)), B),
     OK_REPORT, False, "blocked", None, "count-mismatch"),
    ("count-before-items",
     r.sign_receipt(claims(outcome=outcome(created=3), items_digest=r.items_digest(SALT, ITEMS[:3])),
                    B), None, False, "blocked", None, "count-mismatch"),
    ("partial", r.sign_receipt(claims(outcome=outcome(created=3, failed=1)), B), None, False,
     "blocked", None, "partial"),
    ("items-mismatch", r.sign_receipt(claims(items_digest=r.items_digest(SALT, OTHER_ITEMS)), B),
     None, False, "blocked", None, "items-mismatch"),
    # The no-record verdict. Without a claim of sending it closes as not executed;
    # with one, the two sides disagree and a person decides.
    ("no-record", r.sign_receipt(claims(**NO_RECORD), B), None, False, "not-executed", None,
     "no-record"),
    ("no-record-send-unconfirmed", r.sign_receipt(claims(**NO_RECORD), B),
     {"by": "executor", "sent": False, "status": "unknown"}, False, "not-executed", None,
     "no-record"),
    ("no-record-report-claims-failure", r.sign_receipt(claims(**NO_RECORD), B),
     {"by": "executor", "success": False}, False, "not-executed", None, "no-record"),
    ("no-record-disputed", r.sign_receipt(claims(**NO_RECORD), B), OK_REPORT, False, "blocked",
     None, "no-record-disputed"),
    ("no-record-disputed-sent-flag", r.sign_receipt(claims(**NO_RECORD), B),
     {"by": "executor", "sent": True}, False, "blocked", None, "no-record-disputed"),
    ("no-record-not-permanent-is-malformed",
     r.sign_receipt(claims(verdict="no-record", outcome=outcome()), B), None, False, "blocked",
     None, "malformed"),
    ("wrong-request-before-no-record",
     r.sign_receipt(claims(request_digest=r.request_digest(SIBLING), **NO_RECORD), B), OK_REPORT,
     False, "blocked", None, "wrong-request"),
    ("expected-mismatch-before-no-record",
     r.sign_receipt(claims(expected_effect_digest="sha256:" + "1" * 64, **NO_RECORD), B), None,
     False, "blocked", None, "expected-mismatch"),
]

# sibling_request: B's genuine receipt for one of A's own earlier requests,
# presented against A's current request. Both envelopes are requests A made; they differ in the
# correlation id only. Expectations written by hand: against the earlier request it is a
# matching receipt, against the current one it names another request.
EARLIER = {**ENVELOPE, "correlation_id": "case-16:4b1d0e93c2a75f10"}
SIBLING_RECEIPT = r.sign_receipt(claims(correlation_id=EARLIER["correlation_id"],
                                        request_digest=r.request_digest(EARLIER),
                                        receipt_id="rcpt-0000000000000000", log_seq=40176), B)

# Hand-written canonical forms (RFC 8785): keys sorted by code point, no whitespace, non-ASCII
# left as UTF-8, only '"', '\\' and control characters escaped, and those as \b \t \n \f \r or
# lower-case \u00XX.
CANONICAL = [
    ("key-order", {"b": 1, "a": {"d": [3, 2], "c": None}, "A": True},
     '{"A":true,"a":{"c":null,"d":[3,2]},"b":1}'),
    ("unicode-values", {"name": "Déjà € \U0001f600", "k": " "},
     '{"k":" ","name":"Déjà € \U0001f600"}'),
    ("escapes", {"s": "q\"b\\n\nt\tc\u0001d\u001f\u007f"},
     '{"s":"q\\"b\\\\n\\nt\\tc\\u0001d\\u001f\u007f"}'),
    ("integers", {"n": [0, -1, 9007199254740991]}, '{"n":[0,-1,9007199254740991]}'),
]


def main() -> None:
    (HERE / "keys.json").write_text(json.dumps({
        "rfc8032": RFC8032,
        "b": {"kid": B_KID, "seed": RFC8032[0]["secret"], "public": RFC8032[0]["public"]},
        "other": {"kid": OTHER_KID, "seed": RFC8032[1]["secret"], "public": RFC8032[1]["public"]},
        "salt": SALT.hex(),
    }, indent=2, ensure_ascii=False) + "\n")
    (HERE / "canonical.json").write_text(json.dumps([
        {"name": n, "value": v, "canonical": c,
         "sha256": "sha256:" + hashlib.sha256(c.encode("utf-8")).hexdigest()}
        for n, v, c in CANONICAL], indent=2, ensure_ascii=False) + "\n")
    (HERE / "verify.json").write_text(json.dumps({
        "pinned": PINNED,
        "cases": [{"name": n, "token": t, "expect": {"ok": ok, "reason": reason, "kid": kid}}
                  for n, t, ok, reason, kid in VERIFY]}, indent=2, ensure_ascii=False) + "\n")
    (HERE / "judge.json").write_text(json.dumps({
        "pinned": PINNED, "salt": SALT.hex(), "items": ITEMS, "envelope": ENVELOPE,
        "expected_effect": EXPECTED,
        "request_digest": r.request_digest(ENVELOPE), "expected_effect_digest": EXP.digest(),
        "cases": [{"name": n, "token": t, "executor_report": rep,
                   "expect": {"accept": a, "status": s, "grade": g, "reason": rs}}
                  for n, t, rep, a, s, g, rs in JUDGE]}, indent=2, ensure_ascii=False) + "\n")
    (HERE / "sibling.json").write_text(json.dumps({
        "pinned": PINNED, "salt": SALT.hex(), "expected_effect": EXPECTED,
        "envelopes": {"earlier": EARLIER, "current": ENVELOPE},
        "request_digests": {"earlier": r.request_digest(EARLIER),
                            "current": r.request_digest(ENVELOPE)},
        "token": SIBLING_RECEIPT,
        "expect": {"earlier": {"accept": True, "status": "done", "grade": "signed-by-B",
                               "reason": None},
                   "current": {"accept": False, "status": "blocked", "grade": None,
                               "reason": "wrong-request"}}}, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
