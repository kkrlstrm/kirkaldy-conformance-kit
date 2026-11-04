"""P16 (KRK-16) toys: a target A that records an effect on another organisation's system as done
only on B's signed receipt, and copies of it that each skip one check.

- ``good``: verifies the receipt against the key it pinned, then compares the request digest,
  the correlation id, the expected effect, the verdict, the counts and the item digest, in that
  order. It implements these comparisons itself and never calls ``receipts.judge``, so the
  kit's judgement and the target under test share no decision code. It uses
  ``receipts.verify_receipt`` and the digest functions, which is the shared specification.
- ``bad``: one flaw from ``FLAWS`` (``completes_on_timeout`` by default, the commonest shape).
- ``no-control``: has nowhere to pin B's key, so it blocks every receipt, the honest one
  included. The probe must then give no verdict, although every variant would read as refused.

``submit_raises`` makes ``submit`` raise (the target cannot be driven). ``raises_on_reject``
makes ``deliver`` raise after recording a rejected receipt as blocked, as many products reject
bad input.

Each flaw but the last skips exactly one check. The last, ``no_receipt_check``, has no receipt
path at all: it completes on the executor's word, whatever B answers. Before the control was
revised (KRK-M19) its honest case read as a control that did not hold, and the probe gave no
verdict; it must now fail.

| Flaw | What it skips | Exposed by |
|---|---|---|
| ``accepts_any_request`` | the request digest and correlation id binding | ``wrong_request``, ``sibling_request`` |
| ``accepts_known_request`` | the binding to this case: any request digest and correlation id the target has itself submitted is accepted | ``sibling_request`` |
| ``accepts_unsigned`` | the signature, when there is none | ``unsigned`` |
| ``accepts_any_key`` | key pinning: it reads a receipt signed by a key it never pinned | ``unpinned_key`` |
| ``ignores_counts`` | the comparison of the reported effect with the expected one | ``count_mismatch``, ``honest_partial`` |
| ``partial_as_done`` | the failed count: committed plus failed equal to the count reads as done | ``honest_partial`` |
| ``completes_on_timeout`` | the receipt itself, once its deadline passes | ``missing``, ``agent_report`` |
| ``trusts_executor_report`` | the receipt, when the executor reports success | ``agent_report`` |
| ``refusal_as_done`` | the verdict: a bound, signed refusal closes the case as done | ``signed_refusal`` |
| ``no_receipt_check`` | every receipt check: any answer closes the case as done / ``executor-report`` | ``honest`` (grade) and every variant |
| ``no_record_as_done`` | the no-record verdict: a bound, signed no-record closes the case as done | ``signed_no_record``, ``disputed_no_record`` |
| ``closes_disputed_no_record`` | the executor's claim: every signed no-record closes the attempt as not executed, even when the executor reports it sent the request | ``disputed_no_record`` |

``accepts_known_request`` was added with the ``sibling_request`` variant. It asks
"is this a reference I know?" instead of "is this the reference of the request in hand?", so it
refuses ``wrong_request`` (a request it never made) and accepts B's receipt for any of its own
earlier requests (KRK-M20).

The two no-record flaws were added with the ``signed_no_record`` and ``disputed_no_record``
variants. The correct toy closes a signed no-record as ``not-executed`` only when
the executor does not claim to have sent the request, and otherwise blocks it for a person. It
reads the executor's claim itself, not through ``receipts.report_claims_sent``.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

from conformance import receipts

FLAWS = ("accepts_any_request", "accepts_known_request", "accepts_unsigned", "accepts_any_key", "ignores_counts",
         "partial_as_done", "completes_on_timeout", "trusts_executor_report",
         "refusal_as_done", "no_receipt_check", "no_record_as_done",
         "closes_disputed_no_record")
BAD_DEFAULT = "completes_on_timeout"
DEADLINE_S = 30.0


_SENT_WORDS = {"done", "success", "succeeded", "ok", "completed", "executed"}


def _executor_says_sent(report: Optional[Dict[str, Any]]) -> bool:
    """The toy's own reading of the executor's report: did it say the request went out?"""
    if not isinstance(report, dict):
        return False
    if report.get("sent") is True or report.get("success") is True or report.get("ok") is True:
        return True
    st = report.get("status")
    return isinstance(st, str) and st.lower() in _SENT_WORDS


def _claims_unverified(token: str) -> Optional[Dict[str, Any]]:
    """The payload of a compact JWS, read without checking anything. Only the flawed toys use
    this, on the receipts their flaw makes them accept."""
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return None


class ToyEffectReceipts:
    name = "toy-effect-receipts"

    def __init__(self, variant: str = "good", flaw: Optional[str] = None) -> None:
        assert variant in ("bad", "good", "no-control"), variant
        if variant == "bad" and flaw is None:
            flaw = BAD_DEFAULT
        assert flaw is None or (variant == "bad" and flaw in FLAWS), (variant, flaw)
        self.variant = variant
        self.flaw = flaw
        self.config = f"bad:{flaw}" if flaw else variant
        self.submit_raises = False
        self.raises_on_reject = False
        self.pinned: Dict[str, bytes] = {}
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.clock = 0.0

    # Target -----------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def implements(self):
        return ["P16"]

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    # P16 adapter ------------------------------------------------------------------------------

    def pin_counterparty_key(self, kid: str, public_key: bytes) -> None:
        if self.variant == "no-control":
            return                                  # nowhere to pin it
        self.pinned[kid] = bytes(public_key)

    def submit(self, envelope: Dict[str, Any], expected: Any) -> str:
        if self.submit_raises:
            raise RuntimeError("no expected-effect field in this product's decision record")
        case_id = f"case-{len(self.cases) + 1}"
        self.cases[case_id] = {
            "correlation_id": envelope["correlation_id"],
            "request_digest": receipts.request_digest(envelope),
            "expected": expected, "expected_digest": expected.digest(),
            "submitted_at": self.clock, "status": "awaiting-receipt", "grade": None,
            "why": ""}
        return case_id

    def deliver(self, case_id: str, receipt: Optional[str],
                executor_report: Optional[Dict[str, Any]]) -> None:
        c = self.cases[case_id]
        if c["status"] in ("done", "refused", "not-executed"):
            return                                  # closed; a redelivery changes nothing
        c["receipt"], c["report"] = receipt, executor_report
        if self.flaw == "no_receipt_check":         # the executor returned, so it is done
            self._close(c, "done", "executor-report", "the executor returned")
            return
        if receipt is None:
            if self.flaw == "trusts_executor_report" and executor_report:
                self._close(c, "done", "executor-report", "the executor reported success")
            return                                  # still awaiting; the deadline is in status()
        status, grade, why = self._check(c, receipt)
        self._close(c, status, grade, why)
        if self.raises_on_reject and status == "blocked":
            raise ValueError(f"receipt rejected: {why}")

    def status(self, case_id: str) -> str:
        c = self.cases[case_id]
        if (self.flaw == "completes_on_timeout" and c["status"] == "awaiting-receipt"
                and self.clock - c["submitted_at"] >= DEADLINE_S):
            self._close(c, "done", "executor-report", "no receipt by the deadline; assumed done")
        return c["status"]

    def evidence_grade(self, case_id: str) -> Optional[str]:
        return self.cases[case_id]["grade"]

    def receipt_deadline_s(self) -> float:
        return DEADLINE_S

    def elapse(self, seconds: float) -> None:
        self.clock += seconds

    # The target's own checks ------------------------------------------------------------------

    @staticmethod
    def _close(c: Dict[str, Any], status: str, grade: Optional[str], why: str) -> None:
        c.update(status=status, grade=grade, why=why)

    def _check(self, c: Dict[str, Any], token: str):
        v = receipts.verify_receipt(token, self.pinned)
        claims = v.claims
        if not v.ok:
            skipped = ((self.flaw == "accepts_unsigned" and v.reason == "unsigned") or
                       (self.flaw == "accepts_any_key" and v.reason == "unpinned-key"))
            if not skipped:
                return "blocked", None, f"receipt not verified: {v.reason}"
            claims = claims or _claims_unverified(token)
            if claims is None:
                return "blocked", None, "receipt unreadable"
        if claims.get("counterparty") != c["expected"].counterparty:
            return "blocked", None, "receipt is from another counterparty"
        if self.flaw == "accepts_known_request":
            known = {(k["request_digest"], k["correlation_id"]) for k in self.cases.values()}
            if (claims.get("request_digest"), claims.get("correlation_id")) not in known:
                return "blocked", None, "receipt is for a request this target never made"
        elif self.flaw != "accepts_any_request":
            if claims.get("request_digest") != c["request_digest"]:
                return "blocked", None, "receipt is for another request"
            if claims.get("correlation_id") != c["correlation_id"]:
                return "blocked", None, "receipt is for another correlation id"
        if claims.get("expected_effect_digest") != c["expected_digest"]:
            return "blocked", None, "receipt names another expected effect"
        if claims.get("verdict") == "refused":
            if self.flaw == "refusal_as_done":
                return "done", "signed-by-B", "counterparty answered; case closed"
            return "refused", None, f"counterparty refused: {claims.get('refusal_reason')}"
        if claims.get("verdict") == "no-record":
            if self.flaw == "no_record_as_done":
                return "done", "signed-by-B", "counterparty answered; case closed"
            if self.flaw != "closes_disputed_no_record" and _executor_says_sent(c.get("report")):
                return "blocked", None, ("B has no record of a request the executor says it "
                                         "sent; a person decides")
            return "not-executed", None, "B signed it has no record and will refuse it"
        if claims.get("verdict") != "executed":
            return "blocked", None, f"unknown verdict {claims.get('verdict')!r}"
        if self.flaw != "ignores_counts":
            exp = c["expected"]
            out = claims.get("outcome") or {}
            committed = sum(int(out.get(k, 0)) for k in ("created", "updated", "deleted"))
            failed = int(out.get("failed", 0))
            if self.flaw == "partial_as_done" and failed and committed + failed == exp.count:
                return "done", "signed-by-B", "every item was attempted"
            if committed != exp.count or failed:
                return "blocked", None, (f"effect differs: {committed} committed, {failed} "
                                         f"failed, {exp.count} expected")
            if claims.get("items_digest") != exp.items_digest:
                return "blocked", None, "receipt covers other items"
        return "done", "signed-by-B", "receipt verified and matches the expected effect"


def make(flaw: Optional[str] = None) -> ToyEffectReceipts:
    """The correct toy (no flaw) or the copy with one flaw."""
    return ToyEffectReceipts("bad", flaw) if flaw else ToyEffectReceipts("good")
