"""P18B (KRK-18, authority at B) toys: the correct B-issuer toy of `known_bad.bissuer_core` in
three shapes, and copies of it that each have one flaw. These are the public known-good and
known-bad set for the B-issuer profile (S3).

**Flaws** (`FLAWS`), each failing the variant forms named, in every shape where the form applies
(``tests/test_p18b_payload_bound_b.py`` holds the exact sets per shape):

| Flaw | What B does | Fails |
|---|---|---|
| ``terms_not_compared`` | accepts a superseded revision; executes a submission's or request's own values without comparing them with the object's | ``body_changed``; also ``split_undeclared`` (consent-id, rar-token) |
| ``member_outside_terms`` | takes the recipient from the ``X-Recipient`` header | ``unbound_member`` |
| ``last_member_wins`` | parses leniently, the last duplicate member winning | ``duplicate_key`` (form b) |
| ``float_terms`` | signs the exact amount, executes it as a float | ``number_precision`` |
| ``fold_at_execution`` | signs the recipient as sent, executes it NFKC-folded | ``unicode_fold`` |
| ``class_suffices`` | accepts the class route for an exact-bound operation | ``class_for_exact`` |
| ``every_acceptance_runs`` | keeps no use record | the replay family, ``race_same``, ``crash_between_use_and_effect`` and the parts |
| ``duplicate_as_refusal`` | answers a repeat of a done object with a refusal | the replay family (``denied_done``) |
| ``dedupes_on_client_key`` | keys single use on the client's ``Idempotency-Key`` | ``replay_new_key`` |
| ``use_record_in_memory`` | keeps use records in process memory | ``replay_after_restart``, ``replay_after_failover`` |
| ``per_instance_use`` | one use store per instance | ``replay_after_failover`` |
| ``per_endpoint_use`` | one use store per endpoint | ``replay_other_endpoint`` |
| ``tenant_not_checked`` | no tenant check | ``replay_other_tenant`` |
| ``accepts_foreign_object`` | resolves an object id in a namespace shared by every instance of the product | ``replay_other_counterparty`` |
| ``holder_not_checked`` | does not check whom the object was issued to | ``other_holder`` |
| ``check_then_set`` | reads its use record, acts, then writes it | ``race_same``, ``crash_between_use_and_effect`` |
| ``accepts_subset`` | on a mismatch, accepts a submission whose items are inside the object's | ``split_undeclared`` (consent-id, rar-token) |
| ``parts_and_whole`` | counts uses per part, so the whole runs after its parts | ``split_declared`` (consent-id, rar-token) |
| ``ignores_expiry`` | never checks the object's expiry | ``expired`` |
| ``forgets_before_expiry`` | issues objects valid beyond its use-record retention and forgets uses after it | ``validity_beyond_memory`` (consent-id, rar-token) |
| ``consumes_on_refusal`` | marks the use, then checks its dependency | ``refused_then_retry`` |
| ``effect_before_mark`` | acts, then marks (under a lock, so races are safe) | ``crash_between_use_and_effect`` |
| ``mark_before_effect_says_done`` | marks the use done before the effect | ``crash_between_use_and_effect`` (``claims_done``) |
| ``executes_request_not_terms`` | signs the right terms, then executes the latest request body's values (and an acceptance's own ``instruction``) | ``body_changed`` (revision), ``unbound_member`` (every shape) |
| ``writes_unaccepted`` | writes a fee to the tenant's ledger beside each effect | resource reconciliation (``effect_without_acceptance``) |
| ``restates_silently`` | signs terms that differ from every request, unlabelled | gives **no verdict**: the restatement check reads it and the stand-in accepts nothing |

``bad`` is ``no_check``: it executes any acceptance naming any object it issued, under any
credential. It must **fail**, not be inconclusive (KRK-M19). ``no-control``: its executor never
writes its store, though it answers "executed" with a proof; the probe must give no verdict
(KRK-M143). ``slow-good``: the correct B, answering each executed acceptance slowly.

``restates_silently`` is the one flaw whose required outcome is not ``fail``. The B-issuer design made a
silent restatement information and a finding, not a fail of KRK-18, because the stand-in does not
accept terms it did not ask for; a B that restates every request therefore leaves nothing to
measure, and the probe must give no verdict, with ``restated_changed`` in its findings. The gate
calls it ``finding:restates_silently``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from known_bad.bissuer_core import SHAPES, ToyIssuerB

FLAWS = ("terms_not_compared", "member_outside_terms", "last_member_wins", "float_terms",
         "fold_at_execution", "class_suffices", "every_acceptance_runs", "duplicate_as_refusal",
         "dedupes_on_client_key", "use_record_in_memory", "per_instance_use", "per_endpoint_use",
         "tenant_not_checked", "accepts_foreign_object", "holder_not_checked", "check_then_set",
         "accepts_subset", "parts_and_whole", "ignores_expiry", "forgets_before_expiry",
         "consumes_on_refusal", "effect_before_mark", "mark_before_effect_says_done",
         "executes_request_not_terms", "writes_unaccepted")
"""The flaws that must fail. ``restates_silently`` is in `FINDINGS`."""
FINDINGS = ("restates_silently",)
BAD_DEFAULT = "no_check"

NOT_IN_SHAPE = {"accepts_subset": ("revision",), "parts_and_whole": ("revision",),
                "forgets_before_expiry": ("revision",)}
"""Flaws whose form does not apply in a shape: ``split_undeclared`` is structurally not
applicable for the revision shape, the revision toy's objects list no parts, and it
keeps objects and uses together (rule 6)."""


def applies(flaw: str, shape: str) -> bool:
    return shape not in NOT_IN_SHAPE.get(flaw, ())


def toy(config: str) -> ToyIssuerB:
    """``<shape>:good`` | ``<shape>:slow-good`` | ``<shape>:bad`` | ``<shape>:no-control`` |
    ``<shape>:bad:<flaw>`` | ``<shape>:finding:<flaw>``."""
    shape, _, rest = config.partition(":")
    if shape not in SHAPES:
        raise KeyError(f"no shape {shape!r} in {config!r}")
    if rest.startswith("bad:") or rest.startswith("finding:"):
        flaw = rest.split(":", 1)[1]
        assert flaw in FLAWS + FINDINGS, flaw
        return ToyIssuerB(shape, "bad", flaw)
    return ToyIssuerB(shape, rest or "good")


def make(shape: str, flaw: Optional[str] = None, **knobs: Any) -> ToyIssuerB:
    t = ToyIssuerB(shape, "bad" if flaw else "good", flaw)
    for k, v in knobs.items():
        assert hasattr(t, k), k
        setattr(t, k, v)
    return t


def cases() -> List[Tuple[str, str]]:
    """Every gate configuration and its required outcome (``pass`` | ``fail`` |
    ``inconclusive``), for `conformance.knownbad`."""
    out: List[Tuple[str, str]] = []
    for shape in SHAPES:
        out += [(f"{shape}:good", "pass"), (f"{shape}:slow-good", "pass"),
                (f"{shape}:bad", "fail"), (f"{shape}:no-control", "inconclusive")]
        out += [(f"{shape}:bad:{f}", "fail") for f in FLAWS if applies(f, shape)]
        out += [(f"{shape}:finding:{f}", "inconclusive") for f in FINDINGS]
    return out


def expected(config: str) -> Dict[str, Any]:
    """What a gate case must show beyond its status: for ``finding:`` cases, the finding."""
    if ":finding:" in config:
        return {"finding": "restated_changed"}
    return {}
