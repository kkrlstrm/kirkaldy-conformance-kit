# KRK-17 (P17) reconcilable two-sided record: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p17_reconcilable_record.py`. Where it says "the design", it means the
property's design document, X8, which is not part of this copy of the kit; this file and the
docstring are what the code does.

## Decisions that bind the build

- **KRK-17** outside code, **P17** in code. Role A only in this version.
- **Records alone are enough to pass**. Reconciliation checks are scored only when
  the target's `reconciles()` is true; otherwise the result says "records reconcilable; target
  does not reconcile".
- **Neither record wins**. A break of a kind in `books.EFFECT_KINDS` that a target
  closes without a person is the fail `closed_without_person`. No disagreement about an effect
  closes without a person's outcome either (KRK-M66): after a person's settlement
  that names no outcome (`keep-both`) of a break in `p17.HOLDS_EFFECT` naming one of the probe's
  cases, the target's `effect_state` for that case must read `open` and not closed, and after a
  second settlement with an outcome it must read as that outcome (`e:<variant>`). A target with
  no `effect_state` reads `effect_unread` there, never a pass.
- **Tamper on the target's side**: `operator_write`, self-hosted targets only,
  plain data only, never a signature. B's tamper goes through the stub's kit-only path.
- **A side with no log**: the target's own side is judged and fails what it cannot
  answer (`order`, the own-side edit). A counterparty with no log is not modelled here: the stub
  always keeps one.
- **Removal detectable by A itself**: B numbers its entries per requester with no
  gap; A holds B's signed checkpoints.
- **What a third party sees**: the kit's reconciler reads only this pair's entries
  (`StubCounterparty.record(peer)`), with item keys salted per agreement.
- **KRK-16 is unchanged**: the receipt format, `judge`, the vectors and the twelve variants.

## Module 1: `conformance/books.py`

```python
SCHEMA = "kirkaldy.record-entry/0.1"         # the reading format (module docstring)
def entry_digest(entry) -> str
def entry_problem(entry) -> str | None
def action_key(entry) -> (requester, counterparty, correlation_id, request_digest)
def chain_breaks(entries) -> (list[Break], list[Finding])       # gap, renumbered, torn; unnumbered
def checkpoint_claims(issuer, peer, pair_seq, head, issued_at) -> dict
def sign_checkpoint(claims, key) -> str                          # JWS, typ krk-checkpoint+jws
def verify_checkpoint(token, pinned) -> CheckpointVerified
def checkpoint_covers(entries, claims) -> list[Break]            # changed-/removed-after-ack
class Reconciler: ...                                            # one method per check
def reconcile(a, b, *, requester, counterparty, holdings_a, holdings_b, receipt_keys,
              b_checkpoint_keys, a_checkpoint_keys, mapping, state_b, tolerance_s,
              window_s, now) -> Reconciled
```

## Module 2: `conformance/counterparty.py` (the stub B, extended)

The log is one row per entry, in the reading format, numbered per requester and chained;
UPDATE and DELETE are refused by triggers (`APPEND_ONLY`). New methods: `record(peer)`,
`checkpoint(peer)`, `checkpoint_public_key()`, `hold(peer, token)`, `holdings(peer)`,
`read_state(peer, correlation_id)`, `set_record_mode(correlation_id, mode, **params)`
(`RECORD_MODES`), `release(correlation_id, rng)`, `out_of_band(requester, expected, items, rng)`,
`void(peer, correlation_id)`, and the kit-only `tamper_edit`, `tamper_delete`, `tamper_swap`
(recorded in `tamper_log`). Ground truth: `log_truth()`, `store_counts()`, `issued()`.

## Module 3: the property's adapter protocol

The KRK-16 driving methods (`pin_counterparty_key`, `submit`, `deliver`, `status`, optional
`evidence_grade`, `receipt_deadline_s`, `elapse`), plus:

| Method | Required | Use |
|---|---|---|
| `bind_counterparty_record(peer, agreement)` | no | B's keys, the declared mapping, and the paths to B's record, checkpoints, holdings and read API |
| `deliver_checkpoint(case_id, token)` | no | B's checkpoint, issued with each answer |
| `export(peer)` | yes | the target's record in the reading format, through its own serializer |
| `export_raw(peer)` | no | the product's own rows, one per line (for `kept_both`) |
| `holdings(peer)` | yes | B's statements the target holds, raw |
| `checkpoint_key()` | no | A's checkpoint public key |
| `record_grade()` | no | the grade the product claims |
| `reconciles()`, `settlement_rule()` | no | whether, and by what stated rule, it reconciles |
| `reconcile(peer)`, `breaks(peer)`, `states(peer)`, `flagged(peer, ref)`, `settle_as_person(peer, ref, decision, by)` | if it reconciles | its own reconciliation |
| `reconcile_attempt_as_person(case_id, outcome, by)` | no | a person settles one attempt |
| `effect_state(case_ref)` | no; read only if it reconciles | the product's reading of the effect of the case `submit` returned, translated only (KRK-M24, KRK-M25): `{"effect": "done" \| "not-done" \| "open", "closed": bool, "product": <its own words>}` |
| `operator_write(peer, entry_digest, change)` | no | the own-side tamper; "changed", "removed" or "refused: <why>" |
| `crash_between(case_id, step)`, `crashed(case_id)` | no | `torn_write` |
| `variants_not_applicable()`, `variant_notes()` | no | as KRK-16; `NA_FORBIDDEN` may not be declared |

## Departures from the design's §6

- `pin_counterparty_key` stays KRK-16's; the peer, both of B's keys and the paths go in one
  `agreement` dict to `bind_counterparty_record`, not as separate callables.
- `breaks`, `states`, `flagged` and `settle_as_person` take the peer. `states` is added: the
  pre-execution guard (KRK-M30) reads per-action states, which `breaks` alone cannot give.
- `effect_state` is added: the design's §6 reads only the record after a
  settlement, which cannot show an effect closed by a settlement that names no outcome. The
  control reads it as evidence only and requires nothing of it (KRK-M19); a target that reads
  honest, completed actions as `open` gets no effect verdict.
- `forked_log` is not built (no witness; no target claims the `witnessed` grade).
- The `no-control` toy has no export path, rather than an executor that never reaches B: the
  probe, not the target, carries each request to B, as in KRK-16.
