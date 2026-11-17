# Poppy Operations: test effect observer (discussion draft)

A small, opt-in test interface and local example for checking what actually happened when an approved operation is retried after its response is lost. It supplements, rather than replaces, the existing [Poppy lost-response study](https://github.com/kkrlstrm/kirkaldy-conformance-kit/blob/main/studies/poppy-1.0/notes/validator-and-lost-response.md). The proposed interface is not part of Poppy and does not require a production endpoint.

## Run

Python 3.10+; standard library only:

```sh
python3 observer_demo.py
python3 -m unittest -v test_observer_demo
```

The demo emits three JSON results: safe replay **PASS**; a deliberately duplicated action **FAIL**, although the two responses match; and unavailable observation **INCONCLUSIVE**. An unexpected outcome exits nonzero. The separate unit tests cover these cases, invalid or mismatched observation, pre-existing effects and a mismatched response.

## Observer contract

The company opts in using an isolated staging account and a test action. The harness and company agree ahead of time on how a scoped operation maps to underlying business effects, what constitutes one effect, which data source is authoritative, and when a read is complete. The observer is read-only and queries committed business effects, not a cached response or replay receipt.

Input: `test_run_id`, `account_id`, `operation_id`. These are **test-adapter identifiers**, not new Poppy wire fields. The adapter must bind the scope to the actual approved operation being tested. It must not silently widen the account, operation or test-run scope.

Return exactly one of:

```json
{"status":"observed","scope":{"test_run_id":"run-1","account_id":"test-account","operation_id":"operation-1"},"effect_ids":["return-123"]}
```

```json
{"status":"unavailable","scope":{"test_run_id":"run-1","account_id":"test-account","operation_id":"operation-1"},"reason":"source_unreachable"}
```

- `observed` means the adapter successfully queried **all matching committed effects** through the agreed observation point. `effect_ids: []` means it checked and found none. Each nonempty ID must identify one physical business action, be stable across reads, and distinguish separately committed actions—even when their response or business key is the same. Duplicate or malformed IDs, a scope mismatch, incomplete pagination, inaccessible data, or an unresolved consistency lag must not produce a pass.
- `unavailable` means completeness cannot be established; return a reason and grade the observation **INCONCLUSIVE**. Errors, timeouts, partial results and unsupported observation are unavailable, not empty. The harness must enforce bounded waits and classify adapter exceptions or malformed responses as inconclusive in a real integration.
- A business system without stable individual effect IDs or without a way to enumerate all matching effects cannot satisfy this observer contract for that action; use another observable test action or report inconclusive. An observer is evidence from the company's test system, not proof that a malicious or defective observer reports honestly.

The example's SQLite read is immediately consistent with its local transaction. A real adapter must define a bounded completeness condition—such as a reliable snapshot/watermark covering the operation and retry—and return unavailable if it cannot reach it. Waiting a fixed time alone does not prove completeness. No customer data or live actions are needed.

## First lost-response check

1. Choose a fresh scope and observe a complete empty baseline. An unavailable or nonempty baseline is inconclusive.
2. Send the approved test action. A **test transport** records the original response and drops it before delivery. Observe the effect after the first attempt.
3. Retry the same approval within its permitted validity window. Observe again, with a complete observation through the retry.
4. Pass this check only when the original and retry responses match, the first attempt produced one matching effect, and the retry leaves the **same single effect ID**. Fail on a fully observed duplicate, missing or changed effect, or a mismatched response. A missing, incomplete or invalid required observation is inconclusive. A production-grade harness should preserve independently established failures even if some separate observation is unavailable; this small example chooses the conservative overall inconclusive result for incomplete effect evidence.

The first-response capture is test instrumentation; it must faithfully record the response after the action and before simulated delivery failure. The example simply suppresses delivery in-process. It **does not** exercise HTTP, Poppy approval/identity, network faults, expiry, concurrency, crash recovery, or an actual company. Its successful result is not a Poppy conformance result. The action is assumed already approved.

The proposal builds on the lost-response study linked above and Ariel Smoliar's [process-crash and effect-observer example](https://github.com/personal-agent-protocol/personal-agent-protocol/issues/103#issuecomment-6951286000). The example here is newly written; it does not import Ariel's code. See REPLY.md for a proposed issue comment.
