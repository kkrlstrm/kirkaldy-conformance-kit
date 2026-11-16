# Poppy 1.0 Operations: an independent study

Independent tests of the Personal Agent Protocol (Poppy) 1.0 and its Operations extension v3,
run on a self-hosted, open-source implementation. Kai Karlstrom, November 2026. Self-funded.

The questions are the ones a response check alone cannot answer: did the Company perform the
action exactly as approved, at most once, and what happens after a lost response or a sign-out?
Effects are counted by a recorder that is separate from the Company's own responses and state.

## What was tested

- **Target:** unmodified Datalayer Python SDK `personal-agent-protocol` **0.35.0**, sdist SHA-256
  `9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3`. Version 0.36.1 was
  released afterwards and has not been tested.
- **Protocol:** Poppy at commit `85b41ff27e8f6a098d06b71f14d83b1513c728a5` (1.0, Operations v3).
- **Setting:** local only, synthetic accounts and actions, no hosted service contacted. The host
  store, fictional executor, proxy, recorders, mock Company and approval surface are test
  components written for this study.

## Results

Every verdict needs a positive control that does not itself depend on the guarantee, a
deliberately broken variant that the check must fail, and a no-control run that must come out
inconclusive. Results apply to the named configuration only.

| Test | Result | Notes |
|---|---|---|
| Retry after a lost response (Operations §7) | **Pass**, 3 of 3 | The retry returned the original response; one effect. A broken host store produced two. [Note](notes/validator-and-lost-response.md), [evidence](evidence/lost-response/) |
| Refresh after sign-out (spec §4.6, §5.5) | **Pass**, 3 of 3 | `invalid_grant` |
| New action with a pre-sign-out access token | **Pass** against the SDK's own claim, 3 of 3 | Refused on the first attempt; single process, so no statement about deployments with separate token checking. [Note](notes/sign-out-and-in-flight.md) |
| Approval prepared before sign-out, sent after | Observation | Refused, no effect |
| Sign-out while an operation is performing | Observation | The operation completed and the agent was told it succeeded; one effect. Poppy does not say what should happen |
| Account-settings disconnect | Not available | The demo Company has no such page |
| Personal Agent side, six rules (Operations §5–§7) | **Pass**, 3 of 3 each | Declines, revised terms, lost responses, `Retry-After`, Company text versus the User's approval, instruction coverage. Graded against the SDK's own documented claims. [Note](notes/agent-side.md), [claims](evidence/agent-side/claims.md) |
| Validator comparison | Observation | The Foundation milestone gave 38 pass / 0 fail for receivers that acted early or twice; it sends no approvals. [Note](notes/validator-and-lost-response.md) |

No test failed.

## Coverage and proposed checks

- [`coverage/operations-coverage.md`](coverage/operations-coverage.md): each Company-side
  Operations requirement, whether the official validator checks it, and whether a response check
  can establish it.
- [`coverage/proposed-checks.md`](coverage/proposed-checks.md): opt-in checks that would need a
  test account and a Company-supplied effect observer.
- [`notes/what-a-validator-pass-means.md`](notes/what-a-validator-pass-means.md).

## Layout

- `notes/`: one short write-up per test family.
- `evidence/`: the raw run output each verdict was read from, and the quoted claims.
- `harness/`: the code that produced it, laid out as it ran (`harness/targets/...`).

## Reproduce

Run from `harness/`. Dependencies are hash-locked in
`docs/studies/poppy/evidence/2026-11-15-amo-v1/`; the SDK archive is fetched from PyPI and checked
against the hash above before installation.

- Lost response (Docker): build `targets/poppy_race/Dockerfile` as
  `poppy-datalayer-integration:local`, build `targets/poppy_lost_response/Dockerfile` as
  `poppy-loss-client:local`, run `python3 targets/poppy_lost_response/run.py target` three times
  and once each for `bad`, `no-control` and `expiry`, save the outputs under the names in
  `evidence/lost-response/`, then run `targets/poppy_lost_response/verify.py <dir>`. `run.py`
  checks the Company image ID it was graded on; a rebuild on another machine gets a different ID,
  so compare the recorded predicates rather than IDs.
- Sign-out (no Docker): in a virtual environment with the locked dependencies and the SDK
  installed, `python targets/poppy_withdrawal/run.py out.json`, then
  `python3 targets/poppy_withdrawal/verify.py out.json`.
- Personal Agent side (no Docker): `python targets/poppy_agent_study/run.py out.json`, then
  `python3 targets/poppy_agent_study/verify.py out.json`.

Container IDs, operation IDs and timings differ between runs.

## Not tested

TLS, production identity and credentials, other SDK versions, other stores and transports,
separate authorization and resource servers, multiple replicas, browsers and websites, MCP and
conversation transports, real language-model agents, hosted agents, real accounts or money.

## Method

The test method, including the rules for controls and the catalogue of measurement errors, is
published as Kirkaldy Conformance Properties for Agent Infrastructure,
DOI [10.5281/zenodo.23962761](https://doi.org/10.5281/zenodo.23962761). Corrections to this study
will be added here with a date.
