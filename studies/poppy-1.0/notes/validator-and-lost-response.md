# Validator comparison and a lost-response test

The validator README already says that the Extensions milestone covers only what a run declaring
no extensions sees. This note concerns that coverage gap. It does not identify a vulnerability.

**Validator comparison.** At Poppy commit `85b41ff27e8f6a098d06b71f14d83b1513c728a5`, the
Foundation milestone gave the same result (38 pass, 0 fail, 27 skip) for a test receiver that
performed its action before approval, and for one that performed it twice, as for the correct
receiver; a separate recorder counted the extra effects. This is expected, because the milestone
sends no approvals. It shows what an Operations check would need to observe. The receiver was a
locally owned test fixture, not a third-party implementation, and its code is not included.
[Raw output and recorder counts](https://github.com/kkrlstrm/kirkaldy-conformance-kit/blob/main/studies/poppy-1.0/evidence/validator-comparison/validator-foundation.json).

**Lost-response test: PASS for the tested local configuration and schedule.** Target: unmodified
Datalayer Python SDK `personal-agent-protocol` 0.35.0 (sdist SHA-256
`9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3`), Poppy 1.0, Operations v3,
with a study-owned SQLite store and HTTP between containers. Version 0.36.1 has since been
released and was not tested. In three fresh trials, a TCP proxy captured the Company's completed
response and closed the client connection without forwarding it. The same approval was retried
with a fresh idempotency key. Each retry returned the captured response, and the independent
recorder showed one effect. Each trial included a separate successful approval control. A
deliberately broken host store produced two effects, and an unavailable recorder made the control
inconclusive.
[Trial evidence](https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/main/studies/poppy-1.0/evidence/lost-response).

This does not establish behavior for other stores, transports, actions, or timing schedules. A
separate, ungraded observation advanced the Company's demo clock past the revision's expiry; the
retry returned `invalid_session` and the recorder still showed one effect. Because the Session also
expired, it does not show how an eligible post-expiry retry behaves.

**Reproduce.** The harness is in
[`studies/poppy-1.0/harness`](https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/main/studies/poppy-1.0/harness).
Build the pinned SDK image from `targets/poppy_race/Dockerfile`, run
`targets/poppy_lost_response/run.py` for `target` three times and once each for `bad`,
`no-control` and `expiry`, then check the outputs with `targets/poppy_lost_response/verify.py`.
The SDK is unchanged; the host store, fictional executor, proxy and recorder are test components.
