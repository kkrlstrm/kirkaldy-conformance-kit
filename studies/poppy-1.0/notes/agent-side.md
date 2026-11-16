# Checking the Personal Agent side of Operations

This is an independent check of Personal Agent-side Operations handling in the Datalayer Python SDK 0.35.0 (0.36.1 has since been released and was not tested). The check used a local test Company, a scripted approval surface and an in-process API transport. Each case ran three times with fresh state.

In these trials, the agent-side client handled a declined approval without retrying it and asked the user before approving the next revision. It also asked after an agent approval received revised terms, and when a user instruction did not cover the terms. A Company message saying the user had approved did not produce an approval when the surface answered no.

After a dropped response, the client retried the same approval and reported an unknown outcome when the retry returned a new operation. For a 503 with a one-second `Retry-After`, the retries arrived after at least one second. These observations apply to the SDK client used with this test driver, not to every host that calls it.

A validator for Personal Agents could check:

- Declines and approval of later revisions.
- Revised terms after an agent approval.
- Reuse of the same approval after a lost response, and handling of an unknown outcome.
- Waiting for `Retry-After` while an operation is performing.
- Separation of Company text from the user's own approval surface.
- Whether an instruction covers the terms before an agent approval.
- Website references and earlier-operation status before approving again.

This check did not test website references, browsers, real language-model agents, hosted agents, other transports, or host behavior after a restart.

Evidence and harness: https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/main/studies/poppy-1.0
