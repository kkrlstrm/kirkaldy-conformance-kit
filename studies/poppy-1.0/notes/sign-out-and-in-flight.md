# Sign-out and actions in progress

On the in-flight question: in a local test, an operation that was already performing when the User
signed out still completed. The agent received a success response, and an independent recorder
counted one effect. Neither the specification nor the guides say what should happen in that case,
so this is an observation, not a pass or fail.

The test used a local Company built with Datalayer's Python SDK 0.35.0 (0.36.1 has since been
released and was not tested): the SDK's in-memory store, the Company and agent in one process, a
separate local effect recorder, a one-hour access-token lifetime, and synthetic accounts and
actions. The approval was simulated; no person took part.

Other results, three trials each where graded:

- A revoked refresh token returned `invalid_grant`.
- A new action sent with an access token issued before sign-out was refused (`invalid_token`) on
  the first attempt after sign-out, with no recorded effect. The SDK's Company invalidates the
  sign-in's access tokens at sign-out, as the guides recommend. Because the Company and its token
  store share one process and memory here, this says nothing about how long a token stays usable
  in a deployment where a separate API server checks tokens itself.
- An approval prepared before sign-out and sent afterwards was refused, with no recorded effect.
- Disconnecting from the Company's account settings could not be tested: the demo Company has no
  such page.

The specification refers access-token behavior after refresh-token revocation to RFC 7009 §2.1
and sets no time bound of its own. The guides recommend invalidating access tokens at sign-out, or
checking authorization on each request, so sign-out takes effect right away; failing that, access
tokens lasting a few minutes. Neither says what happens to an operation already performing.

Not tested: separate authorization and resource servers, multiple replicas, other stores or
transports, crashes, real accounts. Evidence and harness:
https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/main/studies/poppy-1.0
