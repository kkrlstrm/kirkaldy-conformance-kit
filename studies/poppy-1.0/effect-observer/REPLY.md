Thanks, Ariel. I put together a small draft observer contract and a runnable lost-response example based on your points about completeness and stable action IDs.

The observer takes a test-run/account/operation scope and returns either a complete list of matching committed effect IDs, or `unavailable`. A complete empty list means the check found no effects; an unavailable or partial observation makes the result inconclusive. The adapter defines how the scope maps to actual business records and when the source is complete.

The example exercises three cases: safe replay leaves one effect and returns the original response; a deliberately broken implementation creates a second effect but returns the original response, which the observer catches; and an unavailable observer makes the check inconclusive. It is a local simulation, not a Poppy implementation or a production endpoint.

[Observer contract and runnable example](https://github.com/kkrlstrm/kirkaldy-conformance-kit/tree/main/studies/poppy-1.0/effect-observer)

Would this contract be a useful starting point for the company kit? I'm interested in how you'd represent completeness for systems whose business records are eventually consistent.
