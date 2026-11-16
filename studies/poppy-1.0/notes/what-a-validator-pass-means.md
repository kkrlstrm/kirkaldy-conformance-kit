# What a validator pass means

A validator exit code of 0 means that the selected milestone's checks found no failing MUST check
on that deployment at that time. Skipped checks are not passes. The result does not establish
behavior for requests the milestone does not send.

In particular, it does not establish what effects occurred downstream, or how concurrent actions,
crashes, and retries behave. Those questions need separate checks against the deployment and its
host systems.

Company review can examine matters beyond the automated checks. The two should be reported
separately, with the selected milestone and any skipped checks named. For Operations, the
validator README says the Extensions milestone checks only what a run declaring no extensions sees;
[this map](https://github.com/kkrlstrm/kirkaldy-conformance-kit/blob/main/studies/poppy-1.0/coverage/operations-coverage.md)
lists each Company-side Operations requirement and whether a response check alone can establish it.
