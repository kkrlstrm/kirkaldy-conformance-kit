# Proposed opt-in Operations checks

These checks would need an opt-in test account and a Company-supplied test effect observer. The hook reports the operation identifier, revision, action, target, terms and committed effect count for test actions. It must observe the effect independently of the Company's response. Missing or unavailable observations make a check inconclusive. Each check needs a separate ordinary successful-action control.

| Coverage row | Validator sends | Hook reports | Pass condition |
|---|---|---|---|
| Action identity | Requests for two distinct test actions, then approves each | Action identifiers and effects | Different actions have different identifiers and only the approved effects occur |
| Complete terms and approved action | Request and approve a test action with distinct target, amount and other material fields | Actual committed action and material fields | Proposed terms and any summary disclose those fields; actual effect matches the approved revision |
| Before approval / request approval | Request a test action without approval | Effects before and after the request | Required interface response appears and no effect occurs |
| At most once | Approve one action repeatedly, including concurrent requests | Committed effects by operation | At most one effect; normal control commits one |
| Optional members and unknown members | Valid approvals with optional fields absent, an unfamiliar input type, and an unfamiliar member | Effects for each distinct controlled action | These variations alone do not cause rejection; unknown fields do not alter the authorized effect |
| Session and account eligibility | Obtain approvals in signed-in and signed-out Sessions, then retry using eligible and ineligible identities | Effects by test identity and operation | Eligible control succeeds; ineligible identity causes no effect and receives the specified handling |
| Website approval recording | Record an approval, then make the eligible browser request | Approval records and effects | Recording alone causes no effect; the eligible browser request uses the approval |
| Decline | Trigger an explicitly supported decline and inspect its response | Effects and approval records | No effect or new operation is produced; the decline uses the interface-specific shape |
| Cross-interface approval | Attempt to approve a website operation at another supported interface and vice versa | Approval records and effects | No cross-interface approval is accepted or applied |
| Website retention and Session binding | Record an approval, try another Session, then use an eligible Session before expiry | Approval records and effects | Ineligible Session cannot use it; eligible Session can use the retained approval |
| Approval checks | Send approvals with ineligible Session, changed terms, unknown revision and expired revision | Complete test-effect stream | No unauthorized effect; response follows the first failed check |
| Declined website approval | Cause an explicitly supported test decline, then retry the website action | Approval records and effects | Declined approval is not recorded or used |
| Lost response / retention | Approve, drop the response after effect commit, retry before expiry; separately observe after expiry | Commit event and all later effects | Before expiry, retry says the same as the original and there is one effect; after expiry, follow the spec's forgetting rule |
| Uncertain outcome | Hold a controlled downstream action in progress or leave its outcome unknown | Whether the effect has committed | Response does not report failure while outcome remains uncertain |

The hook is a proposed test interface, not a requirement on deployment architecture. Test accounts and a safe, reversible test action must be supplied by the Company. This proposal does not determine how maintainers implement their validator.
