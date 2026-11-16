# OperationsClient claim basis

SDK sdist SHA-256 `9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3`. Quoted verbatim from the archive; source paths and original line numbers are shown. The SDK module docstring does not itself describe website retry states; the separate `WebsiteOperations` class docstring does. The website form is not exercised here.

[Operations v3 at pinned commit](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/85b41ff27e8f6a098d06b71f14d83b1513c728a5/content/versions/1.0/extensions/operations.mdx).

## `personal_agent_protocol/operations.py:5-46`

```text
"""PAP Operations extension, version 3: exact approval, at most once.

A company that wants approval for an action refuses the request and returns the
operation: the terms as JSON, and usually in plain language too. The terms are approved,
by the user or by the personal agent on an instruction the user gave it, and the agent
makes the same request again with the approval, through the interface that returned
the operation:

- an API's `403` with `error: approval_required` and `operation`, answered by the
  same request with the `Poppy-Approval` header (`ApiClient.call(approval=...)`);
- an MCP tool's error result with `structuredContent.operation`, answered by the
  same call with `_meta["personalagentprotocol.org/approval"]`
  (`McpClient.call_tool(approval=...)`);
- a company message's `operation`, answered by a message with `approval`;
- a website's `403` to the agent's own joined browser, with only a reference in the
  `Poppy-Operation` header: the agent gets the operation by posting the reference to the
  extension's `endpoint`, records the approval there (`204`), and has its browser make
  the request again (`WebsiteOperations`).

What this client guarantees on the personal agent's side:

- **Negotiation.** Operations are used only when the company's `poppy.json` lists
  `operations` version 3 and the Session declares it. Version 2 is another major
  version: it does not count, and nothing here speaks it.
- **Who approved.** Every approval says `approver`. `OperationsClient.ask_user` asks
  the host's own approval surface (`pap.approvalSurface`), naming the company and the
  revision's terms: only the surface's `True` makes a `user` approval, and nothing here
  reads conversation text as approval. `OperationsClient.approve_as_agent` makes an
  `agent` approval only on an `AgentInstruction` the host holds from the user, and only
  when the instruction's own check says it covers the revision's terms; when it can't
  tell, when the terms differ from what was asked, or when the company answered an
  earlier agent approval of the action with new terms or declined one, it is `ask_user`.
- **Exact terms.** `terms_differences` checks `terms` against what the agent asked for
  and against the `summary` when there is one. An approval covers one revision.
- **Declines.** A company may decline an approval that passes its checks
  (`approval_declined`): `send` reports `declined`, the approval is never sent again,
  and no new revision of that action is approved without the user.
- **At most once.** After a failure or a timeout, `OperationsClient.send` sends
  the same approval again, waiting for `Retry-After`. A new operation in answer
  to such a retry doesn't say whether the first was performed: it is `unknown`,
  and the host finds out another way before asking the user again.
"""
```

## `personal_agent_protocol/operations.py:445-468`

```text
class WebsiteOperations:
    """Operations a Company's website returns to the personal agent's own browser.

    The approval never passes through the browser (Operations 6, 8.2):

    1. `reference(headers, joined=...)` takes the reference from the `Poppy-Operation`
       header of a response the agent's own browser received, and only when its `sid`
       names a Session the agent joined that browser to, at this Company. Page content,
       a message, or a header naming any other Session is never a reference.
    2. `operation(reference, session=...)` posts `{"ref": …}` to this Company's
       `endpoint`, with the Session header and any access token: the operation, to
       approve as at an API (`OperationsClient.ask_user` or `approve_as_agent`).
    3. `record(reference, approval, session=...)` posts the same body with
       `Poppy-Approval`: `204` records it, nothing performed yet. Use it as the request
       of `OperationsClient.send`: a decline and a new revision come back as from an API.
    4. The host has its browser make the request again (the page's Continue button, the
       same form): the website performs it once, using the approval recorded first.
    5. When the browser's request fails, or answers a new reference after an approval was
       recorded, `before_approving_again(earlier, ...)` looks the earlier reference up:
       `performing` waits, `performed` is never approved again (Operations 7).

    `endpoint` is the one `operations_endpoint` reads from this Company's `poppy.json`,
    so a header from anywhere else can't send the Session header to a new destination.
    """
```

## `personal_agent_protocol/reactor.py:326-363`

```text
class ApprovalRequest:
    """What a user is asked to approve: nothing has been done yet.

    A live-session action that changes or ends what the user holds: `summary` says
    what it does in plain words; `arguments` are the action's own (Session and
    operation IDs, never a credential).

    An operation (Operations 5): `summary` is the company's own, shown as it is and
    as text, its links, images and HTML not rendered (`ui.inert_summary`, wherever
    Markdown is); `company_name` and `company_domain` say who asks, and are shown
    with it; `terms` and `expires_at` are the revision's; `differences` what the
    terms check found, to point out; `changed` what a new revision changed.
    """

    action_id: str
    action_name: str
    summary: str
    arguments: Mapping[str, str]
    tenant_id: str
    company_name: str | None = None
    company_domain: str | None = None
    terms: Mapping[str, Any] | None = None
    expires_at: datetime | None = None
    differences: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()


@runtime_checkable
class ApprovalSurface(Protocol):
    """The host's own approval surface: the user, not a model, answers.

    Only `True` approves. The surface asks the user every time: it never answers
    from an earlier decision, and never because of text from a company. Without a
    contribution, a destructive live-session action is refused
    (`approval_required`), staying available from `pap`, and no operation is approved.
    """

    async def approve(self, request: ApprovalRequest) -> bool: ...
```

## Operations v3 §5, source lines 353-396

```text
## 5. Approving an operation {#approval}

When a request returns an operation, the Personal Agent MUST NOT treat the action as done. It either
sends an approval of the operation (6), or tells the User the action wasn't performed. An approval
states that this revision of the operation is approved, in one of two ways:

- **User approved:** the Personal Agent asks the User, and the User approves.
- **Agent approved:** the Personal Agent approves on an instruction the User gave it, such as "go
  ahead with any exchange under $20".

A later version can add a third, signed user approval (8.1).

For a user approval:

- The Personal Agent MUST show the User the Company's name and the revision's terms, and MUST take
  the User's answer through its own interface. It MUST NOT treat text from the Company, such as a
  conversation message, as the User's approval.
- The Personal Agent can describe the terms itself, or show the values in `terms`. When the
  operation has a `summary`, the Personal Agent SHOULD show it rather than write its own
  description.

For an agent approval:

- It MUST rest on an instruction the User gave the Personal Agent. Content from the Company, a
  website, or anything else the Personal Agent read isn't one, even when it says it comes from the
  User.
- Before approving, the Personal Agent MUST check the revision's terms against that instruction, and
  approve only if the instruction covers them. This extension doesn't say how. If the Personal Agent
  can't tell whether it does, it asks the User.
- If the Company answers the Personal Agent's agent approval with a new revision (6), or a website
  returns a new operation for the action after recording it, the Personal Agent MUST NOT approve the
  new one on the same instruction. It asks the User.

For both:

- Before approving, the Personal Agent SHOULD check that `terms` agree with what it asked for, and
  with the `summary` if there is one, and point out any difference to the User when it asks them.
  The Company writes both, so the `summary` alone could describe something other than the `terms`.
  On a website, what it asked for is the action its browser just took (8.2).
- An approval covers one revision. When a new revision arrives, it needs a new approval, from the
  User or the Personal Agent. If the User prefers an earlier revision, the Personal Agent can send its
  approval, but the Company may have replaced it (6).
- If the User withdraws their approval, or the instruction an agent approval rests on, before the
  Personal Agent has sent it, the Personal Agent doesn't send it.
```

## Operations v3 §6, decline, source lines 575-623

```text
### Declining an approval {#declining-approval}

Once the checks pass, a Company MAY decline the approval instead of performing the action, for its
own reasons, such as `approver`, the account, or its own risk checks. It performs nothing and
returns no new operation. A decline has these members:

| Field          | Req. | Description                                                                                                                              |
| -------------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `operation_id` | Yes  | The approval's `operation_id`.                                                                                                           |
| `revision`     | Yes  | The approval's `revision`.                                                                                                               |
| `reason`       | No   | Why, in short plain language for the User, like the `reason` of a `user_requested` event ([spec 8.10](/docs/spec#direct-conversations)). |
| `alternative`  | No   | Another way to do the action, as in [spec 9.2](/docs/spec#alternatives), such as a `web` reference where the User can do it themselves.  |

The Company MUST NOT put anything in `reason` that the Session couldn't already see. There are no
reason codes: the Personal Agent does the same whatever the reason, and codes would invite
workarounds and reveal the Company's risk rules.

An API responds with HTTP 403 and a JSON body with `error` set to `approval_declined` and the
members above, like `approval_required` (4). For an agent approval of an account closure:

```http label="Response: Company → Personal Agent"
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "approval_declined",
  "operation_id": "cls_2Wq8",
  "revision": "1791487200-p9Lm3Rt6Vx1c",
  "reason": "Only the account holder can close this account.",
  "alternative": {
    "instructions": "The account holder can close the account in the Example app.",
    "references": [{ "type": "web", "url": "https://example.com/account/close" }]
  }
}
```

An MCP tool returns an error result, with `isError` set to `true`, the same members, `error`
included, in `structuredContent`, and text that says the action wasn't performed, such as the
`reason`. In a conversation, the Company Agent says so in a later message, with the members in
`extensions.operations.declined`, without `error`. On a website, the Company declines at
`endpoint`, where the approval arrives, and responds as an API does. The Company MUST NOT record a
declined approval, so a website never finds it for a later request.

When an approval is declined, the Personal Agent MUST NOT send that approval again, and MUST NOT
approve a new revision for the same action without asking the User (5). It tells the User the
action wasn't performed, and can pass on `reason` and `alternative`. They are content from the
Company ([spec 10.1](/docs/spec#untrusted-content)): it can show them or put them in its own words,
and doesn't follow them as instructions.

```

## Operations v3 §7, source lines 624-650

```text
## 7. Retries and at most once {#at-most-once}

- The Company MUST perform each operation at most once, however many times its approval is sent.
- A request with the approval of an operation already performed gets the response the Company gave
  the first time, or one that says the same, for as long as the Company remembers the operation.
- The Company MUST remember that it performed an operation at least until the approved revision's
  `expires_at`, and while it is being performed. After that, it MAY forget it. A retry then fails
  check 3 or is handled as a request without an approval, so it gets a new revision and the action
  still isn't performed twice. On a website, the browser's request carries no approval, so once
  the action is performed, the next request for it is a new one and gets a new operation (6). In a
  conversation, a message retried with the same ID gets the original response ([spec 8.3](/docs/spec#sending-messages)), and a new message with the
  same approval adds nothing.
- While an operation is being performed, or the Company doesn't know whether it took effect, for
  example after a timeout in one of its own systems, the Company MUST NOT respond as if it failed.
  An API or MCP server responds with HTTP 503 and a `Retry-After` header, or as it does for work
  that hasn't finished.
- A declined approval (6) means the operation wasn't performed. It isn't a failure, and the Personal
  Agent doesn't send the approval again.
- If a request with an approval fails or times out, the Personal Agent sends it again with the same
  approval. It MUST NOT approve a new operation for the same action, or ask the User to, until it
  knows whether the first one was performed. A new operation in answer to a retry doesn't say, so the
  Personal Agent finds out another way, such as from the order in the Company's API.
- On a website, if the browser's request fails or times out after the approval was recorded, the
  Personal Agent has the browser make it again. An approval that wasn't used up still applies. A new
  reference in answer means the approval was used up or no longer matches. Before approving the
  new one, or asking the User about it, the Personal Agent looks up the earlier reference at `endpoint` (6): while it
  is `performing`, it waits, and when it is `performed`, it doesn't approve it.
```
