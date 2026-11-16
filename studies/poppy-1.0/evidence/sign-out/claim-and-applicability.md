# Withdrawal claim basis and applicability — source inspection

This is a source inspection, not a runtime result. Poppy source is pinned to commit `85b41ff27e8f6a098d06b71f14d83b1513c728a5`. The Datalayer `personal-agent-protocol` 0.35.0 source distribution has SHA-256 `9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3`, verified against the downloaded archive. File:line references below use paths inside that archive. No target was run.

## Protocol

[Spec 1.0 §4.6](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/85b41ff27e8f6a098d06b71f14d83b1513c728a5/content/versions/1.0/spec.mdx#L717-L721):

> The Personal Agent revokes a refresh token at the Company's `revocation_endpoint` ([RFC
> 7009](https://www.rfc-editor.org/rfc/rfc7009)), with `token_type_hint=refresh_token` and its client
> assertion. Revoking every refresh token it holds for an account signs out (5.5).

[Spec 1.0 §5.5](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/85b41ff27e8f6a098d06b71f14d83b1513c728a5/content/versions/1.0/spec.mdx#L1169-L1179):

> **Sign-out.** The Personal Agent signs out of an account by revoking every refresh token it holds
> for it (4.6). The account is signed out once no refresh token the Company issued to that `client_id`
> for the account is still valid. The Sessions that used them continue signed out: the Personal
> Agent sends the Session header without an access token. What happens to access tokens issued under
> a revoked refresh token, including one that a new sign-in replaced (4.7), follows [RFC
> 7009](https://www.rfc-editor.org/rfc/rfc7009) §2.1, and the
> [guides](/docs/guides#company-lifetimes) suggest lifetimes.
>
> The User can also disconnect the Personal Agent in the Company's account settings. That revokes
> its refresh tokens for the account. The Personal Agent finds out when a request fails with
> `invalid_token`, or refresh returns `invalid_grant`, and then continues signed out.

[Guides, Token lifetimes and sign-out](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/85b41ff27e8f6a098d06b71f14d83b1513c728a5/content/versions/1.0/guides.mdx#L832-L843):

> At sign-out, invalidate the access tokens issued under the revoked refresh token, as [RFC
> 7009](https://www.rfc-editor.org/rfc/rfc7009) §2.1 describes, or check on each request whether the
> authorization is still active, so sign-out takes effect right away. If you can do neither, keep
> access tokens to a few minutes ([5.5](/docs/spec#ending-sessions)).

The spec itself states no numeric revocation propagation bound. The guide is advice, not by itself a deployment-specific timing guarantee. W1 concerns a revoked refresh token; W2 must distinguish a deployment claim from guidance and measurements.

## SDK 0.35.0

* `personal_agent_protocol/accounts.py:235-240`: “Revoke the refresh token at the company (RFC 7009, §4.6), then forget it.” The agent client needs the Company's `revocation_endpoint`; it is not an issuer.
* `personal_agent_protocol/company/service.py:24-28` describes the Company's OAuth server and “revocation (RFC 7009) whose sign-in ends whole.” Its route table handles `POST /oauth/revoke` at `service.py:1362-1365`, and `service.py:2245-2278` implements the endpoint and sign-out. The issuer is therefore present in this SDK, and W1–W4 must not be marked unavailable on the basis of the earlier test-only issuer.
* `personal_agent_protocol/company/service.py:2258-2261` says: “Revoke whole sign-ins: their refresh and access tokens stop working.” Default access-token lifetime is one hour (`service.py:414`); verify the actual runtime configuration before measuring.
* `personal_agent_protocol/company/service.py:2342-2353` provides a programmatic `disconnect` method. The demo website handles only its root, exchange and pickup pages (`personal_agent_protocol/demo/manzanita.py:432-475`); other paths return not found. The named demo host has no account-settings disconnect page. W5's user-interface form is **NOT_AVAILABLE** on this source-inspected host; a direct method call is not a substitute for that form.

The claim basis does not establish runtime enforcement. W1–W4 remain INCONCLUSIVE until the specified positive, broken and recorder-down controls and measurements exist. No target failure has been established.
