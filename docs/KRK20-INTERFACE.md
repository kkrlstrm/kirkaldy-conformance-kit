# KRK-20 (P20) standing verifiable offline: the interface as built

This file states the names and signatures the build uses. The protocol itself is the docstring of
`conformance/properties/p20_standing_offline.py`. Where it says "the design", it means the
property's design document, X1, which is not part of this copy of the kit; this file and the
docstring are what the code does.

## Decisions that bind the build

- **KRK-20** outside code, **P20** in code. Graded side B.
- **New modules only**: `conformance/standing.py`, `conformance/issuer.py`,
  `conformance/attenuation.py` (shared with P21), `conformance/role_b.py`, the property module and
  `known_bad/standing_toys.py`. No file P16 to P19 hash changed; `versions.py` shows their
  `probe_version` and `fixture_version` unchanged. P20 imports P19's module for its run, its
  dispatcher and its progress file, unchanged.
- **One T**: P19's `withdrawal_bound()`, read once. `standing_bound()` is used only if
  smaller; a larger one is a finding. B's clock tolerance is not added to T.
- **The reference instant** is the stub's kit-clock signing log joined to the fetch and staple logs
  (`t_f`), or the commit of a key revocation (`t_k`); never a claim (KRK-M67, M68, M74).
- **Negative fixtures are genuine**: the stub signs with a key it has declared retired or
  revoked; another organisation's key signs another organisation's statement; the agent signs
  its own claim. Nothing is altered after signing.
- **`online_only`** is a fail of its own, never vulnerability class; no minimum offline
  window; the window is reported.
- **Staples are optional**; **depth and holder hops are stated by B**: a B that refuses
  them reads `depth_refused`, information.
- **Format gaps** are findings, never a pass.

## Module 1: `conformance/standing.py`

| Format | typ | Claims |
|---|---|---|
| `kirkaldy.keyset/0.1` | `krk-keyset+jws` | `issuer`, `version`, `issued_at` (ms), `ttl_s`, `expires_at`, `keys [{kid, public_key, purposes, state, since}]` |
| `kirkaldy.standing/0.1` | `krk-standing+jws` | `issuer`, `principal`, `classes {operation: limit or null}`, `issued_at` (ms), `not_after` (ms), `audience` (list or null) |

Purposes `grant`, `status`, `standing`, `request`; states `active`, `retired`, `revoked` (a
signature claimed at or after `since` is not A's). The anchor signs key statements only. A revoked
key's signature claimed before `since` may be read as A's or refused: both are conformant
(`strict_revoked`, and `also_conformant` in the KRK-20 vectors).

```python
def keyset_claims(*, issuer, version, issued_at, ttl_s, keys) -> dict
def key_entry(kid, public, purposes, state="active", since=None) -> dict
def standing_claims(*, issuer, principal, classes, issued_at, not_after, audience=None) -> dict
def keyset_problem(claims) -> str | None ;  def standing_problem(claims) -> str | None
def sign(claims, key, typ, *, raw=False) -> str       # raw: a payload the canonical form refuses
def verify(token, pinned, typ, *, problem_of=None, lenient=False) -> Verified
def key_state(keyset, kid, purpose, signed_at, *, strict_revoked=False) -> (state, why)
    # "a-key" | "retired" | "revoked" | "wrong-purpose" | "not-a-key"
def key_readings(keyset, kid, purpose, signed_at) -> tuple  # every conformant state
def standing_readings(assertion, **standing_state_kw) -> tuple  # the same for standing
def standing_state(assertion, *, kid, keyset, issuer, principal, operation, audience, at, T,
                   signed_at=None, snapshot_at=None) -> {"state", "t_f", "why"}
    # current | stale | wrong-key | wrong-org | wrong-principal | wrong-class | wrong-audience
    # | missing
def verify_holder_chain(tokens, anchors, *, lenient=False, problem_of=None) -> ([Hop], problem)
    # the root under a grant key of its organisation's statement; each other hop signed by its
    # parent's organisation the same way, or by its parent's agent_key (holder-signed)
```

Headers: `KRK-Standing` (a stapled assertion), `KRK-Keyset` (a stapled statement). Vectors:
`tests/vectors/krk20/vectors.json`, written by `make_vectors.py` with every expected answer by hand
(verify reasons, eight key-state cases, fifteen standing cases, the clock-skew case, six chains).

## Module 2: `conformance/issuer.py`

`StubIssuer(StubRequester)`: everything P18 and P19 use, unchanged, plus

```python
anchor; std_key; keyset(); keysets(); add_key(purposes, *, state, since_offset_s)
retire_key(kid) / revoke_key(kid) -> KeyChange(kid, kind, since, t_commit, version)
signing_with(kid) (context); set_standing_signer(kid); status_signing_with(kid_or_Keypair, broken)
trust_anchor_x1() -> {issuer, anchor, keyset, keyset_claims, keys, status_source, base_url, ...}
assert_standing(principal, classes, *, audience, kid, not_after, issuer_claim, signer, broken,
                publish, renew) -> Standing
relay_standing(principal, s); withhold_standing(principal); omit_from_snapshots(principal)
serve_standing_to_b(principal, s); standing_log(); current_standing(principal)
note_staple(s, t); latest_delivered(principal, before, *, valid_only=True) -> t_f
latest_snapshot_delivered(principal, before) -> t_f     # the X4-status profile
set_partition(on); baseline_get(path); read_back_x1({"key:<kid>": state, "standing:<p>": s})
peer(issuer=None) -> StubIssuer                        # A′, A2, C: own anchor, keys, source
issue_v2 / delegate_holder / delegate_v2 / delegate_wider / cycle / with_member / chain_v2
issue_v1(...)                                          # grant 0.1 fixtures P19's issue cannot build
under_v2(grant, values, *, audience, chain, loose, staple, staple_keyset, second)
under_raw(tokens, values, *, audience, subject, holder, grant_id, operation, loose)
```

Paths: `/keys`, `/standing/<principal>` (URL-encoded), beside P19's `/status/list` and
`/status/item/<gid>`; the baseline on `/__baseline/...`. A current assertion is re-signed on a
fetch that finds it older than `reissue_s` (`ttl_s/10`). `down`, `hang`, `error` apply to every
path; `partition` only to B's. Snapshots record the key that signed them and whether a fixture
broke them.

## Module 3: `conformance/role_b.py`

`RoleB` defaults for the statements P20 reads besides P19's adapter: `standing_bound()` (None),
`standing_profile()` (None = `kirkaldy`; or `x4-status`), `standing_channels()` (`["pull"]`; of
`pull`, `stapled`, `push`), `keys_from()` (`statement`; or `bind`, `adapter`), `issuers()` (1),
`bind_peer(anchor, source_url)`, `max_depth()` (None), `accepts_holder_hops()` (False), and the
optional `documents_standing()` (disclosure).

## Module 4: `conformance/properties/p20_standing_offline.py`

```python
VARIANTS = ("stale_signed", "a_unreachable", "aged_in_queue", "retired_key", "key_of_other_org",
            "other_organisation", "agent_not_principal", "deep_chain", "clock_skew",
            "restart_offline")
FORMS = {...}                       # as the design's §6.4
TRIALS = {"a_unreachable": 30, "a_unreachable/worst": 5, "*": 5, "static": 5}
DEV_TRIALS = {"a_unreachable": 5, "a_unreachable/worst": 2, "*": 1, "static": 3}
PUBLISHED_TRIALS = {"a_unreachable": 100, ...}
NA_FORBIDDEN = ("control", "stale_signed", "a_unreachable", "agent_not_principal", "retired_key")
MUST_LAND = (stale_signed/served for a pull B, stale_signed/stapled for a stapling B,
             a_unreachable/down, agent_not_principal/omitted and other_principal,
             retired_key/retired_before_bind)
def probe(a, ev, *, run_tag="", seed=None, plan=None) -> Result
```

Bind order: A (`bind_requester(trust_anchor_x1(), source_url)`), then, up to `issuers() - 1`, A′,
A2 and C (`bind_peer`). Before bind the stub adds a key retired a minute ago and one fresh key per
`revoked_key` trial, so a B that reads A's keys once at bind has seen each.

**Static trials** (the kit profile's link variants): W carries the evidence under test, served as
the principal's current assertion and stapled; L the same chain shape with valid evidence; each
presented twice on fresh requests in a seeded order. `refused` passes, `accepted` fails naming the
link. **Timed trials** use P19's dispatcher and P19's `timing` unchanged, with `t_f` or `t_k` in
place of `t_w`; only presentations sent from the fixture on are judged (KRK-M93). In the X4-status
profile the evidence is A's whole status source, so `retired_before_bind` and `key_of_other_org`
are timed from the moment the source starts serving the broken evidence, and the trial waits for
B's next fetch of a snapshot listing the principal (KRK-M94). In the kit profile, for a B whose
standing channels are pull only, static trials and `stale_signed`'s `served` and `aged_at_fetch`
wait for B's fetch of the root principals' assertions, and, through C, of the leaf principals'
assertions and C's key statement (KRK-M95; `fetched_before_present`).
`agent_not_principal/before_first_fetch` (KRK-M95b) presents W to a pull-only B at
once, before B has fetched anything for W's root principal, whose only assertion covers another
operation; W is presented twice and L not at all, and it is graded on W's effect alone (an effect
fails, any refusal passes; `presented_before_fetch`). It is not applicable to a B that is not
pull-only, and a format gap in `x4-status`. Root grants
name B as their audience. Each organisation's key statement lists its agents'
keys for purpose `request`, published as a new version when an agent's key is first used.

**What each profile expresses.** In `x4-status`: `stale_signed/stapled`, `a_unreachable/partition`,
`other_organisation/other_audience`, `agent_not_principal/other_action_class`, `self_attested`,
`undesignated_key` and `before_first_fetch` are format gaps (`X4_GAPS`); `deep_chain` and `c_standing` need holder hops.

**Departures from the design's §6.** Two refinements of fixtures, recorded in the design's §13:
`key_of_other_org`'s assertion names A as its issuer and is signed by A′'s key (so a B that
checks the claimed issuer's keys refuses it, and only one that takes any pinned key accepts it);
`c_standing` uses the three-hop chain, its leaf principal at C, with C's assertion stapled.

## Module 5: `known_bad/standing_toys.py`

`ToyStanding(config, flaw=None, *, T=60.0, clock="virtual")`, `make(flaw=None, *, x4=False)`,
`toy(config)`. `FLAWS` (22), `FAILS`, `FORM`, `PULL_ONLY_FLAWS`. Configurations: `good`,
`slow-good`, `pull-good` (standing only by fetching, on the poll, for the principals A's status
list names; KRK-M95b), `no-control`, `bad` (`no_check`), `bad:<flaw>` (`chain_before_fetch` reads
as `pull-good` does), `x4-good` and `x4-bad:<flaw>` (the X4-status profile: grant 0.1, standing
from snapshots, keys from A's statement). The known-bad gate runs `good`, `bad`, `no-control`,
`slow-good`, `pull-good`, `x4-good`, `x4-bad:pinned_once` and one `bad:<flaw>` per flaw (29).
