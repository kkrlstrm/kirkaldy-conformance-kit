# Measurement failure modes

Two hundred and two ways a probe in this kit produced, or could produce, a wrong reading. They
share one shape: **the measurement agreed with the mistake.** A blocked request that was never
sent through a real failure, a "refusal" caused by something unrelated, a timestamp that happened
to separate two actors.

Each entry is marked observed or anticipated. An observed entry produced, or would have produced,
a wrong reading while a probe was being built or run. An anticipated entry was named while a
property was being designed, and the property guards it from its first version. KRK-M1 to KRK-M17
were observed while the probes ran against real products; none raised an error, and each would
have published a false verdict. The rest belong to the properties that came later: KRK-M18 to
KRK-M26 to P16, KRK-M27 to KRK-M35 and KRK-M66 to P17, KRK-M36 to KRK-M45 to P18, KRK-M46 to
KRK-M48 and KRK-M50 to KRK-M65 to P19, KRK-M67 to KRK-M79, KRK-M93 and KRK-M94 to P20, KRK-M80 to
KRK-M92 to P21, KRK-M95 to P20 and P21, KRK-M96 to KRK-M112 and KRK-M210 to P22, KRK-M113 to KRK-M129 to P23,
KRK-M130 to KRK-M134, KRK-M139 to KRK-M143, KRK-M145 and KRK-M147 to the
B-issuer profile (P18B), KRK-M150 to KRK-M169 to P24, KRK-M170 to
KRK-M189 to P25, KRK-M190 to KRK-M209 to P26, and KRK-M148 to every property. Where an entry also
applies to other properties, the table says so. No entry names a target or describes an
unpublished product finding.

The numbers are the specification's (`KRK-Mn`, spec §5). Entries KRK-M1 to KRK-M66 are written
as the specification states them: there, `KRK-n` is the property this kit calls `Pn`, and a
section sign refers to the specification. The numbers 49 and 149 are not used. KRK-M135 to
KRK-M138, KRK-M144 and KRK-M146 are reserved for B-issuer phases not yet built (at the end).

Each mode states what happened or could happen, why nothing noticed, and the check that now
prevents it, and is pinned to a test that shows the failure and its fix. `tests/test_catalog.py`
fails the build if an entry loses its pin or cites a test that does not exist.

The general rule behind all of them is enforced in code: `Result` refuses to construct a pass or
fail whose control did not hold (`test_result.py::test_no_verdict_without_a_held_control`). The
modes below are the specific ways a control can look held when it is not, and one (KRK-M19) in
which a control could not hold for a target it should have judged.

| Mode | | Property |
|---|---|---|
| `KRK-M1` | One attempt per outage | P1 |
| `KRK-M2` | The late release | P1 |
| `KRK-M3` | The failure that was never induced | P1 |
| `KRK-M4` | No path, counted as blocked | P6 |
| `KRK-M5` | The encoded canary | P2 |
| `KRK-M6` | The probe's own leak | P8 |
| `KRK-M7` | The client's socket, charged to the server | P8 |
| `KRK-M8` | A clock read as identity | P7 |
| `KRK-M9` | A mock unlike the real thing | all |
| `KRK-M10` | Refused for the wrong reason | P4 |
| `KRK-M11` | Late, counted as lost | P3 |
| `KRK-M12` | A record read without its serializer | P7 |
| `KRK-M13` | Driven through the wrong entry point | P8 |
| `KRK-M14` | A warming pool, counted per wait | P8 |
| `KRK-M15` | A retraction in the same second as the approval | P9 |
| `KRK-M16` | The baseline's own request, read as the sandbox's | P6 |
| `KRK-M17` | A "still running" stub, read as a success | P6 |
| `KRK-M18` | The expectation, read as the effect | P16 |
| `KRK-M19` | A control that demands the guarantee | P16 |
| `KRK-M20` | The stranger sibling | P16 |
| `KRK-M21` | Passed by a format gap | P16 |
| `KRK-M22` | The model's step, read as the product's hold | P16 |
| `KRK-M23` | Landed before translation, not after | P16 |
| `KRK-M24` | The adapter's application, graded as the product | P16 |
| `KRK-M25` | The format translator as a hidden verifier | P16 |
| `KRK-M26` | A revocation that never landed, read as failing open | all |
| `KRK-M27` | The receipt read as the counterparty's log | P17 |
| `KRK-M28` | A gap read as a deletion | P17 |
| `KRK-M29` | Matched by count | P17 |
| `KRK-M30` | Reconciled before the counterparty acted | P17 |
| `KRK-M31` | A wall clock ordering two organisations | P17 |
| `KRK-M32` | A tamper that never landed | P17 |
| `KRK-M33` | The tester's mapping as the comparison basis | P17 |
| `KRK-M34` | A settlement judged without its originals | P17 |
| `KRK-M35` | The stand-in's log is not append-only | P17 |
| `KRK-M36` | The seed's own replay | P18 |
| `KRK-M37` | A fixture normalised away by the tester | P18 |
| `KRK-M38` | The transport's retry, charged to the target | P18 |
| `KRK-M39` | Serial presentations, read as a race | P18 |
| `KRK-M40` | The endpoint the recorder could not see | P18 |
| `KRK-M41` | The clock that did the refusing | P18 |
| `KRK-M42` | The binding taken from the adapter | P18 |
| `KRK-M43` | A duplicate answer read as a refusal | P18 |
| `KRK-M44` | A restart of the wrapper, not of the memory | P18 |
| `KRK-M45` | A repeat refusal read as the outcome | P18 |
| `KRK-M46` | An authorisation newer than the list, read as refused | P19 |
| `KRK-M47` | A flaw built by deleting data, read as the flaw | P19 |
| `KRK-M48` | A slow answer widens the bracket past T, read as within | P19 |
| `KRK-M50` | Withdrawn when asked, not when published | P19 |
| `KRK-M51` | Refused as a repeat, read as withdrawn | P19 |
| `KRK-M52` | Every request refused, read as the withdrawn one refused | P19 |
| `KRK-M53` | The mean read as the bound | P19 |
| `KRK-M54` | Withdrawn in a lucky phase | P19 |
| `KRK-M55` | A probe interval wider than the bound | P19 |
| `KRK-M56` | Virtual time read as propagation time | P19 |
| `KRK-M57` | The tester's cache between the receiver and the issuer | P19 |
| `KRK-M58` | One replica read as the deployment | P19 |
| `KRK-M59` | An outage that never happened | P19 |
| `KRK-M60` | Refused at the answer, executed behind it | P19 |
| `KRK-M61` | A stale snapshot that was fresh | P19 |
| `KRK-M62` | A narrowing the format could not say | P19 |
| `KRK-M63` | A re-grant in the same instant as the refusal | P19 |
| `KRK-M64` | A restart that never happened | P19 |
| `KRK-M65` | The receiver's clock charged to propagation | P19 |
| `KRK-M66` | The record settled, read as the effect settled | P17 |
| `KRK-M67` | Fresh from the fetch, read as fresh from A | P20 |
| `KRK-M68` | Evidence that reached the receiver by another path | P20 |
| `KRK-M69` | A sibling that differs in more than the evidence | P20 |
| `KRK-M70` | Another organisation's evidence, refused as unpinned | P20 |
| `KRK-M71` | A key retirement applied by the adapter | P20 |
| `KRK-M72` | Online only, read as enforcing the bound | P20 |
| `KRK-M73` | The sibling behind the same outage | P20 |
| `KRK-M74` | The evidence's own timestamp used as the reference | P20 |
| `KRK-M75` | A depth limit read as a standing check | P20 |
| `KRK-M76` | An action class the format could not say | P20 |
| `KRK-M77` | A stale fixture that was fresh at the receiver | P20 |
| `KRK-M78` | Expiry inside the bound | P20 |
| `KRK-M79` | Every hop signed by A, read as a chain across organisations | P20 |
| `KRK-M80` | Refused for its shape, read as refused for its width | P21 |
| `KRK-M81` | Caught by the leaf's own ceiling | P21 |
| `KRK-M82` | A check of the ends, passing at two hops | P21 |
| `KRK-M83` | The kit's intersection shares the target's assumptions | P21 |
| `KRK-M84` | A widening the format could not say | P21 |
| `KRK-M85` | A parse failure read as an attenuation check | P21 |
| `KRK-M86` | Amounts compared in different units by the kit | P21 |
| `KRK-M87` | A pattern the kit and the receiver read differently | P21 |
| `KRK-M88` | A time widening probed before the parent lapsed | P21 |
| `KRK-M89` | A chain the transport changed | P21 |
| `KRK-M90` | Combination done by the adapter | P21 |
| `KRK-M91` | A parent narrowing read before it landed | P21 |
| `KRK-M92` | A mapping the kit assumed, not the one declared | P21 |
| `KRK-M93` | The previous trial's outage, read as this fixture's refusal | P20 |
| `KRK-M94` | Evidence the receiver never held, read as evidence that aged | P20 |
| `KRK-M95` | Presented before the receiver could fetch, read as its answer to the evidence | P20, P21 |
| `KRK-M96` | Counted at the holder, not where the spend landed | P22 |
| `KRK-M97` | Refused for the amount, read as refused for the total | P22 |
| `KRK-M98` | A race that never overlapped | P22 |
| `KRK-M99` | The kit's stub spender as a hidden enforcer | P22 |
| `KRK-M100` | Headroom left over from another trial | P22 |
| `KRK-M101` | Headroom freed by the tester's own cleanup | P22 |
| `KRK-M102` | A window boundary read on the target's clock | P22 |
| `KRK-M103` | A boundary pair read as an overspend | P22 |
| `KRK-M104` | A reversal counted from the request, not from the spender's record | P22 |
| `KRK-M105` | Totals summed across units by the kit | P22 |
| `KRK-M106` | Committed before the reservation expired, read as after | P22 |
| `KRK-M107` | A partition with a path around it | P22 |
| `KRK-M108` | A lost report the mechanism never expected | P22 |
| `KRK-M109` | A sibling that shares the counter | P22 |
| `KRK-M110` | Refused by a rate or concurrency limit, read as the ceiling holding | P22 |
| `KRK-M111` | A child's spend charged to the child alone by the kit | P22 |
| `KRK-M112` | A ceiling spent before it was in force | P22 |
| `KRK-M113` | The reversal request, read as the reversal | P23 |
| `KRK-M114` | A residue outside the snapshot's scope | P23 |
| `KRK-M115` | A consequence that never happened | P23 |
| `KRK-M116` | The kit's own read, counted as a change | P23 |
| `KRK-M117` | Removed by something other than the reversal | P23 |
| `KRK-M118` | Compensation netted to zero, read as restored | P23 |
| `KRK-M119` | The window started at B's answer | P23 |
| `KRK-M120` | A refusal for another reason, read as a standing check | P23 |
| `KRK-M121` | Restored, then re-applied after the read | P23 |
| `KRK-M122` | A class supplied by the adapter | P23 |
| `KRK-M123` | A class change that never reached B | P23 |
| `KRK-M124` | Deferred commit, read as a failed action or as a free pass | P23 |
| `KRK-M125` | A residue declared by the kit | P23 |
| `KRK-M126` | History read from the current state | P23 |
| `KRK-M127` | Another trial's change attributed to this one | P23 |
| `KRK-M128` | The world's outage, charged to B's reversal time | P23 |
| `KRK-M129` | A consequence hidden from B, charged to B | P23 |
| `KRK-M130` | The adapter's authorisation, graded as B's | P18B (all B-issuer modules) |
| `KRK-M131` | The tester's approval, read as the person's consent | P18B (all B-issuer modules) |
| `KRK-M132` | B's restatement, read as the request | P18B |
| `KRK-M133` | A test route that decides | P18B (all B-issuer modules) |
| `KRK-M134` | A store the restart rebuilt, read as no second effect | P18B (P19B later) |
| `KRK-M139` | The driver's re-consent, read as B accepting | P18B (P19B, P20B later) |
| `KRK-M140` | B's objects verified with B's own verifier | P18B (all B-issuer modules) |
| `KRK-M141` | A superseded object that was still current | P18B |
| `KRK-M142` | The second B that shares the first's keys | P18B (P16B later) |
| `KRK-M143` | B's account of the effect, read as the effect | P18B (P16B later) |
| `KRK-M145` | A reset by the tester, read as B forgetting | P18B |
| `KRK-M147` | A resource someone else touched, read as an unaccepted effect | P18B |
| `KRK-M148` | A form the target never claimed, counted against it | every property (the runner) |
| `KRK-M150` | The tester's purpose map | P24 |
| `KRK-M151` | Caught by the limits, read as caught by the terms | P24 |
| `KRK-M152` | The kit's goal check shares the target's reading | P24 |
| `KRK-M153` | Matched by count | P24 |
| `KRK-M154` | A hidden term that was not hidden | P24 |
| `KRK-M155` | A parse refusal read as a term check | P24 |
| `KRK-M156` | The agent's claim never reached B | P24 |
| `KRK-M157` | Held forever, read as enforced | P24 |
| `KRK-M158` | Held at the answer, performed later | P24 |
| `KRK-M159` | The stranger goal | P24 |
| `KRK-M160` | A confirmation the format could not bind | P24 |
| `KRK-M161` | Free text judged by the tester | P24 |
| `KRK-M162` | A value normalised before B saw it | P24 |
| `KRK-M163` | Items identified by another key | P24 |
| `KRK-M164` | The presented action read as the effect | P24 |
| `KRK-M165` | The linked authority's own limits did the refusing | P24 |
| `KRK-M166` | The kit's seal read differently | P24 |
| `KRK-M167` | The meaning changed under the run | P24 |
| `KRK-M168` | The adapter decided the condition | P24 |
| `KRK-M169` | Refused as used, read as refused for the terms | P24 |
| `KRK-M170` | An attribution read from the wrong row | P25 |
| `KRK-M171` | The tester's own value found in B's record | P25 |
| `KRK-M172` | The resource owner read as the disclosed principal | P25 |
| `KRK-M173` | A level the format could not say, read as minimised | P25 |
| `KRK-M174` | Refused for its shape, read as refused for its disclosure | P25 |
| `KRK-M175` | An attribution form that changed the effect | P25 |
| `KRK-M176` | The attribution field named by the adapter | P25 |
| `KRK-M177` | Two counterparties that were one | P25 |
| `KRK-M178` | A direct request made through the agent's client | P25 |
| `KRK-M179` | A record read before B wrote it | P25 |
| `KRK-M180` | A delegation end that had not landed | P25 |
| `KRK-M181` | A leak found in the tester's own bytes | P25 |
| `KRK-M182` | The adapter's verification, graded as B's basis | P25 |
| `KRK-M183` | A single-use refusal read as a disclosure refusal | P25 |
| `KRK-M184` | A hash of the name read as a pseudonym | P25 |
| `KRK-M185` | A bar that refused everyone | P25 |
| `KRK-M186` | An identifier that repeated from the seed | P25 |
| `KRK-M187` | A normalised identifier read as a different principal | P25 |
| `KRK-M188` | A stored token read as an attribution | P25 |
| `KRK-M189` | The transport's identity read as the agent's | P25 |
| `KRK-M190` | The kit's mapping, not the declared one | P26 |
| `KRK-M191` | The decoder as a hidden verifier | P26 |
| `KRK-M192` | Refused for its shape, read as refused for its width | P26 |
| `KRK-M193` | The kit's image shares the target's assumptions | P26 |
| `KRK-M194` | The rate that moved | P26 |
| `KRK-M195` | Minor units from the kit's own table | P26 |
| `KRK-M196` | Faithful by luck | P26 |
| `KRK-M197` | The kit's semantics for the target's format | P26 |
| `KRK-M198` | A format gap of the target read as a format gap of the test | P26 |
| `KRK-M199` | A cache shared between presentations | P26 |
| `KRK-M200` | Effects compared in the wrong unit | P26 |
| `KRK-M201` | A translated form never used, read as an effect | P26 |
| `KRK-M202` | A receiver credited for checking what it never saw | P26 |
| `KRK-M203` | A default supplied by the kit's receiver | P26 |
| `KRK-M204` | A round trip judged in the intermediate's terms | P26 |
| `KRK-M205` | Time in two units | P26 |
| `KRK-M206` | A rate read in the wrong direction by the kit | P26 |
| `KRK-M207` | A widening below the receiver's resolution | P26 |
| `KRK-M208` | A pricing sheet cached at start | P26 |
| `KRK-M209` | A stale original read as a translation fault | P26 |
| `KRK-M210` | A seeded draw that never reached the flaw | P22 |

---

## KRK-M1 — One attempt per outage

- **Symptom.** A gateway that fails open read as failing closed.
- **Cause.** The gateway refused the first denied request after its policy store went away, while
  it detected the outage, and let every later one through. The probe sent one denied request per
  outage, so it observed one true refusal of the wrong thing.
- **Check.** Every denied request is sent several times per outage.

> `test_failure_modes.py::test_KRK_M1_one_attempt_per_outage_reads_a_delayed_fail_open_as_closed`

---

## KRK-M2 — The late release

- **Symptom.** A request read as blocked was in fact delivered.
- **Cause.** A request sent while the policy engine was paused can be held and released when the
  engine returns. By then the client has timed out and the probe has recorded "blocked". The check
  ran at the only moment it was certain to pass.
- **Check.** After every failure mode is restored, the probe waits and checks every denied request
  again at the recorder.

> `test_known_bad.py::test_p1_catches_a_request_released_after_the_outage`

---

## KRK-M3 — The failure that was never induced

- **Symptom.** A failure-safety run read as failing closed with the policy store still running.
- **Cause.** The command that was meant to stop the policy store failed, because it ran without the
  environment it needed, and its error went to a log nobody read. Every "outage" request was
  judged against a healthy engine, and behaved exactly as requests do when policy works.
- **Check.** The probe confirms the engine is unreachable through a path independent of the
  product, and refuses to judge a failure mode it could not induce.

> `test_failure_modes.py::test_KRK_M3_a_failure_that_was_never_induced_gives_no_verdict`

---

## KRK-M4 — No path, counted as blocked

- **Symptom.** Every sandbox appeared to block public DNS and HTTPS.
- **Cause.** On the development host no container could resolve public names, although image pulls
  worked. "The sandbox could not reach a public site" is what a tight sandbox and a broken host both
  produce.
- **Check.** Every attempt runs first from an unsandboxed container on the same host. An attempt
  the host itself cannot make is recorded as information, never as blocked.

> `test_known_bad.py::test_p6_does_not_call_blocked_what_the_host_cannot_reach_either`

---

## KRK-M5 — The encoded canary

- **Symptom.** A search for a credential's encoded forms could miss an encoded copy.
- **Cause.** A credential-isolation probe searches agent-visible output for encoded forms of the
  canary as well as its literal value. The probe precomputed the canary's base64 form. A shell command that encodes a variable usually
  encodes the value plus a trailing newline, and that encoding does not contain the encoding of the
  value alone. The redactor and the detector made the same assumption about what the secret would
  look like.
- **Check.** The search decodes every base64- and hex-like token it finds instead of matching
  precomputed strings.

> `test_result.py::test_canary_is_found_when_the_encoding_includes_a_trailing_newline`

---

## KRK-M6 — The probe's own leak

- **Symptom.** A durable execution engine appeared to hold open connections for every pending
  approval.
- **Cause.** The test adapter opened a new client on every status call and never closed it. The
  connections were real and were on the engine's server; they belonged to the probe.
- **Check.** Before measuring, the probe repeats its own status calls with no approvals open. If
  those calls grow the counters, the result is inconclusive. The adapter reuses one client.

> `test_known_bad.py::test_p8_refuses_to_measure_through_a_leaky_adapter`

---

## KRK-M7 — The client's socket, charged to the server

- **Symptom.** An agent runtime appeared to hold one connection per waiting approval.
- **Cause.** The client library used to start each wait kept its connection open after it was
  closed, and the server end of that socket was counted as the server's cost. The churn control
  (KRK-M6) checks status calls; these connections came from starting the waits, which is the thing
  being measured.
- **Check.** Each wait is started from a process that exits, so the operating system closes every
  client socket. Resources the server itself holds for a wait are still counted.

> `test_failure_modes.py::test_KRK_M7_a_wait_started_from_a_process_that_exits_leaves_no_client_socket`

---

## KRK-M8 — A clock read as identity

- **Symptom.** The same code passed audit attribution in one run and failed it in the previous one.
- **Cause.** The probe infers which fields identify the actor by discarding fields that differ
  between two runs by the same actor. Run grouped by actor, the human's two actions fell in one
  second and the agent's in the next, so a one-second timestamp looked stable within each actor and
  different between them. The rule was right for every field except one that only moves forward.
- **Check.** Runs are interleaved across actors. For any field that only moves forward, differing
  between human and agent then implies differing between the human's own two runs, so it is
  discarded as noise.

> `test_known_bad.py::test_p7_does_not_mistake_a_coarse_clock_for_attribution`

---

## KRK-M9 — A mock unlike the real thing

- **Symptom.** A gateway appeared to keep no audit record.
- **Cause.** The upstream mock returned the same response identifier every time. The gateway keyed
  its usage log on that identifier, so every logged request after the first collided and was
  dropped. The gateway logged the collision in its own container; the probe saw only absent rows.
- **Check.** The mock returns a fresh identifier per response, as real providers do. More generally,
  a mock must behave like the real counterpart in every respect the target depends on.

> `test_failure_modes.py::test_KRK_M9_the_mock_upstream_returns_a_new_completion_id_every_time`

---

## KRK-M10 — Refused for the wrong reason

- **Symptom.** An impostor's attempt to release an action read as refused.
- **Cause.** The credential the impostor obtained lacked a permission unrelated to approvals, and
  the request was refused for that. The attempt never reached the approval check it was testing.
  The property counts anything short of execution as refused, which is right for the property and
  wrong as evidence when the attempt did not reach the guarantee.
- **Check.** The tester states whether each attempt reached the guarantee. An attempt that did not
  is recorded as information; if none did, the result is inconclusive. The same check appears as
  the capability control in KRK-9, KRK-10, KRK-13 and KRK-14: the changed action, properly
  approved, must be able to run.

> `test_failure_modes.py::test_KRK_M10_a_refusal_for_an_unrelated_reason_is_not_evidence`

---

## KRK-M11 — Late, counted as lost

- **Symptom.** A durable execution engine appeared to lose an approval across a restart.
- **Cause.** When the engine's database restarted, its fast path for waking the waiting action was
  lost, and a slower path woke it later. It executed exactly once, after the probe's window
  had closed. "Not executed yet" and "never will execute" look the same at any single moment, and
  the window had been chosen for products that wake at once.
- **Check.** After a restart the probe waits a long window and records how long the execution took,
  so slow recovery is reported as slow rather than as loss.

> `test_failure_modes.py::test_KRK_M11_a_late_execution_after_restart_is_not_a_lost_one`

---

## KRK-M12 — A record read without its serializer

- **Symptom.** A durable execution engine appeared to write no record of any approval.
- **Cause.** The engine kept every message it delivered, in a serialized binary encoding. The
  adapter searched the stored text for the approver's name and found nothing. An absent record and
  an unreadable one produce the same empty result. This is KRK-M5 on the reading side: the detector
  assumed what the stored value looks like.
- **Check.** Each stored value is decoded through the serialization recorded beside it.

> `test_failure_modes.py::test_KRK_M12_a_stored_message_is_read_through_its_serializer`

---

## KRK-M13 — Driven through the wrong entry point

- **Symptom.** An engine's asynchronous configuration appeared to hold one thread per waiting
  approval.
- **Cause.** The test started asynchronous workflows through the engine's synchronous entry point,
  which gives each one its own thread and event loop. Started the way an asynchronous application
  starts them, from one event loop, the waits added no thread. The waits were real; only the entry
  point differed from what the configuration's name promised.
- **Check.** Each configuration is driven through the entry point an application of that kind uses.

> `test_failure_modes.py::test_KRK_M13_async_waits_started_from_one_event_loop_hold_no_thread`

---

## KRK-M14 — A warming pool, counted per wait

- **Symptom.** A fixed cost read as a cost per wait, and, in the churn control, a fixed set of
  connections read as the adapter leaking.
- **Cause.** A thread pool that starts threads on demand and keeps them grew while the waits were
  being opened, then stopped. Divided by the number of waits, a fixed cost read as a per-wait one.
  Within one batch, "grows with the waits" and "grows once" cannot be told apart. A warm-up phase
  alone would be worse: a pool that really does hold a thread per wait reuses its idle threads and
  would pass. The same shape appeared in the churn control, where a product's first status calls
  opened a fixed set of internal connections and later calls added none.
- **Check.** The probe opens two batches and judges the second; the first batch's growth is kept
  as information. The churn control warms with one round and judges a second.

> `test_failure_modes.py::test_KRK_M14_a_pool_that_warms_up_once_is_not_a_cost_per_wait`
> `test_failure_modes.py::test_KRK_M14_a_status_path_that_warms_a_pool_is_not_a_leak`

---

## KRK-M15 — A retraction in the same second as the approval

- **Symptom.** A target appeared to ignore revocation.
- **Cause.** The probe had the approver retract a fraction of a second after approving. The target
  identified a reply by a timestamp with one-second resolution, so a retraction in the same second
  read as the approval it had already recorded. The execution was real and the retraction really
  was ignored, but the reading generalised from a case that a probe produces every time and a
  person almost never does.
- **Check.** A revocation or a withdrawal of standing is applied after a settling interval longer
  than any clock resolution in the target. Same-second behaviour is reported as its own finding,
  not as the result of the revocation variant.

> `test_failure_modes.py::test_KRK_M15_a_retraction_in_the_same_second_as_the_approval_is_not_a_revocation_test`

---

## KRK-M16 — The baseline's own request, read as the sandbox's

- **Symptom.** Sandboxes read as allowing egress to the tester's listener when they did not.
- **Cause.** The adapters sent the baseline (KRK-M4) to the same listener with the same tag as the
  sandbox attempt, and asked the listener whether that tag had ever been recorded. The listener's
  records are the ground truth the property trusts over a command's output, so the host's own
  baseline request was counted as the sandbox's. The defect had been fixed once before in a single
  adapter, and came back because the property relied on each adapter to remember.
- **Check.** After the baselines and before the sandbox runs anything, the property itself asks
  whether the listener already shows each attempt; if it does, the result is inconclusive.
  Baseline and sandbox requests are tagged differently.

> `test_known_bad.py::test_p6_refuses_a_listener_the_baseline_already_hit`

---

## KRK-M17 — A "still running" stub, read as a success

- **Symptom.** A sandbox read as resolving public names on a host whose own baseline could resolve
  none.
- **Cause.** The reply the adapter read was the runtime's first acknowledgement of a long command,
  a placeholder saying the command was still running. The adapter reported success for any tool
  reply, and public attempts are judged by exit status because the tester owns no public endpoint.
  The property refused to call a failed attempt blocked when the baseline failed too (KRK-M4), but
  trusted a success unconditionally.
- **Check.** A public attempt that succeeds in the sandbox while the host's baseline failed is
  recorded as not counted, with the reason, and does not decide the result. A sandbox that reaches
  what its host cannot is not a plausible reading on one machine.

> `test_known_bad.py::test_p6_does_not_count_a_public_success_the_host_cannot_have`

---

## KRK-M18 — The expectation, read as the effect

- **Status.** Anticipated. Not observed against a product.
- **Symptom.** A target would read as completing an effect on another organisation's system, and
  then as completing it on unsigned, mismatched or missing receipts as well.
- **Cause.** The target records the expected effect with the decision, before the counterparty
  acts. A status set from that record, or an adapter that reads status from it, reads done as soon
  as the action is approved. On the control, where the counterparty executes honestly and signs a
  matching receipt, the expectation and the reported effect are the same numbers by construction,
  so a status read only after the counterparty acts cannot tell "done because the receipt matched"
  from "done because the expectation was written down". The control appears to hold, and every
  variant then reads done although no receipt contributed to any reading.
- **Check.** The probe reads the target's status once after the action is submitted and before
  the counterparty executes. If the control already reads done there, the result is inconclusive.
  A target that really records done at approval violates the property, but the probe cannot tell
  that from an adapter reading the wrong field, so it gives no verdict and keeps the early read in
  the evidence.

> `test_failure_modes.py::test_KRK_M18_a_status_set_from_the_expected_effect_gives_no_verdict`

---

## KRK-M19 — A control that demands the guarantee

- **Status.** Observed. The probe withheld a verdict rather than producing a wrong one.
- **Symptom.** The probe could not return `fail` for a target that records an effect on another
  organisation's system as done without verifying the counterparty's receipt. Such a target
  received `inconclusive`, the outcome reserved for a probe that did not reach the real path.
- **Cause.** The control required the honest case to end done at the highest evidence grade, a
  verified signed receipt from the counterparty. Verifying that receipt is the guarantee the
  property tests. A target with no receipt path completes the honest case at a lower grade, so
  its control never held, and the probe judged none of the variants. The control was meant to
  exclude a target that never completes anything; by also demanding the grade it excluded the
  target the property exists to fail. The known-bad fixtures did not show it, because every
  flawed fixture verified the honest receipt and differed only on the variants.
- **Check.** The control proves only that the real path was exercised: the counterparty's own
  store shows the full effect, the tester's judgement accepts the receipt, the target does not
  read done before the counterparty acts (KRK-M18), and the target ends done at any grade. The
  grade is recorded and judged as a check: done at any grade other than a verified signed
  receipt is a `fail` of its own. A known-bad fixture that completes on the executor's report
  alone MUST yield `fail`.

> `test_failure_modes.py::test_KRK_M19_a_target_that_completes_on_the_executors_report_fails`

---

## KRK-M20 — The stranger sibling

- **Status.** Observed while the probe was being built.
- **Symptom.** A variant meant to show that a target binds a receipt to the request in hand could
  pass a target that checks something weaker.
- **Cause.** The variant answered the target's request with the counterparty's genuine receipt for
  a sibling request: the same items and expected effect, another request identifier, and a request
  the target never made. A target that checks binding ("does this receipt name this request?")
  refuses it. So does a target that checks only membership ("does this receipt name any request I
  made?"), because a request the target never made fails both checks. The refusal was real and was
  what a binding check produces, so nothing showed that the variant could not tell the two apart.
  The known-bad fixture for this check dropped both checks together, so the fixtures could not show
  the gap either.
- **Check.** A further variant uses a request the target did make. The target submits and sends an
  earlier request, the counterparty executes it honestly, and the counterparty then answers the
  current request with the receipt it issued for the earlier one, exactly as signed. The earlier
  receipt is not delivered to the earlier request first, so a target that refuses a reused receipt
  is not credited with checking the binding. The variant counts only if the tester's judgement
  accepts the receipt for the earlier request and rejects it for the current one. Completing the
  current request on it is a `fail`. A known-bad fixture that checks membership only passes every
  other variant and fails this one. The general rule: a variant tests a check only if a target with
  a weaker check would answer it differently.

> `test_failure_modes.py::test_KRK_M20_the_stranger_sibling_passes_a_membership_check`

---

## KRK-M21 — Passed by a format gap

- **Status.** Observed in part. A gap covering a whole format was observed and caught
  by the control. A gap covering a single verdict was found while building the guard for the
  first; it is guarded and has not been observed.
- **Symptom.** A target could read as refusing a receipt it was never able to read.
- **Cause.** A target that reads a different receipt format rejects a receipt it cannot parse.
  Where none of the tester's receipts is in the target's format, the honest receipt is rejected
  too and the control gives no verdict, as it should. The tester then writes receipts in the
  target's format through a translation profile. A profile can carry only the verdicts the
  target's format has a way to express. A receipt whose verdict has no form in that format reaches
  the target unreadable, the target rejects it, and the probe reads the rejection as the target
  refusing what the counterparty said: a pass on that variant, even for a target that would
  mishandle the verdict if it could read it. The control holds, because the honest verdict has a
  form, and the rejection is real and carries an allowed label, so the variant counts.
- **Check.** The counterparty records each receipt it builds under a profile that cannot express
  its verdict, and the probe records that variant as not landed (information), naming the verdict
  and the profile. An adapter may instead declare the variant not applicable, citing the product.

> `test_failure_modes.py::test_KRK_M21_a_verdict_the_targets_format_cannot_say_is_not_a_pass`

---

## KRK-M22 — The model's step, read as the product's hold

- **Status.** Anticipated. Identified while an adapter was being written; that adapter
  avoided it, and the probe now guards it.
- **Symptom.** A target with no gate on an action could read as holding it.
- **Cause.** In some products, deterministic code verifies a receipt when one is given, and a
  model then decides whether to record the action as complete. An adapter drives the deterministic
  code, not the model. On the variants with no receipt (none at all, or only the agent's own
  report), no deterministic code runs, so the action is not done because nothing happened.
  Reported as awaiting a receipt or as blocked, that reads as the product holding the action, when
  the product has no gate there. "Not done" is the correct label for a product that holds, and the
  probe cannot see that the code which would have completed the action never ran.
- **Check.** An adapter reports that nothing was decided when no deterministic code of the product
  acted on the counterparty's answer. The probe records that as information, never as a hold, and
  the property's list of statuses that count as holding cannot include it; the reference test code
  checks this when it loads.

> `test_failure_modes.py::test_KRK_M22_nothing_decided_is_not_a_hold`

---

## KRK-M23 — Landed before translation, not after

- **Status.** Observed while the probe was being built.
- **Symptom.** A target's answer to "no receipt" was recorded as its answer to a signed refusal and
  to a signed statement that the counterparty had no record of the request.
- **Cause.** The probe checks that a fixture landed by reading the counterparty's store and the
  tester's judgement of the counterparty's receipt. The adapter translated the counterparty's
  answer into the target's format, which had no form for a refusal or a no-record, so the adapter
  gave the target no receipt at all. The fixtures had landed for the tester and not in the target,
  and the landed check never looked at what reached the target. Had the target held an action with
  no receipt for a person to decide, those readings would have been passes.
- **Check.** An adapter that translates the counterparty's answer reports, for each delivery, what
  the product received: whether there was a receipt and, if so, its verdict, how it was signed and
  which request it names, in the tester's terms. The probe compares each delivery with what the
  counterparty sent. A mismatch means the variant did not land; on the control it means no verdict.

> `test_failure_modes.py::test_KRK_M23_landed_for_the_kit_is_not_landed_in_the_target`

---

## KRK-M24 — The adapter's application, graded as the product

- **Status.** Observed while the probe was being built.
- **Symptom.** Two variants read as passes that described code the tester wrote, not the target.
- **Cause.** A target that keeps no record of whether an action is done cannot be asked whether it
  completed one, so the adapter had to supply the thinnest application on top of it: an action is
  done exactly when the target accepts a receipt. On the variants with no receipt the target is
  never called. The adapter's application ignores the executor's report and does not complete
  without a receipt, so both variants read as passes. The readings are true of the code that ran.
  Some application had to decide, and the one that decided was the adapter's.
- **Check.** Such an adapter declares not applicable, with the product's reason, the checks that
  only its own application could answer; that is information, never a pass. A check the property
  does not let it declare away, such as a missing receipt, is run and counted, and the adapter
  attaches a note, carried in the evidence and in the check's detail, saying whose reading it is.
  A note changes no outcome.

> `test_failure_modes.py::test_KRK_M24_the_adapters_application_is_not_graded_as_the_product`

---

## KRK-M25 — The format translator as a hidden verifier

- **Status.** Anticipated. The adapter that raised it was written to avoid it and is
  pinned by a test of its own; this entry is the general guard.
- **Symptom.** A target that accepts unsigned receipts could read as refusing them.
- **Cause.** An adapter that translates the counterparty's receipts into the target's format can
  carry a judgement in the translation: passing on only receipts whose signature verifies,
  re-signing one, or binding it to the request in hand rather than the one it names. The target
  then never sees the receipt the variant is about, and its answer to what it did see is read as
  its answer to the variant. The target's reading is genuine. The check that produced the refusal
  is in the adapter, which the probe does not read.
- **Check.** The comparison in KRK-M23: what reached the product is compared with what the
  counterparty sent, including how it was signed and which request it names. A dropped, re-signed
  or re-bound receipt is a mismatch, and the variant does not land.

> `test_failure_modes.py::test_KRK_M25_a_translator_that_verifies_hides_the_targets_check`

---

## KRK-M26 — A revocation that never landed, read as failing open

- **Status.** Observed, in a reading made beside the probe.
- **Symptom.** A verifier read as accepting a revoked receipt.
- **Cause.** The test harness revoked a receipt by changing the issuer's published revocation list,
  in the target's format. The call it used returned a new copy of the list with the change and left
  the published copy as it was, so nothing had been revoked. A verifier accepts an unrevoked
  receipt, which is also what a verifier that ignores revocation does. The fixture was in the
  target's format and outside the tester's own state, so no existing check covered it.
- **Check.** The harness reads the published state back in the format the target reads, and
  refuses to count the reading unless every intended change is there. This is the KRK-M3 rule
  applied to a fixture the tester does not own.

> `test_failure_modes.py::test_KRK_M26_a_revocation_that_never_landed_gives_no_reading`

---

## KRK-M27 — The receipt read as the counterparty's log

- **Status.** Anticipated. Not observed.
- **Symptom.** A target reads as reconciling its record with the counterparty's while it catches
  nothing the counterparty's statements had not already shown.
- **Cause.** The counterparty's side of the comparison is built from the statements the target
  holds, by the target or by its adapter, so the target's record is compared with its own copy of
  the counterparty's statements. When the counterparty's log contradicts a statement it signed,
  the two copies still agree. On an honest series the statements and the log say the same thing,
  so a reconciler that reads either one matches.
- **Check.** The counterparty's log is read only through a path separate from its statements, and
  the variant counts only when the log and store differ from the statement. A fixture that builds
  the counterparty's side from its statements MUST fail the variant.

> `test_failure_modes.py::test_KRK_M27_the_receipt_read_as_the_counterpartys_log_cannot_tell_good_from_bad`

---

## KRK-M28 — A gap read as a deletion

- **Status.** Anticipated. Not observed.
- **Symptom.** Removals reported that never happened, or real removals missed.
- **Cause.** A counterparty's global log number is interleaved with its other customers' entries,
  so the numbers one requester sees have gaps no one made, and a database sequence can skip a
  number when a write is rolled back. A reconciler that reads every gap as a removal reports
  removals that never happened; one that ignores gaps misses real ones. With one requester and no
  rollback, a global number and a per-requester number are the same, so the fault does not show.
- **Check.** The stand-in numbers its entries for each requester without gaps, in the same
  transaction as the entry, and records an aborted request as a void entry that keeps its number.
  The tester's reconciler reads only the per-pair number. A declared void MUST NOT read as a
  removal, and a void over an entry the requester holds a signed statement for MUST.

> `test_failure_modes.py::test_KRK_M28_a_gap_in_a_global_sequence_is_not_a_removal`

---

## KRK-M29 — Matched by count

- **Status.** Anticipated. Not observed.
- **Symptom.** A reconciler reports matched because totals agree.
- **Cause.** One request missing at the counterparty and one extra entry there with the same item
  count leave both totals equal. Every other planted difference changes a total, so a reconciler
  that compares totals finds all of them.
- **Check.** Reconciliation compares per key and per entry, never totals. The tester's reconciler
  has a self-test that plants such a compensating pair, and a copy of the reconciler that compares
  totals MUST fail it. The same holds for every weakened copy: a self-test that a weakened
  reconciler also passes says nothing about the reconciler.

> `test_failure_modes.py::test_KRK_M29_a_reconciler_that_compares_totals_reads_a_compensating_pair_as_matched`

---

## KRK-M30 — Reconciled before the counterparty acted

- **Status.** Anticipated. Not observed against a product.
- **Symptom.** Every variant reads as matched, and so does the control.
- **Cause.** The target, or its adapter, reconciles the target's own expectation or its own copy of
  the exchange against itself, so matched appears before the counterparty has done anything. This
  is KRK-M18 applied to reconciliation. On an honest series the target's copy and the
  counterparty's record agree, so a reconciliation that reads only the target's copy gives the
  right answer for the wrong reason.
- **Check.** The target's reconciliation is run once after the request is submitted and before the
  counterparty acts. An action read as matched then means the reconciliation checks give no
  verdict. The record checks are not affected.

> `test_failure_modes.py::test_KRK_M30_a_reconciler_that_matches_before_the_counterparty_acts_gives_no_verdict`

---

## KRK-M31 — A wall clock ordering two organisations

- **Status.** Anticipated. Not observed.
- **Symptom.** A clock difference reads as a reordering or a late entry, or entries are joined to
  the wrong action.
- **Cause.** A reconciler orders or joins entries across the two sides by their timestamps, and the
  two organisations' clocks differ. A difference inside the reconciler's time window still joins
  correctly, so a probe that skews the clocks by less than that never shows the fault.
- **Check.** The tester's reconciler never uses recorded times to order or join; a difference
  beyond the stated tolerance is recorded as explained, which is information. The skew variant
  draws its skew beyond the tolerance the target states before the run, so a target that joins by
  clock reports a difference there, which is a fail.

> `test_failure_modes.py::test_KRK_M31_a_reconciler_that_joins_by_clock_is_caught_only_beyond_its_tolerance`

---

## KRK-M32 — A tamper that never landed

- **Status.** Observed, in the reference test code's own adapter. Not against a product.
- **Symptom.** A change the probe asked for on the target's own side read as the target refusing
  it.
- **Cause.** The hook that writes into the target's store raised, because it could not find the
  entry it was asked to change, and the probe recorded the exception as a refusal, which is a pass.
  Nothing had been refused and nothing written. A refusal and an error both leave the record
  unchanged, so the target's export looked the same either way.
- **Check.** Only an explicit refusal from the hook, with its reason, counts as the target
  preventing the change. An error is recorded as the fixture not landing. A write the hook reports
  as made counts only when the target's export, read back through its own serializer, shows the
  change: the KRK-M3 and KRK-M26 rule, applied to a write into the target's store.

> `test_failure_modes.py::test_KRK_M32_a_tamper_that_never_landed_gives_no_reading`

---

## KRK-M33 — The tester's mapping as the comparison basis

- **Status.** Anticipated. Not observed.
- **Symptom.** An action that two organisations record in different vocabularies reads as
  matched, or as a difference, according to a mapping the target never declared.
- **Cause.** The adapter or the tester translates one side into the other's terms with a mapping of
  its own, so the comparison has a basis the agreement does not give it: the KRK-M23 and KRK-M25
  shape, applied to records. The mapping is correct, so the translated comparison matches; what it
  hides is that no mapping was declared.
- **Check.** Reconciliation uses only the mapping the agreement declares for the pair, which is
  handed to the target before the run. With none declared, an action recorded in two vocabularies
  has no basis for comparison and is never matched.

> `test_failure_modes.py::test_KRK_M33_the_testers_mapping_is_never_the_comparison_basis`

---

## KRK-M34 — A settlement judged without its originals

- **Status.** Anticipated. While the check was being built, its first version read the correct
  fixture as overwriting; the known-bad run caught it, since the correct fixture must pass.
- **Symptom.** A target that settles a difference by rewriting one of the entries reads as
  settling correctly.
- **Cause.** The probe reads the settled state, which is right, and not the entries the settlement
  was about. After an overwrite the record agrees with the settled account, so every check on the
  settled state passes.
- **Check.** The target's record is exported, raw and in the tester's terms, before and after a
  scripted person settles each difference. Every original entry and every raw row MUST still be
  there byte for byte, with a settlement entry naming the entries it settles.

> `test_failure_modes.py::test_KRK_M34_a_settlement_judged_without_its_originals_hides_an_overwrite`

---

## KRK-M35 — The stand-in's log is not append-only

- **Status.** Anticipated. The cause was present in the tester's own stand-in, which changed its
  log rows in place; it has been removed. Not observed as a wrong reading.
- **Symptom.** A change an insider at the counterparty makes to its log cannot be told from the
  counterparty's normal operation.
- **Cause.** When the counterparty's honest path changes log rows in place, a variant that changes
  a row after the requester acknowledged it looks the same as an honest run.
- **Check.** The stand-in's log and bookkeeping refuse updates and deletions. The tamper variants go
  through a separate path that lifts the refusal for one transaction, records what it changed, and
  restores it. An honest series leaves that record empty.

> `test_failure_modes.py::test_KRK_M35_a_counterparty_log_changed_in_place_looks_like_a_tamper`

---

## KRK-M36 — The seed's own replay

- **Status.** Anticipated. Not observed.
- **Symptom.** A target that remembers uses durably refuses the control on a re-run, or a replay
  variant reads as refused for the wrong reason.
- **Cause.** The identifiers in the authorisations came from the recorded seed, so a second run
  with the same seed presented identifiers the target had already seen, under requests that now
  differ. Repeating a run is what the seed is for, and against a target that forgets, every run
  looks correct.
- **Check.** Issuer identifiers, authorisation identifiers, keys and request references come from
  the operating system's random source. The seed draws only choices: counts, which member
  changes, the order of variants. The pin re-runs one seed twice against one correct target that
  keeps its use records, and the control holds both times.

> `test_failure_modes.py::test_KRK_M36_ids_drawn_from_the_seed_replay_themselves_against_durable_memory`

---

## KRK-M37 — A fixture normalised away by the tester

- **Status.** Anticipated. Not observed.
- **Symptom.** A variant about how input is canonicalised reads on bytes the target never
  received.
- **Cause.** The fixture was built as an object and serialised, or the adapter parsed and
  re-serialised it, so a duplicated member, an integer beyond exact range or a full-width
  character never reached the target: the KRK-M23 shape, before the bytes left the tester. A
  re-serialised request is still a valid request, the target answers it, and the effect has
  plausible values.
- **Check.** Fixtures are raw bytes from construction to the wire. The tester's log records the
  digest of what left it, and the adapter reports what the target recorded receiving; if either
  differs from the fixture, the variant has not landed, and on the control there is no verdict.

> `test_failure_modes.py::test_KRK_M37_a_fixture_normalised_before_it_reached_b_gives_no_reading`

---

## KRK-M38 — The transport's retry, charged to the target

- **Status.** Anticipated. Not observed.
- **Symptom.** A second effect is blamed on the target, or a deduplication credited to it.
- **Cause.** The tester's or the adapter's client retried a request on its own, added an
  idempotency header, or a proxy in the test set-up deduplicated. The target behaves correctly
  towards what it received; only a count of what left the tester shows the extra presentation.
- **Check.** The tester's transport presents each request once, never retries, and adds nothing to
  the bytes or headers. Its log counts every presentation, and the control holds only if each left
  the tester once. Adapters list every header they add.

> `test_failure_modes.py::test_KRK_M38_a_retry_by_the_testers_transport_is_never_charged_or_credited_to_b`

---

## KRK-M39 — Serial presentations, read as a race

- **Status.** Anticipated. Not observed.
- **Symptom.** A target that reads its use records, acts, then writes them passes the race.
- **Cause.** The presentations never overlapped inside the target: the adapter, a connection pool
  or the target's front end handed them over one at a time. Start times in the tester cannot show
  this, since they all start together, and one effect per round is the passing reading.
- **Check.** A round counts only if every presentation began inside the target within half of one
  uncontended presentation's duration, both measured inside the target. Otherwise the round is
  information. With no overlapping round, or no timing from inside the target, the race variant
  has not landed and the result cannot be a pass. KRK-11 applies the same rule.

> `test_failure_modes.py::test_KRK_M39_presentations_serialised_before_b_are_not_a_race`

---

## KRK-M40 — The endpoint the recorder could not see

- **Status.** Anticipated. Not observed.
- **Symptom.** A replay to a second endpoint, tenant or instance reads as refused.
- **Cause.** The second effect happened where the recorder was not connected: the recorder was
  bound only to the first endpoint's executor. No effect at the recorder is the passing reading.
- **Check.** Each such variant first runs a capability control: an authorisation addressed to the
  second endpoint or tenant runs there, and its effect reaches the recorder, before the variant
  counts.

> `test_failure_modes.py::test_KRK_M40_an_effect_where_the_recorder_is_not_connected_reads_as_refused`

---

## KRK-M41 — The clock that did the refusing

- **Status.** Anticipated. Not observed.
- **Symptom.** A refusal reads as the property working, for a reason unrelated to it; or an
  acceptance is charged to the target without its clock being considered.
- **Cause.** A replay's second presentation fell outside the validity window, or the target's
  clock runs far enough ahead that it refuses authorisations that are still valid, so the expiry
  variant reads as passed. Or its clock runs behind and it accepts an expired authorisation. A
  refusal coded as expiry, on an expiry variant, looks correct.
- **Check.** Replays are presented well inside the window, with margins wider than the stated
  tolerance. The expiry variant has a capability control on the valid side of the present by the
  same margin, and counts only if that runs. Each refusal's code is kept in the evidence.

> `test_failure_modes.py::test_KRK_M41_a_refusal_by_a_fast_clock_is_not_a_refusal_of_the_expired`

---

## KRK-M42 — The binding taken from the adapter

- **Status.** Anticipated. Not observed.
- **Symptom.** A target that binds the body of a request but takes its recipient from a header
  passes the variant for members outside the binding.
- **Cause.** The tester changed only the members the adapter declared to be outside the binding,
  and the adapter's declaration, not the target, missed the header the executor reads: the
  KRK-M25 shape, with the adapter as a hidden verifier. Nothing the tester changed reached the
  executor.
- **Check.** The tester changes every member it sends outside the authorised bytes, whatever the
  adapter declares, and reads the values the executor used at the recorder.

> `test_failure_modes.py::test_KRK_M42_members_the_adapter_did_not_declare_are_changed_too`

---

## KRK-M43 — A duplicate answer read as a refusal

- **Status.** Anticipated. Not observed.
- **Symptom.** A correct target reads as answering a repeat of an executed request with a refusal.
- **Cause.** The target answered "already performed" with a status number that the adapter mapped
  to a refusal. "Refused" and "already performed" are both answers other than success, and a
  status number is an easy thing to map.
- **Check.** The adapter maps every answer class from a product code it quotes from the product's
  documentation. An answer the adapter cannot place is an error, which is information and never a
  refusal.

> `test_failure_modes.py::test_KRK_M43_an_answer_class_read_from_a_status_number_reads_duplicate_as_refused`

---

## KRK-M44 — A restart of the wrapper, not of the memory

- **Status.** Anticipated. Not observed.
- **Symptom.** A target that keeps its use records in process memory passes the replay after a
  restart.
- **Cause.** The restart hook restarted a wrapper, a worker pool or a container, while the process
  holding the records kept running: the KRK-M3 shape. The hook returned, a fresh request ran after
  it, and the replay was answered as a duplicate.
- **Check.** The hook reports the boot or instance identifier of the process that holds the
  target's state, before and after, read through a path that does not ask the target's request
  handler. The variant counts only if the two differ and a fresh authorisation runs afterwards.

> `test_failure_modes.py::test_KRK_M44_a_restart_that_left_the_memory_running_is_not_a_restart`

---

## KRK-M45 — A repeat refusal read as the outcome

- **Status.** Observed.
- **Symptom.** A requester whose own record contradicted what the counterparty did read as handling
  the exchange correctly.
- **Cause.** The requester sent a request; the tester's transport dropped the counterparty's answer
  after the counterparty acted; and the requester's retry carried different bytes under the same
  authorisation. The counterparty refused the retry with a genuine signed refusal for those bytes,
  and the requester recorded the action as refused, while the counterparty's store held the effect
  of the first send. The probe judged the retry and stopped there: no check compared the
  requester's record of the outcome with what the counterparty did. Every statement the probe
  looked at was true. An answer to a repeat says what the counterparty did with that presentation,
  not whether the request was performed.
- **Check.** After an honest retry, the probe reads the requester's own reading of the outcome and
  compares it with what the counterparty did, counted from the rows of its store, never from its
  answers. A requester that reads not done where the effect stands, or done where there is none,
  fails. A disputed reading passes only where the counterparty's answers conflict with its store;
  an open reading, or none, is information. The control requires none of this (KRK-M19). A fixture
  that changes its bytes on a retry and records the refusal as the outcome MUST fail.

> `test_failure_modes.py::test_KRK_M45_a_refusal_of_a_repeat_read_as_the_outcome`

---

## KRK-M46 — An authorisation newer than the list, read as refused

- **Status.** Anticipated. Named when the status format came to state what an absent
  authorisation means.
- **Symptom.** A correct receiver reads as unable to accept anything, so the control does not hold
  and the run gives no verdict.
- **Cause.** A receiver that checks status from a list it fetches holds a list signed before an
  authorisation existed. The authorisation is absent from it, and the receiver refuses requests
  under it until its next fetch. The format did not say what an absent entry means, so refusing
  was a reasonable fail-safe reading, and the tester's own statement of a correct reading disagreed
  with its own correct fixture.
- **Check.** The format states the rule. An authorisation absent from a snapshot signed before the
  authorisation was issued, or in the same instant, is not yet listed: it is in force only until
  the receiver's next fetch, which the receiver must make within T. Absent from a snapshot signed
  after it was issued, it is unknown and refused. Authorisations carry their own issue time for
  this purpose. The probe presents a new authorisation again, fresh each time, for a settling
  period before it reads the authorisation as refused.

> `test_failure_modes.py::test_KRK_M46_a_grant_newer_than_the_receivers_list_is_not_read_as_refused`
> `test_status.py::test_absence_reads_by_issue_time`

---

## KRK-M47 — A flaw built by deleting data, read as the flaw

- **Status.** Observed, in the reference test code's own known-bad fixtures. The known-bad run
  caught it, and no result was published from it.
- **Symptom.** A fixture built to ignore one check started refusing everything, and still carried
  its old name.
- **Cause.** The fixture modelled "ignores the principal's standing" by handing the status reader a
  snapshot whose standing section had been removed. That was the same thing while a missing
  principal read as having standing. When the format came to read a missing principal as unknown,
  the same fixture refused every request: a receiver that fails safe on everything, not one that
  ignores standing. A flaw modelled by removing data means whatever the format says absence means,
  and that changed under it.
- **Check.** A fixture states its flaw as a reading, not as missing data. Each flawed fixture must
  fail the variant it was built to fail, not merely fail to pass, so a flaw that turns into a
  different behaviour shows up (§3.5).

> `test_failure_modes.py::test_KRK_M47_a_flaw_built_by_deleting_data_changes_with_the_format`
> `test_status.py::test_a_principal_a_listing_snapshot_leaves_out_reads_unknown`

---

## KRK-M48 — A slow answer widens the bracket past T, read as within

- **Status.** Observed. The run gave no verdict, so nothing false was published, but its per-trial
  readings would have counted as passes.
- **Symptom.** Trials read as refused within T although nothing had tested the receiver between a
  moment before T and a moment well after it.
- **Cause.** The receiver answered each request in seconds. The probe sent one presentation, waited
  for its answer, then sent the next, so its spacing was the receiver's answer time, not the
  planned interval. A trial whose last acceptance came before T, and whose next presentation went
  out well after T because the previous answer was slow, read as within, because nothing sent
  after T was accepted. A receiver that refused just after T would have read the same. The boundary
  presentations either side of T were in the schedule, but a slot whose time had passed was sent
  only when the previous answer came back.
- **Check.** Presentations are sent at their slots whether or not earlier ones have been answered,
  with a limit on how many may await an answer at once, places kept free for the presentations
  under the withdrawn authorisation, a timeout on each answer, and every skipped slot recorded. A
  trial whose bracket starts at or before T and ends after it, by more than the boundary spacing
  and the tester's own sending time, reads inconclusive, and a variant with such a trial passes
  only with as many clean trials as its plan asks for (§3.7). The same rule reads a recovery
  against its stated bound. A correct fixture that answers slowly MUST pass, and a slow fixture
  that acts late MUST fail.

> `test_failure_modes.py::test_KRK_M48_a_slow_answer_widens_the_bracket_past_T_read_as_within`
> `test_timing.py::test_a_bracket_that_crosses_t_is_inconclusive_not_within`
> `test_timing.py::test_a_variant_with_an_inconclusive_trial_passes_only_with_enough_clean_trials`
> `test_p19_withdrawal_within_t.py::test_the_dispatcher_on_the_real_clock_bounds_what_is_in_flight_and_times_out`

---

## KRK-M50 — Withdrawn when asked, not when published

- **Status.** Anticipated. Not observed.
- **Symptom.** Times to refusal come out too long, or too short, by the issuer's publishing delay.
- **Cause.** The tester takes the withdrawal's time when it asks its stand-in to withdraw, while
  the stand-in's status source serves the change later, or the tester reads the time long after
  the source served it. A quick receiver reads as slow, and the delay is charged to the wrong
  organisation.
- **Check.** The withdrawal time is the stand-in's commit of the snapshot that first shows the
  change, on the tester's clock, and a trial counts only after the published state reads back in
  the receiver's format.

> `test_failure_modes.py::test_KRK_M50_a_withdrawal_timed_when_asked_charges_the_publishing_delay_to_b`

---

## KRK-M51 — Refused as a repeat, read as withdrawn

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver with no withdrawal check reads as refusing a withdrawn authority.
- **Cause.** The tester presented the same request again after the withdrawal, and the receiver's
  single-use check (KRK-18) refused the repeat. The refusal is genuine and comes at the right time;
  it is about a different guarantee.
- **Check.** Every presentation is a fresh request with its own identifier and payload, and the
  live sibling is presented on the same schedule.

> `test_failure_modes.py::test_KRK_M51_a_repeated_request_refused_by_single_use_reads_as_withdrawn`

---

## KRK-M52 — Every request refused, read as the withdrawn one refused

- **Status.** Anticipated. Not observed.
- **Symptom.** An immediate refusal of the withdrawn authority.
- **Cause.** The receiver was refusing everything: it was down, rate-limiting, or blocking the
  agent outright.
- **Check.** Each trial interleaves fresh requests under a live sibling with the same agent and
  operation. A refused sibling makes the trial information, except where refusing it is the
  expected fail-safe (the status source unreachable, stale or rolled back); there the recovery step
  shows whether the refusal was about the withdrawal.

> `test_failure_modes.py::test_KRK_M52_a_receiver_that_refuses_everything_is_not_read_as_refusing_the_withdrawn`

---

## KRK-M53 — The mean read as the bound

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver with a long tail reads as within its bound.
- **Cause.** Most withdrawals take effect quickly, and an average over trials stays under T while
  some trials exceed it. An average is a normal way to summarise repeated timings, and it looks
  best for exactly this receiver.
- **Check.** The probe reports the maximum with its bracket, the median, the 90th and 99th
  percentiles only from 30 and 100 trials, the late and not-refused counts and the rule-of-three
  bound, and never a mean (§3.7). A fixture whose fetch intervals average under T, with a tail
  beyond it, MUST fail.

> `test_failure_modes.py::test_KRK_M53_a_long_tail_under_its_mean_is_read_from_its_worst_case`

---

## KRK-M54 — Withdrawn in a lucky phase

- **Status.** Anticipated. Not observed.
- **Symptom.** A polling receiver reads as faster than it is.
- **Cause.** Every withdrawal lands just before the receiver's next fetch, because trials start in
  step with its schedule or share one phase. Each reading is a true time to refusal; the sample is
  biased.
- **Check.** The withdrawal time is drawn uniformly across the receiver's observed fetch interval,
  presentations are jittered, and worst-phase trials withdraw just after a fetch ends.

> `test_failure_modes.py::test_KRK_M54_withdrawals_timed_just_before_each_fetch_hide_the_worst_phase`

---

## KRK-M55 — A probe interval wider than the bound

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver that still accepts just after T reads as within.
- **Cause.** The presentations were too far apart to place the refusal relative to T: nothing was
  presented between T and the refusal. A wide bracket is not an error by itself, so nothing
  flagged it.
- **Check.** Presentations are spaced at most T/20 apart, with one just before T and one just
  after, and a stated T below twice the method's floor is reported as below what it can measure.
  Since KRK-M48, a bracket that crosses T reads inconclusive.

> `test_failure_modes.py::test_KRK_M55_presentations_wider_than_the_bound_miss_an_acceptance_after_it`

---

## KRK-M56 — Virtual time read as propagation time

- **Status.** Anticipated. Not observed.
- **Symptom.** A real target reads as refusing at once, or never.
- **Cause.** The adapter advanced a clock instead of letting real time pass, so the target's real
  caches never aged while the probe's clock moved. The probe's own clock is consistent; only the
  target runs on another one.
- **Check.** Only a known-bad fixture may declare a virtual clock. A real target is driven on real
  time, and an adapter outside the fixtures that declares a virtual clock gives no verdict.

> `test_failure_modes.py::test_KRK_M56_a_real_target_on_a_virtual_clock_gives_no_verdict`

---

## KRK-M57 — The tester's cache between the receiver and the issuer

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as late.
- **Cause.** Something on the tester's side (a cache, a proxy, a stored response) served the
  receiver an old snapshot after the withdrawal. The snapshot was genuinely signed, and the cache is
  the tester's footprint, not the receiver's.
- **Check.** The stand-in's source answers every fetch from its current state, marked not to be
  stored, through no proxy, and every fetch by the receiver is logged.

> `test_failure_modes.py::test_KRK_M57_a_cache_on_the_testers_side_is_charged_to_the_receiver`

---

## KRK-M58 — One replica read as the deployment

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as within T while another of its endpoints still accepts the
  withdrawn authority.
- **Cause.** Every presentation went to one endpoint, and that endpoint was correct.
- **Check.** Presentations rotate over every endpoint the receiver declares, and a trial's refusal
  onset is the latest across them.

> `test_failure_modes.py::test_KRK_M58_presenting_at_one_replica_hides_another_that_still_accepts`

---

## KRK-M59 — An outage that never happened

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as failing safe, or failing open, during an outage of the issuer's
  status source that it never saw.
- **Cause.** The receiver reached the source another way: a kept-alive connection, a cached
  address, a second port. The tester took its source down, and the tester's own client confirmed
  it.
- **Check.** An outage lands only if the tester's own client fails to reach the source and the
  fetch log shows no successful fetch by the receiver during it; otherwise the trial has not
  landed. This is the KRK-M3 rule.

> `test_failure_modes.py::test_KRK_M59_an_outage_the_receiver_did_not_see_is_not_read_as_failing_safe`

---

## KRK-M60 — Refused at the answer, executed behind it

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as refusing in time while it performs the effect anyway.
- **Cause.** The receiver answers "refused" and executes the request, or executes after the bound
  a request it accepted before the withdrawal. Its answers are refusals, on time.
- **Check.** Acceptance is an effect at the tester's recorder, timed by its commit on the tester's
  clock. An answer is evidence of a refusal only with no effect behind it, and the in-flight
  variant holds an effect past the bound on purpose.

> `test_failure_modes.py::test_KRK_M60_a_refusal_answered_over_an_effect_reads_from_the_effect`

---

## KRK-M61 — A stale snapshot that was fresh

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as refusing a stale signed snapshot when the "stale" snapshot
  already showed the withdrawal, or was younger than the receiver's bound.
- **Cause.** The snapshot is genuinely signed and is presented as the fixture says, so nothing in
  it looks wrong.
- **Check.** A stapled or served snapshot must predate the withdrawal: its version is older than
  the one that first shows it, and reading it back does not show the change. Otherwise the trial
  has not landed.

> `test_failure_modes.py::test_KRK_M61_a_stale_snapshot_that_already_showed_the_withdrawal_is_no_fixture`

---

## KRK-M62 — A narrowing the format could not say

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as ignoring a narrowing.
- **Cause.** The status format the receiver reads has no form for a narrower ceiling, so the
  receiver received no change: the KRK-M21 and KRK-M23 shape.
- **Check.** What a status profile cannot express is recorded. In such a profile the narrowing runs
  as a withdrawal followed by a narrower reissue, and a change that does not read back in the
  receiver's profile has not landed.

> `test_failure_modes.py::test_KRK_M62_a_narrowing_a_binary_list_cannot_carry_is_not_charged_to_the_receiver`

---

## KRK-M63 — A re-grant in the same instant as the refusal

- **Status.** Observed while the probe was being built, in the probe itself, against the correct
  fixture.
- **Symptom.** The correct fixture failed the re-grant variant.
- **Cause.** The probe issues the re-grant at the first refusal after the withdrawal, and judges
  the part of the trial before the re-grant on its own. On the fixtures' virtual clock nothing
  moves during a presentation, so the refusal and the re-grant had the same time; a strict
  comparison put the refusal after the re-grant, and the part before it ended in acceptances. A
  target that orders a re-grant and a withdrawal by whole-second timestamps can make the same
  mistake.
- **Check.** A presentation at the re-grant's own instant belongs before it. A re-grant is issued a
  settling interval after the withdrawal, and status versions, not times, order the stand-in's
  snapshots.

> `test_failure_modes.py::test_KRK_M63_a_regrant_at_the_refusals_own_instant_is_judged_after_it`

---

## KRK-M64 — A restart that never happened

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as keeping its refusal across a restart.
- **Cause.** The adapter's restart returned without restarting anything, and the receiver kept
  refusing, which is what a correct receiver does.
- **Check.** A restart counts only when the hook reports a new boot or process identifier read from
  the receiver; otherwise the trial has not landed.

> `test_failure_modes.py::test_KRK_M64_a_restart_hook_that_restarted_nothing_is_not_a_restart`

---

## KRK-M65 — The receiver's clock charged to propagation

- **Status.** Anticipated. Not observed.
- **Symptom.** A receiver reads as late, or as within, by its own clock's offset.
- **Cause.** The times compared came from the receiver's timestamps rather than the tester's, and
  the receiver's timestamps look authoritative.
- **Check.** The late or within call reads only the tester's times for presentations and effects.
  The receiver's offset is estimated from its own timestamps and reported beside the reading as
  information.

> `test_failure_modes.py::test_KRK_M65_a_receivers_clock_offset_is_reported_not_charged`

---

## KRK-M66 — The record settled, read as the effect settled

- **Status.** Observed.
- **Symptom.** A target passed although it closed a disagreement about whether an effect happened
  without a person deciding the outcome.
- **Cause.** The probe had a scripted person settle every open difference with a decision that
  names no outcome ("keep both"), then checked only the record: every original entry kept byte for
  byte, and a person's settlement naming each difference's entries. The target recorded the
  settlement correctly, and also took it as the end of the dispute about the effect. An action whose
  effect the other side's log contradicted went back to completed, and an action settled as not
  executed, which a later entry from the other side contradicted, went back to open so that it
  could run again. Every check the probe made was true; it read the record and never read the
  effect after the settlement. A check outside the probe found the fault.
- **Check.** After a settlement that names no outcome, the probe reads the target's own reading of
  each effect the difference was about: it MUST be open, neither done nor not done, and the action
  not closed. A scripted person then gives an outcome in a second settlement, and the effect MUST
  read as that outcome. A target that reports no reading of the effect is information, never a
  pass. The control reads the effect only as evidence (KRK-M19). A fixture that treats an effect as
  settled once every difference about it is settled for the record MUST fail.

> `test_failure_modes.py::test_KRK_M66_the_record_settled_read_as_the_effect_settled`

---

## KRK-M67 — Fresh from the fetch, read as fresh from A

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver that measures the age of standing evidence from its own receipt reads as acting within T, because the kit took the reference instant as the time the receiver fetched the evidence.

**Why nothing would notice.** The fetch log is the kit's own record and its times are on the kit's clock, so the reading looks measured.

**The fix.** `t_f` is the stub's kit-clock signing time, joined to the fetch log by serial (`StubIssuer.latest_delivered`). The `aged_at_fetch` form serves evidence already 0.8 T old; the `age_from_fetch` toy must fail it.

> `test_failure_modes_x1x5.py::test_KRK_M67_fresh_from_the_fetch_is_not_fresh_from_A`

---

## KRK-M68 — Evidence that reached the receiver by another path

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver reads as accepting beyond T when it held newer evidence than the kit counted: a staple on another request, a notice, a second source.

**Why nothing would notice.** Each path's log looks complete on its own.

**The fix.** `t_f` is the newest signing time over every delivery path, fetch and staple (`note_staple`), and staples ride only on the request that names them.

> `test_failure_modes_x1x5.py::test_KRK_M68_evidence_that_reached_B_by_a_staple_counts`

---

## KRK-M69 — A sibling that differs in more than the evidence

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver that checks only the agent's key reads as checking standing, because W and L differed in agent, chain shape or request as well as in the evidence, and the receiver refused W for one of those.

**Why nothing would notice.** W refused and L accepted is the reading a correct receiver gives.

**The fix.** In the static variants L has the same agent shape, chain shape and request shape as W; only the evidence differs, and the evidence records each chain's signers.

> `test_failure_modes_x1x5.py::test_KRK_M69_the_sibling_differs_only_in_the_evidence`

---

## KRK-M70 — Another organisation's evidence, refused as unpinned

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver that takes standing from any pinned issuer reads as checking the organisation, because only A was pinned and A′'s evidence failed for an unpinned key (KRK-M20).

**Why nothing would notice.** The refusal is real and its code names a key, which is close to the link under test.

**The fix.** `key_of_other_org` and `other_issuer` land only with A′ pinned (`needs_second_issuer`); otherwise they read `issuer_not_supported`.

> `test_failure_modes_x1x5.py::test_KRK_M70_another_organisations_evidence_lands_only_with_it_pinned`

---

## KRK-M71 — A key retirement applied by the adapter

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver reads as honouring A's key changes because the adapter turned A's key statement into the receiver's pinned configuration during the run, so the check was the adapter's (spec §5.1 rule 11).

**Why nothing would notice.** The receiver's own code did the refusing.

**The fix.** An adapter states how the receiver learns A's keys (`keys_from`: statement, bind or adapter). A `revoked_key` reading that rests on the adapter's translation is information, `adapter_reading`.

> `test_failure_modes_x1x5.py::test_KRK_M71_a_key_change_the_adapter_applied_is_information`

---

## KRK-M72 — Online only, read as enforcing the bound

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver that refuses as soon as A is unreachable reads as a clean pass: it never accepts beyond T.

**Why nothing would notice.** Only the safety half was judged.

**The fix.** The offline window and the refusal onset are reported for every `a_unreachable` trial, and `online_only` is judged as a fail of its own, never vulnerability class.

> `test_failure_modes_x1x5.py::test_KRK_M72_online_only_is_judged`

---

## KRK-M73 — The sibling behind the same outage

**Anticipated**, while designing P20. Not observed.

**What could happen.** Every offline refusal reads as collateral, or every one as about age, because L's evidence came from A's sources and aged with W's.

**Why nothing would notice.** Both readings are consistent with the trial.

**The fix.** In the offline variants L is A2's agent, whose sources stay up; without A2 the trial is marked fail-safe and attribution comes from timing and recovery, and the evidence says which (`sibling`).

> `test_failure_modes_x1x5.py::test_KRK_M73_the_offline_sibling_sits_behind_no_outage`

---

## KRK-M74 — The evidence's own timestamp used as the reference

**Anticipated**, while designing P20. Not observed.

**What could happen.** `clock_skew` reads late or within by the offset, because the kit read `issued_at` from the claims, which the fixture offsets.

**Why nothing would notice.** The claim is signed by A and looks authoritative.

**The fix.** Every reference instant comes from the kit-clock signing log; claims are evidence, not the clock. The `trusts_issuer_time` toy must fail `issuer_ahead`.

> `test_failure_modes_x1x5.py::test_KRK_M74_the_reference_instant_is_the_signing_log_not_the_claim`

---

## KRK-M75 — A depth limit read as a standing check

**Anticipated**, while designing P20. Not observed.

**What could happen.** `root_source_down` or `root_missing` reads as passed because the receiver refuses three-hop chains, or holder-signed hops, for its own limit.

**Why nothing would notice.** A refusal is what the variant expects.

**The fix.** Deep forms run only where the receiver states it takes them, and `three_hops` with fresh evidence must be accepted first; otherwise every deep form reads `depth_refused`, information.

> `test_failure_modes_x1x5.py::test_KRK_M75_a_depth_limit_is_not_a_standing_check`

---

## KRK-M76 — An action class the format could not say

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver reads as ignoring the class, or as checking it, when its format has no member for the action class, so it received no difference (KRK-M21 and M62's shape).

**Why nothing would notice.** The fixture was built and sent.

**The fix.** Each standing profile states what it cannot carry (`X4_GAPS`); such a form does not land and is listed in `format_gaps` as a finding, never a pass.

> `test_failure_modes_x1x5.py::test_KRK_M76_an_action_class_the_format_cannot_say_is_a_gap`

---

## KRK-M77 — A stale fixture that was fresh at the receiver

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver reads as refusing stale evidence it refused for something else, or as accepting evidence that was within its bound, because the fixture was presented before its age passed T.

**Why nothing would notice.** The fixture is called stale in the code.

**The fix.** Presentations are timed from the signing log with P19's boundary slots, and a stale fixture counts only once its age passes T plus 2 ε (`stale_enough`).

> `test_failure_modes_x1x5.py::test_KRK_M77_a_stale_fixture_is_stale`

---

## KRK-M78 — Expiry inside the bound

**Anticipated**, while designing P20. Not observed.

**What could happen.** A receiver that reads `not_after` as freshness passes `stale_signed`, because the fixture's own expiry fell before `t_f + T`, so age and expiry gave the same answer (spec §5.1 rule 10).

**Why nothing would notice.** The fixture is genuinely stale.

**The fix.** Every assertion the stub signs is valid by its own `not_after` for twelve hours (`standing.LIFETIME_S`), and the static read-back checks it (`not_after_far`).

> `test_failure_modes_x1x5.py::test_KRK_M78_every_fixtures_own_expiry_is_far_beyond_T`

---

## KRK-M79 — Every hop signed by A, read as a chain across organisations

**Anticipated**, while designing P20. Not observed.

**What could happen.** `deep_chain` passes but no hop crossed into C, because the stub signed every hop with A's key, so a receiver that verifies only A's signatures passes.

**Why nothing would notice.** The chain has three hops and names C's agents.

**The fix.** The second and third hops are holder-signed (`delegate_holder`), the third by C's agent, and the evidence names each hop's signer (`chain_signers`).

> `test_failure_modes_x1x5.py::test_KRK_M79_every_hop_after_the_root_is_holder_signed`

---

## KRK-M80 — Refused for its shape, read as refused for its width

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver that refuses every three-hop or holder-signed chain reads as enforcing every dimension.

**Why nothing would notice.** It refuses the widened chain, as a correct receiver does.

**The fix.** L, of the same shape, signers and members, must be accepted; otherwise the trial is `shape_refused` (or `collateral_refusal`), information.

> `test_failure_modes_x1x5.py::test_KRK_M80_a_shape_refusal_is_not_a_width_refusal`

---

## KRK-M81 — Caught by the leaf's own ceiling

**Anticipated**, while designing P21. Not observed.

**What could happen.** A leaf-only receiver passes `wider_child` because the drawn request was outside the child as well as the parent.

**Why nothing would notice.** The request is outside the intersection, as the variant requires.

**The fix.** Every widening request is drawn inside the leaf, and the kit checks it with `attenuation.inside` against the leaf alone before presenting (`truth`).

> `test_failure_modes_x1x5.py::test_KRK_M81_the_widening_request_is_inside_the_leaf`

---

## KRK-M82 — A check of the ends, passing at two hops

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver that compares with the root and the leaf only reads as computing the intersection, because every chain had two hops and the root was the parent.

**Why nothing would notice.** Two-hop chains exercise every dimension.

**The fix.** `middle_narrow` uses three hops for each dimension it covers, and the `ends_only` toy must fail it.

> `test_failure_modes_x1x5.py::test_KRK_M82_a_check_of_the_ends_is_caught_at_three_hops`

---

## KRK-M83 — The kit's intersection shares the target's assumptions

**Anticipated**, while designing P21. Not observed.

**What could happen.** The kit and a target agree where both are wrong, because the kit's expectation came from a library the target also uses, or from a policy evaluator whose semantics are unsettled.

**Why nothing would notice.** Agreement looks like confirmation.

**The fix.** `attenuation.py` implements the design's table only, from hand-written vectors (`tests/vectors/krk21/`), and imports nothing but the standard library (spec §5.1 rule 7).

> `test_failure_modes_x1x5.py::test_KRK_M83_the_kits_intersection_imports_no_target`

---

## KRK-M84 — A widening the format could not say

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as enforcing a dimension because its format has no member for it, so the widened child reached it looking like its parent.

**Why nothing would notice.** The chain was signed and sent.

**The fix.** A form needing a dimension or feature outside the receiver's `constraint_profile` and `format_features` does not land (`gaps_for`), and is listed as a finding.

> `test_failure_modes_x1x5.py::test_KRK_M84_a_widening_the_format_cannot_say_does_not_land`

---

## KRK-M85 — A parse failure read as an attenuation check

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as catching a currency or unit widening because it refused the child for not parsing the member at all, whatever its value.

**Why nothing would notice.** The refusal is for the widened chain.

**The fix.** L carries the same members with values that do not widen; L refused is `collateral_refusal`.

> `test_failure_modes_x1x5.py::test_KRK_M85_the_sibling_carries_the_same_members`

---

## KRK-M86 — Amounts compared in different units by the kit

**Anticipated**, while designing P21. Not observed.

**What could happen.** A correct receiver reads as widening, or a flawed one as correct, because the kit drew a request amount in major units against a ceiling in minor units, or read the wrong request member.

**Why nothing would notice.** Both numbers look plausible.

**The fix.** `attenuation.amount_le` scales both amounts to the larger number of minor units and compares integers exactly; the receiver's `constraint_bindings` say which request member each dimension reads; the `ignores_units` toy must fail `units`.

> `test_failure_modes_x1x5.py::test_KRK_M86_amounts_compare_in_one_unit`

---

## KRK-M87 — A pattern the kit and the receiver read differently

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as widening, or as refusing, a resource it read under another pattern rule (glob, literal, prefix).

**Why nothing would notice.** Each reading is self-consistent.

**The fix.** The drawn resources are chosen so that literal, prefix and glob readings agree on inside and outside for every form except `prefix_broader`, whose expected outcome holds under each.

> `test_failure_modes_x1x5.py::test_KRK_M87_pattern_readings_agree_except_where_the_form_needs_them_not_to`

---

## KRK-M88 — A time widening probed before the parent lapsed

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as enforcing the parent's window because the presentation was sent before the parent's `not_after` plus the receiver's tolerance had passed.

**Why nothing would notice.** The parent's window had ended by the kit's clock.

**The fix.** `time_after` is presented after the parent's end plus the stated tolerance plus a second, and `time_before` sets the parent's start beyond the tolerance.

> `test_failure_modes_x1x5.py::test_KRK_M88_a_time_widening_is_probed_after_the_parent_lapsed_with_tolerance`

---

## KRK-M89 — A chain the transport changed

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as refusing a cycle, or a second chain, it never received, because the adapter, a proxy or a header limit truncated, reordered or deduplicated the chain.

**Why nothing would notice.** The kit built the chain correctly.

**The fix.** Each presentation's chain headers are digested as they left the kit (`chain_digest`) and recorded, for comparison with what the receiver reports it received where its adapter can say.

> `test_failure_modes_x1x5.py::test_KRK_M89_the_chain_that_left_the_kit_is_digested`

---

## KRK-M90 — Combination done by the adapter

**Anticipated**, while designing P21. Not observed.

**What could happen.** A receiver reads as refusing, or combining, two grants because the adapter picked one chain, or merged them, before the receiver saw them (spec §5.1 rule 11).

**Why nothing would notice.** The receiver's answer is its own.

**The fix.** The second chain travels in its own headers as built, and the `unions_grants` toy, which combines them, must fail `combined`.

> `test_failure_modes_x1x5.py::test_KRK_M90_both_chains_reach_B_as_built`

---

## KRK-M91 — A parent narrowing read before it landed

**Anticipated**, while designing P21. Not observed.

**What could happen.** `narrowed_parent` times too long or too short, because the reference instant was taken when the kit called `narrow`, not when the source served it.

**Why nothing would notice.** The kit knows when it narrowed.

**The fix.** P19's rule (KRK-M50): the reference is the stub's commit of the new version, confirmed by read-back in the receiver's format; without the read-back the trial reads `fixture_not_landed`.

> `test_failure_modes_x1x5.py::test_KRK_M91_a_parent_narrowing_counts_once_it_reads_back`

---

## KRK-M92 — A mapping the kit assumed, not the one declared

**Anticipated**, while designing P21. Not observed.

**What could happen.** `translated_hop` reads wrongly either way, because the kit derived the widening from a mapping other than the one the agreement declares, or from one the adapter applied.

**Why nothing would notice.** The mapping is plausible.

**The fix.** The mapping is read from the receiver's `mappings()` before the run (`mapping_from_agreement`); with none declared, `mapping_widens` is a format gap.

> `test_failure_modes_x1x5.py::test_KRK_M92_the_mapping_is_the_one_declared`

---

## KRK-M93 — The previous trial's outage, read as this fixture's refusal

**Observed**, against the kit's own `x4-good` toy while building P20.

**What happened.** In the X4-status profile the `served` form of `stale_signed` read `flapped` for the correct toy: W was refused in the first seconds, then accepted, then refused once the stale snapshot aged. The receiver still held a snapshot aged by the previous trial's outage when presentations began, and accepted once it fetched the snapshot under test.

**Why nothing noticed.** A refusal followed by an acceptance is exactly what `flapped` describes, and the toy's refusals were genuine.

**The fix.** Presentations begin only once the receiver has fetched the evidence under test (`fetched_stale` in the evidence; otherwise `fixture_not_landed`); timed trials judge only presentations sent from the fixture on (`_Trial.t_o`), while counting the effects of earlier ones.

> `test_failure_modes_x1x5.py::test_KRK_M93_the_previous_trials_outage_is_not_this_fixtures_refusal`

---

## KRK-M94 — Evidence the receiver never held, read as evidence that aged

**Observed**, against the kit's own `x4-good` toy while building P20.

**What happened.** `aged_in_queue` and `restart_offline` did not land in the X4-status profile: no valid evidence for the principal had reached the receiver before the outage. The receiver had accepted W on a snapshot signed before W's grant existed, which the X4-status format reads as not yet listed and in force until the next fetch, so it acted for the principal while holding nothing that named them.

**Why nothing noticed.** W was accepted before the fixture, as every timed trial requires.

**The fix.** For a receiver that reads status lists, the trial waits for its next fetch of a snapshot that lists the principal before the fixture (`fetched_listing_principal`). Whether P20 should grade that window is an open question.

> `test_failure_modes_x1x5.py::test_KRK_M94_evidence_B_never_held_is_not_judged`

---

## KRK-M95 — Presented before the receiver could fetch, read as its answer to the evidence

**Observed**, in development readings of the reference implementation.

**What happened.** In P20's kit profile, the static trials and `stale_signed` presented W and L within milliseconds of the stub signing the principal's first assertion. A receiver that obtains standing evidence only by fetching it, on its own poll, held nothing for the principal yet. In the static trials it refused W and L alike, which read `collateral_refusal`. In `served` it refused W, accepted it once it had fetched the assertion, and refused it again once the assertion aged, which read `flapped`. In P21's `root_exceeds_standing` the receiver held no standing limit for the principal yet and bounded W by the chain alone, which read `outside_effect`. A hop signed by C's agent had the same shape: it rests on C's key statement listing the agent's key, which the receiver had not yet fetched either.

**Why nothing noticed.** Each reading is one the outcome rules define, and the receiver's answers were genuine. The X4-status profile already waited for the receiver's fetch (KRK-M94); the kit's profile and P21's standing form were written without the wait.

**The fix.** For a receiver whose standing channels are pull only, a trial presents only once the receiver has fetched what the request rests on: W's and L's root principals' assertions (for W, A's answer that it has none counts), and for a chain through a hop C's agent signed, the leaf principals' assertions and C's key statement listing the agent. In P21, where the receiver reads standing limits, every static trial waits for its fetch for both root principals, because such a receiver learns even that A publishes no assertion only by asking (`waits_for_fetch`, `await_fetches`, recorded as `fetched_before_present`). `served` with no such fetch is `fixture_not_landed`, as in the X4-status profile; elsewhere a fetch not seen within the limit is recorded and the trial goes on. What this leaves out: a receiver that acts before its first fetch is no longer exercised by these forms, so that window is a separate question.

**KRK-M95b.** That window now has a form of its own in each property, presented to a pull-only receiver at once and graded on W's effect alone: an effect beyond what the standing A publishes allows fails, and a refusal, for any reason, is safe. P20's `agent_not_principal/before_first_fetch` presents W, whose root principal's only assertion covers another operation; P21's `root_exceeds_standing/before_first_fetch` presents W, inside the chain and above the standing limit. Each records `presented_before_fetch`; a receiver that had already fetched leaves the trial without a verdict. For a receiver that is not pull-only both read not applicable, because the other forms already present before its first fetch. Two toys pin it in each property: `pull-good` (must pass) and `bad:chain_before_fetch`, which reads standing only by fetching and acts on the chain alone before A has answered (must fail, on that form only).

Building it showed a second defect in the P21 wait: P21 measured B's fetch interval only in `narrowed_parent`, so a static trial run before that variant waited `max(2 × 0, 5 s) + 1 s` whatever B's poll, and a receiver polling less often than that was presented before its fetch. P21's control now measures the interval from B's fetches of the control principal's standing, as P20's control does, and each wait re-reads it first.

**KRK-M95c: the probe only ever presented complete chains.** Every chain P21 built ended at a root and was sent whole, so a receiver that verifies the links it is given and never requires the chain to reach a root passed every form. No fixture P21 built could have shown it.

**Why nothing noticed.** Each form changes one value in a complete chain. A receiver that checks each supplied link against its parent catches every one of them, whether or not it also requires a root, so the two readings never differed on any fixture.

**The fix.** A vulnerable variant, `incomplete_chain`, with three forms whose W must be refused: `stops_before_root` (the root is signed and withheld, so the middle grant names a parent nobody supplied), `no_ancestors` (a child presented with none of its ancestors) and `mutual_no_root` (two grants, ids chosen before signing, each naming the other, and no root). In the first two the withheld ancestor's bound excludes W's request, so the effect lies outside a parent's stated bound. The sibling is the same chain made complete and rooted. Each trial records the withheld grants (`withheld`). The correct toys (`good`, `good-strict`, `pull-good`) refuse all three; `walks_supplied_only`, which reads the last grant supplied as the root, fails each, and passes every other variant except the two cycle forms with no root.

> `test_failure_modes_x1x5.py::test_KRK_M95_a_pull_only_receiver_is_presented_after_it_could_fetch`
> `test_failure_modes_x1x5.py::test_KRK_M95_KRK_M95b_p20_presents_before_the_first_fetch_and_grades_W_alone`
> `test_failure_modes_x1x5.py::test_KRK_M95_KRK_M95b_the_flaw_is_seen_only_before_the_first_fetch`
> `test_failure_modes_x1x5.py::test_KRK_M95_KRK_M95b_p21_presents_before_the_first_fetch_and_grades_W_alone`
> `test_failure_modes_x1x5.py::test_KRK_M95_KRK_M95b_p21_measures_the_poll_before_it_waits`
> `test_failure_modes_x1x5.py::test_KRK_M95_KRK_M95c_p21_presents_chains_that_do_not_reach_a_root`

---

## KRK-M96 — Counted at the holder, not where the spend landed

**Anticipated**, while designing P22. Not observed.

**What could happen.** A holder that under-counts reads as within its ceiling. The kit took the total from the holder's own account, or from the spenders' answers.

**Why nothing would notice.** Both are the system under test reporting on itself, and a holder whose account is behind agrees with itself.

**The fix.** Totals come only from the recorder downstream of every spender (`ceiling.charges`, `ceiling.judge`). The holder's own account is read and compared, and a disagreement is information (`over_counted`, `ledger_behind`), never a verdict.

> `test_failure_modes_x9.py::test_KRK_M96_counted_where_the_spend_landed_not_at_the_holder`

---

## KRK-M97 — Refused for the amount, read as refused for the total

**Anticipated**, while designing P22. Not observed.

**What could happen.** A target that checks each request only against a per-request limit reads as keeping the total. The decisive spend was itself larger than a per-request limit, or larger than the target can perform.

**Why nothing would notice.** A refusal looks the same whatever its reason.

**The fix.** `truth` checks that every spend in W lies inside every per-request limit before anything is sent, and the sibling L runs the same amounts under twenty times the ceiling and must be accepted in full (`collateral_refusal` otherwise).

> `test_failure_modes_x9.py::test_KRK_M97_refused_for_the_amount_is_not_refused_for_the_total`

---

## KRK-M98 — A race that never overlapped

**Anticipated**, while designing P22. Not observed.

**What could happen.** A check-then-record holder reads as atomic. The presentations were serialised by the kit's dispatcher, a connection pool, a single-threaded adapter or the target's own front end, so no two checks ran together (KRK-M39's shape, across counterparties).

**Why nothing would notice.** Every round holds; nothing in the answers says the requests ran one after another.

**The fix.** A round counts only when every presentation was sent before any answer and, where the target gives its own times, they overlapped inside it (`p18_payload_bound.overlapped`), with the adapter's `max_in_flight` at least K; otherwise `no_overlap`.

> `test_failure_modes_x9.py::test_KRK_M98_a_race_that_never_overlapped_gives_no_reading`

---

## KRK-M99 — The kit's stub spender as a hidden enforcer

**Anticipated**, while designing P22. Not observed.

**What could happen.** A holder that over-issues reads as within its ceiling. A stub spender refused a presentation on its own (its own counter, a parse failure, a translation in the adapter), so the excess the holder allowed never happened.

**Why nothing would notice.** The stub is the kit's own and is trusted.

**The fix.** Stub spenders execute exactly what the holder's issuance allows as the kit's profile reads it and keep no account of the root (`ledger.StubSpender`); a stub refusal the issuance did not require is `stub_refused` and the trial gives no reading.

> `test_failure_modes_x9.py::test_KRK_M99_the_kits_stub_spender_is_no_hidden_enforcer`

---

## KRK-M100 — Headroom left over from another trial

**Anticipated**, while designing P22. Not observed.

**What could happen.** A correct target reads as refusing early, or an incorrect one as keeping the total. W's root, principal, agent or the key the target groups budgets by was reused from an earlier trial or run, so earlier spending counted.

**Why nothing would notice.** Each trial on its own looks well formed.

**The fix.** Every trial opens a fresh principal, agent and ceiling for W and for L, from the operating system (`_Trial._open_side`).

> `test_failure_modes_x9.py::test_KRK_M100_every_trial_has_a_fresh_root_principal_and_ceiling`

---

## KRK-M101 — Headroom freed by the tester's own cleanup

**Anticipated**, while designing P22. Not observed.

**What could happen.** A release or reversal variant reads as passing. The kit cancelled reservations or reversed spends at the end of a step, before the decisive spend, outside the fixture.

**Why nothing would notice.** Cleanup is ordinary code and is not logged as part of the fixture.

**The fix.** The kit cancels, claims or reverses only as a fixture step, logged as one; no other form calls them.

> `test_failure_modes_x9.py::test_KRK_M101_the_kit_frees_headroom_only_as_a_fixture_step`

---

## KRK-M102 — A window boundary read on the target's clock

**Anticipated**, while designing P22. Not observed.

**What could happen.** A target whose clock is skewed reads as keeping its window. The kit assigned charges to windows by the target's or a stub's timestamps.

**Why nothing would notice.** The timestamps are genuine and signed.

**The fix.** Charges are placed by the recorder's kit-clock time (`Charge.t_kit`); a target's times only estimate its offset, which widens the tolerance in the offset search (spec §3.7 rule 1).

> `test_failure_modes_x9.py::test_KRK_M102_charges_are_placed_by_the_recorders_clock`

---

## KRK-M103 — A boundary pair read as an overspend

**Anticipated**, while designing P22. Not observed.

**What could happen.** A correct fixed-window target fails `window/boundary`. The kit slid a window of length P over the charges, so a spend either side of a boundary added to twice the limit.

**Why nothing would notice.** The sum inside a sliding interval is a real sum.

**The fix.** The judge uses the window kind and anchor the target declares; a fixed window passes if some offset within the tolerance clears every window (`ceiling.window_feasible`).

> `test_failure_modes_x9.py::test_KRK_M103_a_boundary_pair_is_not_an_overspend`

---

## KRK-M104 — A reversal counted from the request, not from the spender's record

**Anticipated**, while designing P22. Not observed.

**What could happen.** A holder that frees headroom on the agent's word reads as correct, or a correct net-rule holder as over. The kit counted a reversal because a fixture asked for one, not because the recorder showed it.

**Why nothing would notice.** The fixture's own log says a reversal happened.

**The fix.** Reversals are recorder entries referring to the effect they reverse; a `claimed` reversal has none, so the net total is unchanged.

> `test_failure_modes_x9.py::test_KRK_M104_a_reversal_counts_only_from_the_recorder`

---

## KRK-M105 — Totals summed across units by the kit

**Anticipated**, while designing P22. Not observed.

**What could happen.** A correct target reads as over, or a flawed one as within. The kit added amounts in different `minor_units` or currencies, or compared with floating point.

**Why nothing would notice.** The numbers add up.

**The fix.** `ceiling.quantity` scales every amount exactly to 10^-18 of its currency; amounts in different currencies are never summed, and an effect the ceiling cannot count is itself outside it; the vectors cover every unit pair a fixture uses.

> `test_failure_modes_x9.py::test_KRK_M105_totals_are_never_summed_across_units_by_the_kit`

---

## KRK-M106 — Committed before the reservation expired, read as after

**Anticipated**, while designing P22. Not observed.

**What could happen.** A spender that commits in time reads as committing late, or the reverse. The held effect was released before `E + τ_B` on the target's clock, because the kit mapped `E` with a wrong offset or ignored the tolerance.

**Why nothing would notice.** The late commit is real either way.

**The fix.** The recorder holds B's effect past the reservation's expiry plus the larger of the spender's tolerance and the holder's tolerance plus capture lag, plus a margin (`_b_commit_after_expiry`); a hold that did not happen is `fixture_not_landed`.

> `test_failure_modes_x9.py::test_KRK_M106_a_commit_after_expiry_is_placed_past_the_spenders_tolerance`

---

## KRK-M107 — A partition with a path around it

**Anticipated**, while designing P22. Not observed.

**What could happen.** A spender reads as spending safely while cut off. The kit blocked one route to the holder while the spender reached it by another (a pooled connection, a second endpoint, a cached answer).

**Why nothing would notice.** The spender's refusals look like the partition's effect.

**The fix.** The stub holder's request log must show no request from that spender after the partition began; otherwise `fixture_not_landed`.

> `test_failure_modes_x9.py::test_KRK_M107_a_partition_with_a_path_around_it_does_not_land`

---

## KRK-M108 — A lost report the mechanism never expected

**Anticipated**, while designing P22. Not observed.

**What could happen.** `report_lost` or `late_capture` passes. The holder does not take captures at all, so dropping them tested nothing.

**Why nothing would notice.** A holder that ignores captures is unaffected by losing them.

**The fix.** Those forms land only for a reservation holder; elsewhere they read not applicable, with the reason.

> `test_failure_modes_x9.py::test_KRK_M108_a_lost_report_lands_only_where_the_holder_takes_captures`

---

## KRK-M109 — A sibling that shares the counter

**Anticipated**, while designing P22. Not observed.

**What could happen.** W's refusals read as collateral, or L's spending eats W's headroom. L and W were under roots the target groups together (one principal, one agent, one key).

**Why nothing would notice.** Each root is fresh.

**The fix.** L has its own principal, agent and ceiling in every trial.

> `test_failure_modes_x9.py::test_KRK_M109_the_sibling_has_its_own_principal_agent_and_ceiling`

---

## KRK-M110 — Refused by a rate or concurrency limit, read as the ceiling holding

**Anticipated**, while designing P22. Not observed.

**What could happen.** A holder that would overspend reads as atomic. Concurrent spends were refused by a rate limiter or a concurrency cap, not by the account.

**Why nothing would notice.** A refusal looks the same whatever its reason.

**The fix.** L's concurrent round under twenty times the ceiling must be accepted in full; a refused L in a round is `capacity_refused` and gives no reading.

> `test_failure_modes_x9.py::test_KRK_M110_a_rate_limit_is_not_the_ceiling_holding`

---

## KRK-M111 — A child's spend charged to the child alone by the kit

**Anticipated**, while designing P22. Not observed.

**What could happen.** A `redelegated` form reads wrongly either way. The kit's account charged an effect only to the presented grant's ceiling, or took the chain from the target's records.

**Why nothing would notice.** The child's own total is a real total.

**The fix.** Charges go to every ceiling id on the chain the kit issued and the agent presented, from the kit's issuance log (`Charge.ceiling_ids`).

> `test_failure_modes_x9.py::test_KRK_M111_a_childs_spend_is_charged_to_every_ceiling_on_its_chain`

---

## KRK-M112 — A ceiling spent before it was in force

**Anticipated**, while designing P22. Not observed.

**What could happen.** A holder or spender reads as overspending when the kit spent during its own set-up, or a target that ignores a new ceiling for its first seconds is never exercised. Spends were sent before the target could know the root or share (KRK-M95's shape).

**Why nothing would notice.** The spends are genuine and the excess is real.

**The fix.** Trials start after read-back and the stated propagation time plus 50 ms (for a share, after the share is issued); the one form that does not wait, `fresh_ceiling`, is graded on effects alone (an excess fails; a refusal is safe), so the wait does not hide the case.

> `test_failure_modes_x9.py::test_KRK_M112_a_ceiling_is_spent_only_once_in_force_and_the_fresh_form_keeps_the_case`

---

## KRK-M113 — The reversal request, read as the reversal

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B reads as reversing every action, because it records "reversed" in its own store when the request arrives, or because the adapter reads status from the request it sent.

**Why nothing would notice.** On a correct B the answer and the world agree, so a reading taken from the answer looks right; KRK-M18's shape, applied to reversals.

**The fix.** Restoration is read only from the world. Every "reversed" answer and status is kept with its kit time and compared with the world R later (`done_while_present`); the `marks_only` toy, which answers done and calls nothing, must fail.

> `test_failure_modes_x10.py::test_KRK_M113_a_reversal_answered_done_is_read_at_the_world`

---

## KRK-M114 — A residue outside the snapshot's scope

**Anticipated**, while designing P23. Not observed.

**What could happen.** A compensation that also sends a notice, or makes a new transfer, reads clean, because the diff covered only the entities tagged with the trial's values and the new effect carried no tag.

**Why nothing would notice.** Every tagged entity is restored.

**The fix.** The diff covers every entity B changed in the partition between S0 and the final read, tagged or not (`World.diff`, `_judge_at`); each change no residue declares is `new_effect_undeclared`.

> `test_world.py::test_KRK_M114_the_diff_covers_every_change_tagged_or_not`
> `test_failure_modes_x10.py::test_KRK_M114_an_untagged_notice_is_a_new_effect`

---

## KRK-M115 — A consequence that never happened

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B that declares a message reversible with no condition passes `read_before_recall`, because the reversal was sent before the world committed the read and the recall succeeded.

**Why nothing would notice.** The recall is genuine.

**The fix.** The reversal is sent only after the read is in the world and B's own view of the world shows it (`_plant`); otherwise the trial reads `fixture_not_landed`.

> `test_failure_modes_x10.py::test_KRK_M115_a_consequence_that_did_not_land_is_not_a_reading`

---

## KRK-M116 — The kit's own read, counted as a change

**Anticipated**, while designing P23. Not observed.

**What could happen.** Residues or reads appear that B did not cause, because the kit read through an interface whose reads mark a message read or write a history entry.

**Why nothing would notice.** A read is not expected to change anything.

**The fix.** The kit reads through its own interface, which changes nothing; the control takes two reads with nothing done between them and requires no difference, and gives no verdict otherwise.

> `test_world.py::test_KRK_M116_the_kits_reads_change_nothing`
> `test_failure_modes_x10.py::test_KRK_M116_a_read_that_changes_the_world_withholds_the_control`

---

## KRK-M117 — Removed by something other than the reversal

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B that does nothing reads as restoring, because the effect was removed by an expiry, by the kit's own cleanup, or by the reversal of the sibling.

**Why nothing would notice.** The effect is gone, which is what a restoration looks like.

**The fix.** The world has no expiry and the kit cleans nothing up before the final read. L is made after X by the same agent and read after every reversal; K, never reversed, is read at the end. The `reverses_latest` toy, which reverses L, must fail with `other_effect_touched`.

> `test_failure_modes_x10.py::test_KRK_M117_an_effect_removed_by_reversing_the_sibling_is_not_a_restoration`

---

## KRK-M118 — Compensation netted to zero, read as restored

**Anticipated**, while designing P23. Not observed.

**What could happen.** A refund under a `reversible` claim passes, because the comparison used the balances, which net to zero, rather than the entries.

**Why nothing would notice.** The balances are exactly those of S0.

**The fix.** Under `reversible` the ledger entries are compared: the original transfer must be voided, and a counter-transfer is a new effect. Balances alone are compared only under `compensable` (KRK-M29's rule).

> `test_failure_modes_x10.py::test_KRK_M118_a_refund_under_a_reversible_claim_is_judged_on_entries`

---

## KRK-M119 — The window started at B's answer

**Anticipated**, while designing P23. Not observed.

**What could happen.** `inside_late` and `outside` read the wrong way round for a B with a slow forward path, because the window's start was taken from B's answer or B's timestamp.

**Why nothing would notice.** B's answer comes soon after the commit on a fast B.

**The fix.** The window starts at `t_e`, the world's commit of the action, read from the world's history (`window_open`, `_reversal_trial`). A correct B that answers 3 s after the commit must still pass `inside_late` and `outside`.

> `test_failure_modes_x10.py::test_KRK_M119_the_window_starts_at_the_worlds_commit_not_at_bs_answer`

---

## KRK-M120 — A refusal for another reason, read as a standing check

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B with no standing check passes `no_standing`, because A′'s request was malformed, named the action in another format, or was refused because B does not serve A′ at all.

**Why nothing would notice.** A refusal is what the variant expects.

**The fix.** A′ first makes one genuine action of its own, which must land (`fixture_not_landed` otherwise); after the refused attempt, A's own reversal of X must restore it (`capability_not_held` otherwise, no verdict).

> `test_failure_modes_x10.py::test_KRK_M120_a_refusal_for_another_reason_is_not_a_standing_check`

---

## KRK-M121 — Restored, then re-applied after the read

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B whose retry queue re-commits the action reads as restoring, because the world was read once, at `t_x`.

**Why nothing would notice.** At `t_x` the world is restored.

**The fix.** The world is judged at `t_x + S` and at H as well; an effect that returns is `reapplied`. The `lets_held_action_land` toy must fail `overtake` that way.

> `test_failure_modes_x10.py::test_KRK_M121_a_held_action_that_lands_after_its_reversal_is_reapplied`

---

## KRK-M122 — A class supplied by the adapter

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B reads as declaring, or enforcing, classes it does not have, because the adapter mapped B's vocabulary at run time or filled in a class B never stated.

**Why nothing would notice.** The class is plausible.

**The fix.** Claims are read once, from B's statement, before the control; a claim with no quote is a finding (`claim_without_quote`), a malformed one is read as irreversible and reported, and nothing is mapped during the run.

> `test_failure_modes_x10.py::test_KRK_M122_claims_are_read_once_before_the_run_and_need_a_quote`

---

## KRK-M123 — A class change that never reached B

**Anticipated**, while designing P23. Not observed.

**What could happen.** `catalogue_changed` reads as B enforcing the new class, or as B ignoring it, because the operator's change was not yet in B's running configuration when the request arrived.

**Why nothing would notice.** The kit made the change.

**The fix.** The change is read back through B's own path (`read_claims`) before the request is presented; otherwise `fixture_not_landed` (KRK-M26, KRK-M95's shape).

> `test_failure_modes_x10.py::test_KRK_M123_a_class_change_b_never_took_is_not_a_reading`

---

## KRK-M124 — Deferred commit, read as a failed action or as a free pass

**Anticipated**, while designing P23. Not observed.

**What could happen.** A deferred B reads as never acting, or as reversing perfectly when it never commits anything, because the world was read before B's stated commit delay, or because no unreversed action was checked.

**Why nothing would notice.** A deferred effect that is reversed and one that is never committed look the same at the world.

**The fix.** Unreversed actions (K, L, the control's) are read after the stated commit delay and must land; a deferred B whose effects never land fails the control and gives no verdict.

> `test_failure_modes_x10.py::test_KRK_M124_a_deferred_b_whose_unreversed_actions_never_land_fails_the_control`

---

## KRK-M125 — A residue declared by the kit

**Anticipated**, while designing P23. Not observed.

**What could happen.** An undeclared notice or read passes, because the kit's claim reader added default residues.

**Why nothing would notice.** Every reversal leaves something, so a default residue seems reasonable.

**The fix.** Residues come only from B's statement; an empty list allows nothing (`judge`, and a vector).

> `test_failure_modes_x10.py::test_KRK_M125_an_empty_residue_list_allows_nothing`

---

## KRK-M126 — History read from the current state

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B that claims to restore history passes although the history shows the action, because the judge compared the current state only.

**Why nothing would notice.** The current state is exactly S0.

**The fix.** The `history` aspect is read from the world's history interface: every change B made to the action's entities is a trace.

> `test_failure_modes_x10.py::test_KRK_M126_history_is_read_from_the_history`

---

## KRK-M127 — Another trial's change attributed to this one

**Observed**, against the kit's own `good-deferred` toy while building P23.

**What happened.** In `downstream_consequence`, a trial that ended early (a planted consequence cannot follow a deferred effect) left K, X and L accepted at B. Their deferred commits landed 30 s later, inside the next trial, and read as that trial's new effects: the correct deferred toy failed with `new_effect_undeclared`.

**Why nothing noticed.** Every change in a trial's interval is meant to belong to it, and these were genuine changes by B.

**The fix.** Each trial starts only once every action and every reversal presented before it has had its stated time to land: a deferred action its commit delay plus the settle time, a held call its retry, a reversal the horizon H (`_Run.busy_until`). A deferred operation's planted-consequence trial is now decided before anything is presented. Pinned with the correct `slow-good` toy, whose control reversals complete after its answer and must not land in the first trial.

> `test_failure_modes_x10.py::test_KRK_M127_an_earlier_late_commit_is_not_this_trials_residue`

---

## KRK-M128 — The world's outage, charged to B's reversal time

**Anticipated**, while designing P23. Not observed.

**What could happen.** A B that recovers within its stated bound reads late, because the time to reverse was measured from the request across an outage the kit induced.

**Why nothing would notice.** The time is measured on the kit's clock, correctly.

**The fix.** In the `partition` forms with an outage, the reversal is timed from the end of the outage against B's stated recovery bound `rec`.

> `test_failure_modes_x10.py::test_KRK_M128_a_world_outage_is_not_charged_to_bs_reversal_time`

---

## KRK-M129 — A consequence hidden from B, charged to B

**Anticipated**, while designing P23. Not observed.

**What could happen.** A correct B fails `downstream_consequence`, because the planted consequence was not visible through the interface B uses, so no B could have known.

**Why nothing would notice.** The consequence is real in the world.

**The fix.** Before the reversal, the consequence is read through B's credential and B's interface to the world (`read_at`, `delivered_to`, `moved_on`); when B's view does not show it, the trial reads `fixture_not_landed`. On a real target, a consequence B's documentation does not describe is reported as a finding, not graded.

> `test_failure_modes_x10.py::test_KRK_M129_a_consequence_b_cannot_see_is_not_charged_to_b`

---

## KRK-M130 — The adapter's authorisation, graded as B's

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a receiver B that issues its own authority (a revision, a consent with its own id, a token carrying one transaction's details) reads as passing or failing an A-issued probe (P16, P18, P19, P20).

**Why nothing would notice.** An adapter had to turn the kit's authorisations into B's grants, requests and acceptances, deciding audience, window, digest, class and uses itself (KRK-M25, M42). Its translation then answered for B.

**The fix.** The runner reads the adapter's own `authority()` and refuses P16, P18, P19 and P20 for an adapter whose authority is at B, naming the B-issuer id to run; it refuses a B-issuer property for an adapter at A; and P18B refuses issuer A itself. A refusal is inconclusive and the probe is not called (`runner.authority_refusal`).

> `test_failure_modes_bissuer.py::test_KRK_M130_an_adapter_at_b_is_never_graded_by_the_a_issued_probe`

---

## KRK-M131 — The tester's approval, read as the person's consent

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a result says a person's consent was honoured.

**Why nothing would notice.** The kit played the person at B's page through a hook; B's own record says the user approved.

**The fix.** Every B-issuer summary opens with a fixed sentence (`bissuer.SUMMARY_SENTENCE`) and then names the hook kind; `extra.authority` carries it; the words "person's consent" never appear in a result (`bissuer.FORBIDDEN_WORDS`).

> `test_failure_modes_bissuer.py::test_KRK_M131_the_result_names_the_hook_and_never_a_persons_consent`

---

## KRK-M132 — B's restatement, read as the request

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a B that rewrites requests into different signed terms passes, because every effect equals its terms.

**Why nothing would notice.** The judge compared the effect with B's terms only, and the stand-in accepted whatever B signed.

**The fix.** Rule 8: B's first signed terms are compared with the kit's request (`bissuer.restatement`); the stand-in accepts only terms it asked for, a counter-proposal B labelled, or, for ambiguous input, one of the readings. A silent restatement is information and a finding (`restated_changed`). A B that restates every request gives no verdict, because nothing it signed is accepted.

> `test_failure_modes_bissuer.py::test_KRK_M132_a_silent_restatement_is_not_accepted`

---

## KRK-M133 — A test route that decides

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: b's consent path reads as working when the hook made the decision.

**Why nothing would notice.** A route that issues the credential, or marks the consent approved, by itself, bypassing B's page.

**The fix.** The hook's kind must be one of three (`bissuer.HOOKS`) and the one the agreement declares; once per run the same hook declines a fresh identity's consent and the kit records whether B still issued a credential (`decline_check`: `consent_not_enforced`, information here, graded in P20B). The decline check is never part of a control.

> `test_failure_modes_bissuer.py::test_KRK_M133_the_hook_kinds_and_the_decline_check`

---

## KRK-M134 — A store the restart rebuilt, read as no second effect

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a replay after a restart reads `ran_once` for a B that executed it twice.

**Why nothing would notice.** B's store resets to start-up data on restart, erasing the first effect, and the count was read after the restart only.

**The fix.** A pair counts every effect any of its store reads has shown, by B's operation id, so the read just before the kill and the reads after it are added (`PairB.seen`). The agreement states whether B's store survives a restart (`store_survives_restart`).

> `test_failure_modes_bissuer.py::test_KRK_M134_a_store_the_restart_rebuilt_does_not_hide_the_first_effect`

---

## KRK-M139 — The driver's re-consent, read as B accepting

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: presentations read as B accepting an object under a consent the pair no longer had, or a variant reads a state the probe did not set up.

**Why nothing would notice.** The stand-in refreshed its credential or re-ran consent on its own.

**The fix.** One consent per identity per pair, each a step the probe asks for; every decision the hook makes goes into its own log, and a pair whose hook log holds a decision the probe did not ask for reads `fixture_not_landed` (the control: not held).

> `test_failure_modes_bissuer.py::test_KRK_M139_a_driver_that_consents_on_its_own_voids_the_reading`

---

## KRK-M140 — B's objects verified with B's own verifier

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a fault in B's signing is not seen.

**Why nothing would notice.** The kit used the target's verifier library, or its keys as the target serves them to its own clients.

**The fix.** `bissuer.verify_b_object` is the kit's own JOSE code on `cryptography` (EdDSA, ES256; `alg: none` and every other algorithm refused), checked against RFC 8037's vector; B's keys come from `published_keys()`, the kit's baseline path; the kit reads the signed members itself, through the member names the agreement states, and an object the stand-in read differently does not count. An object that does not verify is never accepted.

> `test_failure_modes_bissuer.py::test_KRK_M140_b_objects_are_verified_by_the_kit_against_published_keys`

---

## KRK-M141 — A superseded object that was still current

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: `body_changed` reads `refused` for a B that never issued r+1, or `ran_changed` for a correct B whose revision r was still current.

**Why nothing would notice.** The kit's counter-proposal did not land: B opened a new proposal, or answered with r again, so r was never superseded.

**The fix.** The landed check reads B's own later signed object naming r in its `supersedes` member, verified by the kit (`BObjectLog.superseded`), before r is judged; otherwise `fixture_not_landed`.

> `test_failure_modes_bissuer.py::test_KRK_M141_a_supersession_is_read_from_bs_own_signed_object`

---

## KRK-M142 — The second B that shares the first's keys

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: `replay_other_counterparty` does not test what it says.

**Why nothing would notice.** The second instance of the product was started with the first's key, so its objects are the first's in all but name.

**The fix.** The RFC 7638 thumbprints of the two instances' published keys must differ, and the second instance's object must verify under its own keys and not under the target's; otherwise `fixture_not_landed`.

> `test_failure_modes_bissuer.py::test_KRK_M142_the_second_instance_must_not_share_the_targets_keys`

---

## KRK-M143 — B's account of the effect, read as the effect

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a count taken from B's proof package or its "executed" answer.

**Why nothing would notice.** B's own statement that it executed was used as the effect.

**The fix.** Effects come from B's store, read through B's read path (`store`); B's answers and proofs are recorded and never counted. The `no-control` toy answers "executed" with a proof and writes nothing, and must give no verdict; at the `B-answer` grade every variant that counts effects is `not_driven`.

> `test_failure_modes_bissuer.py::test_KRK_M143_bs_account_of_an_effect_is_never_counted`

---

## KRK-M145 — A reset by the tester, read as B forgetting

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: a replay after a reset reads as a second effect.

**Why nothing would notice.** The adapter called a reset aid B offers for testing, between pairs.

**The fix.** The adapter reports every reset it made (`resets()`); a run during which one was made is inconclusive, and the resets are in `extra.resets`.

> `test_failure_modes_bissuer.py::test_KRK_M145_a_reset_by_the_tester_reads_inconclusive`

---

## KRK-M147 — A resource someone else touched, read as an unaccepted effect

**Anticipated**, in the B-issuer profile's design, and pinned while P18B
was built. No B-issuer target has been run, so none was observed.

**What happened.** Nothing yet. The reading it would produce: `effect_without_acceptance` on a correct B.

**Why nothing would notice.** The target's own background activity (a scheduled job, say) changed a test resource, or the change predates the run.

**The fix.** The agreement declares the test resources and any background writers before the run; the resource history is read before the first pair as a baseline; changes in the baseline and by declared writers are not counted. An undeclared writer still fails, because the kit cannot tell its change from an unaccepted effect.

> `test_failure_modes_bissuer.py::test_KRK_M147_background_writers_and_the_baseline_are_declared`

---

## KRK-M148 — A form the target never claimed, counted against it

**Observed**, in a development run of an outside target.

**What happened.** The target's test plan records, for every form, the target's own claim, and marks some forms `not_claimed`: the target's documents say nothing that the form tests. The probe has no claim-basis input, so its status and its disclosure class counted those forms too. The plan's claimed-only reading had to be made by hand beside the probe's own result.

**Why nothing would notice.** Every reading is genuine: the target did what the probe saw. A fail on a form the target never claimed looks the same as a fail on one it did, and a headline built from the probe's status would have charged the target with a guarantee it never offered (spec §3.4).

**The fix.** An adapter may state `not_claimed()` (form → reason) and `claim_basis()` (form → quote, location, source). The runner, outside every probe's closure, judges each result on claimed forms only (`conformance/claim_basis.py`): a reading on an unclaimed form is kept with `ok: null` and `ok_as_read`, each check is re-read from its claimed forms, the verdict, the summary and the matrix count claimed forms only, and the disclosure class is never raised. Every result of a stated target carries `claim_basis` and lists `claim_rule_version` in its renewal condition, and relies on a known-bad record made with that rule: every property's known-bad run now applies the rule to its own toys' results (`claims:` cases). An adapter that states neither is run exactly as before. No probe or fixture version moved.

> `test_claim_basis.py::test_KRK_M148_a_toy_that_fails_only_on_unclaimed_forms_reads_pass`
> `test_claim_basis.py::test_KRK_M148_a_toy_that_fails_on_a_claimed_form_still_fails`

---

## KRK-M150 — The tester's purpose map

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B reads as failing, or passing, `purpose` forms against a meaning it never stated.

**Why nothing would notice.** The kit derived "research does not cover delete" from a draft's example or from the code's name, and the reading looks like B's.

**The fix.** Purpose forms land only with B's own `purpose_map()`, quoted with its location. With none they read `format_gap` and the gap is a finding; `terms.purpose_covers` returns False for a map that is not given. A B that declares `purpose` and states no map reads inconclusive.

> `test_failure_modes_x2.py::test_KRK_M150_purpose_forms_land_only_with_bs_own_map`

---

## KRK-M151 — Caught by the limits, read as caught by the terms

**Anticipated**, while designing P24. Not observed.

**What could happen.** A limits-only B passes a term form.

**Why nothing would notice.** The drawn W action was also outside a limit (an amount above `max_amount`, an operation outside `operations`), so the limit check refused it and the refusal looked like a term check.

**The fix.** `truth` confirms, before anything is sent, that every W action is inside every limit of every grant presented (`attenuation.inside`, the linked authorisation included) and outside a term; a fixture that is not raises, and the result is inconclusive.

> `test_failure_modes_x2.py::test_KRK_M151_a_w_action_outside_a_limit_is_refused_as_a_fixture`

---

## KRK-M152 — The kit's goal check shares the target's reading

**Anticipated**, while designing P24. Not observed.

**What could happen.** The kit and a target agree that a partial cart is inside, or that an empty acceptable list admits any item.

**Why nothing would notice.** The kit's evaluator was written from a target's code, or shares its subset-only check, so both read the same wrong way and the target passes.

**The fix.** `conformance/terms.py` is written from the design's table, imports only `attenuation` and `receipts`, and is checked against hand-written vectors (`tests/vectors/krk24/`) that include `partial` and `empty_slot`. The exact fill is an integer max flow, never a target's helper.

> `test_failure_modes_x2.py::test_KRK_M152_the_kits_goal_check_shares_no_target_reading`

---

## KRK-M153 — Matched by count

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B that compares total quantities reads as checking composition.

**Why nothing would notice.** Every `goal_items` form changed the total as well as the composition, so a count check refused each of them by luck.

**The fix.** `not_acceptable` keeps every slot's count and the total equal to the goal's and changes only which item fills which slot; the `count_only` toy must fail it.

> `test_failure_modes_x2.py::test_KRK_M153_not_acceptable_keeps_the_counts_so_a_count_check_fails_it`

---

## KRK-M154 — A hidden term that was not hidden

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as refusing an action outside a withheld term.

**Why nothing would notice.** The disclosure reached B anyway: the presentation builder included every disclosure, or the adapter re-attached them from the mandate. B then read the term and refused, which is a different property.

**The fix.** Before presenting, the probe reads the disclosures W carries (`landed_disclosures`); a W that carries the hidden term's disclosure reads `not_landed`.

> `test_failure_modes_x2.py::test_KRK_M154_a_hidden_term_whose_disclosure_reached_b_is_not_landed`

---

## KRK-M155 — A parse refusal read as a term check

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as enforcing slots, fixed values or purposes.

**Why nothing would notice.** B refused the mandate because it cannot parse the terms at all, whatever their values.

**The fix.** L carries the same members, of the same shape, with values that admit the action. L refused is `collateral_refusal` and the trial gives no reading.

> `test_failure_modes_x2.py::test_KRK_M155_a_parse_refusal_is_not_read_as_a_term_check`

---

## KRK-M156 — The agent's claim never reached B

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as ignoring the agent's purpose or goal header.

**Why nothing would notice.** The transport, a proxy or the adapter dropped `KRK-Purpose` or `KRK-Goal`, so B never saw the claim it is said to ignore.

**The fix.** The probe digests every P24 header and the request bytes as they left the kit (`mandator.headers_digest`) and, where the adapter reports what B received (`received`), compares the two; a difference reads `not_landed`. A W whose spec names a header the presentation lacks is `not_landed` too.

> `test_failure_modes_x2.py::test_KRK_M156_the_agents_claim_that_never_reached_b_is_not_landed`

---

## KRK-M157 — Held forever, read as enforced

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B that never completes any conditioned action reads as requiring the confirmation.

**Why nothing would notice.** No trial showed that a confirmed action completes, so holding everything looked like enforcing the condition.

**The fix.** The control presents a conditioned action with the principal's genuine confirmation and requires one effect. If it does not complete, every `condition` form reads `shape_refused`, and a B that declares `confirm` and cannot land its core forms gives no verdict (`hold_forever`).

> `test_failure_modes_x2.py::test_KRK_M157_held_forever_is_not_read_as_enforced`

---

## KRK-M158 — Held at the answer, performed later

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads `pending` and passes while the effect lands after the trial ends.

**Why nothing would notice.** The trial was classified at B's answer.

**The fix.** After a trial in which any answer was pending, the recorder is watched for S (B's stated hold resolution, else 10 s); a W effect inside S is `outside_effect`, whatever B answered. The `late_executor` toy, which performs 2 s after answering `queued`, must fail `condition`. A B that answers *refused* and performs later would still be missed after 2 s, so in a published run every `condition` and `hidden_terms` trial is watched for S whatever B answered (a probe change, spec §3.10); a toy that answers refused and performs 5 s later fails `condition` in a published run and passes it, wrongly, in a development run.

> `test_failure_modes_x2.py::test_KRK_M158_held_at_the_answer_and_performed_later_fails`
> `test_failure_modes_x2.py::test_KRK_M158_refused_at_the_answer_and_performed_before_S_fails_when_published`

---

## KRK-M159 — The stranger goal

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B that checks only that a payment authority names some goal it knows reads as checking the link.

**Why nothing would notice.** `cross_goal`'s other goal was one B had never seen, so a membership check refused it.

**The fix.** G1, the goal the payment authority serves, is completed at B earlier in the same trial, so the authority names a goal B knows; only a check against the action's own goal refuses.

> `test_failure_modes_x2.py::test_KRK_M159_the_other_goal_is_one_b_knows`

---

## KRK-M160 — A confirmation the format could not bind

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as refusing `confirmed_sibling`.

**Why nothing would notice.** B's format carries a confirmation with no action digest, so the sibling's confirmation and this action's are the same bytes, and the refusal was of something else.

**The fix.** The adapter states `confirmation_binds_action()`; where it is false, `confirmed_sibling` is a format gap, never a pass.

> `test_failure_modes_x2.py::test_KRK_M160_a_confirmation_that_cannot_bind_an_action_is_a_format_gap`

---

## KRK-M161 — Free text judged by the tester

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B reads as failing or passing because the tester decided what free text means.

**Why nothing would notice.** A text form was graded on the text's meaning.

**The fix.** Only `text_wider` is graded, and only through the structured terms, which exclude the action; `text_narrower` is information (`text_applied` or `text_ignored`) and never counted.

> `test_failure_modes_x2.py::test_KRK_M161_free_text_is_never_judged_by_the_tester`

---

## KRK-M162 — A value normalised before B saw it

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as comparing fixed values or purpose codes exactly.

**Why nothing would notice.** The kit's JSON encoder, the transport or the adapter normalised the lookalike value (case, Unicode composition) before it reached B.

**The fix.** Presentations are sent as raw bytes (the encoder never normalises), and where the adapter reports what B received, its digest must equal the kit's; a difference reads `not_landed`.

> `test_failure_modes_x2.py::test_KRK_M162_a_value_normalised_before_b_saw_it_is_not_landed`

---

## KRK-M163 — Items identified by another key

**Anticipated**, while designing P24. Not observed.

**What could happen.** A correct B reads as substituting items, or a flawed one as correct.

**Why nothing would notice.** The kit matched items by `id` while B matches by another member.

**The fix.** `item_key()` is declared before the run and every action is drawn under it. A B that reads another key than it declares fails the control, which carries a slot keyed as declared: no verdict, never a false one.

> `test_failure_modes_x2.py::test_KRK_M163_items_are_identified_by_bs_declared_key`

---

## KRK-M164 — The presented action read as the effect

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as clamping, or as performing W, when it did the other.

**Why nothing would notice.** The reading came from the presented action or B's answer, not from what the recorder received.

**The fix.** A W effect is judged on the recorder's body with `terms.meets`; `clamped` is credited only at the `recorder` and `b-signed` grades. Below them an accepted W is `outside_effect`.

> `test_failure_modes_x2.py::test_KRK_M164_a_clamp_is_credited_only_where_the_effect_is_seen`

---

## KRK-M165 — The linked authority's own limits did the refusing

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B that checks each authority on its own reads as checking the goal link.

**Why nothing would notice.** G2's action exceeded the payment authority's amount or payee limits, so its own limits refused it.

**The fix.** `truth` confirms G2's action is inside every limit of the payment authority it is presented with and of G2's mandate; it fails only the goal link.

> `test_failure_modes_x2.py::test_KRK_M165_ws_action_is_inside_the_linked_authoritys_limits`

---

## KRK-M166 — The kit's seal read differently

**Anticipated**, while designing P24. Not observed.

**What could happen.** B reads as refusing a disclosed term, or accepting a hidden one.

**Why nothing would notice.** The kit's seal digest used a different canonical form, salt encoding or path syntax from what the format states.

**The fix.** The kit's seal is checked against digests computed outside the kit (`openssl`, in the vectors) and against a second, test-only implementation written from the design; the control discloses every sealed term, and the correct toy reads every disclosed term.

> `test_failure_modes_x2.py::test_KRK_M166_the_kits_seal_matches_a_second_implementation`

---

## KRK-M167 — The meaning changed under the run

**Anticipated**, while designing P24. Not observed.

**What could happen.** `purpose` readings differ within a run.

**Why nothing would notice.** B reloaded its configuration or its purpose map between the statement and the trials.

**The fix.** B's term profile and purpose map are read again after the run and compared by digest (`statements_digest`); a change makes the result inconclusive, and the digest is recorded with the statements.

> `test_failure_modes_x2.py::test_KRK_M167_a_meaning_changed_under_the_run_gives_no_verdict`

---

## KRK-M168 — The adapter decided the condition

**Anticipated**, while designing P24. Not observed.

**What could happen.** A library-level B reads as refusing, or holding, a conditioned action.

**Why nothing would notice.** The thinnest receiver turned a PENDING into a refusal, or completed on PERMIT where the library said PENDING.

**The fix.** The adapter records the library's verdict as given; at the `library-decision` grade an in-progress answer reads mode `pending`, its own reading, and the result says it is a library-level reading.

> `test_failure_modes_x2.py::test_KRK_M168_a_pending_verdict_at_library_level_reads_pending`

---

## KRK-M169 — Refused as used, read as refused for the terms

**Anticipated**, while designing P24. Not observed.

**What could happen.** A B that treats a mandate as single use reads as refusing W.

**Why nothing would notice.** W-in was presented first under W's mandate and used it up, so W was refused as a repeat.

**The fix.** W is always presented before W-in under the same mandate (the trial's `order`); where the adapter can say a refusal was a repeat (`is_repeat_refusal`), that W reads `not_landed`.

> `test_failure_modes_x2.py::test_KRK_M169_w_is_presented_before_w_in`

---

## KRK-M170 — An attribution read from the wrong row

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as recording P1 for a1's effect, because the kit matched B's record to the effect by time or by order and read a neighbouring row.

**Why nothing would notice.** The neighbouring row is a genuine record of a genuine effect, and it names a principal the kit drew.

**The fix.** Records are read only by B's operation id, taken from B's own answer to that request (`operation_of`; KRK-M134's rule). An answer that names no operation id leaves the kit no row to read: the control does not hold (`_control`).

> `test_failure_modes_x6.py::test_KRK_M170_a_record_is_read_by_bs_operation_id_only`

---

## KRK-M171 — The tester's own value found in B's record

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as recording a principal because the identifier was in the request body and B stored the body verbatim in a free-text field.

**Why nothing would notice.** The identifier is in B's record, where the kit searches.

**The fix.** A drawn principal identifier never appears in a request body or path; a presentation that would carry one is not sent (`_Run.send`). A field holding request content (the request's own drawn ref, recipient or note), and everything decoded inside it, is echo (`disclosure.echo_paths`); a hit only there reads `echoed`, never attribution. The asserted principal of `asserted_principal/body_member` is found only in echo when B stores the body.

> `test_failure_modes_x6.py::test_KRK_M171_request_content_echoed_back_is_not_attribution`

---

## KRK-M172 — The resource owner read as the disclosed principal

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as recording P1 from the disclosure, because the request touched P1's own account and B recorded the account's owner.

**Why nothing would notice.** The owner is P1 whatever was disclosed.

**The fix.** In `a-issued` every resource the kit names is neutral: a recipient drawn from the operating system at a neutral domain (`_Run.values`). A B that records the account touched therefore records nobody the kit drew, and a request whose values would name the principal is not presented (the KRK-M171 guard).

> `test_failure_modes_x6.py::test_KRK_M172_the_resource_owner_is_not_the_disclosed_principal`

---

## KRK-M173 — A level the format could not say, read as minimised

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as keeping a `pairwise` or `organisation` level because its format has no member for the principal at that level, so nothing could be recorded (the KRK-M21 shape).

**Why nothing would notice.** An empty record is what minimisation looks like.

**The fix.** Levels are read from `levels()` before the run, each with a quote. A level no operation's agreement sets reads `format_gap`, with `ok` null; it is never a pass of clause (b) or (d).

> `test_failure_modes_x6.py::test_KRK_M173_a_level_the_format_cannot_carry_is_a_format_gap`

---

## KRK-M174 — Refused for its shape, read as refused for its disclosure

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as refusing a foreign, self-asserted or missing disclosure because it refuses every request of that shape, or every agent request for the operation.

**Why nothing would notice.** W was refused, which is what the form asks for.

**The fix.** L, the sibling with a valid disclosure of the same shape, and D, the person's own request where B has a direct path, must be accepted. Otherwise the trial reads `collateral_refusal` (information; KRK-M10, M80).

> `test_failure_modes_x6.py::test_KRK_M174_a_refusal_of_the_shape_is_not_a_refusal_of_the_disclosure`

---

## KRK-M175 — An attribution form that changed the effect

**Anticipated**, while designing P25. Not observed.

**What could happen.** `asserted_principal` reads as a fail or a pass of P25, because B's executor read the asserted member and the effect went somewhere else, which is P18's question.

**Why nothing would notice.** B's record and the effect are both genuine.

**The fix.** W's effect at the recorder must equal L's in every member but the request's own `ref` (`_Run.same_effect`). Otherwise the form reads `not_landed` here and is reported for P18.

> `test_failure_modes_x6.py::test_KRK_M175_a_member_that_changes_the_effect_is_x3s`

---

## KRK-M176 — The attribution field named by the adapter

**Anticipated**, while designing P25. Not observed.

**What could happen.** `actor_shown` passes because the adapter pointed at a field that happens to differ between runs (the KRK-7 rule; the KRK-M33 shape).

**Why nothing would notice.** The field does differ between the agent's rows and the person's.

**The fix.** The adapter returns B's raw record and store rows; it never names a field. The kit searches by value (`disclosure.find`) and infers the fields that tell actors apart from interleaved runs (`disclosure.infer_fields`). The probe never reads a field name from the adapter.

> `test_failure_modes_x6.py::test_KRK_M176_the_adapter_never_names_the_attribution_field`

---

## KRK-M177 — Two counterparties that were one

**Anticipated**, while designing P25. Not observed.

**What could happen.** `pseudonym_linkable` passes or fails wrongly because the two tenants shared keys or a pseudonym scope, or were two endpoints of one company.

**Why nothing would notice.** Two tenant names were used.

**The fix.** Each counterparty's signing keys are told apart by RFC 7638 thumbprint (`bissuer.thumbprints`, KRK-M142); tenants that share a key read `not_landed`. B's statement of its pseudonym scope names the unit it is per (`pseudonyms()`).

> `test_failure_modes_x6.py::test_KRK_M177_two_counterparties_with_one_key_are_not_two`

---

## KRK-M178 — A direct request made through the agent's client

**Anticipated**, while designing P25. Not observed.

**What could happen.** `actor_shown/person_direct` reads B as unable to tell the actors apart because D was sent with an agent's credential, so both rows show an agent.

**Why nothing would notice.** D was sent, and B recorded it.

**The fix.** D uses the person's own credential through the path `direct_path()` names; a direct request whose authorisation is signed by any agent key the kit's organisations list, or that carries a disclosure, is not sent (`_AIssued.direct`). The control includes D, so it does not hold.

> `test_failure_modes_x6.py::test_KRK_M178_a_direct_request_with_an_agent_credential_is_not_sent`

---

## KRK-M179 — A record read before B wrote it

**Anticipated**, while designing P25. Not observed.

**What could happen.** `unattributed`, because B writes attribution asynchronously and the kit read too early.

**Why nothing would notice.** The read path answered; it said nothing about the operation yet.

**The fix.** The kit waits until B's read path shows the operation, up to `READ_WAIT_S` (`_Run.record`). A record still absent at the limit reads `record_late`, information, not `unattributed` (KRK-M95's shape).

> `test_failure_modes_x6.py::test_KRK_M179_a_record_written_late_is_waited_for`

---

## KRK-M180 — A delegation end that had not landed

**Anticipated**, while designing P25. Its millisecond case was observed while building P25, against the kit's own correct toy.

**What could happen.** `outlives_delegation` passes because the end had not reached B when the record was re-read, so a B that resolves the principal through the live delegation still resolved it.

**Why nothing would notice.** The re-read names the principal.

**The fix.** The end is confirmed through B's own path before the re-read: a fresh request by the agent must be refused and leave no effect (KRK-M26). Otherwise the trial reads `not_landed`. In `a-issued` the confirming request is made only once A's clock is past the end the key statement states, which it gives to the millisecond: a request inside that millisecond is signed before the end, and B is right to accept it (found while building, against the correct toy).

> `test_failure_modes_x6.py::test_KRK_M180_an_end_b_never_learned_of_is_not_a_reading`

---

## KRK-M181 — A leak found in the tester's own bytes

**Anticipated**, while designing P25. Not observed.

**What could happen.** `level_exceeded` reads a fail because the search ran over the kit's wire log, or a proxy log that held what the kit sent.

**Why nothing would notice.** The principal is in those bytes: A's disclosure names them.

**The fix.** Only B-originated bytes are searched: B's answers as received (`_Run.answer_flat`), B's records and B's store rows. The kit's outgoing bytes are never searched (KRK-M6, M16).

> `test_failure_modes_x6.py::test_KRK_M181_the_kits_own_bytes_are_never_searched`

---

## KRK-M182 — The adapter's verification, graded as B's basis

**Anticipated**, while designing P25. Not observed.

**What could happen.** B reads as recording an agent-asserted disclosure at the right basis because the adapter verified or dropped the disclosure before B saw it (spec §5.1 rule 11; KRK-M25).

**Why nothing would notice.** B recorded nothing stronger than the evidence, because it saw no evidence.

**The fix.** The adapter passes the disclosure as received. Where it reports what B received (`received(pid)`), a difference from the kit's wire log makes the presentation `not_landed`. The basis is read from B's record only.

> `test_failure_modes_x6.py::test_KRK_M182_a_disclosure_the_adapter_dropped_is_not_bs_basis`

---

## KRK-M183 — A single-use refusal read as a disclosure refusal

**Anticipated**, while designing P25. Not observed.

**What could happen.** `foreign_disclosure` reads a pass because W reused R1's authorisation, so P18's single use refused it.

**Why nothing would notice.** W was refused.

**The fix.** W carries its own fresh authorisation; only the disclosure is foreign. In `a-issued` an authorisation already presented in the run is never presented again (`_Run.send`; KRK-M51).

> `test_failure_modes_x6.py::test_KRK_M183_a_reused_authorisation_is_not_presented`

---

## KRK-M184 — A hash of the name read as a pseudonym

**Anticipated**, while designing P25. Not observed.

**What could happen.** `named_in_pairwise` or `pseudonym_linkable` passes because B recorded a deterministic hash of the named identifier, which is the same for every counterparty and can be recomputed.

**Why nothing would notice.** The value is not the named identifier.

**The fix.** The kit searches for its own SHA-256 of each named identifier and reports a hit (`plain_hash`); where B claims per-counterparty pseudonyms, a value equal across counterparties fails whatever its form (the composition draft: "A plain deterministic hash of a principal identifier is not sufficient for concealment").

> `test_failure_modes_x6.py::test_KRK_M184_a_hash_of_the_name_is_not_a_pseudonym`

---

## KRK-M185 — A bar that refused everyone

**Anticipated**, while designing P25. Not observed.

**What could happen.** `missing_disclosure/agent_barred` reads a pass because B refused every request for the operation, the person's included.

**Why nothing would notice.** The agent's request was refused.

**The fix.** D, the person's own request, must be accepted; otherwise `collateral_refusal` (KRK-M52). Without a direct path the form reads `no_sibling`.

> `test_failure_modes_x6.py::test_KRK_M185_a_bar_that_refuses_everyone_is_not_a_bar`

---

## KRK-M186 — An identifier that repeated from the seed

**Anticipated**, while designing P25. Not observed.

**What could happen.** Attribution forms read wrongly across runs because principals and agents drawn from the recorded seed matched identities B remembered from an earlier run.

**Why nothing would notice.** Each run is internally consistent.

**The fix.** Identifiers that must be fresh (principals, agents, keys, refs, pairwise secrets and salts) come from the operating system (`StubDiscloser.principal`; spec §3.9, KRK-M36).

> `test_failure_modes_x6.py::test_KRK_M186_identifiers_are_fresh_whatever_the_seed`

---

## KRK-M187 — A normalised identifier read as a different principal

**Anticipated**, while designing P25. Not observed.

**What could happen.** `misattributed` or `unattributed`, because B case-folded or trimmed the principal's identifier.

**Why nothing would notice.** The exact identifier is not in B's record.

**The fix.** Identifiers are compared exactly unless B declared a normalisation before the run (`normalisation()`); then under it. The kit draws mixed-case principals, so folding shows. An undeclared normalisation that still identifies the principal reads `undeclared_normalisation`, information.

> `test_failure_modes_x6.py::test_KRK_M187_an_undeclared_normalisation_is_information`

---

## KRK-M188 — A stored token read as an attribution

**Anticipated**, while designing P25. Not observed.

**What could happen.** `principal_shown` passes because B kept the raw disclosure on the row, which contains P1, and records no attribution of its own.

**Why nothing would notice.** The principal is on the row, inside the token.

**The fix.** `disclosure.flatten` decodes a stored compact JWS under `#jws`; a hit only inside a token reads `stored_token`, information (`disclosure.in_token`). Clause (b) needs B's own field or statement.

> `test_failure_modes_x6.py::test_KRK_M188_a_stored_token_is_not_an_attribution`

---

## KRK-M189 — The transport's identity read as the agent's

**Anticipated**, while designing P25. Not observed.

**What could happen.** `actor_shown` passes because B recorded the endpoint, source address or client certificate each request came in on, which differs between D and the agents only because they were sent differently.

**Why nothing would notice.** The field is stable within each actor and differs between them, as the inference asks.

**The fix.** A field whose value on each row is one of that row's transport values (the endpoint and tenants the kit used) is excluded from inference (`disclosure.transport_paths`; the KRK-M7 shape).

> `test_failure_modes_x6.py::test_KRK_M189_a_field_that_tracks_the_transport_is_not_identity`

---

## KRK-M190 — The kit's mapping, not the declared one

**Anticipated**, while designing P26. Not observed.

**What could happen.** A target reads as faithful or as widening according to a mapping it never declared.

**Why nothing would notice.** The kit, or the adapter, derived the image from a profile of its own (the KRK-M33 and KRK-M92 shape). Every reading would then be consistent with itself and wrong about the target.

**The fix.** P26 reads the profile from the target's side (`translation_profile()`), checks its shape, pins it by digest before the control and records the digest and its owner. With no declared profile the probe gives no verdict; `translation.py` never supplies, completes or corrects one, and an undeclared pair, value or unit is refused.

> `test_failure_modes_x11.py::test_KRK_M190_the_profile_is_the_targets_never_the_kits`

---

## KRK-M191 — The decoder as a hidden verifier

**Anticipated**, while designing P26. Not observed.

**What could happen.** A translator reads as narrowing.

**Why nothing would notice.** The adapter's decoder dropped a member of the translated form it could not decode, so the kit's faithful receiver R′ enacted a narrower form than the target issued (the KRK-M25 shape).

**The fix.** The raw bytes of every translated form are kept. The decoder returns every member it could read and names every one it could not (`unreadable`). R′ commits nothing under a form with an unreadable member, and the trial reads `unreadable_translation`, information, never `held`.

> `test_failure_modes_x11.py::test_KRK_M191_a_member_the_decoder_cannot_read_is_never_read_as_narrowing`

---

## KRK-M192 — Refused for its shape, read as refused for its width

**Anticipated**, while designing P26. Not observed.

**What could happen.** A translator that refuses every original with a currency, or every original with a window, reads as converting safely.

**Why nothing would notice.** Without a sibling of the same shape, a refusal of everything looks like a refusal of the wider thing.

**The fix.** Every trial presents L, the sibling whose value under test the faithful and the weak readings agree on, and L must be accepted. A trial whose L was refused reads `collateral_refusal` and is not counted; a must-land form with no counted trial makes the result inconclusive.

> `test_failure_modes_x11.py::test_KRK_M192_a_translator_that_refuses_the_shape_is_not_credited_with_converting`

---

## KRK-M193 — The kit's image shares the target's assumptions

**Anticipated**, while designing P26. Not observed.

**What could happen.** The kit and a target agree where both are wrong.

**Why nothing would notice.** The image came from a library the target also uses (a payment SDK, an ODRL evaluator, a currency table).

**The fix.** `conformance/translation.py` implements the design's §2.3 from hand-written vectors (`tests/vectors/krk26/vectors.json`), in exact rational arithmetic, and imports only the standard library: nothing from the kit, no target library and no float. A source-format writer that uses a target's SDK may only write bytes.

> `test_failure_modes_x11.py::test_KRK_M193_the_kits_image_is_its_own`

---

## KRK-M194 — The rate that moved

**Anticipated**, while designing P26. Not observed.

**What could happen.** A rounding or currency form reads wrongly either way.

**Why nothing would notice.** The target used a different rate, or a different profile version, from the one the kit computed with.

**The fix.** The profile is read again at the end of the run and its digest compared with the one pinned before the control; a change gives no verdict. Version 1 has no served rate: a target whose rate source is not the static profile reads `not_landed` on its currency and rounding forms (KRK-M208).

> `test_failure_modes_x11.py::test_KRK_M194_a_profile_that_moves_during_the_run_gives_no_verdict`

---

## KRK-M195 — Minor units from the kit's own table

**Anticipated**, while designing P26. Not observed.

**What could happen.** A correct translator reads as widening a currency with disputed or changed minor units.

**Why nothing would notice.** The kit used an ISO 4217 table the target does not share.

**The fix.** `translation.py` has no currency table. Minor units come from the original and from the profile's pair, and an amount whose minor units differ from the pair's source is refused as incomparable, never rescaled. Drawn currencies are the profile's own.

> `test_failure_modes_x11.py::test_KRK_M195_minor_units_come_from_the_profile_never_a_table`

---

## KRK-M196 — Faithful by luck

**Anticipated**, while designing P26. Not observed.

**What could happen.** A face-value or assumed-unit translator passes.

**Why nothing would notice.** A rate near 1, a currency with two minor units, or an excess smaller than the coarser format's unit, so the weak reading and the correct one gave the same answer.

**The fix.** Each form draws only from declared pairs that separate its weak check: a rate at or below 4/5 for `face_value` and `rate_inverted`, a source with more than two minor units for `minor_units`, more than six decimals for `token_decimals`, a residue of at least one half for `max_up`, a double-precision trap for `float_rate`. With no such pair the form reads `not_applicable` with that reason. `face_value` and `minor_units` must land; when no declared pair separates them, their `not_applicable` reading with the probe's reason counts as present, for every target (before, the result read inconclusive). In R and TR every W request drawn from the predicted weak reading is checked to lie outside the original before it is presented (`draw_failed` otherwise).

> `test_failure_modes_x11.py::test_KRK_M196_a_draw_that_cannot_separate_the_weak_check_does_not_run`

---

## KRK-M197 — The kit's semantics for the target's format

**Anticipated**, while designing P26. Not observed.

**What could happen.** In topology T, R′ enacts a translated form more or less widely than the target's own receivers would.

**Why nothing would notice.** R′ read a member by the kit's idea of it.

**The fix.** Every member R′ reads needs a documented semantics (`enforced`, `informational` or `ignorable_extension`) quoted from the target (`translated_profile()`); a statement without one gives no verdict. A member of an issued form with no stated semantics is a gap: R′ commits nothing under that form.

> `test_failure_modes_x11.py::test_KRK_M197_a_member_without_documented_semantics_is_a_gap`

---

## KRK-M198 — A format gap of the target read as a format gap of the test

**Anticipated**, while designing P26. Not observed.

**What could happen.** A translator that drops a constraint reads as `not_landed`.

**Why nothing would notice.** The probe treated the target format's missing member as the kit's inability to express the fixture (the KRK-M21 reflex).

**The fix.** In `dropped_constraint` the original is in the kit's own format and always lands; the request breaks the constraint the target cannot carry, and an effect is `outside_effect` in that dimension. The dimensions the target's format cannot carry are listed in the result's headline.

> `test_failure_modes_x11.py::test_KRK_M198_a_dropped_constraint_is_the_reading_not_a_format_gap_of_the_test`

---

## KRK-M199 — A cache shared between presentations

**Observed**, while building P26.

**What happened.** L reads W's translation, or the reverse; or a caching translator passes `cached_image`.

**Why nothing would notice.** The trial reused a subject, session or client across presentations, or presented them in an order that let one fill the cache another reads.

**The fix.** W and L have fresh subjects; W-in uses W's own original and translated form. In `cached_image` the wider original O1 is presented first in every trial, before W, L and W-in in whatever seeded order. **Observed while building P26, against the kit's own toy:** O1 was presented inside W, so when the seeded order put W-in first, W-in filled the subject's cache with O2's narrow image and `cache_by_subject` passed under seed 99. The fix is the order above; the pin runs that seed.

> `test_failure_modes_x11.py::test_KRK_M199_presentations_never_share_a_cache_except_in_cached_image`

---

## KRK-M200 — Effects compared in the wrong unit

**Anticipated**, while designing P26. Not observed.

**What could happen.** An effect reads as inside or outside by a factor.

**Why nothing would notice.** The recorder held the effect in target units and the comparison used the original's.

**The fix.** The recorder stores currency, minor units and count unit with each effect, and every effect is judged with `translation.effect_outside` against the original in its own terms through a declared pair. The same number in another currency, or in the same currency without a declared pair, is never read as inside.

> `test_failure_modes_x11.py::test_KRK_M200_effects_are_compared_in_the_originals_own_terms`

---

## KRK-M201 — A translated form never used, read as an effect

**Anticipated**, while designing P26. Not observed.

**What could happen.** A T reading is reported as end to end.

**Why nothing would notice.** The receiver was the kit's R′, not a receiver the target deploys.

**The fix.** Topology T is graded at `translated-signed`, and the grade is part of the summary, which says the forms were enacted by the kit's faithful receiver and not end to end.

> `test_failure_modes_x11.py::test_KRK_M201_a_translator_alone_is_never_reported_end_to_end`

---

## KRK-M202 — A receiver credited for checking what it never saw

**Anticipated**, while designing P26. Not observed.

**What could happen.** A receiver that holds only the translated form reads as enforcing the original.

**Why nothing would notice.** `two_forms` ran where R had no original.

**The fix.** `original_visible()` is read first; with none, `two_forms` does not run and its forms read `not_landed` with the reason. `two_forms/amount` must land, so the result gives no verdict.

> `test_failure_modes_x11.py::test_KRK_M202_a_receiver_that_never_sees_the_original_is_not_graded_on_it`

---

## KRK-M203 — A default supplied by the kit's receiver

**Anticipated**, while designing P26. Not observed.

**What could happen.** A translator that leaves a member out reads as narrow.

**Why nothing would notice.** R′ filled the missing member from its own default.

**The fix.** R′ reads absence only as the target documents it (`absent`: `unbounded` or `nothing`). An enforced member whose absence the target does not describe gives no verdict.

> `test_failure_modes_x11.py::test_KRK_M203_absence_means_what_the_target_documents`

---

## KRK-M204 — A round trip judged in the intermediate's terms

**Anticipated**, while designing P26. Not observed.

**What could happen.** `round_trip` passes with O′ wider than O.

**Why nothing would notice.** The kit compared the intermediate form with O′, not O′ with O.

**The fix.** O′ is enacted by the kit's source receiver S′ and every effect is judged against O in the source format's terms (`translation.source_effect_outside`).

> `test_failure_modes_x11.py::test_KRK_M204_a_round_trip_is_judged_against_the_first_original`

---

## KRK-M205 — Time in two units

**Anticipated**, while designing P26. Not observed.

**What could happen.** A window form reads wrongly by a factor of 1000.

**Why nothing would notice.** The kit compared seconds with milliseconds.

**The fix.** Every original carries its `time_unit` and the profile its target unit; conversion floors an end and ceils a start, and the vectors cover both directions.

> `test_failure_modes_x11.py::test_KRK_M205_time_carries_its_unit`

---

## KRK-M206 — A rate read in the wrong direction by the kit

**Anticipated**, while designing P26. Not observed.

**What could happen.** A correct translator reads as widening in `rate_inverted`.

**Why nothing would notice.** The profile's rate is target per source and the kit applied it as source per target.

**The fix.** The direction is a fact of the profile (target major units per source major unit). The vectors convert each pair forward and with the rate inverted, and the correct toy holds `rate_inverted` while `rate_backwards` fails it.

> `test_failure_modes_x11.py::test_KRK_M206_the_rate_is_applied_in_the_profiles_direction`

---

## KRK-M207 — A widening below the receiver's resolution

**Anticipated**, while designing P26. Not observed.

**What could happen.** `max_up` cannot be seen.

**Why nothing would notice.** The receiver keeps fewer minor units than the image, so a one-unit widening rounds away at the receiver.

**The fix.** A target may state a member's `resolution`; where it is coarser than the pair's target minor units, the rounding forms read `not_applicable` with that reason.

> `test_failure_modes_x11.py::test_KRK_M207_rounding_forms_need_a_receiver_that_resolves_the_residue`

---

## KRK-M208 — A pricing sheet cached at start

**Anticipated**, while designing P26. Not observed.

**What could happen.** A gateway in topology TR reads as ignoring a rate the kit served.

**Why nothing would notice.** The target loaded the sheet at start and never read it again.

**The fix.** Version 1 serves no rate. A target whose `rate_source()` is not the static profile reads `not_landed` on its currency and rounding forms, so a must-land form among them leaves the result without a verdict unless the plan states it not claimed. A served, versioned rate with a read-back is for the target that needs it.

> `test_failure_modes_x11.py::test_KRK_M208_a_served_rate_is_not_read_as_the_profiles`

---

## KRK-M209 — A stale original read as a translation fault

**Anticipated**, while designing P26. Not observed.

**What could happen.** A translated form reads as outliving its original after A narrowed it.

**Why nothing would notice.** A narrowing happened during the trial, which is P19's case.

**The fix.** A's stand-in signs each original once, under a fresh authority id, and never changes, re-signs or withdraws one during a P26 trial; the target is checked to have received exactly the bytes A signed. A withdrawal case belongs to P19.

> `test_failure_modes_x11.py::test_KRK_M209_originals_are_signed_once_and_never_changed`

---

## KRK-M210 — A seeded draw that never reached the flaw

**Observed**, in P22's own known-bad gate, against the kit's own toy.

**What happened.** P22's toy `a-bad:nets_under_gross`, a holder that nets confirmed reversals
against spend even where the ceiling counts gross, read pass under seeds 103, 128 and
1556072351281476649; the gate requires it to fail. `reversal/confirmed` drew the ceiling's
reversal rule for each trial from the rules the target declares, with the run's seeded random
generator. The toy declares `gross` and `net-recorded`. Under those seeds all five trials drew
`net-recorded`, where netting is correct, so the flaw was never exercised and the form read held.

**Why nothing would notice.** Every trial was genuine and correctly judged: the holder kept the
ceiling under the rule each trial stated. The gate recorded when P22 was built happened to draw a
seed that reached `gross`, and the full gate test draws a fresh seed each run, so the gap showed
only as a gate test that failed now and then.

**The fix.** `reversal/confirmed` takes the declared rules in turn, trial by trial, `gross` first
(`p22_cumulative_ceiling._make_fixture`), so every declared rule is judged in every run on every
seed. A target that declares one rule is judged under it on every trial, as before. A seed sweep of
every property's known-bad toys (`tests/test_gate_seed_sweep.py`) now checks the gate under many
seeds. This moved P22's probe version.

> `test_failure_modes_x9.py::test_KRK_M210_every_declared_reversal_rule_is_judged_whatever_the_seed`

---

## Reserved for later B-issuer phases

KRK-M135 (the revocation route's own latency, charged as propagation; P19B), KRK-M136 (one
instance's acknowledgement, read as the deployment's; P19B), KRK-M137 (expired, counted as
withdrawn; P19B, P20B), KRK-M138 (a sibling under the same consent; P19B), KRK-M144 (the relay's
re-encoding, read as B's answer; P16B) and KRK-M146 (a store read's time, read as the commit time;
P19B, P20B) are named in the B-issuer design and get their entries, with pins, when
P19B, P20B and P16B are built.
