# The replacement was ready when the agent scheduled the cancellation

> Switch my service to B. Cancel A only if B is usable when A actually ends service.

I tested this instruction with a scripted coordinator and two synthetic Companies using Poppy Operations v3. The new provider accepted one activation order. The old provider accepted one scheduled cancellation. Both local approvals stayed valid. In one run, the old service ended while the replacement was unavailable.

| Fixture tick | Same schedule, readiness renewed | Same schedule, readiness expired |
| --- | --- | --- |
| 0 | B is usable. A schedules the cutoff for tick 3 and stays active. | B is usable. A schedules the cutoff for tick 3 and stays active. |
| 1–2 | B renews readiness at tick 1 and remains usable. | B’s readiness expires at tick 2. A is still active. |
| 3 | A ends service once while B is usable. | A ends service once while B is unavailable. |

Both runs used the same coordinator policy, which checked readiness when it scheduled the cancellation. The cutoff was executed by the old provider later. The activation and scheduling records show what each Company accepted. The ordered business records show whether the user’s condition held when the old service actually ended.

## Recorded traces

- [Ready at cutoff](ready-at-cutoff.json) records the matched control. The replacement is usable at the actual cutoff.
- [Readiness expired](readiness-expired.json) records the violation of the coordinator’s accepted condition. The replacement is unavailable at the actual cutoff.

These are extracts from the two recorded runs. They retain the ordered business events, fixture ticks, readiness coverage, approval validity, and verdict. Operation and revision identifiers, request details, and harness internals are omitted. The ticks are simulated time.

The case illustrates a delayed effect under [KRK-13](https://doi.org/10.5281/zenodo.24278774). A test of the coordinator’s readiness claim needs to observe the service ending, even when the scheduling request finished earlier. If the old provider accepts and enforces the readiness condition as a mandate term, that receiver-side claim falls under KRK-24.

The two Companies used [Datalayer’s Python SDK 1.0.1](https://github.com/datalayer/personal-agent-protocol/releases/tag/v1.0.1) locally. The Companies, readiness policy, and coordinator were test-owned. The result applies to the scripted coordinator and its stated condition.

**What can still stop the cutoff after the agent schedules it?**
