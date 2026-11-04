"""The property catalog. One module per property; each exposes ID, TITLE, Adapter, probe.

`ALL` is ordered by property number, and `ordered()` sorts any list of ids the same way, so
P10 follows P9 rather than P1.

`ALL_BISSUER` holds the B-issuer profile's modules (`b-issuer/0.1`, ids ending in ``B``), apart
from `ALL`. `ALL` is exactly P1 to P26: everything that iterates it (the full known-bad gate,
the matrix's columns, the P1 to P15 toy catalogue test) takes P24 to P26 as it took P22 and P23,
and a B-issuer result is never a column beside its A-issued property (design §5.3). Code that
looks a property up by id uses `module` or `known`, which read both registries."""
from . import (p1_failure_direction, p2_credential_reachability, p3_approval_durability,
               p4_who_may_resume, p5_self_widening, p6_default_egress, p7_actor_in_audit,
               p8_wait_cost, p9_grant_validity, p10_parameter_binding,
               p11_concurrent_executors, p12_crash_before_receipt, p13_world_unchanged,
               p14_forged_approval, p15_approver_sees_what_runs, p16_effect_receipt,
               p17_reconcilable_record, p18_payload_bound, p19_withdrawal_within_t,
               p20_standing_offline, p21_no_widening, p22_cumulative_ceiling,
               p23_reversibility, p24_mandate_bound)
from . import p25_counterparty_disclosure, p26_translation
from . import p18b_payload_bound_b


def ordered(ids):
    return sorted(ids, key=lambda p: (int(p[1:]) if p[1:].isdigit() else 10**6, p))


ALL = {m.ID: m for m in sorted(
    (p1_failure_direction, p2_credential_reachability, p3_approval_durability,
     p4_who_may_resume, p5_self_widening, p6_default_egress, p7_actor_in_audit, p8_wait_cost,
     p9_grant_validity, p10_parameter_binding, p11_concurrent_executors,
     p12_crash_before_receipt, p13_world_unchanged, p14_forged_approval,
     p15_approver_sees_what_runs, p16_effect_receipt,
               p17_reconcilable_record, p18_payload_bound, p19_withdrawal_within_t,
     p20_standing_offline, p21_no_widening, p22_cumulative_ceiling, p23_reversibility,
     p24_mandate_bound, p25_counterparty_disclosure, p26_translation),
    key=lambda m: int(m.ID[1:]))}

ALL_BISSUER = {m.ID: m for m in (p18b_payload_bound_b,)}
"""The B-issuer modules (design §6.7). Never merged into `ALL`."""


def known(pid):
    """Whether `pid` names a property in either registry."""
    return pid in ALL or pid in ALL_BISSUER


def module(pid):
    """The property module for `pid`, from either registry; KeyError if neither has it."""
    if pid in ALL:
        return ALL[pid]
    return ALL_BISSUER[pid]


def is_bissuer(pid):
    return pid in ALL_BISSUER
