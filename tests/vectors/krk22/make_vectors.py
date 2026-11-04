"""Writes the KRK-22 test vectors in this directory. Run from the repo root:

    python tests/vectors/krk22/make_vectors.py

The kit's own account of `X9-CUMULATIVE-CEILING-DESIGN.md` §2.6, as cases whose expected answers
are written here by hand: what one request counts against a limit (in the kit's units, 10^-18 of
the currency for amounts), totals across spenders under both reversal rules, charges through two-
and three-hop chains and a holder hop, fixed-window offset searches with charges on and either
side of boundaries, rolling windows, the 2^53 boundary, and role B's attribution. Nothing is
computed by `conformance.ceiling`, so a bug in it cannot make its own vector agree with it
(spec §5.1 rule 7).
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
E18 = 10 ** 18
E16 = 10 ** 16      # one EUR cent in the kit's units
E15 = 10 ** 15      # a tenth of a cent


def amt(v, cur="EUR", mu=2):
    return {"value": v, "currency": cur, "minor_units": mu}


def alim(v, cur="EUR", mu=2):
    return {"kind": "amount", "value": v, "currency": cur, "minor_units": mu}


def clim(v, unit="message"):
    return {"kind": "count", "value": v, "unit": unit}


def eff(ref, spender, values, t, kind="spend", reverses=None):
    body = {"ref": ref, "spender": spender, "kind": kind, "values": values}
    if reverses:
        body["reverses"] = reverses
    return {"t_kit": t, "effect": body}


R, K1, K2, H = "cl-00000000000000a1", "cl-00000000000000b2", "cl-00000000000000c3", \
    "cl-00000000000000d4"

QUANTITY = [  # (values, limit, expected kit units or None) -- by hand
    ({"amount": amt(100)}, alim(1000), 100 * E16),
    ({"amount": amt(1, mu=0)}, alim(1000), 100 * E16),            # 1 EUR = 100 cents
    ({"amount": amt(5, mu=3)}, alim(1000), 5 * E15),              # half a cent
    ({"amount": amt(100, "USD")}, alim(1000), None),              # no conversion
    ({"amount": {"value": 1.5, "currency": "EUR", "minor_units": 2}}, alim(1000), None),
    ({"amount": {"value": "100", "currency": "EUR", "minor_units": 2}}, alim(1000), None),
    ({"amount": amt(2 ** 53)}, alim(1000), None),                 # beyond 2^53 - 1
    ({"amount": amt(2 ** 53 - 1)}, alim(1000), (2 ** 53 - 1) * E16),
    ({"amount": amt(-50)}, alim(1000), -50 * E16),                # a credit as a spend
    ({"amount": amt(100)}, clim(3), 1),                           # no count member: one
    ({"amount": amt(100), "count": {"value": 2, "unit": "message"}}, clim(3), 2),
    ({"amount": amt(100), "count": {"value": 1, "unit": "recipient"}}, clim(3), None),
    ({}, alim(1000), None),                                       # no amount
    ({"amount": amt(True)}, alim(1000), None),
]

CEILINGS_1 = {R: {"limits": [alim(1000)]}}
ACCOUNTS = [
    # (name, effects, issuance, ceilings, rule, expected totals {cid: [..]}, uncountable)
    ("sum_across_three", [eff("q1", "B1", {"amount": amt(400)}, 1.0),
                          eff("q2", "B2", {"amount": amt(400)}, 2.0),
                          eff("q3", "B3", {"amount": amt(400)}, 3.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]},
      {"ref": "q3", "ceiling_ids": [R]}], CEILINGS_1, "gross", {R: [1200 * E16]}, []),
    ("units_mixed_minor", [eff("q1", "B1", {"amount": amt(600)}, 1.0),
                           eff("q2", "B2", {"amount": amt(6, mu=0)}, 2.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]}], CEILINGS_1,
     "gross", {R: [1200 * E16]}, []),
    ("other_currency_uncountable", [eff("q1", "B1", {"amount": amt(500)}, 1.0),
                                    eff("q2", "B2", {"amount": amt(300, "USD")}, 2.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]}], CEILINGS_1,
     "gross", {R: [500 * E16]}, ["q2"]),
    ("reversal_gross", [eff("q1", "B1", {"amount": amt(500)}, 1.0),
                        eff("r1", "B1", {"amount": amt(400)}, 2.0, "reversal", "q1")],
     [{"ref": "q1", "ceiling_ids": [R]}], CEILINGS_1, "gross", {R: [500 * E16]}, []),
    ("reversal_net", [eff("q1", "B1", {"amount": amt(500)}, 1.0),
                      eff("r1", "B1", {"amount": amt(400)}, 2.0, "reversal", "q1")],
     [{"ref": "q1", "ceiling_ids": [R]}], CEILINGS_1, "net-recorded", {R: [100 * E16]}, []),
    ("negative_spend_frees_nothing", [eff("q1", "B1", {"amount": amt(600)}, 1.0),
                                      eff("q2", "B2", {"amount": amt(-500)}, 2.0),
                                      eff("q3", "B3", {"amount": amt(600)}, 3.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]},
      {"ref": "q3", "ceiling_ids": [R]}], CEILINGS_1, "net-recorded", {R: [1200 * E16]}, []),
    ("two_hop_chain", [eff("q1", "B1", {"amount": amt(700)}, 1.0),
                       eff("q2", "B2", {"amount": amt(700)}, 2.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R, K1]}],
     {R: {"limits": [alim(1000)]}, K1: {"limits": [alim(1000)]}}, "gross",
     {R: [1400 * E16], K1: [700 * E16]}, []),
    ("three_hop_chain", [eff("q1", "B1", {"amount": amt(300)}, 1.0),
                         eff("q2", "B2", {"amount": amt(300)}, 2.0),
                         eff("q3", "B3", {"amount": amt(300)}, 3.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R, K1]},
      {"ref": "q3", "ceiling_ids": [R, K1, K2]}],
     {R: {"limits": [alim(1000)]}, K1: {"limits": [alim(500)]}, K2: {"limits": [alim(200)]}},
     "gross", {R: [900 * E16], K1: [600 * E16], K2: [300 * E16]}, []),
    ("holder_hop_inherits", [eff("q1", "B1", {"amount": amt(700)}, 1.0),
                             eff("q2", "B2", {"amount": amt(700)}, 2.0)],
     [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]}], CEILINGS_1,
     "gross", {R: [1400 * E16]}, []),
    ("two_limits", [eff(f"q{i}", "B1", {"amount": amt(200),
                                         "count": {"value": 1, "unit": "message"}}, float(i))
                    for i in range(4)],
     [{"ref": f"q{i}", "ceiling_ids": [R]} for i in range(4)],
     {R: {"limits": [alim(1000), clim(3)]}}, "gross", {R: [800 * E16, 4]}, []),
    ("large_integer_exact", [eff("q1", "B1", {"amount": amt(3002399751580330)}, 1.0),
                             eff("q2", "B2", {"amount": amt(3002399751580330)}, 2.0),
                             eff("q3", "B3", {"amount": amt(3002399751580331)}, 3.0),
                             eff("q4", "B1", {"amount": amt(1, mu=3)}, 4.0)],
     [{"ref": f"q{i}", "ceiling_ids": [R]} for i in range(1, 5)],
     {R: {"limits": [alim(2 ** 53 - 1)]}}, "gross",
     {R: [(2 ** 53 - 1) * E16 + E15]}, []),
    ("unattributed_charged_to_root", [eff("zz", "B9", {"amount": amt(100)}, 1.0)], [],
     CEILINGS_1, "gross", {R: [100 * E16]}, []),
]

JUDGE = [  # (name, account case name, overshoot, within, where)
    ("three_over", "sum_across_three", {}, False, ["q3"]),
    ("mixed_minor_over", "units_mixed_minor", {}, False, ["q2"]),
    ("uncountable_is_outside", "other_currency_uncountable", {}, False, []),
    ("gross_within", "reversal_gross", {}, True, []),
    ("two_hop_root_over", "two_hop_chain", {}, False, ["q2"]),
    ("negative_over", "negative_spend_frees_nothing", {}, False, ["q3"]),
    ("count_over", "two_limits", {}, False, ["q3"]),
    ("large_integer_over_by_a_tenth_cent", "large_integer_exact", {}, False, ["q4"]),
    ("overshoot_allows", "sum_across_three", {f"{R}/0": 200 * E16}, True, []),
    ("overshoot_one_short", "sum_across_three", {f"{R}/0": 200 * E16 - 1}, False, ["q3"]),
]

P, A = 20.0, 1000.0
WIN_FIXED = {"kind": "fixed", "period_s": 20, "anchor_ms": 0}
WINDOWS = [
    # (name, charge times and cents, window, limit cents, tolerance, lag, passes) -- by hand
    ("boundary_pair_split", [(A + P - 2, 800), (A + P + 2, 800)], WIN_FIXED, 1000, 1.0, 0.0,
     True),
    ("one_window_over", [(A + 2, 800), (A + 3, 300)], WIN_FIXED, 1000, 1.0, 0.0, False),
    ("within_tolerance_either_side", [(A + P - 0.5, 800), (A + P + 0.5, 800)], WIN_FIXED,
     1000, 1.0, 0.0, True),
    ("tolerance_cannot_split_three", [(A + P - 0.5, 600), (A + P + 0.2, 600),
                                      (A + P + 0.7, 600)], WIN_FIXED, 1000, 1.0, 0.0, False),
    ("on_the_boundary", [(A + P, 800), (A + P + 3, 300)], WIN_FIXED, 1000, 0.0, 0.0, False),
    ("on_the_boundary_other_side", [(A + P - 3, 800), (A + P, 300)], WIN_FIXED, 1000, 0.0,
     0.0, True),
    ("skew_beyond_tolerance", [(A + 8, 800), (A + 12, 800)], WIN_FIXED, 1000, 1.0, 0.0,
     False),
    ("rolling_two_in_period", [(A + 18, 900), (A + 22, 900)],
     {"kind": "rolling", "period_s": 20}, 1000, 1.0, 0.0, False),
    ("rolling_apart", [(A + 1, 900), (A + 21, 900)], {"kind": "rolling", "period_s": 20},
     1000, 1.0, 0.0, True),
    ("rolling_tolerances_shrink", [(A + 1, 900), (A + 19.5, 900)],
     {"kind": "rolling", "period_s": 20}, 1000, 1.0, 0.0, True),
    ("rolling_with_lag", [(A + 1, 900), (A + 17.5, 900)],
     {"kind": "rolling", "period_s": 20}, 1000, 1.0, 1.0, True),
    ("rolling_with_lag_inside", [(A + 1, 900), (A + 14, 900)],
     {"kind": "rolling", "period_s": 20}, 1000, 1.0, 1.0, False),
]

ATTRIBUTION = [
    # (name, B's spends cents, confirmations [(kind, cents)], over?) -- by hand
    ("within_share", [300, 200], [("share", 500)], False),
    ("over_share", [300, 300], [("share", 500)], True),
    ("released_after_commit", [600], [("reservation", 600), ("release", 600)], True),
    ("expired_then_committed", [600], [("reservation", 600), ("expired", 600)], True),
    ("two_reservations", [300, 300], [("reservation", 300), ("reservation", 300)], False),
]


def main() -> None:
    doc = {"note": "written by make_vectors.py; every expected answer by hand",
           "kit_units": {"amount": "10^-18 of the currency", "count": "effects"},
           "quantity": [{"values": v, "limit": l, "expected": e} for v, l, e in QUANTITY],
           "accounts": [{"name": n, "effects": ef, "issuance": iss, "ceilings": cs, "rule": r,
                         "totals": t, "uncountable": u}
                        for n, ef, iss, cs, r, t, u in ACCOUNTS],
           "judge": [{"name": n, "account": a, "overshoot": o, "within": w, "where": wh}
                     for n, a, o, w, wh in JUDGE],
           "windows": [{"name": n, "charges": [[t, c] for t, c in ch], "window": w,
                        "limit_cents": lim, "anchor_kit": A, "tolerance_s": tol,
                        "commit_lag_s": lag, "passes": ok}
                       for n, ch, w, lim, tol, lag, ok in WINDOWS],
           "attribution": [{"name": n, "spends_cents": s, "confirmations": c, "over": o}
                           for n, s, c, o in ATTRIBUTION]}
    (HERE / "vectors.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
