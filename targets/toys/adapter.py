"""An example adapter: it drives the kit's own toys (`known_bad/`) through the runner, the same
path a real target's adapter takes.

A configuration names one property and one of its toys: ``<property>-<toy configuration>``.

    python -m conformance known-bad --record -p P1
    python -m conformance run toys@P1-bad -p P1        # the broken gateway: P1 must fail
    python -m conformance run toys@P16-good -p P16      # the correct receipt handler: P16 passes
    python -m conformance run toys@P21-bad:leaf_only -p P21

The toy configurations of each property are listed by `conformance.knownbad.cases`. A toy is a
few lines that model one mechanism; it is not a simulation of any product. Results land in
`results/<run>/<toy name>@<configuration>/<property>/`, as for any target.

This file is also the shortest worked example of the adapter contract: `make(config)` returns an
object with `name`, `config`, `start()`, `stop()`, `version()`, `vendor_claims()`,
`not_applicable()`, `implements()` and the methods the property's protocol lists. Every toy has
them already, so the adapter only selects one. For a real product, start from
`targets/_template/adapter.py`.
"""
from __future__ import annotations

from typing import Any, List

from conformance import knownbad

CONFIGS: List[str] = ["P1-good", "P1-bad", "P1-no-control", "P16-good", "P16-bad",
                      "P21-good", "P21-bad:leaf_only"]
"""Examples for `python -m conformance targets`; any ``<property>-<toy configuration>`` that
`conformance.knownbad.cases` lists is accepted."""


def make(config: str = "P1-good") -> Any:
    pid, sep, toy_config = config.partition("-")
    if not sep or not toy_config:
        raise ValueError(f"configuration {config!r} is not <property>-<toy configuration>")
    pid = pid.upper()
    known = {c for c, _ in knownbad.cases(pid)}
    if toy_config not in known:
        raise ValueError(f"{pid} has no toy {toy_config!r}; one of {sorted(known)}")
    toy = knownbad._toy(pid, toy_config)
    toy.config = config
    if not callable(getattr(toy, "implements", None)) or pid not in toy.implements():
        toy.implements = lambda: [pid]
    return toy
