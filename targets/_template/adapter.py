"""A template for a target adapter. Copy this directory to `targets/<name>/` and fill it in.

The adapter drives one product, pinned to one version, under one named configuration. Its
docstring says what each property means for this product: what counts as "the approval", who
"the agent" is, which store holds the record. Those interpretations are where a vendor is most
likely to disagree, so they are written down here, beside the code that acts on them.

Rules that every adapter keeps (spec §3 and §5.1):

- Pin the product: an image digest in `compose.yaml`, or a documented, pinned binary or package.
  `version()` reads the version from the running target, never from this file.
- The adapter drives the target and reports what it observed. It never decides an outcome, never
  verifies on the target's behalf, and never maps a value during a run that the target did not
  declare before it (KRK-M23, KRK-M25, KRK-M42).
- State the claim basis (spec §3.4). `not_claimed()` names the forms the product's own documents
  do not claim, each with a reason; `claim_basis()` quotes the passage for the forms they do. A
  run marked published is refused before it starts while any form is neither.
- Every method a property's protocol lists is implemented, or the property is left out of
  `implements()`. Each probe module's docstring and its `Adapter` protocol list the methods; the
  interface files in `docs/` give the cross-organisation properties' adapters.

Run `make test`, then `python -m conformance run <name> -p <property>`, and read every
`inconclusive` before trusting any `pass`.
"""
from __future__ import annotations

from typing import Any, Dict, List

CONFIGS = ["default"]


class Adapter:
    name = "my-product"

    def __init__(self, config: str) -> None:
        self.config = config

    # lifecycle ---------------------------------------------------------------------------------

    def start(self) -> None:
        """Start the pinned target (for example `docker compose up` on this directory's
        `compose.yaml`) and wait until it answers."""
        raise NotImplementedError

    def stop(self) -> None:
        """Stop it and remove what `start` created. Called even after a failed start."""
        raise NotImplementedError

    def version(self) -> str:
        """The exact version, commit or digest, read from the running target."""
        raise NotImplementedError

    # what the product states ----------------------------------------------------------------

    def implements(self) -> List[str]:
        """The properties this adapter can drive, for example ``["P1", "P2"]``."""
        return []

    def vendor_claims(self) -> Dict[str, str]:
        """Property id -> the product's own statement, quoted with its source, or ``not stated``
        (`conformance.claims` reads `claims/<name>.json` for this)."""
        return {}

    def not_applicable(self) -> Dict[str, str]:
        """Property id -> one line on why the product has no such mechanism."""
        return {}

    def not_claimed(self) -> Dict[str, Dict[str, str]]:
        """Property id -> {form: reason the product's documents do not claim it}."""
        return {}

    def claim_basis(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Property id -> {form: {"quote", "location", "source"}}; ``"*"`` as the form covers
        every check of a check-level property."""
        return {}

    # the property's protocol: add the methods each implemented property lists -------------------


def make(config: str = "default") -> Any:
    if config not in CONFIGS:
        raise ValueError(f"unknown configuration {config!r}; one of {CONFIGS}")
    return Adapter(config)
