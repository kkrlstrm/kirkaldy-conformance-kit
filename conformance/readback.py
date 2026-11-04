"""Fixtures the kit sets in a target's own format, confirmed by reading them back (KRK-M26).

Some readings depend on state the harness publishes for the target rather than state the kit
owns: a counterparty's revocation status list, say. When that state is built in the target's
format, a bug in building it leaves the published state unchanged, and the target then reads
exactly what it would read if it ignored the state. A revoked receipt that is accepted looks like
a verifier failing open when the revocation was never published.

`require_landed` is the guard: the harness reads the published state back, in the format the
target reads, and the reading counts only if every change it meant to make is there.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


class FixtureNotLanded(RuntimeError):
    """A fixture in the target's format was not what the harness meant to publish."""


def require_landed(what: str, wanted: Iterable[Any], read_back: Mapping[Any, Any]) -> None:
    """Raise unless every key in `wanted` reads back true in `read_back`, the state as the
    target would read it. `what` names the fixture for the message."""
    keys = list(wanted)
    missing = [k for k in keys if read_back.get(k) is not True and read_back.get(str(k)) is not True]
    if missing:
        raise FixtureNotLanded(f"{what}: {missing} did not land in the published state "
                               f"(read back {dict(read_back)}); a reading on it would describe "
                               f"the harness, not the target")
