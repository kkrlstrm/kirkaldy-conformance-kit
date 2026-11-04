"""What every target adapter provides, whatever properties it implements."""
from __future__ import annotations

from typing import Dict, Protocol, runtime_checkable


@runtime_checkable
class Target(Protocol):
    name: str
    """Short id used in the matrix ("toy-gateway", "my-product")."""

    config: str
    """Which configuration this adapter instance runs: "default" or a named variant."""

    def version(self) -> str:
        """Exact version/commit/digest of what is under test, read from the running target."""
        ...

    def vendor_claims(self) -> Dict[str, str]:
        """Property id -> what the vendor's documentation states, quoted, or "not stated"."""
        ...

    def not_applicable(self) -> Dict[str, str]:
        """Property id -> why this target has no such mechanism."""
        ...

    def start(self) -> None: ...

    def stop(self) -> None: ...
