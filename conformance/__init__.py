"""Agent-boundary conformance kit: probes for the guarantees agent infrastructure leaves unstated.

**Where results are written.** ``KIRKALDY_RESULTS_DIR``, when set, names the results root in
place of the kit's own `results/`: every run's evidence and the known-bad store go there
(`evidence.RESULTS`; `knownbad.store_dir`), so a repository that keeps its adapters outside the
kit keeps its results outside it too. ``evidence_dir`` in a result stays relative to the kit
root. The setting is applied here, when the package is first imported, and not in `evidence.py`:
every probe imports `evidence`, so a change there would move every probe version
(`conformance.versions`) for a change to where results are written, not to what is measured.
The adapter roots (``KIRKALDY_TARGETS_PATH``) are `targets`'s and the claims ledgers
(``KIRKALDY_CLAIMS_DIR``) are `conformance.claims`'s.
"""
import os as _os
from pathlib import Path as _Path

RESULTS_ENV = "KIRKALDY_RESULTS_DIR"


def _apply_results_dir() -> None:
    if _os.environ.get(RESULTS_ENV):
        from . import evidence
        evidence.RESULTS = _Path(_os.environ[RESULTS_ENV]).expanduser().resolve()


_apply_results_dir()
