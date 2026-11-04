"""Raw evidence for every result: what was sent, what came back, versions, config.

Layout: results/<run_id>/<target>/<property>/ with result.json beside the raw files. A result
without its evidence directory is a claim, and this project does not publish claims.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def new_run_id() -> str:
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime())


class Evidence:
    def __init__(self, run_id: str, target: str, property_id: str, config: str = "default") -> None:
        sub = f"{target}" if config == "default" else f"{target}@{config}"
        self.dir = RESULTS / run_id / sub / property_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._n = 0

    def write(self, name: str, content: Any) -> Path:
        """Write one evidence file. Dicts and lists are stored as JSON. Files are numbered so
        the order things happened in survives."""
        self._n += 1
        safe = "".join(ch if ch.isalnum() or ch in "-_.@" else "_" for ch in name).strip("_")
        path = self.dir / f"{self._n:02d}-{safe[:120]}"
        if isinstance(content, (dict, list)):
            path = path.with_suffix(".json")
            path.write_text(json.dumps(content, indent=2, sort_keys=True, default=str))
        else:
            path.write_text(str(content))
        return path

    def relpath(self) -> str:
        return os.path.relpath(self.dir, ROOT)
