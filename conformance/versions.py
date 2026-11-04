"""What a verdict was measured with: content hashes of the probe, its fixtures and the target
adapter, and the environment fields a property declares relevant (spec §3.5).

No file in the kit carries a version number, so each version is a SHA-256 over the files it
covers. The digest is taken over one line per file, sorted by path: the path relative to the kit
root, a NUL, the SHA-256 of the file's bytes, a newline. Renaming, adding or removing a file
changes it as well as editing one. The file lists are recorded beside the digests, so a reader
can see what each one covers.

- **Probe.** The property module and every kit module it imports, followed transitively through
  imports of `conformance`, `targets` and `known_bad` (imports inside functions included).
  Package `__init__` files are followed only when imported by name, so P16's version does not
  move when P3 changes. For P16 this covers `receipts.py` and `counterparty.py`: the stub B that
  generates P16's bad receipts is part of the probe.
- **Fixture.** The known-bad fixtures and vectors the property is checked against, and the test
  that states their required outcomes. A property module names them in `FIXTURES` (globs, kit
  root relative); otherwise `DEFAULT_FIXTURES` applies. `known_bad/toys.py` holds the toys of
  P1 to P15 in one file, so a change to any of them lapses all fifteen.
- **Adapter.** Every file in the adapter's own directory under `targets/` or under an outside
  adapter root (``KIRKALDY_TARGETS_PATH``, `targets.roots`), or, for an adapter defined
  elsewhere, such as a known-bad toy, its module file, plus the import closure of the Python
  files among them. The adapter drives the target and often makes the control's observation, so
  a change to it changes what was measured. A file under an outside root is recorded as
  ``targets/<path in that root>``, as it would be under the kit's own `targets/`, so an adapter's
  version does not depend on where its root is checked out.
- **Environment.** Fields a property module names in `ENVIRONMENT`: ``python`` (the kit
  interpreter's version), ``platform`` (system and machine), or ``package:<distribution>``.
"""
from __future__ import annotations

import ast
import glob
import hashlib
import importlib
import inspect
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .evidence import ROOT

SCHEME = "sha256 over sorted '<path>\\0<sha256 of file>\\n' lines"
PACKAGES = ("conformance", "targets", "known_bad")
DEFAULT_FIXTURES = ("known_bad/__init__.py", "known_bad/toys.py", "tests/test_known_bad.py")


def _target_roots() -> List[Path]:
    """Every directory adapters live in (`targets.roots`), the kit's own `targets/` first."""
    import targets
    return targets.roots()


def _root_of(path: Path) -> Optional[Path]:
    """The adapter root holding `path` (the innermost, if roots nest), or None."""
    p = path.resolve()
    held = [r for r in _target_roots() if r in p.parents]
    return max(held, key=lambda r: len(r.parts)) if held else None


def _rel(path: Path) -> str:
    """Kit-root relative, with a file under an adapter root as ``targets/<path in the root>``;
    absolute for a file outside both (an adapter defined in a test)."""
    r = _root_of(path)
    if r is not None:
        return "targets/" + path.resolve().relative_to(r).as_posix()
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _file(rel: str) -> Path:
    """The file a recorded path names: under ``targets/``, the first adapter root that has it
    (the one `import` reads); otherwise kit-root relative, or absolute as recorded."""
    if rel.startswith("targets/"):
        sub = rel[len("targets/"):]
        for r in _target_roots():
            if (r / sub).is_file():
                return r / sub
    return ROOT / rel


def _module_file(name: str) -> Optional[Path]:
    """The kit file for a dotted module name, or None if it is not a kit module. A ``targets.``
    name is looked up in every adapter root, in import order."""
    parts = name.split(".")
    if parts[0] not in PACKAGES:
        return None
    if parts[0] == "targets" and len(parts) > 1:
        bases = [r.joinpath(*parts[1:]) for r in _target_roots()]
    else:
        bases = [ROOT.joinpath(*parts)]
    for base in bases:
        for cand in (base.with_suffix(".py"), base / "__init__.py"):
            if cand.is_file():
                return cand
    return None


def _module_name(path: Path) -> str:
    rel = Path(_rel(path))
    if rel.is_absolute():
        raise ValueError(f"{path} is outside the kit and every adapter root")
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(path: Path) -> Set[Path]:
    """Kit files imported by `path`, anywhere in it."""
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return set()
    try:
        me = _module_name(path)
    except ValueError:                       # outside the kit: absolute imports only
        me = ""
    package = me if path.name == "__init__.py" else me.rpartition(".")[0]
    found: Set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                f = _module_file(alias.name)
                if f:
                    found.add(f)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".") if package else []
                parts = parts[:len(parts) - (node.level - 1)] if node.level > 1 else parts
                base = ".".join(parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            for alias in node.names:
                f = _module_file(f"{base}.{alias.name}") if base else None
                if f:                       # `from pkg import module`
                    found.add(f)
                elif base:                  # `from module import name`
                    f = _module_file(base)
                    if f and (f.name != "__init__.py" or not node.level or node.module):
                        found.add(f)
    found.discard(path.resolve())
    return found


def closure(paths: Iterable[Path]) -> List[str]:
    """`paths` and every kit file they import, transitively, as sorted kit-relative paths."""
    todo = [Path(p).resolve() for p in paths]
    seen: Set[Path] = set()
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        if p.suffix == ".py":
            todo.extend(f.resolve() for f in _imports(p) if f.resolve() not in seen)
    return sorted(_rel(p) for p in seen)


def digest(files: Sequence[str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        p = _file(rel)
        content = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "missing"
        h.update(f"{rel}\0{content}\n".encode())
    return "sha256:" + h.hexdigest()


def _property_module(pid: str):
    from .properties import module
    return module(pid)            # P1 to P23, or a B-issuer module


def probe_files(pid: str) -> List[str]:
    return closure([Path(inspect.getsourcefile(_property_module(pid)))])


def fixture_files(pid: str) -> List[str]:
    globs = getattr(_property_module(pid), "FIXTURES", DEFAULT_FIXTURES)
    out: Set[str] = set()
    for g in globs:
        hits = [Path(h) for h in glob.glob(str(ROOT / g))]
        out.update(_rel(h) for h in hits if h.is_file())
        if not hits:
            out.add(g)                       # recorded, and hashed as "missing"
    return sorted(out)


def adapter_module(adapter: Any) -> str:
    return type(adapter).__module__


def adapter_files(module: str) -> List[str]:
    """The files that define an adapter, from its module name."""
    try:
        src = Path(inspect.getsourcefile(sys.modules.get(module) or importlib.import_module(module)))
    except Exception:
        return []
    src = src.resolve()
    root = _root_of(src)
    if root is not None and src.parent != root:
        own = src.parent
        while own.parent != root:
            own = own.parent
        files = [p for p in own.rglob("*") if p.is_file() and "__pycache__" not in p.parts
                 and p.suffix != ".pyc" and not p.name.startswith(".")]
    else:
        files = [src]
    return closure(files)


def measure(name: str) -> str:
    """The current value of one environment field."""
    if name == "python":
        return platform.python_version()
    if name == "platform":
        return f"{platform.system()} {platform.machine()}"
    if name.startswith("package:"):
        try:
            return metadata.version(name.split(":", 1)[1])
        except metadata.PackageNotFoundError:
            return "not installed"
    raise ValueError(f"unknown environment field {name!r}")


def environment(pid: str) -> Dict[str, str]:
    """The environment fields `pid` declares in `ENVIRONMENT`, measured now."""
    return {name: measure(name) for name in getattr(_property_module(pid), "ENVIRONMENT", ())}


def unseeded(pid: str) -> List[str]:
    return list(getattr(_property_module(pid), "UNSEEDED", ()))


def snapshot(pid: str, module: str) -> Dict[str, Any]:
    """The current probe, fixture and adapter versions and environment for `pid` measured
    through the adapter defined in `module`."""
    probe, fixture, adapter = probe_files(pid), fixture_files(pid), adapter_files(module)
    return {"probe_version": digest(probe), "fixture_version": digest(fixture),
            "adapter_version": digest(adapter), "environment": environment(pid),
            "hashed": {"scheme": SCHEME, "probe": probe, "fixture": fixture,
                       "adapter": adapter, "adapter_module": module}}


def current(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The probe, fixture and adapter versions and the environment fields a recorded result
    lists, measured from this tree now. A value that cannot be measured is left out (None), so
    `validity` reads it as unknown, never as unchanged."""
    pid = doc.get("property_id")
    hashed = doc.get("hashed") if isinstance(doc.get("hashed"), dict) else {}
    module = hashed.get("adapter_module")
    renewal = doc.get("renewal") if isinstance(doc.get("renewal"), dict) else {}
    env: Dict[str, str] = {}
    for n in renewal.get("lapses_on_change") or []:
        if isinstance(n, str) and n.startswith("environment."):
            try:
                env[n.split(".", 1)[1]] = measure(n.split(".", 1)[1])
            except ValueError:
                pass                          # unknown field: left unmeasured, so unknown
    from .properties import known
    out: Dict[str, Any] = {"probe_version": None, "fixture_version": None,
                           "adapter_version": None, "environment": env,
                           "claim_rule_version": None}
    if doc.get("claim_rule_version"):
        from .claim_basis import rule_version
        out["claim_rule_version"] = rule_version()
    if known(pid):
        out["probe_version"] = digest(probe_files(pid))
        out["fixture_version"] = digest(fixture_files(pid))
    if module:
        files = adapter_files(module)
        out["adapter_version"] = digest(files) if files else None
    return out
