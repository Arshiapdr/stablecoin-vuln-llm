"""Stage 0 — corpus construction.

Clones each protocol's official repository (shallow) and collects only the
files that contain stabilisation logic. Nothing is scraped from a block
explorer, so the corpus is reproducible with git alone and needs no API key.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import Config, norm_rel

SOURCE_SUFFIXES = {".sol", ".go", ".ride", ".vy", ".rs"}


@dataclass
class SourceFile:
    protocol: str
    tier: str
    language: str
    repo: str
    rel_path: str
    sha256: str
    n_lines: int
    n_bytes: int
    # Directory under data/raw/ holding this file, when it differs from
    # `protocol` (benchmarks live under _benchmarks/<name>). Empty means the
    # protocol name is also the directory name.
    root: str = ""


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 900) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)[-2000:]


def _is_commit_sha(ref: str) -> bool:
    """True if `ref` looks like a full or abbreviated commit hash, not a branch."""
    return bool(ref) and 7 <= len(ref) <= 40 and all(c in "0123456789abcdef"
                                                     for c in ref.lower())


def _clone_at_commit(repo: str, sha: str, dest: Path) -> bool:
    """Fetch exactly one commit. `git clone --branch` cannot take a SHA.

    Used when a protocol is deliberately pinned to a historical state (e.g.
    Beanstalk before the April 2022 governance attack). There is NO branch
    fallback here on purpose: silently landing on main/master would hand back
    the post-remediation code while the ground-truth labels still claim the
    vulnerable function is present, which would quietly corrupt the evaluation.
    A pinned protocol either resolves to its exact commit or fails loudly.
    """
    dest.mkdir(parents=True, exist_ok=True)
    steps = [
        ["git", "init", "--quiet", str(dest)],
        ["git", "-C", str(dest), "remote", "add", "origin", repo],
        ["git", "-C", str(dest), "fetch", "--depth", "1", "--quiet", "origin", sha],
        ["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
    ]
    for cmd in steps:
        code, _ = _run(cmd)
        if code != 0:
            shutil.rmtree(dest, ignore_errors=True)
            return False
    return True


def clone(repo: str, ref: str, dest: Path, force: bool = False) -> bool:
    """Shallow-clone `repo` at `ref` into `dest`. Returns True on success.

    `ref` may be a branch name (with fallback to main/master/develop) or a
    commit SHA (exact, no fallback — see `_clone_at_commit`).
    """
    if dest.exists() and not force:
        return True
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if _is_commit_sha(ref):
        return _clone_at_commit(repo, ref, dest)

    for candidate in ([ref] if ref else []) + ["main", "master", "develop"]:
        code, _ = _run(["git", "clone", "--depth", "1", "--branch", candidate,
                        "--quiet", repo, str(dest)])
        if code == 0:
            return True
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
    code, _ = _run(["git", "clone", "--depth", "1", "--quiet", repo, str(dest)])
    return code == 0


def _excluded(rel: str, cfg: Config) -> bool:
    low = "/" + norm_rel(rel).lower()
    for pat in cfg.get("corpus.exclude_dir_patterns", []):
        if pat.lower() in low:
            return True
    name = Path(rel).name
    for pat in cfg.get("corpus.exclude_file_patterns", []):
        if pat.lower() in name.lower():
            return True
    return False


def collect(cfg: Config, protocols: list[dict], raw_dir: Path) -> list[SourceFile]:
    """Walk the cloned repos and keep only in-scope source files."""
    max_bytes = int(cfg.get("corpus.max_file_bytes", 400_000))
    out: list[SourceFile] = []
    for proto in protocols:
        # `root` lets a benchmark live under _benchmarks/<name> while still
        # carrying a clean protocol name in findings and labels.
        root = raw_dir / proto.get("root", proto["name"])
        if not root.exists():
            continue
        wanted: set[Path] = set()
        for glob in proto.get("paths", []):
            wanted |= {p for p in root.glob(glob) if p.is_file()}
        if not wanted:  # fall back to every source file in the repo
            wanted = {p for p in root.rglob("*") if p.suffix in SOURCE_SUFFIXES}
        for p in sorted(wanted):
            if p.suffix not in SOURCE_SUFFIXES:
                continue
            # POSIX form, always: corpus.json is read back by labels,
            # few-shot selection and evaluation, which all use "/".
            rel = p.relative_to(root).as_posix()
            if _excluded(rel, cfg):
                continue
            data = p.read_bytes()
            if not data or len(data) > max_bytes:
                continue
            text = data.decode("utf-8", errors="replace")
            out.append(SourceFile(
                protocol=proto["name"],
                tier=proto.get("tier", "study"),
                language=proto.get("language", p.suffix.lstrip(".")),
                repo=proto["repo"],
                rel_path=rel,
                sha256=hashlib.sha256(data).hexdigest(),
                n_lines=text.count("\n") + 1,
                n_bytes=len(data),
                root=proto.get("root", ""),
            ))
    return out


def build(cfg: Config, only: list[str] | None = None, force: bool = False,
          include_benchmarks: bool = False) -> dict:
    """Clone + collect. Writes data/interim/corpus.json and returns a summary."""
    raw = cfg.path("raw")
    protos = cfg.protocol_list()
    if only:
        protos = [p for p in protos if p["name"] in only]

    cloned, failed = [], []
    for proto in protos:
        ok = clone(proto["repo"], proto.get("ref", ""), raw / proto["name"], force=force)
        (cloned if ok else failed).append(proto["name"])

    bench_protos: list[dict] = []
    if include_benchmarks:
        for b in cfg.benchmark_list():
            ok = clone(b["repo"], b.get("ref", ""),
                       raw / "_benchmarks" / b["name"], force=force)
            # Only SmartBugs-Curated ships machine-readable ground truth, so it
            # is the only benchmark collected as source. It is tagged
            # tier=benchmark and is deliberately kept out of the headline
            # stablecoin result — it exists for external comparability of the
            # implementation-layer classes (V9/V10), whose labels are assigned
            # by SmartBugs rather than by this project.
            if ok and b["name"] == "smartbugs-curated":
                bench_protos.append({
                    "name": b["name"],
                    "root": f"_benchmarks/{b['name']}",
                    "tier": "benchmark",
                    "language": "solidity",
                    "repo": b["repo"],
                    "paths": ["dataset/**/*.sol"],
                })
                cloned.append(b["name"])

    files = collect(cfg, [p for p in protos if p["name"] in cloned] + bench_protos, raw)
    out_path = cfg.path("interim") / "corpus.json"
    out_path.write_text(json.dumps([asdict(f) for f in files], indent=1), "utf-8")

    by_proto: dict[str, int] = {}
    for f in files:
        by_proto[f.protocol] = by_proto.get(f.protocol, 0) + 1
    return {
        "cloned": cloned, "failed": failed,
        "files": len(files), "lines": sum(f.n_lines for f in files),
        "by_protocol": by_proto, "output": str(out_path),
    }


def load(cfg: Config) -> list[SourceFile]:
    path = cfg.path("interim") / "corpus.json"
    if not path.exists():
        raise FileNotFoundError("corpus.json missing — run `asv corpus` first")
    return [SourceFile(**d) for d in json.loads(path.read_text("utf-8"))]


def source_text(cfg: Config, f: SourceFile) -> str:
    p = cfg.path("raw") / (f.root or f.protocol) / f.rel_path
    return p.read_text("utf-8", errors="replace") if p.exists() else ""
