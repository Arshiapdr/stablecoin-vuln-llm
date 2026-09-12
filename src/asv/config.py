"""Configuration loading. Single entry point for every path and setting."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def norm_rel(path: str) -> str:
    """Return a repository-relative path in the project's canonical form.

    The corpus is collected on whatever OS the user runs: `Path.relative_to`
    yields `x\\market\\keeper\\swap.go` on Windows and
    `x/market/keeper/swap.go` everywhere else, while every `file_contains` in
    `labels/*.yaml` is written with forward slashes. Comparing the two raw
    forms anchors ZERO labels on Windows -- no exemplars, no true positives,
    no metrics -- so both sides are normalised here, and only here.
    """
    return path.replace("\\", "/")


def file_matches(file_contains: str, file: str) -> bool:
    """Does a label's `file_contains` anchor to this corpus path?

    Separator- and case-insensitive, so a corpus built on one OS stays
    readable on another.
    """
    return norm_rel(file_contains).lower() in norm_rel(file).lower()


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _deep_get(d: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


@dataclass
class Config:
    pipeline: dict = field(default_factory=dict)
    models: dict = field(default_factory=dict)
    protocols: dict = field(default_factory=dict)
    root: Path = REPO_ROOT

    @classmethod
    def load(cls, root: Path | str | None = None) -> "Config":
        root = Path(root) if root else REPO_ROOT
        c = root / "configs"
        return cls(
            pipeline=_read_yaml(c / "pipeline.yaml"),
            models=_read_yaml(c / "models.yaml"),
            protocols=_read_yaml(c / "protocols.yaml"),
            root=root,
        )

    # ---- settings ----------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        return _deep_get(self.pipeline, dotted, default)

    def path(self, key: str) -> Path:
        p = self.root / _deep_get(self.pipeline, f"paths.{key}", key)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def knowledge_dir(self) -> Path:
        return self.root / "knowledge"

    # ---- providers ---------------------------------------------------------
    def provider(self, name: str) -> dict:
        provs = self.models.get("providers", {})
        if name not in provs:
            raise KeyError(f"unknown provider {name!r}; known: {sorted(provs)}")
        return provs[name]

    @property
    def provider_order(self) -> list[str]:
        return list(self.get("llm.providers_order", ["mock"]))

    def available_providers(self) -> list[str]:
        """Providers usable right now: mock and local never need a key."""
        out = []
        for name in self.provider_order:
            try:
                spec = self.provider(name)
            except KeyError:
                continue
            env = spec.get("api_key_env")
            if spec.get("kind") == "mock" or name == "local" or (env and os.getenv(env)):
                out.append(name)
        return out

    # ---- corpus ------------------------------------------------------------
    def protocol_list(self, tier: str | None = None,
                      algorithmic: str | list[str] | None = None) -> list[dict]:
        """Protocols, filtered on either axis.

        `tier` is the ROLE (study / control); `algorithmic` is the MECHANISM
        (pure / partial / none). They are independent: Beanstalk-patched is
        `pure` but a control, and Reflexer RAI is `partial` but a control.
        "primary" is accepted as a deprecated alias for "study" so older
        commands and notebooks keep working.
        """
        items = self.protocols.get("protocols", [])
        if tier == "primary":
            tier = "study"
        if tier:
            items = [p for p in items if p.get("tier") == tier]
        if algorithmic:
            want = {algorithmic} if isinstance(algorithmic, str) else set(algorithmic)
            items = [p for p in items if p.get("algorithmic", "none") in want]
        return items

    def protocol_meta(self) -> dict[str, dict]:
        return {p["name"]: p for p in self.protocols.get("protocols", [])}

    def benchmark_list(self) -> list[dict]:
        return self.protocols.get("benchmarks", [])
