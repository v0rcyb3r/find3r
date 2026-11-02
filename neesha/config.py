"""Configuration loader.

Reads a small TOML file and exposes a typed Config. Env vars (e.g. the
store key and preflight key) are read at their point of use, not here, so
credentials stay out of the config file.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("neesha.toml")


def harden_path(path: Path) -> None:
    """Best-effort restrict local harness storage to its owner.

    The harness database and reports hold personal data and are not encrypted
    at rest, so they must not be group- or world-readable: directories become
    0700 and files 0600. A directory at 0700 also blocks other local users
    from traversing to the files inside it, which is the control that matters
    for the SQLite database created lazily within. POSIX only; a no-op where
    chmod is unavailable.
    """
    try:
        if path.is_dir():
            path.chmod(0o700)
        elif path.exists():
            path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass


@dataclass
class Config:
    mode: str = "local"  # local | vps | hybrid
    data_dir: str = "data"
    runs_dir: str = "runs"
    reports_dir: str = "reports"
    retention_days: int = 30
    allowed_sources: list[str] = field(default_factory=list)
    denied_sources: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        if not path.exists():
            return cls()
        raw = tomllib.loads(path.read_text())
        valid = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        return cls(**valid)

    def to_toml(self) -> str:
        lines = [
            f'mode = "{self.mode}"',
            f'data_dir = "{self.data_dir}"',
            f'runs_dir = "{self.runs_dir}"',
            f'reports_dir = "{self.reports_dir}"',
            f"retention_days = {self.retention_days}",
        ]
        if self.allowed_sources:
            quoted = ", ".join(f'"{s}"' for s in self.allowed_sources)
            lines.append(f"allowed_sources = [{quoted}]")
        if self.denied_sources:
            quoted = ", ".join(f'"{s}"' for s in self.denied_sources)
            lines.append(f"denied_sources = [{quoted}]")
        return "\n".join(lines) + "\n"
