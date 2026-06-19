from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class EnvLoadStatus:
    path: Path
    present: bool
    loaded: bool


def load_project_env() -> EnvLoadStatus:
    env_path = PROJECT_ROOT / ".env"
    present = env_path.exists()
    loaded = load_dotenv(env_path, override=False) if present else False
    return EnvLoadStatus(path=env_path, present=present, loaded=loaded)


def env_flag(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def set_project_env_value(name: str, value: str) -> bool:
    env_path = PROJECT_ROOT / ".env"
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    prefix = f"{name}="
    updated = False
    next_lines: list[str] = []

    for line in lines:
        if line.startswith(prefix):
            next_lines.append(f"{name}={value}")
            updated = True
        else:
            next_lines.append(line)

    if not updated:
        next_lines.append(f"{name}={value}")

    env_path.write_text("\n".join(next_lines).rstrip() + "\n", encoding="utf-8")
    os.environ[name] = value
    return True
