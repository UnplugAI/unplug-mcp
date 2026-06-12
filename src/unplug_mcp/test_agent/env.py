"""Shared env setup for SDK + ML integration tests."""

from __future__ import annotations

import os
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_CHECKPOINT = (
    WORKSPACE_ROOT / "repos/unplug_exp/dist/vm-v10-750k-diagnostic-bundle/"
    "experiments/unplug-tiny-v10-350k/checkpoint-24615"
)
DEFAULT_PROBES = WORKSPACE_ROOT / "repos/unplug_exp/configs/fp_probe_queries.json"
DOTENV_PATH = WORKSPACE_ROOT / "jakarta/.env"


def load_dotenv(path: Path | None = None) -> None:
    env_path = path or DOTENV_PATH
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def resolve_checkpoint(explicit: Path | None = None) -> Path | None:
    if explicit is not None and explicit.is_dir():
        return explicit
    env_path = os.environ.get("UNPLUG_MODEL_PATH")
    if env_path and Path(env_path).is_dir():
        return Path(env_path)
    if DEFAULT_CHECKPOINT.is_dir():
        return DEFAULT_CHECKPOINT
    return None


def configure_ml_env(*, checkpoint: Path | None = None, require: bool = False) -> Path | None:
    """Set UNPLUG_ACTIVE_MODEL / UNPLUG_MODEL_PATH when a checkpoint is available."""
    ckpt = resolve_checkpoint(checkpoint)
    if ckpt is None:
        if require:
            msg = (
                "ML checkpoint required but not found. "
                "Set UNPLUG_MODEL_PATH or extract vm-v10-750k-diagnostic-bundle."
            )
            raise FileNotFoundError(msg)
        return None
    os.environ.setdefault("UNPLUG_ACTIVE_MODEL", "small")
    os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
    return ckpt
