"""Lazy Guard construction for MCP tools."""

from __future__ import annotations

import os
from contextlib import contextmanager
from threading import RLock
from typing import Any

from unplug import Guard
from unplug.config.loader import load

_guard: Guard | None = None
_guard_fingerprint: tuple[Any, ...] | None = None
_guard_lock = RLock()


def _env_fingerprint() -> tuple[Any, ...]:
    return (
        os.environ.get("UNPLUG_MODE", "local"),
        os.environ.get("UNPLUG_CONFIG"),
        os.environ.get("UNPLUG_SERVER_URL"),
        os.environ.get("UNPLUG_API_KEY"),
        os.environ.get("UNPLUG_ACTIVE_MODEL"),
        os.environ.get("UNPLUG_MODEL_PATH"),
    )


def get_guard(*, reset: bool = False) -> Guard:
    global _guard, _guard_fingerprint

    with _guard_lock:
        fp = _env_fingerprint()
        if reset or _guard is None or _guard_fingerprint != fp:
            config_path = os.environ.get("UNPLUG_CONFIG")
            cfg = load(file_path=config_path) if config_path else load()
            mode = os.environ.get("UNPLUG_MODE", "local")
            _guard = Guard(
                config=cfg,
                mode=mode,
                server_url=os.environ.get("UNPLUG_SERVER_URL"),
                server_api_key=os.environ.get("UNPLUG_API_KEY"),
            )
            _guard_fingerprint = fp
        return _guard


@contextmanager
def guard_session_lock():
    with _guard_lock:
        yield


def reset_guard() -> None:
    global _guard, _guard_fingerprint
    with _guard_lock:
        _guard = None
        _guard_fingerprint = None
