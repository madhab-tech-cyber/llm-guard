"""Strict local lab runtime configuration, separate from policy YAML."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .loader import PolicyError
from .rate_limit import RateLimiter


@dataclass(frozen=True)
class LabConfig:
    audit_path: Path
    quota_limit: int
    quota_window_seconds: int
    quota_max_keys: int

    def quota(self) -> RateLimiter:
        return RateLimiter(limit=self.quota_limit, window_seconds=self.quota_window_seconds,
                           max_keys=self.quota_max_keys)


def load_config(path: str | Path) -> LabConfig:
    source = Path(path)
    try:
        raw = source.read_bytes()
        if len(raw) > 4096:
            raise PolicyError("Config too large")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("Invalid lab config") from exc
    keys = {"audit_path", "quota_limit", "quota_window_seconds", "quota_max_keys"}
    if not isinstance(value, dict) or set(value) != keys:
        raise PolicyError("Invalid config fields")
    audit_path = value["audit_path"]
    if not isinstance(audit_path, str) or not 1 <= len(audit_path) <= 256 or "\x00" in audit_path:
        raise PolicyError("Invalid audit path")
    for name, upper in (("quota_limit", 100000), ("quota_window_seconds", 86400),
                        ("quota_max_keys", 100000)):
        v = value[name]
        if type(v) is not int or not 1 <= v <= upper:
            raise PolicyError("Invalid quota config")
    return LabConfig(Path(audit_path), value["quota_limit"], value["quota_window_seconds"],
                     value["quota_max_keys"])
