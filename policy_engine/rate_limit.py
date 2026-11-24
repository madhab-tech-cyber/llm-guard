"""Process-local, bounded fixed-window quota for synthetic lab callers."""

from __future__ import annotations

import re
import time

SAFE_KEY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RateLimiter:
    def __init__(self, *, limit: int, window_seconds: float, max_keys: int = 1024):
        if type(limit) is not int or limit < 1 or type(max_keys) is not int or max_keys < 1:
            raise ValueError("Invalid quota bounds")
        if type(window_seconds) not in (int, float) or not 0 < window_seconds <= 86400:
            raise ValueError("Invalid quota window")
        self.limit, self.window_seconds, self.max_keys = limit, window_seconds, max_keys
        self._state: dict[str, tuple[float, int]] = {}

    def allow(self, key: str, *, now: float | None = None) -> bool:
        if not isinstance(key, str) or not SAFE_KEY.fullmatch(key):
            return False
        tick = time.monotonic() if now is None else now
        if type(tick) not in (int, float) or not 0 <= tick < float("inf"):
            return False
        start, count = self._state.get(key, (tick, 0))
        if tick < start:
            return False
        if tick - start >= self.window_seconds:
            start, count = tick, 0
        if key not in self._state and len(self._state) >= self.max_keys:
            expired = [k for k, (s, _) in self._state.items() if tick - s >= self.window_seconds]
            for k in expired:
                del self._state[k]
            if len(self._state) >= self.max_keys:
                return False
        if count >= self.limit:
            return False
        self._state[key] = (start, count + 1)
        return True
