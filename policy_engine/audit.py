"""Minimal append-only JSONL audit for synthetic lab decisions."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
DECISIONS = frozenset({"ALLOW", "BLOCK", "REDACT", "FLAG"})


class AuditError(RuntimeError):
    """Audit append failed; caller must fail closed."""


class AuditWriter:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, *, request_id: str, stage: str, decision: str,
               policy_version: str, reason_code: str, rule_id: str | None) -> None:
        # Only allow bounded identifiers; never accept prompt/reply or detector reason text.
        identifiers = (request_id, reason_code)
        if not all(isinstance(x, str) and SAFE_ID.fullmatch(x) for x in identifiers):
            raise AuditError("Invalid audit identifier")
        if not isinstance(policy_version, str) or not SAFE_VERSION.fullmatch(policy_version):
            raise AuditError("Invalid policy version")
        if rule_id is not None and (not isinstance(rule_id, str) or not SAFE_ID.fullmatch(rule_id)):
            raise AuditError("Invalid audit rule ID")
        if stage not in ("input", "output") or decision not in DECISIONS:
            raise AuditError("Invalid audit decision")
        row = {"time_utc": datetime.now(timezone.utc).isoformat(), "request_id": request_id,
               "stage": stage, "decision": decision, "policy_version": policy_version,
               "reason_code": reason_code, "rule_id": rule_id}
        encoded = (json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            try:
                with os.fdopen(fd, "ab", closefd=False) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise AuditError("Audit append unavailable") from exc
