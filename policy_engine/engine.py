"""Standalone first-match policy decisions; draft signal contract only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit import AuditError, AuditWriter
from .loader import PolicyError
from .matcher import matching_rules


@dataclass(frozen=True)
class Decision:
    action: str
    reason_code: str
    rule_id: str | None
    audit_ok: bool


def decide(*, policy: dict[str, Any], request_id: str, stage: str,
           verdict: str, scores: dict[str, float], masked_available: bool,
           audit: AuditWriter) -> Decision:
    """Decide and audit. Any invalid signal or failed append returns BLOCK."""
    action, code, rule_id = "BLOCK", "INVALID_CONTEXT", None
    try:
        if verdict not in ("clean", "suspicious", "blocked") or type(masked_available) is not bool:
            raise PolicyError("Invalid guard result")
        matches = matching_rules(policy, stage, scores)
        if verdict == "blocked":
            action, code = "BLOCK", "GUARD_BLOCKED"
        elif matches:
            first = matches[0]
            action, rule_id, code = first["action"], first["name"], "RULE_MATCH"
            if action == "REDACT" and not masked_available:
                action, code = "BLOCK", "MASK_UNAVAILABLE"
        elif verdict == "suspicious":
            action, code = "FLAG", "GUARD_SUSPICIOUS"
        else:
            action, code = "ALLOW", "CLEAN_DEFAULT"
    except (PolicyError, TypeError, ValueError, KeyError):
        pass
    try:
        audit.append(request_id=request_id, stage=stage, decision=action,
                     policy_version=policy.get("policy_version", "unknown") if isinstance(policy, dict) else "unknown",
                     reason_code=code, rule_id=rule_id)
    except AuditError:
        return Decision("BLOCK", "AUDIT_UNAVAILABLE", None, False)
    return Decision(action, code, rule_id, True)
