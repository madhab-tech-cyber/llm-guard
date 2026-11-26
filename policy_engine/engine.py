"""Standalone priority-based policy decisions; draft signal contract only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit import AuditError, AuditWriter
from .loader import PolicyError
from .matcher import matching_rules
from .rate_limit import RateLimiter

_SEVERITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ACTION = {"ALLOW": 0, "FLAG": 1, "REDACT": 2, "BLOCK": 3}


def risk_score(scores: dict[str, float], *, stage: str) -> float:
    """Conservative maximum detector score for the current stage."""
    if stage not in ("input", "output") or not isinstance(scores, dict) or not scores:
        raise PolicyError("Invalid risk context")
    from .loader import SIGNALS
    import math
    if any(not isinstance(k, str) or k not in SIGNALS or type(v) not in (int, float) or not math.isfinite(v)
           or not 0 <= v <= 1 for k, v in scores.items()):
        raise PolicyError("Invalid risk scores")
    return max(scores.values())


@dataclass(frozen=True)
class Decision:
    action: str
    reason_code: str
    rule_id: str | None
    audit_ok: bool


def decide(*, policy: dict[str, Any], request_id: str, stage: str,
           verdict: str, scores: dict[str, float], masked_available: bool,
           audit: AuditWriter, quota: RateLimiter | None = None,
           caller_id: str | None = None) -> Decision:
    """Decide and audit. Any invalid signal or failed append returns BLOCK."""
    action, code, rule_id = "BLOCK", "INVALID_CONTEXT", None
    try:
        if verdict not in ("clean", "suspicious", "blocked") or type(masked_available) is not bool:
            raise PolicyError("Invalid guard result")
        matches = matching_rules(policy, stage, scores)
        if quota is not None and (caller_id is None or not quota.allow(caller_id)):
            action, code = "BLOCK", "QUOTA_DENIED"
        elif verdict == "blocked":
            action, code = "BLOCK", "GUARD_BLOCKED"
        elif matches:
            first = max(matches, key=lambda rule: (_SEVERITY[rule["severity"]], _ACTION[rule["action"]]))
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
