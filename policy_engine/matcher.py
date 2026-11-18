"""Deterministic matching of validated lab rules against detector scores."""

from __future__ import annotations

import math
from typing import Any

from .loader import PolicyError, SIGNALS, validate_policy


def matching_rules(policy: dict[str, Any], stage: str, scores: dict[str, float]) -> list[dict[str, Any]]:
    """Return rules in policy order; never treat missing signals as zero."""
    validate_policy(policy)
    if stage not in ("input", "output") or not isinstance(scores, dict):
        raise PolicyError("Invalid signal envelope")
    if not scores or any(not isinstance(key, str) or key not in SIGNALS for key in scores):
        raise PolicyError("Unknown or empty signal set")
    for score in scores.values():
        if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
            raise PolicyError("Invalid detector score")
    matched = []
    for rule in policy["rules"]:
        condition = rule["condition"]
        if condition["stage"] != stage:
            continue
        signal = condition["signal"]
        if signal not in scores:
            raise PolicyError("Missing required detector score")
        score = scores[signal]
        threshold = condition["value"]
        if (condition["operator"] == "gte" and score >= threshold) or (
            condition["operator"] == "lte" and score <= threshold
        ):
            matched.append(rule)
    return matched
