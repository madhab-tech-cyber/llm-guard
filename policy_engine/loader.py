"""Bounded, strict YAML policy loader for synthetic lab rules."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

import yaml

MAX_BYTES = 64 * 1024
MAX_RULES = 100
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SIGNALS = frozenset({"injection", "jailbreak_encoding", "pii", "secrets", "limits", "sanitizer", "toxicity", "prompt_leakage", "format", "grounding", "input"})
ACTIONS = frozenset({"ALLOW", "BLOCK", "REDACT", "FLAG"})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class PolicyError(ValueError):
    """Safe, bounded policy validation error."""


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise PolicyError("YAML aliases are not allowed")
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise PolicyError("YAML anchors are not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        self.flatten_mapping(node)
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise PolicyError("Duplicate or non-string YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _fields(obj: Any, required: set[str], where: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != required:
        raise PolicyError(f"Invalid fields in {where}")
    return obj


def validate_policy(data: Any) -> dict[str, Any]:
    root = _fields(data, {"policy_version", "policy_id", "rules"}, "policy")
    if root["policy_version"] != "0.1":
        raise PolicyError("Unsupported policy version")
    if not isinstance(root["policy_id"], str) or not SAFE_ID.fullmatch(root["policy_id"]):
        raise PolicyError("Invalid policy ID")
    rules = root["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise PolicyError("Invalid rule count")
    names: set[str] = set()
    for item in rules:
        rule = _fields(item, {"name", "condition", "action", "severity", "reason"}, "rule")
        name = rule["name"]
        if not isinstance(name, str) or not SAFE_ID.fullmatch(name) or name in names:
            raise PolicyError("Invalid or duplicate rule name")
        names.add(name)
        condition = _fields(rule["condition"], {"stage", "signal", "operator", "value"}, "condition")
        if condition["stage"] not in ("input", "output"):
            raise PolicyError("Invalid stage")
        if not isinstance(condition["signal"], str) or condition["signal"] not in SIGNALS:
            raise PolicyError("Unknown signal")
        if condition["operator"] not in ("gte", "lte"):
            raise PolicyError("Invalid operator")
        value = condition["value"]
        if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
            raise PolicyError("Invalid score threshold")
        if (not isinstance(rule["action"], str) or rule["action"] not in ACTIONS
                or not isinstance(rule["severity"], str) or rule["severity"] not in SEVERITIES):
            raise PolicyError("Invalid action or severity")
        reason = rule["reason"]
        if not isinstance(reason, str) or not 1 <= len(reason) <= 160 or any(ord(c) < 32 for c in reason):
            raise PolicyError("Invalid static reason")
    return root


def load_policy(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if source.stat().st_size > MAX_BYTES:
        raise PolicyError("Policy file too large")
    try:
        raw = source.read_bytes()
        if len(raw) > MAX_BYTES:
            raise PolicyError("Policy file too large")
        data = yaml.load(raw.decode("utf-8"), Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError) as exc:
        raise PolicyError("Invalid policy YAML") from exc
    return validate_policy(data)
