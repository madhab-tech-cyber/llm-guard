"""Member 3 output guard: PII, toxicity, format, grounding and leakage checks."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    PASS = "PASS"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    REPLACE = "REPLACE"


@dataclass(frozen=True)
class Finding:
    checker: str
    category: str
    reason: str
    confidence: float
    action: str


@dataclass
class GuardResult:
    verdict: Verdict
    cleaned_response: str
    reasons: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    checker_timings_ms: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable pipeline result."""
        result = asdict(self)
        result["verdict"] = self.verdict.value
        return result


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 1, 2, 3, 4],
    [6, 5, 9, 8, 7, 1, 0, 2, 3, 4], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 0, 1, 3, 2, 4, 9, 6, 7, 5],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 4, 6, 1, 0, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_ok(value: str) -> bool:
    checksum = 0
    for index, char in enumerate(reversed(value)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(char)]]
    return checksum == 0


def _luhn_ok(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_PII_PATTERNS = (
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("AADHAAR", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("CARD", re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")),
    ("PHONE", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)
_SECRET_PATTERNS = (
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET_KEY", re.compile(r"(?:aws_secret_access_key|aws secret key|secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}", re.I)),
    ("GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")),
    ("STRIPE_LIVE_KEY", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("API_KEY", re.compile(r"(?:api_key|apikey|access_token|auth_token|secret)\s*[:=]\s*[\"']?([A-Za-z0-9_-]{16,})[\"']?", re.I)),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("PASSWORD", re.compile(r"(?:password\s*[:=]|my password is)\s*[A-Za-z0-9!@#$%^&*_+\-=]{6,}", re.I)),
    ("DB_CREDENTIALS", re.compile(r"(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+", re.I)),
    ("WEBHOOK_URL", re.compile(r"https://(?:hooks\.slack\.com/services/T[A-Z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+|discord\.com/api/webhooks/\d+/[\w-]+)", re.I)),
)
_TOXIC_PATTERNS = {
    "threat": r"\b(i will|i'm going to|we will) (kill|hurt|attack) you\b",
    "targeted_abuse": r"\b(you are|you're) (a )?(worthless|disgusting|subhuman)\b",
    "violent_hate": r"\b(kill all|exterminate all) [a-z -]{2,30}\b",
}
_LEAK_PATTERNS = (
    r"(?i)\b(system prompt|hidden instructions|developer message)\s*[:=]",
    r"(?i)\bhere (is|are) (my|the) (system prompt|hidden instructions)\b",
    r"(?i)\bthe exact instructions I was given are\b",
)
_CANDIDATE = re.compile(r"\b(?:\d+(?:[.,]\d+)?%?|[A-Z][a-z]{2,}|\d{4}-\d{2}-\d{2})\b")
SAFE_FALLBACK = (
    "I can’t provide that response safely. I can help with a safer, "
    "high-level alternative or a benign explanation."
)


def _mask_pii(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Mask PII and return type-only metadata; never retain matched values."""
    spans: list[tuple[int, int, str]] = []
    for kind, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "AADHAAR" and not _verhoeff_ok(re.sub(r"\D", "", value)):
                continue
            if kind == "CARD" and not _luhn_ok(value):
                continue
            if kind == "PHONE" and not 10 <= len(re.sub(r"\D", "", value)) <= 13:
                continue
            if kind == "IP" and any(int(part) > 255 for part in value.split(".")):
                continue
            spans.append((match.start(), match.end(), kind))

    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if kind == "API_KEY":
                value = match.group(1)
                if value.upper() in {"YOUR_API_KEY", "YOURAPIKEY", "REPLACE_ME", "EXAMPLE"}:
                    continue
                if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
                    continue
            spans.append((match.start(), match.end(), kind))

    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    selected: list[tuple[int, int, str]] = []
    end = -1
    for item in spans:
        if item[0] >= end:
            selected.append(item)
            end = item[1]
    cleaned = text
    for start, stop, kind in reversed(selected):
        cleaned = cleaned[:start] + f"[REDACTED:{kind}]" + cleaned[stop:]
    return cleaned, [(kind, "Sensitive value detected.") for _, _, kind in selected]

def _check_json(text: str, required_fields: list[str] | None) -> tuple[bool, str]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        return False, f"Invalid JSON: {getattr(exc, 'msg', 'input is not text')}."
    if required_fields:
        if not isinstance(value, dict):
            return False, "JSON root must be an object."
        missing = [key for key in required_fields if key not in value]
        if missing:
            return False, "Missing required fields: " + ", ".join(missing) + "."
    return True, "Valid JSON."


def _grounding_signal(answer: str, context: str) -> tuple[float, list[str]]:
    """Flag unsupported numeric/date claims more strongly than isolated capitals."""
    if not context.strip():
        return 0.0, []
    source = context.casefold()
    unsupported = list(dict.fromkeys(
        token for token in _CANDIDATE.findall(answer) if token.casefold() not in source
    ))
    if not unsupported:
        return 0.0, []
    numeric_or_date = [
        token for token in unsupported
        if re.fullmatch(r"\d+(?:[.,]\d+)?%?|\d{4}-\d{2}-\d{2}", token)
    ]
    # A single unsupported number/date crosses REPLACE (0.75); one isolated
    # capitalised word remains below it to avoid replacing ordinary prose.
    confidence = 0.75 if numeric_or_date else min(0.70, 0.55 + 0.1 * len(unsupported))
    return confidence, unsupported[:20]

def check_output(
    response: str,
    *,
    prompt: str = "",
    context: str = "",
    expected_format: str | None = None,
    required_fields: list[str] | None = None,
    pii_policy: str = "mask",
) -> GuardResult:
    """Return PASS/REDACT/REPLACE after checking a model response.

    A checker error fails closed. Grounding is a weak heuristic and cannot prove
    that an answer is true. Unsupported-claim signals trigger replacement because
    the guard cannot safely edit a factual claim without changing its meaning.
    """
    if not isinstance(response, str) or not response.strip():
        return GuardResult(Verdict.REPLACE, SAFE_FALLBACK,
                           ["Empty or non-text model output."], {"input": 1.0})
    timings: dict[str, float] = {}
    scores: dict[str, float] = {}
    findings: list[Finding] = []
    reasons: list[str] = []

    def run(name: str, function: Any) -> Any:
        started = time.perf_counter()
        try:
            result = function()
        except Exception as exc:
            timings[name] = round((time.perf_counter() - started) * 1000, 3)
            raise RuntimeError(f"{name} checker failed") from exc
        timings[name] = round((time.perf_counter() - started) * 1000, 3)
        return result

    try:
        if pii_policy not in {"mask", "drop"}:
            raise ValueError("pii_policy must be 'mask' or 'drop'")
        cleaned, sensitive = run("pii", lambda: _mask_pii(response))
        secret_types = {
            "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN", "STRIPE_LIVE_KEY",
            "API_KEY", "PRIVATE_KEY", "JWT", "PASSWORD", "DB_CREDENTIALS", "WEBHOOK_URL"
        }
        pii = [(kind, reason) for kind, reason in sensitive if kind not in secret_types]
        secrets = [(kind, reason) for kind, reason in sensitive if kind in secret_types]
        scores["pii"] = 0.8 if pii else 0.0
        scores["secrets"] = 0.95 if secrets else 0.0
        for kind, reason in pii:
            findings.append(Finding("pii", kind, reason, 0.8, pii_policy.upper()))
            reasons.append(f"PII detected: {kind}.")
        for kind, reason in secrets:
            findings.append(Finding("secrets", kind, reason, 0.95, "REPLACE"))
            reasons.append(f"Secret detected: {kind}.")
        if pii and pii_policy == "drop":
            return GuardResult(Verdict.BLOCK, "", reasons, scores, findings, timings)

        toxic = run("toxicity", lambda: [
            category for category, pattern in _TOXIC_PATTERNS.items()
            if re.search(pattern, cleaned, re.I)
        ])
        scores["toxicity"] = 0.9 if toxic else 0.0
        for category in toxic:
            findings.append(Finding("toxicity", category, "Potential harmful content detected.",
                                    0.9, "BLOCK"))
            reasons.append(f"Potential harmful content: {category}.")

        leaked = run("prompt_leakage", lambda: any(
            re.search(pattern, cleaned) for pattern in _LEAK_PATTERNS
        ))
        scores["prompt_leakage"] = 0.95 if leaked else 0.0
        if leaked:
            findings.append(Finding("prompt_leakage", "instruction_disclosure",
                                    "Possible hidden-instruction disclosure.", 0.95, "BLOCK"))
            reasons.append("Possible hidden-instruction disclosure.")

        if expected_format == "json":
            valid, detail = run("format", lambda: _check_json(cleaned, required_fields))
            scores["format"] = 0.0 if valid else 0.9
            if not valid:
                findings.append(Finding("format", "invalid_json", detail, 0.9, "BLOCK"))
                reasons.append(detail)
        else:
            scores["format"] = 0.0

        if context:
            confidence, unsupported = run(
                "grounding", lambda: _grounding_signal(cleaned, context)
            )
            scores["grounding"] = confidence
            if unsupported:
                # Do not copy candidate values into findings or reasons.
                # The type-only signal avoids retaining potentially sensitive text.
                findings.append(Finding("grounding", "unsupported_claim_signal",
                                        "Unsupported claim signal detected by context heuristic.",
                                        confidence, "BLOCK"))
                reasons.append("Possible unsupported claims detected by heuristic.")
        else:
            scores["grounding"] = 0.0

        if secrets or toxic or leaked or scores["format"] >= 0.9 or scores["grounding"] >= 0.75:
            return GuardResult(Verdict.REPLACE, SAFE_FALLBACK, reasons,
                               scores, findings, timings)
        if pii:
            return GuardResult(Verdict.REDACT, cleaned, reasons,
                               scores, findings, timings)
        return GuardResult(Verdict.PASS, cleaned, reasons, scores, findings, timings)
    except Exception as exc:
        return GuardResult(Verdict.REPLACE, SAFE_FALLBACK,
                           reasons + [str(exc) + "; failing closed."],
                           {**scores, "checker_failure": 1.0}, findings, timings)


class StreamingOutputGuard:
    """Fail-safe streaming adapter: buffer all chunks, validate, then release.

    feed() intentionally returns no content. This prevents a sensitive value split
    across chunk boundaries from leaking before a whole-answer check can run.
    """
    def __init__(self, **options: Any) -> None:
        self._chunks: list[str] = []
        self._options = options
        self._finished = False

    def feed(self, chunk: str) -> str:
        if self._finished:
            raise RuntimeError("stream already finished")
        if not isinstance(chunk, str):
            raise TypeError("chunk must be text")
        self._chunks.append(chunk)
        return ""

    def finish(self) -> GuardResult:
        if self._finished:
            raise RuntimeError("stream already finished")
        self._finished = True
        return check_output("".join(self._chunks), **self._options)
