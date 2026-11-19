"""Member 3 output guard: PII, toxicity, format, grounding and leakage checks."""
from __future__ import annotations

import json
import re
import time
import unicodedata
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


_PII_PATTERNS = (
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("EMAIL", re.compile(r"(?i)(?<![\w.+-])[\w.+-]+\s*(?:\[at\]|\(at\)|@|\bat\b)\s*[\w-]+\s*(?:\[dot\]|\(dot\)|\[\.\]|\bdot\b|\.)\s*[\w-]+")),
    ("EMAIL", re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+\[\.\][\w-]+")),
    ("PHONE", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
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


def _normalize_for_detection(text: str) -> str:
    """Normalize common Unicode homoglyphs and punctuation evasions for matching."""
    normalized = unicodedata.normalize("NFKC", text).translate(str.maketrans({
        "і": "i", "І": "I", "ӏ": "l", "Ӏ": "I", "ο": "o", "Ο": "O",
        "а": "a", "А": "A", "е": "e", "Е": "E", "с": "c", "С": "C",
        "р": "p", "Р": "P", "х": "x", "Х": "X", "у": "y", "У": "Y",
    }))
    return re.sub(r"(?<=[A-Za-z])[\W_]+(?=[A-Za-z])", " ", normalized)


def _mask_pii(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Mask likely PII and return only type/value-free finding metadata."""
    spans: list[tuple[int, int, str]] = []
    for kind, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "PHONE" and not 10 <= len(re.sub(r"\D", "", value)) <= 13:
                continue
            if kind == "IP" and any(int(part) > 255 for part in value.split(".")):
                continue
            if kind == "PAN" and not re.search(r"\b(PAN|tax|identity)\b", text, re.I):
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
    return cleaned, [(kind, "Potential personal data detected.") for _, _, kind in selected]


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
    """Lexically flag candidate names/numbers absent from context; not fact verification."""
    if not context.strip():
        return 0.0, []
    source = context.casefold()
    unsupported = list(dict.fromkeys(
        token for token in _CANDIDATE.findall(answer) if token.casefold() not in source
    ))
    return (min(0.95, 0.55 + 0.1 * len(unsupported)) if unsupported else 0.0,
            unsupported[:20])


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
        cleaned, pii = run("pii", lambda: _mask_pii(response))
        scores["pii"] = 0.8 if pii else 0.0
        for kind, reason in pii:
            findings.append(Finding("pii", kind, reason, 0.8, pii_policy.upper()))
            reasons.append(f"PII detected: {kind}.")
        if pii and pii_policy == "drop":
            return GuardResult(Verdict.BLOCK, "", reasons, scores, findings, timings)

        normalized_for_detection = _normalize_for_detection(cleaned)
        toxic = run("toxicity", lambda: [
            category for category, pattern in _TOXIC_PATTERNS.items()
            if re.search(pattern, normalized_for_detection, re.I)
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
                sample = ", ".join(unsupported[:5])
                findings.append(Finding("grounding", "unsupported_claim_signal",
                                        "Tokens absent from supplied context: " + sample,
                                        confidence, "BLOCK"))
                reasons.append("Possible unsupported claims (heuristic): " + sample + ".")
        else:
            scores["grounding"] = 0.0

        if toxic or leaked or scores["format"] >= 0.9 or scores["grounding"] >= 0.75:
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
