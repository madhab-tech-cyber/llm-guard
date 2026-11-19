"""Pipeline-facing adapter for the proposed LLM Guard v1 contract.

The Member 2 interface document is still marked pending Member 1 sign-off.
This adapter therefore mirrors its field conventions without claiming the
cross-team contract is approved.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .output_guard import Verdict, check_output


@dataclass(frozen=True)
class OutputGuardRequest:
    """Metadata and generated text supplied to the output guard."""
    output_text: str
    source: str
    turn_number: int
    context: str = ""
    expected_format: str | None = None
    required_fields: list[str] = field(default_factory=list)
    pii_policy: str = "mask"


@dataclass
class OutputGuardResponse:
    """Pipeline-friendly verdict and safe-to-release output."""
    verdict: str
    reasons: list[str]
    scores: dict[str, float]
    masked_output: str
    detector_timings_ms: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible response matching the shared field style."""
        return asdict(self)


def inspect_output(request: OutputGuardRequest) -> OutputGuardResponse:
    """Validate generated output and map internal verdicts to pipeline terms.

    PASS -> clean; REDACT -> suspicious; BLOCK/REPLACE -> blocked.
    """
    if not request.source.strip():
        return OutputGuardResponse(
            "blocked", ["Missing source metadata; output held fail-closed."],
            {"input": 1.0}, "", {},
        )
    if request.turn_number < 1:
        return OutputGuardResponse(
            "blocked", ["turn_number must be a positive integer."],
            {"input": 1.0}, "", {},
        )
    result = check_output(
        request.output_text,
        context=request.context,
        expected_format=request.expected_format,
        required_fields=request.required_fields or None,
        pii_policy=request.pii_policy,
    )
    mapped = {
        Verdict.PASS: "clean",
        Verdict.REDACT: "suspicious",
        Verdict.BLOCK: "blocked",
        Verdict.REPLACE: "blocked",
    }[result.verdict]
    safe_text = result.cleaned_response if mapped != "blocked" else ""
    return OutputGuardResponse(
        verdict=mapped,
        reasons=result.reasons,
        scores=result.scores,
        masked_output=safe_text,
        detector_timings_ms=result.checker_timings_ms,
    )
