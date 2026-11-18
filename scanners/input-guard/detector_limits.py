"""Detector 5 v1 — limits checker (LLM Guard, Member 2, Day 10).

Counts only. No judgement about meaning — it stops oversize and
filler-stuffed prompts before they reach the other detectors (Day 4
design doc: "over the limit is a block on its own, whatever the
other scores say").

v1 limits are PROPOSALS, not measured facts. No limit was set in the
Day 4 design doc or the Day 5 interface agreement, so these numbers
are picked here, labelled v1, and left for the team / Day 13 baseline
to confirm or change:
- MAX_CHARS = 8000  (a normal chat prompt is a few hundred chars;
  8000 is roughly 2 pages of text)
- MAX_TOKENS_EST = 2000  (estimated, see below)
- MAX_LINES = 100  (a prompt pasted as 100+ lines is a document dump,
  not a question)

Tokens are ESTIMATED, not counted with a real tokenizer: est_tokens
= ceil(chars / 4). That is the usual rough rule for English text.
It is good enough to catch a 50,000-char paste; it is not a real
token count, and it must not be quoted as one. A real tokenizer is
a Day 36 / Member 1 job, not this detector's.

Over any one limit -> "blocked", score 1.0. Under all three ->
"clean", score 0.0. There is no suspicious band in v1: a prompt is
either inside the limits or it is stopped.
Lab-only: synthetic prompts only, never real user data.
"""
import math

MAX_CHARS = 8000
MAX_TOKENS_EST = 2000
MAX_LINES = 100

# Rough English estimate: ~4 characters per token. Labelled an estimate
# everywhere it is used — never present it as a measured token count.
_CHARS_PER_TOKEN = 4


def estimate_tokens(prompt_text: str) -> int:
    """Rough token estimate (chars / 4, rounded up). Not a tokenizer."""
    return math.ceil(len(prompt_text) / _CHARS_PER_TOKEN)


def count_lines(prompt_text: str) -> int:
    """Lines in the prompt. An empty prompt has 0 lines, not 1."""
    if not prompt_text:
        return 0
    return prompt_text.count("\n") + 1


def check_limits(prompt_text: str) -> dict:
    """Detector 5 v1. Returns verdict, score, reasons and the counts."""
    counts = {
        "chars": len(prompt_text),
        "tokens_est": estimate_tokens(prompt_text),
        "lines": count_lines(prompt_text),
    }
    over = []
    if counts["chars"] > MAX_CHARS:
        over.append(f"{counts['chars']} characters (limit {MAX_CHARS})")
    if counts["tokens_est"] > MAX_TOKENS_EST:
        over.append(f"~{counts['tokens_est']} estimated tokens "
                    f"(limit {MAX_TOKENS_EST})")
    if counts["lines"] > MAX_LINES:
        over.append(f"{counts['lines']} lines (limit {MAX_LINES})")
    if over:
        return {"verdict": "blocked", "score": 1.0,
                "reasons": [f"Limits detector 1.00: prompt over the limit — "
                            + "; ".join(over) + "."],
                "counts": counts, "masked_prompt": prompt_text}
    return {"verdict": "clean", "score": 0.0, "reasons": [],
            "counts": counts, "masked_prompt": prompt_text}


if __name__ == "__main__":
    tests = [
        "Explain how login systems work in general.",
        "x" * 8001,
        "line\n" * 101,
    ]
    for t in tests:
        print(check_limits(t))
