"""Detector 4 v1 — secrets scanner (LLM Guard, Member 2, Day 9).

Builds only on the Day 3 list, Part B (10 secret types). Prefix-based
patterns first (AKIA, ghp_, sk_live_, BEGIN PRIVATE KEY, eyJ), then the
key-name + value rule and the context-gated AWS-secret rule.

Handling (Day 3 + Day 4 v1 thresholds): a live secret is a live break-in,
so any real secret -> "blocked" (0.90+), masked prompt returned in the
Day 5 shape. Test keys (sk_test_) are the one exception Day 3 names:
developers paste them constantly, so they are "suspicious" (0.50),
masked, allowed through at low severity. No secret -> "clean".
Mask format (Day 3 handoff, shared with Day 8): [REDACTED:TYPE].

Never log the raw value: reasons name the TYPE only, never the value.
Lab-only: synthetic prompts only, never real user data.
"""
import re

# Each finder returns [(start, end, TYPE, reason)] for one secret type.
# Scores: 0.95 = prefix proves it (near-zero false positives),
# 0.90 = pattern + context proves it, 0.50 = test key, allowed through.

def _find_aws_key(t):
    return [(m.start(), m.end(), "AWS_ACCESS_KEY", "AWS access key found")
            for m in re.finditer(r"AKIA[0-9A-Z]{16}", t)]


def _near(text, start, end, words, window=60):
    """True if any of `words` appears within `window` chars of the match."""
    low = text[max(0, start - window):min(len(text), end + window)].lower()
    return any(w in low for w in words)


def _find_aws_secret(t):
    # Day 3 trap: a bare 40-char token matches anything. Flag only with
    # AWS context words nearby.
    out = []
    for m in re.finditer(r"[A-Za-z0-9/+=]{40}", t):
        if _near(t, m.start(), m.end(),
                 ("aws_secret", "aws secret", "secret key", "secret_access_key")):
            out.append((m.start(), m.end(), "AWS_SECRET_KEY",
                        "AWS secret key found"))
    return out


def _find_github_token(t):
    out = [(m.start(), m.end(), "GITHUB_TOKEN", "GitHub personal access token found")
           for m in re.finditer(r"ghp_[A-Za-z0-9]{36}", t)]
    out += [(m.start(), m.end(), "GITHUB_TOKEN", "GitHub personal access token found")
            for m in re.finditer(r"github_pat_[A-Za-z0-9_]{22,}", t)]
    return out


def _find_stripe_key(t):
    # sk_live_ is critical; sk_test_ is the Day 3 exception (suspicious, allowed).
    out = [(m.start(), m.end(), "STRIPE_LIVE_KEY", "live Stripe key found")
           for m in re.finditer(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}", t)]
    out += [(m.start(), m.end(), "STRIPE_TEST_KEY", "test Stripe key found (low severity)")
            for m in re.finditer(r"(?:sk|rk)_test_[A-Za-z0-9]{16,}", t)]
    return out


def _find_generic_key(t):
    # Day 3 rule: key name + = / : + a real-looking 16+ char value.
    # Day 7 lesson: a bare `api_key` variable name in code must NOT flag
    # (that was a known false positive). So a value is required, it must
    # mix letters and digits (or look like a token), and placeholders and
    # short values stay clean.
    out = []
    pat = re.compile(
        r"(?:api_key|apikey|access_token|auth_token|secret)"
        r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?", re.IGNORECASE)
    for m in pat.finditer(t):
        value = m.group(1)
        if value.upper() in ("YOUR_API_KEY", "YOURAPIKEY", "REPLACE_ME", "EXAMPLE"):
            continue
        if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
            continue
        out.append((m.start(1), m.end(1), "API_KEY", "API key / token value found"))
    return out


def _find_private_key(t):
    # Day 3: this header in a prompt is always a secret. Block immediately,
    # header alone is enough. If a full block is pasted, mask to the END line.
    out = []
    for m in re.finditer(
            r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", t):
        end = m.end()
        end_m = re.search(r"-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
                          t[end:])
        if end_m:
            end = end + end_m.end()
        out.append((m.start(), end, "PRIVATE_KEY", "private key block found"))
    return out


def _find_jwt(t):
    return [(m.start(), m.end(), "JWT", "JSON Web Token found")
            for m in re.finditer(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", t)]


def _find_password(t):
    # Only flag when a value is actually given. "Set your password" (docs)
    # and "how do I reset my password?" have no value and stay clean.
    # The value must not be code: a trailing dot/paren (getpass.getpass())
    # kills the match via the lookahead.
    out = []
    pat = re.compile(
        r"(?:password\s*[:=]|my password is)\s*"
        r"([A-Za-z0-9!@#$%^&*_+\-=]{6,})(?![\w.()])", re.IGNORECASE)
    for m in pat.finditer(t):
        out.append((m.start(1), m.end(1), "PASSWORD", "plain-text password found"))
    return out


def _find_db_string(t):
    # A password inside a URL is the secret, not the host: mask user:pass@ only.
    out = []
    pat = re.compile(
        r"(?:postgres|mysql|mongodb|redis)://([^:\s]+):([^@\s]+)@[^\s]+")
    for m in pat.finditer(t):
        out.append((m.start(1), m.end(2), "DB_CREDENTIALS",
                    "password inside a database connection string found"))
    return out


def _find_webhook(t):
    out = [(m.start(), m.end(), "WEBHOOK_URL", "Slack webhook URL found")
           for m in re.finditer(
               r"https://hooks\.slack\.com/services/T[A-Z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+", t)]
    out += [(m.start(), m.end(), "WEBHOOK_URL", "Discord webhook URL found")
            for m in re.finditer(
                r"https://discord\.com/api/webhooks/\d+/[\w-]+", t)]
    return out


_FINDERS = [
    (_find_aws_key, 0.95), (_find_aws_secret, 0.90), (_find_github_token, 0.95),
    (_find_stripe_key, 0.95), (_find_generic_key, 0.90), (_find_private_key, 0.95),
    (_find_jwt, 0.95), (_find_password, 0.90), (_find_db_string, 0.95),
    (_find_webhook, 0.90),
]
# Test keys are the Day 3 exception: suspicious, not blocked.
_TEST_KEY_SCORE = 0.50


def detect_secrets(prompt_text: str) -> dict:
    """Detector 4 v1. Returns verdict, score, confidence, reasons, masked prompt (Day 5 shape).

    Day 19 confidence: a prefix that proves the format (0.95 finder
    score: AKIA, ghp_, sk_live_, BEGIN PRIVATE KEY, eyJ, DB string)
    is 0.95 confident; a pattern-plus-context match (0.90 finder
    score: generic key, password, webhook, AWS secret) is 0.85. A
    test key is still 0.95 confident as a finding — its format is
    exact, only its severity is low (0.50). No finding is 0.80: the
    ten listed shapes are swept well, but a novel secret format
    could still pass. v1 guesses.
    """
    found = []  # (start, end, TYPE, reason, score)
    for finder, score in _FINDERS:
        for start, end, typ, reason in finder(prompt_text):
            if typ == "STRIPE_TEST_KEY":
                found.append((start, end, typ, reason, _TEST_KEY_SCORE))
            else:
                found.append((start, end, typ, reason, score))
    if not found:
        return {"verdict": "clean", "score": 0.0, "confidence": 0.80,
                "reasons": [], "masked_prompt": prompt_text}
    best = max(f[4] for f in found)
    confidence = max(0.95 if (f[2] == "STRIPE_TEST_KEY" or f[4] >= 0.95) else 0.85
                     for f in found)
    reasons = [f"Secrets detector {f[4]:.2f}: {f[3]}." for f in found]
    if best >= 0.90:
        verdict = "blocked"
    elif best >= 0.50:
        verdict = "suspicious"
    else:
        verdict = "clean"
    # Mask longest spans first so nested matches do not double-mask.
    masked = prompt_text
    for start, end, typ, _reason, _score in sorted(found, key=lambda f: -f[1]):
        masked = masked[:start] + f"[REDACTED:{typ}]" + masked[end:]
    return {"verdict": verdict, "score": best, "confidence": confidence,
            "reasons": reasons, "masked_prompt": masked}


if __name__ == "__main__":
    tests = [
        "Here is my key AKIAIOSFODNN7EXAMPLE for the deploy.",
        "api_key = \"FAKE-1234-5678-90ab-cdef12345678\"",
        "def call(api_key): return headers(api_key)",
        "sk_test_FAKE1234567890abcdefghijklmnop",
    ]
    for t in tests:
        print(detect_secrets(t))
