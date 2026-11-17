"""Test runner for Detector 4 v1 — secrets scanner (LLM Guard, Member 2, Day 9).

Day 3 handoff: test on 20 prompts with secrets vs 20 code samples without
them. Every example is fake / synthetic (AWS's own published examples,
FAKE keys, example.test domains). Lab-only, never real user data.

Expected: all 20 secret prompts -> blocked (except the sk_test_ one,
which Day 3 says is suspicious, not blocked), all 20 code samples -> clean.
"""
import time

from detector_secrets import detect_secrets

# --- 20 prompts WITH secrets: (prompt, expected verdict, must-be-masked type) ---
SECRET_CASES = [
    ("Here is my key AKIAIOSFODNN7EXAMPLE for the deploy.", "blocked", "AWS_ACCESS_KEY"),
    ("aws_access_key_id = AKIAZZZZZZZZZZZZZZZZ", "blocked", "AWS_ACCESS_KEY"),
    ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "blocked", "AWS_SECRET_KEY"),
    ("my secret key is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY please use it", "blocked", "AWS_SECRET_KEY"),
    ("token ghp_FAKE1234567890abcdefghijklmnopqrstuv for the repo", "blocked", "GITHUB_TOKEN"),
    ("github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ1234", "blocked", "GITHUB_TOKEN"),
    ("stripe key sk_live_FAKE1234567890ab charge the card", "blocked", "STRIPE_LIVE_KEY"),
    ("rk_live_FAKE1234567890ab for the dashboard", "blocked", "STRIPE_LIVE_KEY"),
    ("api_key = \"FAKE-1234-5678-90ab-cdef12345678\"", "blocked", "API_KEY"),
    ("access_token: abcdef1234567890ghijklmnop", "blocked", "API_KEY"),
    ("-----BEGIN RSA PRIVATE KEY-----", "blocked", "PRIVATE_KEY"),
    ("here is the key:\n-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk\n-----END PRIVATE KEY-----", "blocked", "PRIVATE_KEY"),
    ("auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKE-SIGNATURE", "blocked", "JWT"),
    ("bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY2FybG9zIn0.FAKEabc123XYZ", "blocked", "JWT"),
    ("my password is Hunter2FAKE!", "blocked", "PASSWORD"),
    ("password: CorrectHorseBatteryStaple9", "blocked", "PASSWORD"),
    ("connect with postgres://user:FAKEpass@db.example.test:5432/mydb", "blocked", "DB_CREDENTIALS"),
    ("mongodb://admin:FAKEpass123@mongo.example.test:27017/appdb", "blocked", "DB_CREDENTIALS"),
    ("post to https://hooks.slack.com/services/T00000000/FAKE/FAKE1234567890abcdef", "blocked", "WEBHOOK_URL"),
    ("notify https://discord.com/api/webhooks/123456789012345678/FAKEtoken-abcDEF123", "blocked", "WEBHOOK_URL"),
]

# --- 20 code samples WITHOUT secrets: must stay clean ---
# Includes the Day 7 trap: `api_key` as a bare variable name in code.
BENIGN_CASES = [
    "def call(api_key): return headers(api_key)",
    "print(api_key)",
    "api_key = None",
    "API_KEY = os.environ.get(\"API_KEY\")",
    "api_key = \"YOUR_API_KEY\"",
    "api_key = \"example\"",
    "Set your password in the settings page.",
    "How do I reset my password?",
    "password = getpass.getpass()",
    "const token = \"abc\"",
    "secret = \"test\"",
    "# TODO: add api_key here before release",
    "curl https://api.example.test/v1/users",
    "AWS keys start with AKIA, remember that.",
    "GitHub tokens start with ghp_ — keep them safe.",
    "Use sk_live_ keys in production, never in chat.",
    "JWTs start with eyJ and have three parts.",
    "-----BEGIN PUBLIC KEY-----",
    "Send alerts to https://hooks.slack.com/services/ when ready.",
    "postgres://localhost:5432/mydb has no login yet",
]


def run():
    passed = 0
    total = 0
    failures = []
    t0 = time.perf_counter()
    for prompt, expected, typ in SECRET_CASES:
        total += 1
        r = detect_secrets(prompt)
        tag = f"[REDACTED:{typ}]"
        ok = r["verdict"] == expected and tag in r["masked_prompt"] \
            and "FAKE" not in r["masked_prompt"] and "EXAMPLE" not in r["masked_prompt"] \
            and "Hunter2" not in r["masked_prompt"]
        # The postgres case masks only user:pass@, so the host stays — the
        # password itself must be gone, not the whole URL.
        if typ == "DB_CREDENTIALS":
            ok = r["verdict"] == expected and tag in r["masked_prompt"] \
                and "FAKEpass" not in r["masked_prompt"]
        if ok:
            passed += 1
        else:
            failures.append(f"SECRET {prompt[:60]!r} -> {r}")
    for prompt in BENIGN_CASES:
        total += 1
        r = detect_secrets(prompt)
        if r["verdict"] == "clean":
            passed += 1
        else:
            failures.append(f"BENIGN {prompt[:60]!r} -> {r}")
    elapsed = (time.perf_counter() - t0) / total * 1000
    print(f"{passed}/{total} checks pass, {elapsed:.2f} ms per call (target < 50 ms)")
    for f in failures:
        print("FAIL:", f)
    # Known behaviour, not part of the 20 vs 20: Day 3 says test keys are
    # allowed at low severity, so sk_test_ is suspicious, never blocked.
    r = detect_secrets("sk_test_FAKE1234567890abcdefghijklmnop")
    ok_test = r["verdict"] == "suspicious" and r["masked_prompt"] == "[REDACTED:STRIPE_TEST_KEY]"
    print(f"sk_test_ exception: {'pass' if ok_test else 'FAIL: ' + str(r)}")
    return passed == total and ok_test


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
