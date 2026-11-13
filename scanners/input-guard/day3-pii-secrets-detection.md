# Day 3 — Member 2 Input Guard: PII types + secrets to detect

**Date:** Saturday 2026-11-14 (Day 3)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** List PII types to detect (names, emails, phones, Aadhaar/PAN-style IDs, addresses) + secrets (API keys, tokens).
**Lab-only rule (from the Member 2 schedule, p.1):** use only synthetic test prompts the team writes itself. Never test on real user data. Every example below is fake — made-up names, `example.test` domains, `FAKE` keys. Test them only against your own Input Guard module / lab setup.
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/day3-pii-secrets-detection.md` (next to the Day 1 and Day 2 files)

## Why this day matters, in simple words

Days 1–2 were about bad instructions. Day 3 is about bad *data*: a user pastes their own private details — or someone else's — into the prompt, and the model then stores it, repeats it, or leaks it in an answer. The Input Guard must spot private data and secrets *before* the prompt reaches the LLM, so the guard can mask them or block the request.

Two different jobs, one scanner family:
- **PII (personal data):** things that identify a real person. Mask them, don't block — the user usually pasted them by accident.
- **Secrets (credentials):** keys, tokens, passwords. Block or heavily mask — a leaked key is a live break-in, not a typo.

## Part A. PII types to detect (1–14)

Each entry: what it is, a fake example, the pattern the scanner looks for, and the false-positive trap to watch for.

### 1. Person name
**Example:** `Rahul Sharma`, `Priya Nair`
**Pattern:** named-entity recognition (a name list / NER model) — regex alone cannot do names safely.
**Trap:** common words are also names ("Hope", "Summer", "Kumar" as a word). Needs context: "my name is ___", "contact ___".

### 2. Email address
**Example:** `rahul.sharma@example.test`
**Pattern:** `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` — then check the domain is not a known fake/test domain.
**Trap:** very reliable pattern, low false positives. Still, `user@localhost` and code like `a@b` need a length check.

### 3. Phone number (India + international)
**Example:** `+91 98765 43210`, `09876543210`, `+1 (415) 555-0132`
**Pattern:** `\+?\d[\d\s\-()]{7,}\d` plus a country-code check; Indian mobiles: `[6-9]\d{9}` after stripping spaces.
**Trap:** order numbers, ticket IDs and years look like phone numbers. Require 10+ digits and a phone-like context.

### 4. Aadhaar number (India)
**Example:** `2345 6789 0123` (fake — real Aadhaar follows the Verhoeff checksum)
**Pattern:** `\d{4}\s?\d{4}\s?\d{4}` + Verhoeff checksum validation to kill false positives.
**Trap:** any 12-digit number matches the shape. The checksum check is what makes this safe to flag.

### 5. PAN card number (India)
**Example:** `ABCDE1234F` (fake)
**Pattern:** `[A-Z]{5}[0-9]{4}[A-Z]{1}` — 5 letters, 4 digits, 1 letter.
**Trap:** product codes and serial numbers share the shape. Flag only when it appears near identity words ("PAN", "tax", "my card").

### 6. Passport number
**Example:** `A1234567` (fake, Indian format: 1 letter + 7 digits)
**Pattern:** `[A-Z][0-9]{7}` with context words ("passport", "travel document").
**Trap:** weak alone — many IDs share this shape. Context words are mandatory.

### 7. Postal / home address
**Example:** `12, MG Road, Bengaluru, Karnataka 560001`
**Pattern:** no single regex — look for the combination: house number + street word (Road/Street/Nagar) + city + PIN code `\d{6}`.
**Trap:** a PIN code alone is just 6 digits. Only flag the full combination.

### 8. Date of birth
**Example:** `14 March 1998`, `14/03/1998`, `1998-03-14`
**Pattern:** date shapes `\d{1,2}[/-]\d{1,2}[/-]\d{2,4}` near "DOB", "born", "birth date".
**Trap:** every date in a prompt (deadlines, event dates) matches the shape. Context words decide.

### 9. Credit / debit card number
**Example:** `4111 1111 1111 1111` (test card range, fake)
**Pattern:** `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}` + Luhn checksum validation.
**Trap:** like Aadhaar — the Luhn check is what separates a real card shape from a random 16-digit number.

### 10. Bank account / IFSC (India)
**Example:** account `12345678901`, IFSC `SBIN0001234` (fake)
**Pattern:** IFSC `[A-Z]{4}0[A-Z0-9]{6}`; account numbers 9–18 digits near "account", "bank", "IFSC".
**Trap:** account numbers alone are just digits — require the banking context.

### 11. Driving licence number (India)
**Example:** `DL1420110012345` (fake)
**Pattern:** `[A-Z]{2}[0-9]{2}[0-9]{4}[0-9]{7}` (state code + RTO + year + number).
**Trap:** long digit strings overlap with other IDs — keep the state-code prefix strict.

### 12. IP address
**Example:** `192.168.1.10` (private range, fake), `203.0.113.45` (test range)
**Pattern:** `\b(?:\d{1,3}\.){3}\d{1,3}\b` + validate each octet 0–255.
**Trap:** version numbers like `1.2.3.4` match. Only flag private/public IP context ("my IP", "server at").

### 13. Location / GPS coordinates
**Example:** `12.9716, 77.5946` (Bengaluru, public landmark coords)
**Pattern:** `-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}` — two decimals with 4+ places.
**Trap:** prices and measurements look similar. Require the comma-pair shape.

### 14. Username / handle that identifies a person
**Example:** `@rahul_sharma_98` (fake)
**Pattern:** `@[A-Za-z0-9_.]{3,}` near identity context — weak on its own.
**Trap:** mentions in code and text are everywhere. Only flag when the prompt is about a person.

## Part B. Secrets to detect (1–10)

Secrets are more urgent than PII: a leaked key works immediately. Rule: **block the request or mask the whole secret** — never pass it to the LLM, never write it to logs.

### 1. AWS access key
**Example:** `AKIAIOSFODNN7EXAMPLE` (AWS's own published example, not real)
**Pattern:** `AKIA[0-9A-Z]{16}` — fixed `AKIA` prefix + 16 chars.
**Trap:** almost no false positives. The prefix is unique to AWS.

### 2. AWS secret key (40-char base64)
**Example:** `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (AWS example)
**Pattern:** `[A-Za-z0-9/+=]{40}` near "aws_secret" or "secret key" — needs context, the shape alone is generic.
**Trap:** any 40-char token matches. Only flag with AWS context words nearby.

### 3. GitHub personal access token
**Example:** `ghp_FAKE1234567890abcdefghij1234567890` (fake)
**Pattern:** `ghp_[A-Za-z0-9]{36}` (classic) and `github_pat_[A-Za-z0-9_]{22,}` (fine-grained).
**Trap:** the `ghp_` / `github_pat_` prefix makes this very safe to flag.

### 4. Stripe API key
**Example:** `sk_test_FAKE1234567890abcdefghijklmnop` (fake, test prefix)
**Pattern:** `(sk|rk)_(live|test)_[A-Za-z0-9]{16,}`.
**Trap:** test keys are safe to show, live keys are not — the guard must treat `sk_live_` as critical and `sk_test_` as lower severity.

### 5. Generic API key / token in a prompt
**Example:** `api_key = "FAKE-1234-5678-90ab-cdef12345678"`
**Pattern:** key names (`api_key`, `apikey`, `access_token`, `auth_token`, `secret`) followed by `=`, `:` and a 16+ char value.
**Trap:** variable names in code samples. Flag only when a real-looking value follows the key name.

### 6. Private key block
**Example:** `-----BEGIN RSA PRIVATE KEY-----` (header only, no body)
**Pattern:** `-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`.
**Trap:** none — this header in a prompt is always a secret. Block immediately.

### 7. JSON Web Token (JWT)
**Example:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKE-SIGNATURE` (fake)
**Pattern:** `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` — three base64url parts, first two starting with `eyJ`.
**Trap:** very safe pattern. A JWT is a live session — treat as critical.

### 8. Password in plain text
**Example:** `my password is Hunter2FAKE!`
**Pattern:** `password\s*[:=]\s*\S{6,}` and "my password is ___" phrasing.
**Trap:** the word "password" in documentation ("set your password"). Only flag when a value is actually given.

### 9. Database connection string
**Example:** `postgres://user:FAKEpass@db.example.test:5432/mydb`
**Pattern:** `(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@[^\s]+` — a password inside a URL.
**Trap:** the password inside the URL is the secret, not the host. Mask the `user:pass@` part.

### 10. Slack / Discord webhook URL
**Example:** `https://hooks.slack.com/services/T00000000/FAKE/FAKE1234567890abcdef`
**Pattern:** `hooks\.slack\.com/services/T[A-Z0-9]+` and `discord\.com/api/webhooks/\d+/[\w-]+`.
**Trap:** safe pattern — a webhook URL is a live credential. Block or mask the token part.

## How the guard should handle each type

| Type | Action | Why |
|---|---|---|
| PII (names, emails, phones, IDs, addresses) | Mask with `[REDACTED:EMAIL]` style tags, let the prompt through | Usually accidental; blocking annoys real users |
| Secrets (keys, tokens, private keys, JWTs) | Block the request, or mask the whole secret and flag critical | A leaked secret is a live break-in |
| Test/example keys (`sk_test_`, example domains) | Allow, log at low severity | Developers paste these constantly; blocking them breaks testing |

## What the scanner must never do

- **Never write the raw secret or full PII into logs.** Log the type and the mask, never the value. `email found` is fine; the email itself is not.
- **Never send detected PII/secrets to the LLM** — mask first, then forward.
- **Never invent a PII type.** If the scanner cannot prove it with a pattern + context, it stays silent.

## Handoff to Day 8 + Day 9

- **Day 8 (PII scanner):** build the regex set from Part A, add the checksum checks (Verhoeff for Aadhaar, Luhn for cards), add the context-word rules, and measure false positives on 50 benign prompts.
- **Day 9 (secrets scanner):** build the prefix-based patterns from Part B (AKIA, ghp_, sk_live_, BEGIN PRIVATE KEY, eyJ), add the key-name + value rule, and test on 20 prompts with secrets vs 20 code samples without them.
- **Shared rule:** one masking format for both scanners — `[REDACTED:TYPE]` — so Member 3 (Output Guard) and Member 4 (Policy Engine) read the same tags.

## Sources used for the patterns (not copied word-for-word)

- OWASP Top 10 for LLM Applications — LLM02 Sensitive Information Disclosure: https://genai.owasp.org
- Microsoft Presidio — PII entity types and recognizers (what counts as PII, and why names need NER not regex): https://microsoft.github.io/presidio/
- Gitleaks / detect-secrets — secret pattern catalogues (AWS, GitHub, Stripe, JWT, private keys): https://github.com/gitleaks/gitleaks
- PortSwigger Web Security Academy — API key and authentication material: https://portswigger.net/web-security
