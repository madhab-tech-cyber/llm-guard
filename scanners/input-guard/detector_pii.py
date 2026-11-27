"""Detector 3 v1 — PII scanner (LLM Guard, Member 2, Day 8).

Builds only on the Day 3 list (14 PII types). Regex + context rules + two
checksum checks (Verhoeff for Aadhaar, Luhn for cards). Names need context —
regex alone cannot do names safely (Day 3) — so v1 only flags a name after
"my name is / I am / contact" phrasing.

Handling (Day 3 + Day 4 v1 thresholds): PII is masked, not blocked — the
user usually pasted it by accident. Any PII found -> "suspicious" (0.70),
masked prompt returned in the Day 5 shape. No PII -> "clean".
Mask format (Day 3 handoff, shared with Day 9): [REDACTED:TYPE].

Never log the raw value: reasons name the TYPE only, never the value.
Lab-only: synthetic prompts only, never real user data.
"""
import re

# --- checksum helpers (Day 3: these are what make Aadhaar / card safe to flag) ---
_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
               [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
               [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
               [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
               [5, 9, 8, 7, 6, 0, 1, 2, 3, 4],
               [6, 5, 9, 8, 7, 1, 0, 2, 3, 4],
               [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
               [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
               [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
               [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 0, 1, 3, 2, 4, 9, 6, 7, 5],
               [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
               [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 4, 6, 1, 0, 5],
               [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def _verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    total = 0
    for i, v in enumerate(reversed(digits)):
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0


def _near(text: str, start: int, end: int, words, window: int = 50) -> bool:
    """True if any of `words` appears within `window` chars of the match."""
    low = text[max(0, start - window):min(len(text), end + window)].lower()
    return any(w in low for w in words)


# Each finder returns [(start, end, TYPE, reason)] for one PII type.
def _find_email(t):
    return [(m.start(), m.end(), "EMAIL", "email address found")
            for m in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", t)]


def _find_phone(t):
    out = []
    for m in re.finditer(r"\+?\d[\d\s\-()]{7,}\d", t):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) < 10 or len(digits) > 13:
            continue
        # Day 3 trap: order numbers / ticket IDs look like phones.
        # Flag on a +country code, an Indian mobile shape, or phone context.
        if m.group(0).strip().startswith("+") or (
                len(digits) == 10 and digits[0] in "6789" and
                _near(t, m.start(), m.end(), ("phone", "mobile", "call me", "contact", "reach me"))):
            out.append((m.start(), m.end(), "PHONE", "phone number found"))
        elif m.group(0).strip().startswith("+"):
            out.append((m.start(), m.end(), "PHONE", "phone number found"))
    return out


def _find_aadhaar(t):
    out = []
    for m in re.finditer(r"\b\d{4}\s?\d{4}\s?\d{4}\b", t):
        if _verhoeff_ok(re.sub(r"\D", "", m.group(0))):
            out.append((m.start(), m.end(), "AADHAAR", "Aadhaar number found (Verhoeff check passed)"))
    return out


def _find_pan(t):
    return [(m.start(), m.end(), "PAN", "PAN number found")
            for m in re.finditer(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", t)
            if _near(t, m.start(), m.end(), ("pan", "tax", "my card", "card number"))]


def _find_passport(t):
    return [(m.start(), m.end(), "PASSPORT", "passport number found")
            for m in re.finditer(r"\b[A-Z][0-9]{7}\b", t)
            if _near(t, m.start(), m.end(), ("passport", "travel document"))]


def _find_address(t):
    # Day 3: no single regex — house no. + street word + city + 6-digit PIN.
    out = []
    for m in re.finditer(r"\b\d{6}\b", t):
        if _near(t, m.start(), m.end(),
                 ("road", "street", "nagar", "avenue", "lane", "colony", "sector")):
            # Mask from the start of the address-ish run to the PIN.
            start = max(0, m.start() - 60)
            out.append((start, m.end(), "ADDRESS", "home address found (street + PIN)"))
    return out


def _find_dob(t):
    out = []
    for pat in (r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
                r"\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b",
                r"\b\d{4}-\d{2}-\d{2}\b"):
        for m in re.finditer(pat, t, re.I):
            if _near(t, m.start(), m.end(), ("dob", "born", "birth", "date of birth")):
                out.append((m.start(), m.end(), "DOB", "date of birth found"))
    return out


def _find_card(t):
    out = []
    for m in re.finditer(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", t):
        if _luhn_ok(m.group(0)):
            out.append((m.start(), m.end(), "CARD", "card number found (Luhn check passed)"))
    return out


def _find_ifsc(t):
    return [(m.start(), m.end(), "IFSC", "IFSC code found")
            for m in re.finditer(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t)]


def _find_bank_account(t):
    return [(m.start(), m.end(), "BANK_ACCOUNT", "bank account number found")
            for m in re.finditer(r"\b\d{9,18}\b", t)
            if _near(t, m.start(), m.end(), ("account", "bank", "ifsc", "account number"))]


def _find_driving_licence(t):
    return [(m.start(), m.end(), "DRIVING_LICENCE", "driving licence number found")
            for m in re.finditer(r"\b[A-Z]{2}[0-9]{2}[0-9]{4}[0-9]{7}\b", t)]


def _find_ip(t):
    out = []
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t):
        if all(0 <= int(o) <= 255 for o in m.group(0).split(".")) and \
                _near(t, m.start(), m.end(), ("ip", "server", "my address", "host")):
            out.append((m.start(), m.end(), "IP", "IP address found"))
    return out


def _find_gps(t):
    return [(m.start(), m.end(), "GPS", "GPS coordinates found")
            for m in re.finditer(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}", t)]


def _find_name(t):
    out = []
    # Cue words case-insensitive by spelling them out; the name itself must
    # stay capitalised, or "contact me there" would match as a name.
    for m in re.finditer(r"(?:[Mm]y name is|[Ii] am|[Ii]'m|[Cc]ontact)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)", t):
        out.append((m.start(1), m.end(1), "NAME", "person name found"))
    return out


def _find_handle(t):
    return [(m.start(), m.end(), "HANDLE", "username / handle found")
            for m in re.finditer(r"@[A-Za-z0-9_.]{3,}", t)
            if _near(t, m.start(), m.end(), ("my handle", "my username", "contact me", "username", "handle"))]


_FINDERS = [_find_email, _find_phone, _find_aadhaar, _find_pan, _find_passport,
            _find_address, _find_dob, _find_card, _find_ifsc, _find_bank_account,
            _find_driving_licence, _find_ip, _find_gps, _find_name, _find_handle]


# Day 19: confidence per PII type — how much the match itself can be
# trusted. 0.95 = exact format plus a check digit (email shape,
# Verhoeff-checked Aadhaar, Luhn-checked card, strict IFSC, GPS
# coordinates). 0.80 = strict format plus a nearby cue word (PAN,
# passport, phone, IP, driving licence). 0.65 = cue-word based and
# fuzzy (address, date of birth, name, handle, bank account digits).
# No finding at all is 0.85: the listed types are swept well, but a
# type outside the list could still be present. v1 guesses.
_TYPE_CONFIDENCE = {
    "EMAIL": 0.95, "AADHAAR": 0.95, "CARD": 0.95, "IFSC": 0.95,
    "GPS": 0.95, "PAN": 0.80, "PASSPORT": 0.80, "PHONE": 0.80,
    "IP": 0.80, "DRIVING_LICENCE": 0.80, "BANK_ACCOUNT": 0.65,
    "ADDRESS": 0.65, "DOB": 0.65, "NAME": 0.65, "HANDLE": 0.65,
}


def detect_pii(prompt_text: str) -> dict:
    """Detector 3 v1. Returns verdict, score, confidence, reasons, findings, masked prompt."""
    try:
        found = []
        for finder in _FINDERS:
            found.extend(finder(prompt_text))
        # Drop overlaps: keep the earliest, longest match for a span.
        found.sort(key=lambda f: (f[0], -(f[1] - f[0])))
        kept, last_end = [], -1
        for f in found:
            if f[0] >= last_end:
                kept.append(f)
                last_end = f[1]
        reasons = [f"PII detector 0.70: {r}." for _, _, _, r in kept]
        masked = prompt_text
        for start, end, typ, _ in sorted(kept, reverse=True):
            masked = masked[:start] + f"[REDACTED:{typ}]" + masked[end:]
        verdict = "suspicious" if kept else "clean"
        confidence = (max(_TYPE_CONFIDENCE.get(typ, 0.65)
                          for _, _, typ, _ in kept) if kept else 0.85)
        return {"verdict": verdict, "score": 0.70 if kept else 0.0,
                "confidence": confidence,
                "reasons": reasons,
                "findings": [{"type": typ} for _, _, typ, _ in kept],
                "masked_prompt": masked}
    except Exception as exc:  # fail closed (Day 4 design)
        return {"verdict": "blocked", "score": 1.0, "confidence": 0.0,
                "reasons": [f"PII detector crashed, failing closed: {exc}."],
                "findings": [], "masked_prompt": prompt_text}


if __name__ == "__main__":
    tests = [
        "My email is rahul.sharma@example.test, please write to me.",
        "My Aadhaar is 2345 6789 0121, verify me.",
        "Explain how login systems work in general.",
    ]
    for t in tests:
        print(detect_pii(t))
