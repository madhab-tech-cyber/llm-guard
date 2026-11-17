"""Test runner — Detector 3 (Day 8 PII scanner), LLM Guard Member 2.
Run: python3 test_detector_pii_day8.py   (from this folder)
All examples are synthetic / fake, from the Day 3 list. Lab-only.
"""
import time

from detector_pii import detect_pii

# (prompt, expected verdict, expected types in masked prompt, label)
CASES = [
    ("My name is Rahul Sharma, nice to meet you.", "suspicious", ["NAME"], "Day 3 #1 name, with context"),
    ("My email is rahul.sharma@example.test, please write to me.", "suspicious", ["EMAIL"], "Day 3 #2 email"),
    ("Call me on +91 98765 43210 tomorrow.", "suspicious", ["PHONE"], "Day 3 #3 phone, +91"),
    ("My Aadhaar is 2345 6789 0121, verify me.", "suspicious", ["AADHAAR"], "Day 3 #4 Aadhaar, Verhoeff-valid fake"),
    ("My PAN is ABCDE1234F for tax filing.", "suspicious", ["PAN"], "Day 3 #5 PAN, with tax context"),
    ("My passport number is A1234567, check my travel document.", "suspicious", ["PASSPORT"], "Day 3 #6 passport, with context"),
    ("I live at 12, MG Road, Bengaluru, Karnataka 560001.", "suspicious", ["ADDRESS"], "Day 3 #7 address (street + PIN)"),
    ("My date of birth is 14 March 1998, I was born then.", "suspicious", ["DOB"], "Day 3 #8 DOB, with born context"),
    ("My card is 4111 1111 1111 1111, charge it.", "suspicious", ["CARD"], "Day 3 #9 card, Luhn-valid test range"),
    ("My IFSC is SBIN0001234 and my account number is 12345678901 at the bank.", "suspicious", ["IFSC", "BANK_ACCOUNT"], "Day 3 #10 IFSC + bank account"),
    ("My driving licence is DL1420110012345.", "suspicious", ["DRIVING_LICENCE"], "Day 3 #11 driving licence"),
    ("My IP is 192.168.1.10, the server is down.", "suspicious", ["IP"], "Day 3 #12 IP, with server context"),
    ("Meet me at 12.9716, 77.5946 tomorrow.", "suspicious", ["GPS"], "Day 3 #13 GPS coordinates"),
    ("My handle is @rahul_sharma_98, contact me there.", "suspicious", ["HANDLE"], "Day 3 #14 handle, with contact context"),
    # Benign — must stay clean
    ("Explain how login systems work in general.", "clean", [], "benign, no PII"),
    ("My order number is 9876543210, where is my parcel?", "clean", [], "benign trap: 10-digit order number, no phone context"),
    ("The software version is 1.2.3.4, please update it.", "clean", [], "benign trap: version number, not an IP"),
    ("The meeting is on 14 March 1998? No — 14 March 2026, the deadline.", "clean", [], "benign trap: a date with no DOB context"),
    ("My Aadhaar is 2345 6789 0123, verify me.", "clean", [], "Day 3 #4 as written: fails Verhoeff, so NOT flagged — by design"),
    ("Product code ABCDE1234F is out of stock.", "clean", [], "benign trap: PAN-shaped code, no identity context"),
]

passed = 0
for prompt, want_verdict, want_types, label in CASES:
    r = detect_pii(prompt)
    got_types = [f["type"] for f in r["findings"]]
    ok = r["verdict"] == want_verdict and sorted(got_types) == sorted(want_types)
    # also check the raw value never appears in the masked prompt
    if want_types and any(t in r["masked_prompt"] for t in ("rahul.sharma@example.test", "98765", "ABCDE1234F", "4111")):
        ok = False
    passed += ok
    print(("PASS" if ok else "FAIL"), "|", label, "|", r["verdict"], got_types, "| masked:", r["masked_prompt"][:90])

t0 = time.perf_counter()
for _ in range(100):
    detect_pii("My email is rahul.sharma@example.test, please write to me.")
print(f"\n{passed}/{len(CASES)} pass. Timing: {(time.perf_counter() - t0) / 100 * 1000:.2f} ms/call (target < 50 ms).")
