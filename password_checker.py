#!/usr/bin/env python3
"""
password_checker.py

Interactive password strength checker CLI.

Features:
 - Interactive mode (getpass)
 - File input mode (one password per line)
 - Optional rockyou.txt support for common-password matching
 - Optional Bloom filter backing for rockyou for memory-efficiency
 - CSV and JSON outputs
 - Examples included (can be disabled)
"""

from __future__ import annotations
import argparse
import csv
import json
import math
import os
import re
import sys
import hashlib
from getpass import getpass
from typing import Iterable, Tuple, Dict, Any, Optional, List, Set

# -------------------------
# Basic scoring utilities
# -------------------------
COMMON_PASSWORDS = {
    "123456","password","123456789","12345678","12345","111111","1234567","qwerty","abc123",
    "password1","admin","letmein","welcome","iloveyou","monkey","dragon","sunshine","princess"
}
KEYBOARD_ROWS = ["qwertyuiop","asdfghjkl","zxcvbnm"]

def estimate_pool_size(pw: str) -> int:
    pool = 0
    if re.search(r'[a-z]', pw): pool += 26
    if re.search(r'[A-Z]', pw): pool += 26
    if re.search(r'[0-9]', pw): pool += 10
    if re.search(r'[^A-Za-z0-9]', pw): pool += 33
    return pool or 1

def entropy_bits(pw: str) -> float:
    pool = estimate_pool_size(pw)
    return len(pw) * math.log2(pool)

def contains_sequence(pw: str, minlen: int = 3) -> bool:
    s = pw.lower()
    # alphabetic/numeric sequences
    for i in range(len(s) - minlen + 1):
        chunk = s[i:i+minlen+2]
        if len(chunk) < 3:
            continue
        if all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j+1]) == 1 for j in range(len(chunk)-1)):
            return True
    # keyboard sequences
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - minlen + 1):
            seq = row[i:i+minlen+2]
            if seq in s or seq[::-1] in s:
                return True
    return False

def long_repetitions(pw: str) -> bool:
    if re.findall(r'(.)\1{3,}', pw):  # 'aaaa'
        return True
    if re.search(r'(.{2})\1{2,}', pw):  # 'ababab'
        return True
    return False

def has_date_like(pw: str) -> bool:
    return bool(re.search(r'(19\d{2}|20\d{2})', pw))

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    prev = list(range(lb+1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0]*lb
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j-1] + 1
            sub = prev[j-1] + (0 if ca == cb else 1)
            cur[j] = min(add, delete, sub)
        prev = cur
    return prev[-1]

# -------------------------
# Small Bloom filter impl
# -------------------------
class SimpleBloom:
    """
    Simple Bloom filter using multiple hash functions (sha256-based).
    Not cryptographic security, only set membership test with false positives possible.
    """
    def __init__(self, capacity: int = 2_000_000, error_rate: float = 0.001):
        # determine bit array size m and k hash functions
        # using approximate formulas: m = -n ln(p) / (ln2^2), k = (m/n) ln2
        n = max(1, capacity)
        p = max(1e-6, min(0.5, error_rate))
        m = int(-n * math.log(p) / (math.log(2)**2))
        k = max(1, int((m / n) * math.log(2)))
        self.size = m
        self.k = k
        # bytearray for bits
        self.bits = bytearray((m + 7) // 8)
    def _hashes(self, s: str):
        # create k hash positions from sha256(s + i)
        for i in range(self.k):
            h = hashlib.sha256(f"{i}:{s}".encode("utf-8")).digest()
            pos = int.from_bytes(h[:8], "big") % self.size
            yield pos
    def add(self, s: str):
        for pos in self._hashes(s):
            self.bits[pos // 8] |= (1 << (pos % 8))
    def __contains__(self, s: str) -> bool:
        return all((self.bits[pos // 8] & (1 << (pos % 8))) for pos in self._hashes(s))

# -------------------------
# Scoring function
# -------------------------
def is_common_or_similar(pw: str, common_set: Optional[Set[str]]=None, bloom: Optional[SimpleBloom]=None) -> Tuple[Optional[str], float]:
    s = pw.lower()
    if common_set is not None:
        if s in common_set:
            return ("common", 1.0)
        # similarity: check top short list only to avoid cost; fallback to built-in
        for c in ("password","123456","qwerty","abc123","letmein","iloveyou","admin"):
            d = levenshtein(s, c)
            if d <= 2 and len(s) >= max(4, len(c)-1):
                return ("similar", 1.0 - d/max(1,len(c)))
    if bloom is not None:
        if s in bloom:
            return ("common", 0.9)
    if s in COMMON_PASSWORDS:
        return ("common", 1.0)
    return (None, 0.0)

def score_password(pw: str, common_set: Optional[Set[str]]=None, bloom: Optional[SimpleBloom]=None) -> Dict[str, Any]:
    score = 0.0
    reasons: List[str] = []
    bits = entropy_bits(pw)
    score += max(0, min(60, bits))
    reasons.append(f"entropy_bits={bits:.1f}")
    if len(pw) >= 12:
        bonus = min(10, (len(pw)-11)*1.5)
        score += bonus
        reasons.append(f"length_bonus={bonus:.1f}")
    classes = sum(bool(re.search(p, pw)) for p in [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]'])
    score += (classes - 1) * 5
    reasons.append(f"char_classes={classes}")
    comm, sim_score = is_common_or_similar(pw, common_set, bloom)
    if comm == "common":
        score -= 40
        reasons.append("penalty=common_password")
    elif comm == "similar":
        score -= 20
        reasons.append("penalty=similar_to_common")
    if contains_sequence(pw):
        score -= 10
        reasons.append("penalty=sequence_detected")
    if long_repetitions(pw):
        score -= 12
        reasons.append("penalty=repetitions_detected")
    if has_date_like(pw):
        score -= 8
        reasons.append("penalty=date_like")
    # keyboard cluster
    s = pw.lower()
    keyboard_cluster = (len(s) >= 4) and (all(ch in "qwertyuiop" for ch in s) or all(ch in "asdfghjkl" for ch in s) or all(ch in "zxcvbnm" for ch in s))
    if keyboard_cluster:
        score -= 6
        reasons.append("penalty=keyboard_cluster")
    score = max(0, min(100, score))
    if score < 30: verdict = "Very weak"
    elif score < 50: verdict = "Weak"
    elif score < 70: verdict = "Moderate"
    elif score < 85: verdict = "Strong"
    else: verdict = "Very strong"
    feedback: List[str] = []
    if comm == "common":
        feedback.append("This is a widely used password — never use common passwords.")
    elif comm == "similar":
        feedback.append("Password is similar to a common password; make it more unique.")
    if len(pw) < 12:
        feedback.append("Use at least 12 characters; longer is better (use passphrases).")
    if classes < 3:
        feedback.append("Include a mix of lowercase, uppercase, digits, and symbols.")
    if contains_sequence(pw):
        feedback.append("Avoid sequential characters (e.g., 'abcd', '1234').")
    if long_repetitions(pw):
        feedback.append("Avoid long repeated patterns like 'aaaa' or 'ababab'.")
    if has_date_like(pw):
        feedback.append("Don't include obvious dates (birthdays, years).")
    if keyboard_cluster:
        feedback.append("Avoid using only nearby keyboard keys (e.g., 'asdfg', 'qwerty').")
    if not feedback:
        feedback.append("Good password! Consider using a password manager and unique passwords per site.")
    return {
        "password": pw,
        "score": int(round(score)),
        "verdict": verdict,
        "bits": round(bits, 1),
        "reasons": reasons,
        "feedback": feedback
    }

# -------------------------
# I/O helpers
# -------------------------
def load_rockyou_set(path: str) -> Set[str]:
    s = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.strip().lower()
            if pw:
                s.add(pw)
    return s

def load_rockyou_bloom(path: str, capacity: int = 3_000_000, error_rate: float = 0.001) -> SimpleBloom:
    b = SimpleBloom(capacity=capacity, error_rate=error_rate)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.strip().lower()
            if pw:
                b.add(pw)
    return b

def read_passwords_from_file(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\n")
            if pw:
                yield pw

# -------------------------
# CLI and main
# -------------------------
EXAMPLES = [
    "password", "123456", "P@ssw0rd", "correcthorsebattery", "Tr0ub4dor&3",
    "letmein123", "Qwerty123!", "S0m3$tr0ngP@ss!", "aaaa1111", "Summer2020",
    "iloveyou", "7h!s1sAP@ssw0rdThatIsVeryLong", "abcd1234", "Passw0rd!Passw0rd!"
]

def process_passwords(passwords: Iterable[str],
                      common_set: Optional[Set[str]] = None,
                      bloom: Optional[SimpleBloom] = None,
                      json_out: bool = False,
                      csv_writer: Optional[csv.writer] = None,
                      suppress_prints: bool = False) -> List[Dict[str, Any]]:
    """
    Evaluate passwords and return list of result dicts.

    json_out: if True, print a JSON object per password as we go (useful for streaming).
    suppress_prints: if True, do not print human-readable output (useful for batch collection).
    """
    results = []
    for pw in passwords:
        r = score_password(pw, common_set=common_set, bloom=bloom)
        results.append(r)

        # If streaming JSON output requested, print JSON per-password (stdout)
        if json_out:
            print(json.dumps({
                "password": r["password"],
                "score": r["score"],
                "verdict": r["verdict"],
                "bits": r["bits"],
                "feedback": r["feedback"],
                "reasons": r["reasons"]
            }, ensure_ascii=False))
        else:
            # Only print human-friendly text when not suppressed (interactive / normal mode)
            if not suppress_prints:
                print(f"{r['password']}: score={r['score']} ({r['verdict']}), bits={r['bits']}")
                print("  Feedback:", "; ".join(r['feedback']))
                print("  Reasons:", ", ".join(r['reasons']))
                print("-"*70)

        # CSV writing is independent of printing; always write if csv_writer provided
        if csv_writer is not None:
            csv_writer.writerow([r['password'], r['score'], r['verdict'], r['bits'], " | ".join(r['feedback'])])

    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Interactive Password Strength Checker")
    parser.add_argument("--interactive", action="store_true", help="Enter interactive mode (secure input)")
    parser.add_argument("--file", help="File with passwords (one per line)")
    parser.add_argument("--rockyou", help="Path to rockyou.txt (local file only)")
    parser.add_argument("--bloom", action="store_true", help="Use Bloom filter for rockyou (memory-efficient)")
    parser.add_argument("--csv", help="Save results to CSV file")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--no-examples", action="store_true", help="Don't run built-in example list")
    args = parser.parse_args(argv)

    common_set = None
    bloom = None

    if args.rockyou:
        if not os.path.exists(args.rockyou):
            print(f"rockyou file not found: {args.rockyou}", file=sys.stderr)
            sys.exit(2)
        print("Loading rockyou... (this may take a moment)", file=sys.stderr)
        if args.bloom:
            bloom = load_rockyou_bloom(args.rockyou)
            print("Rockyou loaded into Bloom filter (approx).",file=sys.stderr)
        else:
            common_set = load_rockyou_set(args.rockyou)
            print(f"Rockyou loaded as set (entries={len(common_set)}).", file=sys.stderr)

    csv_file = None
    csv_writer = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["password", "score", "verdict", "bits", "feedback"])

    try:
        # 1) examples
        if not args.no_examples:
            print("Running example passwords:\n", file=sys.stderr)
            results_examples = process_passwords(EXAMPLES, common_set=common_set, bloom=bloom, json_out=False, csv_writer=csv_writer, suppress_prints=True)
            # If the user asked for JSON, print the whole examples result as a JSON array
            if args.json:
                print(json.dumps(results_examples, indent=2, ensure_ascii=False))

        # 2) file input
        if args.file:
            if not os.path.exists(args.file):
                print(f"Input file not found: {args.file}", file=sys.stderr)
                sys.exit(2)
            print(f"\nReading passwords from file: {args.file}\n", file=sys.stderr)
            results_file = process_passwords(read_passwords_from_file(args.file), common_set=common_set, bloom=bloom, json_out=False, csv_writer=csv_writer, suppress_prints=True)
            if args.json:
                print(json.dumps(results_file, indent=2, ensure_ascii=False))

        # 3) interactive
        # default to interactive if no file and running in a TTY, or if --interactive passed
        if args.interactive or (not args.file and not args.interactive and sys.stdin.isatty()):
            print("\nInteractive mode. Press Enter on empty password to quit.", file=sys.stderr)
            while True:
                try:
                    pw = getpass("Enter password: ")
                except (KeyboardInterrupt, EOFError):
                    print("\nExiting interactive mode.", file=sys.stderr )
                    break
                if not pw:
                    break
                r = score_password(pw, common_set=common_set, bloom=bloom)
                if args.json:
                    # print a single JSON object per password (interactive-friendly)
                    print(json.dumps({
                        "password": r["password"],
                        "score": r["score"],
                        "verdict": r["verdict"],
                        "bits": r["bits"],
                        "feedback": r["feedback"],
                        "reasons": r["reasons"]
                    }, ensure_ascii=False))
                else:
                    print(f"\nScore: {r['score']} ({r['verdict']}) — bits={r['bits']}")
                    print("Feedback:")
                    for f in r['feedback']:
                        print(" -", f)
                if csv_writer is not None:
                    csv_writer.writerow([r['password'], r['score'], r['verdict'], r['bits'], " | ".join(r['feedback'])])
    finally:
        if csv_file is not None:
            csv_file.close()
            print(f"\nSaved results to {args.csv}", file=sys.stderr)

if __name__ == "__main__":
    main()

