#!/usr/bin/env python3
"""
batch_check.py – analyze multiple passwords from a file or list.
Usage:
    python batch_check.py passwords.txt
    python batch_check.py --demo
"""

import sys
import os
from password_analyzer import analyze_password, calculate_entropy, check_complexity, rate_strength, check_dictionary

MAX_BATCH_FILE_BYTES = 10 * 1024 * 1024
MAX_BATCH_ENTRIES = 100_000
MAX_PASSWORD_LENGTH = 1024

DEMO_PASSWORDS = [
    "password",
    "P@ssw0rd",
    "Tr0ub4dor&3",
    "correcthorsebatterystaple",
    "X#9kL!mQ2@nP",
    "123456",
    "MyS3cur3P@ssw0rd!2024",
]


def batch_analyze(passwords: list[str]) -> None:
    if len(passwords) > MAX_BATCH_ENTRIES:
        raise ValueError(f"Batch exceeds the {MAX_BATCH_ENTRIES:,}-password safety limit.")
    if any(not isinstance(pwd, str) or len(pwd) > MAX_PASSWORD_LENGTH for pwd in passwords):
        raise ValueError(f"Each password must be at most {MAX_PASSWORD_LENGTH} characters.")
    print(f"\n{'PASSWORD':<30} {'STRENGTH':<12} {'ENTROPY':>8}  {'SCORE':>5}")
    print("-" * 65)
    for pwd in passwords:
        entropy = calculate_entropy(pwd)
        score, _ = check_complexity(pwd)
        dict_issues = check_dictionary(pwd)
        score -= len(dict_issues)
        strength, icon = rate_strength(score, entropy)
        masked = "*" * len(pwd)
        print(f"  {masked:<28} {icon} {strength:<10} {entropy:>8.1f}  {score:>5}")
    print()


if __name__ == "__main__":
    if "--demo" in sys.argv:
        print("\n🔐 Demo Batch Analysis")
        batch_analyze(DEMO_PASSWORDS)
    elif len(sys.argv) == 2:
        filepath = sys.argv[1]
        try:
            if os.path.getsize(filepath) > MAX_BATCH_FILE_BYTES:
                raise ValueError("Input file exceeds the 10 MiB safety limit.")
            pwds = []
            with open(filepath, "r", encoding="utf-8", errors="strict") as f:
                for line in f:
                    password = line.rstrip("\\r\\n")
                    if password == "":
                        continue
                    if len(pwds) >= MAX_BATCH_ENTRIES:
                        raise ValueError(f"Batch exceeds the {MAX_BATCH_ENTRIES:,}-password safety limit.")
                    if len(password) > MAX_PASSWORD_LENGTH:
                        raise ValueError(f"A password exceeds the {MAX_PASSWORD_LENGTH}-character safety limit.")
                    pwds.append(password)
            print(f"\n🔐 Analyzing {len(pwds)} passwords from '{filepath}'")
            batch_analyze(pwds)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"Error: {exc}")
            sys.exit(2)
    else:
        print("Usage:")
        print("  python batch_check.py <passwords_file.txt>")
        print("  python batch_check.py --demo")
