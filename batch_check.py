#!/usr/bin/env python3
"""
batch_check.py – analyze multiple passwords from a file or list.
Usage:
    python batch_check.py passwords.txt
    python batch_check.py --demo
"""

import sys
from password_analyzer import analyze_password, calculate_entropy, check_complexity, rate_strength, check_dictionary

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
    print(f"\n{'PASSWORD':<30} {'STRENGTH':<12} {'ENTROPY':>8}  {'SCORE':>5}")
    print("-" * 65)
    for pwd in passwords:
        entropy = calculate_entropy(pwd)
        score, _ = check_complexity(pwd)
        dict_issues = check_dictionary(pwd)
        score -= len(dict_issues)
        strength, icon = rate_strength(score, entropy)
        masked = pwd[:2] + "***" if len(pwd) > 4 else "****"
        print(f"  {masked:<28} {icon} {strength:<10} {entropy:>8.1f}  {score:>5}")
    print()


if __name__ == "__main__":
    if "--demo" in sys.argv:
        print("\n🔐 Demo Batch Analysis")
        batch_analyze(DEMO_PASSWORDS)
    elif len(sys.argv) == 2:
        filepath = sys.argv[1]
        try:
            with open(filepath) as f:
                pwds = [line.strip() for line in f if line.strip()]
            print(f"\n🔐 Analyzing {len(pwds)} passwords from '{filepath}'")
            batch_analyze(pwds)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)
    else:
        print("Usage:")
        print("  python batch_check.py <passwords_file.txt>")
        print("  python batch_check.py --demo")
