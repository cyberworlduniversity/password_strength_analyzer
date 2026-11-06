#!/usr/bin/env python3
"""
Password Strength Analyzer
Author: hemanathan115
Description: A comprehensive tool to analyze password strength, detect weaknesses,
             estimate brute force time, and suggest stronger passwords.
"""

import re
import math
import hashlib
import secrets
import string
import os
from typing import Tuple, List, Dict


# ─────────────────────────────────────────────
#  Common / Dictionary word lists
# ─────────────────────────────────────────────
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "abc123", "monkey", "1234567", "12345678", "123456789", "iloveyou",
    "sunshine", "princess", "welcome", "shadow", "superman", "dragon",
    "master", "login", "passw0rd", "hello", "charlie", "donald",
    "football", "baseball", "soccer", "batman", "trustno1", "test",
    "pass", "1111", "111111", "000000", "654321", "696969",
    "123123", "password1", "adobe123", "admin123", "root",
    "changeme", "secret", "access", "hottie", "cheese",
]

DICTIONARY_WORDS = [
    "apple", "banana", "orange", "grape", "mango", "cherry",
    "computer", "internet", "network", "security", "system",
    "house", "water", "music", "movie", "phone", "money",
    "happy", "love", "blue", "green", "black", "white",
    "summer", "winter", "spring", "autumn", "morning", "night",
]

LEET_MAP = {
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t",
}


# ─────────────────────────────────────────────
#  Entropy & charset helpers
# ─────────────────────────────────────────────
def get_charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        size += 32
    return size or 1


def calculate_entropy(password: str) -> float:
    charset = get_charset_size(password)
    return len(password) * math.log2(charset)


# ─────────────────────────────────────────────
#  Brute-force time estimator
# ─────────────────────────────────────────────
GUESSES_PER_SECOND = {
    "Online (throttled)":   100,
    "Online (unthrottled)": 10_000,
    "Offline (bcrypt)":     10_000,
    "Offline (MD5/GPU)":    10_000_000_000,
}


def estimate_brute_force_time(password: str) -> Dict[str, str]:
    charset = get_charset_size(password)
    combinations = charset ** len(password)
    results = {}
    for scenario, gps in GUESSES_PER_SECOND.items():
        seconds = combinations / gps
        results[scenario] = _format_time(seconds)
    return results


def _format_time(seconds: float) -> str:
    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 3153600000:
        return f"{seconds/31536000:.1f} years"
    else:
        return f"{seconds/31536000:.2e} years"


# ─────────────────────────────────────────────
#  Dictionary / common password detection
# ─────────────────────────────────────────────
def _deleet(password: str) -> str:
    """Convert leet-speak back to plain letters."""
    result = password.lower()
    for leet, plain in LEET_MAP.items():
        result = result.replace(leet, plain)
    return result


def check_dictionary(password: str) -> List[str]:
    issues = []
    lower = password.lower()
    deleet = _deleet(password)

    if lower in [p.lower() for p in COMMON_PASSWORDS]:
        issues.append("❌ This is one of the most commonly used passwords.")

    for word in DICTIONARY_WORDS + COMMON_PASSWORDS:
        if word in lower or word in deleet:
            issues.append(f"⚠️  Contains common word/pattern: '{word}'")
            break

    # Keyboard walk patterns
    keyboard_walks = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx"]
    for walk in keyboard_walks:
        if walk in lower:
            issues.append(f"⚠️  Contains keyboard walk pattern: '{walk}'")
            break

    return issues


# ─────────────────────────────────────────────
#  Complexity checks
# ─────────────────────────────────────────────
def check_complexity(password: str) -> Tuple[int, List[str]]:
    """Returns (score_delta, issues_list). Score delta is positive for good things."""
    score = 0
    issues = []

    if len(password) >= 8:
        score += 1
    else:
        issues.append("❌ Password is shorter than 8 characters.")

    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("❌ No lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("❌ No uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        issues.append("❌ No digits.")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        score += 2
    else:
        issues.append("❌ No special characters (!@#$%^&* etc.).")

    # Penalise repeating characters
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        issues.append("⚠️  Repeating characters detected (e.g. 'aaa').")

    # Penalise sequential numbers/letters
    for seq in ["0123", "1234", "2345", "3456", "4567", "5678", "6789",
                "abcd", "bcde", "cdef", "defg", "efgh"]:
        if seq in password.lower():
            score -= 1
            issues.append(f"⚠️  Sequential pattern detected: '{seq}'.")
            break

    return score, issues


# ─────────────────────────────────────────────
#  Strength rating
# ─────────────────────────────────────────────
def rate_strength(score: int, entropy: float) -> Tuple[str, str]:
    if score <= 2 or entropy < 28:
        return "Very Weak", "🔴"
    elif score <= 4 or entropy < 40:
        return "Weak", "🟠"
    elif score <= 6 or entropy < 60:
        return "Moderate", "🟡"
    elif score <= 8 or entropy < 80:
        return "Strong", "🟢"
    else:
        return "Very Strong", "💪"


# ─────────────────────────────────────────────
#  Hash the password (for demonstration)
# ─────────────────────────────────────────────
def hash_password(password: str) -> Dict[str, str]:
    return {
        "MD5":    hashlib.md5(password.encode()).hexdigest(),
        "SHA-1":  hashlib.sha1(password.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(password.encode()).hexdigest(),
    }


# ─────────────────────────────────────────────
#  Password generator / suggestion
# ─────────────────────────────────────────────
def generate_strong_password(length: int = 16) -> str:
    if not isinstance(length, int) or not 8 <= length <= 128:
        raise ValueError("Generated password length must be between 8 and 128 characters.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r"[a-z]", pwd) and re.search(r"[A-Z]", pwd)
                and re.search(r"\d", pwd)
                and re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", pwd)):
            return pwd


def suggest_improvements(password: str) -> List[str]:
    suggestions = []

    if len(password) < 12:
        suggestions.append("✅ Increase length to at least 12 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("✅ Add uppercase letters (A-Z).")
    if not re.search(r"[a-z]", password):
        suggestions.append("✅ Add lowercase letters (a-z).")
    if not re.search(r"\d", password):
        suggestions.append("✅ Include numbers (0-9).")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        suggestions.append("✅ Add special characters (!@#$%^&*).")
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("✅ Avoid repeating the same character multiple times.")

    suggestions.append(f"✅ Try this strong password: {generate_strong_password()}")
    suggestions.append(f"✅ Or this one:              {generate_strong_password(20)}")
    return suggestions


# ─────────────────────────────────────────────
#  Main analysis function
# ─────────────────────────────────────────────
def analyze_password(password: str, show_hashes: bool = False) -> None:
    print("\n" + "=" * 60)
    print("        🔐 PASSWORD STRENGTH ANALYZER")
    print("=" * 60)

    masked = "*" * len(password)
    print(f"\n  Password : {masked}  (length: {len(password)})")

    # Entropy
    entropy = calculate_entropy(password)
    print(f"  Entropy  : {entropy:.1f} bits")

    # Charset
    cs = get_charset_size(password)
    print(f"  Charset  : {cs} characters")

    # Complexity score
    score, complexity_issues = check_complexity(password)

    # Dictionary check
    dict_issues = check_dictionary(password)
    if dict_issues:
        score -= len(dict_issues)

    # Strength rating
    strength, icon = rate_strength(score, entropy)
    print(f"\n  Strength : {icon}  {strength}  (score: {score})")

    # Strength meter
    meter_width = 30
    filled = max(0, min(meter_width, int((score / 10) * meter_width)))
    bar = "█" * filled + "░" * (meter_width - filled)
    color_map = {"Very Weak": "🔴", "Weak": "🟠", "Moderate": "🟡",
                 "Strong": "🟢", "Very Strong": "💪"}
    print(f"  Meter    : [{bar}]")

    # Issues
    all_issues = complexity_issues + dict_issues
    if all_issues:
        print("\n─── Issues Found ────────────────────────────────────")
        for issue in all_issues:
            print(f"  {issue}")

    # Brute-force estimates
    print("\n─── Estimated Crack Time ────────────────────────────")
    for scenario, time_str in estimate_brute_force_time(password).items():
        print(f"  {scenario:<30} {time_str}")

    # Suggestions
    print("\n─── Improvement Suggestions ─────────────────────────")
    for tip in suggest_improvements(password):
        print(f"  {tip}")

    # Hashes (optional)
    if show_hashes:
        print("\n─── Password Hashes (demo only) ─────────────────────")
        for algo, digest in hash_password(password).items():
            print(f"  {algo:<8}: {digest}")

    print("\n" + "=" * 60 + "\n")


# ─────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────
def main():
    import getpass
    print("\n🔐 Welcome to the Password Strength Analyzer")
    print("   (Your password is never stored or transmitted)\n")

    while True:
        try:
            password = getpass.getpass("   Enter password to analyze (or Ctrl+C to quit): ")
        except (KeyboardInterrupt, EOFError):
            print("\n\n   Goodbye! Stay secure 🔒\n")
            break

        if not password:
            print("   ⚠️  No password entered. Please try again.\n")
            continue

        show_h = input("   Show hashes? (y/N): ").strip().lower() == "y"
        analyze_password(password, show_hashes=show_h)

        again = input("   Analyze another password? (Y/n): ").strip().lower()
        if again == "n":
            print("\n   Goodbye! Stay secure 🔒\n")
            break


if __name__ == "__main__":
    main()
