#!/usr/bin/env python3
"""
test_analyzer.py – Unit tests for password_analyzer.py
Run with: python -m pytest test_analyzer.py -v
       or: python test_analyzer.py
"""

import unittest
from password_analyzer import (
    calculate_entropy,
    get_charset_size,
    check_complexity,
    check_dictionary,
    rate_strength,
    estimate_brute_force_time,
    generate_strong_password,
    suggest_improvements,
)


class TestCharsetSize(unittest.TestCase):
    def test_lowercase_only(self):
        self.assertEqual(get_charset_size("abcdef"), 26)

    def test_mixed_case(self):
        self.assertEqual(get_charset_size("AaBb"), 52)

    def test_alphanumeric(self):
        self.assertEqual(get_charset_size("Aa1"), 62)

    def test_full_charset(self):
        self.assertEqual(get_charset_size("Aa1!"), 94)


class TestEntropy(unittest.TestCase):
    def test_weak_password_low_entropy(self):
        self.assertLess(calculate_entropy("abc"), 30)

    def test_strong_password_high_entropy(self):
        self.assertGreater(calculate_entropy("X#9kL!mQ2@nP"), 70)


class TestComplexity(unittest.TestCase):
    def test_very_short_password(self):
        score, issues = check_complexity("abc")
        self.assertTrue(any("shorter" in i for i in issues))

    def test_no_uppercase(self):
        score, issues = check_complexity("password1!")
        self.assertTrue(any("uppercase" in i.lower() for i in issues))

    def test_no_special_chars(self):
        score, issues = check_complexity("Password1")
        self.assertTrue(any("special" in i.lower() for i in issues))

    def test_strong_password_high_score(self):
        score, issues = check_complexity("X#9kL!mQ2@nP16")
        self.assertGreaterEqual(score, 7)


class TestDictionary(unittest.TestCase):
    def test_common_password_detected(self):
        issues = check_dictionary("password")
        self.assertTrue(len(issues) > 0)

    def test_keyboard_walk_detected(self):
        issues = check_dictionary("qwerty123")
        self.assertTrue(len(issues) > 0)

    def test_strong_password_no_issues(self):
        issues = check_dictionary("X#9kL!mQ2@nP")
        self.assertEqual(len(issues), 0)


class TestStrengthRating(unittest.TestCase):
    def test_very_weak(self):
        strength, _ = rate_strength(1, 20)
        self.assertEqual(strength, "Very Weak")

    def test_strong(self):
        strength, _ = rate_strength(8, 75)
        self.assertEqual(strength, "Strong")

    def test_very_strong(self):
        strength, _ = rate_strength(10, 90)
        self.assertEqual(strength, "Very Strong")


class TestBruteForce(unittest.TestCase):
    def test_short_password_instant(self):
        times = estimate_brute_force_time("ab")
        self.assertIn("Instantly", times["Offline (MD5/GPU)"])

    def test_long_password_takes_time(self):
        times = estimate_brute_force_time("X#9kL!mQ2@nP16!!")
        self.assertNotIn("Instantly", times["Online (throttled)"])


class TestGenerator(unittest.TestCase):
    def test_generated_length(self):
        pwd = generate_strong_password(16)
        self.assertEqual(len(pwd), 16)

    def test_generated_has_variety(self):
        import re
        pwd = generate_strong_password(20)
        self.assertTrue(re.search(r"[a-z]", pwd))
        self.assertTrue(re.search(r"[A-Z]", pwd))
        self.assertTrue(re.search(r"\d", pwd))


class TestSuggestions(unittest.TestCase):
    def test_suggestions_for_weak_password(self):
        tips = suggest_improvements("abc")
        self.assertTrue(len(tips) >= 3)

    def test_suggestions_include_generated(self):
        tips = suggest_improvements("abc")
        self.assertTrue(any("strong password" in t.lower() for t in tips))


if __name__ == "__main__":
    unittest.main(verbosity=2)
