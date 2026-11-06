import contextlib
import io
import unittest
from unittest.mock import patch

import batch_check
import password_analyzer


class PasswordAnalyzerPrivacyTests(unittest.TestCase):
    def test_generated_password_length_is_validated(self):
        for length in [0, 7, 129, -1]:
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    password_analyzer.generate_strong_password(length)

    @patch("password_analyzer.suggest_improvements", return_value=[])
    def test_single_password_report_does_not_reveal_fragments(self, _suggestions):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            password_analyzer.analyze_password("SensitivePassword123!")
        self.assertNotIn("SensitivePassword123!", output.getvalue())
        self.assertIn("*" * len("SensitivePassword123!"), output.getvalue())

    def test_batch_report_masks_every_character(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            batch_check.batch_analyze(["SensitivePassword123!"])
        self.assertNotIn("SensitivePassword123!", output.getvalue())
        self.assertIn("*" * len("SensitivePassword123!"), output.getvalue())

    def test_batch_rejects_oversized_password_entries(self):
        with self.assertRaises(ValueError):
            batch_check.batch_analyze(["x" * (batch_check.MAX_PASSWORD_LENGTH + 1)])


if __name__ == "__main__":
    unittest.main()
