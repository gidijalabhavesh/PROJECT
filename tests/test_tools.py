import unittest

from tools import analyze_message, extract_urls


class ScamAnalysisTests(unittest.TestCase):
    def test_kyc_link_with_urgency_is_critical(self):
        result = analyze_message(
            "Your SBI account is deactivated. Update KYC immediately at https://sbi-check.top/login",
            "+91 9811023456",
        )
        self.assertTrue(result.is_scam)
        self.assertEqual(result.risk_level, "CRITICAL")
        self.assertEqual(result.scam_category, "KYC_Suspension")

    def test_upi_pin_for_reward_is_fraudulent_upi_request(self):
        result = analyze_message("Enter your UPI PIN to receive your cashback reward.")
        self.assertTrue(result.is_scam)
        self.assertEqual(result.risk_level, "CRITICAL")
        self.assertEqual(result.scam_category, "Fraudulent_UPI_Request")

    def test_transaction_alert_without_scam_signals_is_safe(self):
        result = analyze_message("INR 1200 debited from A/C via UPI Ref 12345678", "AX-ICICIB")
        self.assertFalse(result.is_scam)
        self.assertEqual(result.risk_level, "SAFE")
        self.assertEqual(result.scam_category, "Legitimate_Notification")

    def test_apk_request_is_remote_access_risk(self):
        result = analyze_message("Install this support.apk to keep your account active")
        self.assertTrue(result.is_scam)
        self.assertEqual(result.risk_level, "CRITICAL")
        self.assertEqual(result.scam_category, "Remote_Access_Trojan")

    def test_extract_urls_removes_trailing_punctuation(self):
        self.assertEqual(extract_urls("Visit https://example.top/path now."), ["https://example.top/path"])


if __name__ == "__main__":
    unittest.main()
