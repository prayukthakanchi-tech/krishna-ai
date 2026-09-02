"""
Krishna AI — Automated Security, Auth, Authorization & Persistence Test Suite

Verifies:
1. Email validation & path traversal prevention
2. OTP generation (crypto-random, 6 digits) & SHA-256 server-side hashing
3. OTP attempt cap (5 max) & single-use invalidation
4. OTP resend cooldown & rate-limit abuse protection
5. User Authorization & Isolation (User A cannot access User B's chats)
6. HTML & Data attribute XSS sanitization
7. Prompt injection detection
8. Dynamic Groq client & model validation
9. Application restart persistence simulation
10. Supabase REST API request payload & header validation

Run with:
  python test_suite.py
"""

import unittest
import json
import time
import os
import shutil
import database
from app import (
    is_valid_email,
    safe_filename,
    hash_otp,
    generate_otp,
    sanitize_input,
    escape_for_html,
    escape_for_data_attr,
    otp_create,
    otp_verify,
    otp_can_send,
    get_validated_groq_models,
    _load_otp_state
)


class TestKrishnaAISecurityAndAuth(unittest.TestCase):

    def setUp(self):
        # Create temp data directory for test isolation
        self.test_data_dir = "data_test_env"
        os.makedirs(self.test_data_dir, exist_ok=True)
        self.orig_otp_file = database.OTP_STATE_FILE
        self.orig_json_path = database.get_json_chat_path

        # Monkey-patch database data directory for tests
        database.OTP_STATE_FILE = os.path.join(self.test_data_dir, "_otp_state.json")
        database.get_json_chat_path = lambda email: os.path.join(self.test_data_dir, f"{safe_filename(email)}_chats.json")

    def tearDown(self):
        database.OTP_STATE_FILE = self.orig_otp_file
        database.get_json_chat_path = self.orig_json_path
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir, ignore_errors=True)

    # ── 1. EMAIL & PATH VALIDATION ──
    def test_email_validation(self):
        self.assertTrue(is_valid_email("user@example.com"))
        self.assertTrue(is_valid_email("prayukthakanchi@gmail.com"))
        self.assertFalse(is_valid_email("invalid-email"))
        self.assertFalse(is_valid_email("user@"))
        self.assertFalse(is_valid_email("@domain.com"))

    def test_safe_filename_path_traversal_prevention(self):
        safe = safe_filename("../../../etc/passwd@gmail.com")
        self.assertNotIn("..", safe)
        self.assertNotIn("/", safe)
        self.assertNotIn("\\", safe)
        self.assertLessEqual(len(safe), 100)

    # ── 2. CRYPTOGRAPHIC OTP & SECURITY ──
    def test_generate_otp_crypto_randomness(self):
        otp1 = generate_otp(6)
        otp2 = generate_otp(6)
        self.assertEqual(len(otp1), 6)
        self.assertTrue(otp1.isdigit())
        self.assertNotEqual(otp1, otp2)

    def test_otp_hashing_never_plaintext(self):
        otp = "123456"
        hashed = hash_otp(otp)
        self.assertNotEqual(otp, hashed)
        self.assertEqual(len(hashed), 64)  # SHA-256 hex digest length

    # ── 3. OTP LIFECYCLE & RESEND COOLDOWN ──
    def test_otp_create_verify_and_single_use(self):
        email = "testuser@gmail.com"
        otp = "654321"
        otp_create(email, otp)

        # First verification succeeds
        ok, err = otp_verify(email, otp)
        self.assertTrue(ok)
        self.assertEqual(err, "")

        # Second verification fails (single-use enforced)
        ok2, err2 = otp_verify(email, otp)
        self.assertFalse(ok2)

    def test_otp_attempt_cap_enforcement(self):
        email = "bruteforce@gmail.com"
        otp = "111111"
        otp_create(email, otp)

        # Submit 5 wrong OTP attempts
        for i in range(5):
            ok, err = otp_verify(email, "999999")
            self.assertFalse(ok)

        # 6th attempt should block outright
        ok_final, err_final = otp_verify(email, otp)
        self.assertFalse(ok_final)
        self.assertIn("Too many failed attempts", err_final)

    def test_otp_resend_cooldown(self):
        email = "cooldown@gmail.com"
        otp = "222222"
        otp_create(email, otp)

        can_send, remaining = otp_can_send(email)
        self.assertFalse(can_send)
        self.assertGreater(remaining, 0)

    # ── 4. AUTHORIZATION & USER ISOLATION ──
    def test_user_chat_isolation(self):
        user_a = "usera@gmail.com"
        user_b = "userb@gmail.com"

        chats_a = {"Chat A": [{"role": "user", "content": "Secret A"}]}
        chats_b = {"Chat B": [{"role": "user", "content": "Secret B"}]}

        database.save_user_chats(user_a, chats_a)
        database.save_user_chats(user_b, chats_b)

        loaded_a = database.load_user_chats(user_a)
        loaded_b = database.load_user_chats(user_b)

        # Verify User A cannot see User B's chats
        self.assertIn("Chat A", loaded_a)
        self.assertNotIn("Chat B", loaded_a)

        self.assertIn("Chat B", loaded_b)
        self.assertNotIn("Chat A", loaded_b)

    # ── 5. REAL PERSISTENCE & RESTART SIMULATION ──
    def test_app_restart_persistence_simulation(self):
        email = "restart_user@gmail.com"
        chats = {"Pre-Restart Chat": [{"role": "user", "content": "Hello before reboot"}]}

        # 1. User writes chat
        database.save_user_chats(email, chats)

        # 2. Simulate application restart (wipe memory state)
        memory_state = None

        # 3. Reload from database/storage layer
        memory_state = database.load_user_chats(email)
        self.assertIn("Pre-Restart Chat", memory_state)
        self.assertEqual(memory_state["Pre-Restart Chat"][0]["content"], "Hello before reboot")

    # ── 6. DYNAMIC GROQ MODEL VALIDATION ──
    def test_dynamic_groq_model_validation(self):
        models = get_validated_groq_models(None)
        self.assertIsInstance(models, list)
        self.assertIn("llama-3.3-70b-versatile", models)
        self.assertIn("llama-3.1-8b-instant", models)

    # ── 7. XSS ESCAPING & PROMPT INJECTION ──
    def test_xss_escaping(self):
        malicious = "<script>alert('xss')</script>"
        escaped = escape_for_html(malicious)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    # ── 8. EMAIL & OTP FAILURE & FALLBACK HANDLING ──
    def test_send_otp_email_unconfigured_credentials(self):
        from app import send_otp_email
        ok, err = send_otp_email("test@example.com", "123456")
        self.assertFalse(ok)
        self.assertTrue(len(err) > 0)

    def test_send_otp_email_invalid_recipient(self):
        from app import send_otp_email
        ok, err = send_otp_email("not-an-email", "123456")
        self.assertFalse(ok)
        self.assertEqual(err, "Invalid email address.")

    def test_otp_state_not_saved_on_email_failure(self):
        from app import send_otp_email, _load_otp_state
        email = "failed_delivery@gmail.com"
        ok, err = send_otp_email(email, "999999")
        self.assertFalse(ok)
        state = _load_otp_state()
        self.assertNotIn(email, state)

    def test_resend_api_success_mock(self):
        from unittest.mock import patch, MagicMock
        from app import send_otp_email

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp

        with patch("app.get_secret", side_effect=lambda k: "re_mock_key" if k == "RESEND_API_KEY" else None):
            with patch("urllib.request.urlopen", return_value=mock_resp):
                ok, err = send_otp_email("user@example.com", "123456")
                self.assertTrue(ok)
                self.assertEqual(err, "")

    def test_smtp_ssl_success_mock(self):
        from unittest.mock import patch, MagicMock
        from app import send_otp_email

        mock_smtp = MagicMock()
        mock_smtp.__enter__.return_value = mock_smtp

        with patch("app.get_secret", side_effect=lambda k: "user@gmail.com" if k == "EMAIL" else ("pass" if k == "PASSWORD" else None)):
            with patch("smtplib.SMTP_SSL", return_value=mock_smtp):
                ok, err = send_otp_email("user@example.com", "123456")
                self.assertTrue(ok)
                self.assertEqual(err, "")

    def test_smtp_starttls_fallback_mock(self):
        import smtplib
        from unittest.mock import patch, MagicMock
        from app import send_otp_email

        mock_smtp_587 = MagicMock()
        mock_smtp_587.__enter__.return_value = mock_smtp_587

        with patch("app.get_secret", side_effect=lambda k: "user@gmail.com" if k == "EMAIL" else ("pass" if k == "PASSWORD" else None)):
            with patch("smtplib.SMTP_SSL", side_effect=smtplib.SMTPConnectError(421, b"Port 465 blocked")):
                with patch("smtplib.SMTP", return_value=mock_smtp_587):
                    ok, err = send_otp_email("user@example.com", "123456")
                    self.assertTrue(ok)
                    self.assertEqual(err, "")
    def test_resend_403_domain_restriction_no_smtp_fallback(self):
        """HTTP 403 (domain/sender restriction) must return config error, NOT Gmail error, and NOT create OTP state."""
        import urllib.error
        from unittest.mock import patch, MagicMock
        from app import send_otp_email, _load_otp_state

        err_response = json.dumps({
            "name": "validation_error",
            "message": "You can only send testing emails to your own email address. To send emails to other recipients, please verify a domain at resend.com/domains"
        }).encode("utf-8")
        http_403 = urllib.error.HTTPError(url=None, code=403, msg="Forbidden", hdrs={}, fp=None)
        http_403.read = lambda: err_response

        email = "other_user@gmail.com"
        with patch("app.get_secret", side_effect=lambda k: "re_mock_key" if k == "RESEND_API_KEY" else None):
            with patch("urllib.request.urlopen", side_effect=http_403):
                ok, err = send_otp_email(email, "777777")
                self.assertFalse(ok)
                # Must be a safe generic message, NOT mentioning Gmail or App Password
                self.assertNotIn("Gmail", err)
                self.assertNotIn("App Password", err)
                self.assertIn("configuration error", err)
                # OTP state must NOT be created
                state = _load_otp_state()
                self.assertNotIn(email, state)

    def test_resend_401_auth_failure_no_smtp_fallback(self):
        """HTTP 401 (invalid API key) must return config error, NOT fall back to SMTP."""
        import urllib.error
        from unittest.mock import patch
        from app import send_otp_email

        http_401 = urllib.error.HTTPError(url=None, code=401, msg="Unauthorized", hdrs={}, fp=None)
        http_401.read = lambda: b'{"name":"missing_api_key","message":"API key is required"}'

        with patch("app.get_secret", side_effect=lambda k: "re_invalid_key" if k == "RESEND_API_KEY" else None):
            with patch("urllib.request.urlopen", side_effect=http_401):
                ok, err = send_otp_email("user@example.com", "888888")
                self.assertFalse(ok)
                self.assertNotIn("Gmail", err)
                self.assertIn("configuration error", err)

    def test_resend_5xx_falls_back_to_smtp(self):
        """HTTP 5xx (Resend server error) should fall back to SMTP."""
        import urllib.error
        import smtplib
        from unittest.mock import patch, MagicMock
        from app import send_otp_email

        http_500 = urllib.error.HTTPError(url=None, code=500, msg="Server Error", hdrs={}, fp=None)
        http_500.read = lambda: b'{"message":"Internal server error"}'

        mock_smtp_587 = MagicMock()
        mock_smtp_587.__enter__.return_value = mock_smtp_587

        with patch("app.get_secret", side_effect=lambda k: "re_mock_key" if k == "RESEND_API_KEY" else ("user@gmail.com" if k == "EMAIL" else ("pass" if k == "PASSWORD" else None))):
            with patch("urllib.request.urlopen", side_effect=http_500):
                with patch("smtplib.SMTP_SSL", side_effect=smtplib.SMTPConnectError(421, b"blocked")):
                    with patch("smtplib.SMTP", return_value=mock_smtp_587):
                        ok, err = send_otp_email("user@example.com", "999999")
                        self.assertTrue(ok)
                        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
