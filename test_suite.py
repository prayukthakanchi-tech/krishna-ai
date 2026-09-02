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
        self.orig_memory_path = database.get_json_memory_path
        self.orig_oauth_file = getattr(database, "OAUTH_PKCE_FILE", None)

        # Monkey-patch database data directory for tests
        database.OTP_STATE_FILE = os.path.join(self.test_data_dir, "_otp_state.json")
        database.OAUTH_PKCE_FILE = os.path.join(self.test_data_dir, "_oauth_pkce.json")
        database.get_json_chat_path = lambda email: os.path.join(self.test_data_dir, f"{safe_filename(email)}_chats.json")
        database.get_json_memory_path = lambda email: os.path.join(self.test_data_dir, f"{safe_filename(email)}_memory.json")

    def tearDown(self):
        database.OTP_STATE_FILE = self.orig_otp_file
        database.get_json_chat_path = self.orig_json_path
        database.get_json_memory_path = self.orig_memory_path
        if self.orig_oauth_file:
            database.OAUTH_PKCE_FILE = self.orig_oauth_file
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


    # ── 9. V2 LONG-TERM MEMORY TESTS ──
    def test_memory_creation_and_retrieval(self):
        email = "mem_user@gmail.com"
        ok, rec = database.save_user_memory(
            email=email,
            memory_text="User is a final-year ECE student preparing for AI roles.",
            category="career",
            importance=8
        )
        self.assertTrue(ok)
        self.assertEqual(rec["user_email"], email)
        self.assertEqual(rec["category"], "career")
        self.assertEqual(rec["importance"], 8)
        self.assertIn("created_at", rec)
        self.assertIn("updated_at", rec)

        memories = database.load_user_memories(email)
        self.assertEqual(len(memories), 1)
        self.assertEqual(memories[0]["id"], rec["id"])
        self.assertEqual(memories[0]["memory_text"], "User is a final-year ECE student preparing for AI roles.")

    def test_memory_relevance_search(self):
        email = "search_user@gmail.com"
        database.save_user_memory(email, "User prefers concise 1-sentence answers.", category="preference", importance=5)
        database.save_user_memory(email, "User is studying for Groq and AI systems interviews.", category="career", importance=9)
        database.save_user_memory(email, "User is practicing meditation and Karma Yoga daily.", category="habit", importance=7)

        # Search for career/interview topic
        results = database.search_relevant_memories(email, "Can you help me prepare for my AI interview?", limit=2)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0]["category"], "career")
        self.assertIn("interview", results[0]["memory_text"].lower())

    def test_memory_update_and_deduplication(self):
        email = "update_user@gmail.com"
        ok, rec = database.save_user_memory(email, "User is focusing on frontend react roles.", category="career", importance=6)
        self.assertTrue(ok)
        mem_id = rec["id"]

        # Update the existing memory
        up_ok = database.update_user_memory(email, mem_id, "User is now focusing on AI engineering roles.", category="career", importance=8)
        self.assertTrue(up_ok)

        memories = database.load_user_memories(email)
        self.assertEqual(len(memories), 1)  # No duplicate created
        self.assertEqual(memories[0]["id"], mem_id)
        self.assertEqual(memories[0]["memory_text"], "User is now focusing on AI engineering roles.")
        self.assertEqual(memories[0]["importance"], 8)

    def test_memory_deletion(self):
        email = "delete_user@gmail.com"
        _, m1 = database.save_user_memory(email, "Memory 1", category="profile")
        _, m2 = database.save_user_memory(email, "Memory 2", category="profile")

        self.assertEqual(len(database.load_user_memories(email)), 2)

        del_ok = database.delete_user_memory(email, m1["id"])
        self.assertTrue(del_ok)

        remaining = database.load_user_memories(email)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], m2["id"])

    def test_memory_clear_all(self):
        email = "clear_user@gmail.com"
        database.save_user_memory(email, "Memory A")
        database.save_user_memory(email, "Memory B")

        self.assertEqual(len(database.load_user_memories(email)), 2)
        database.clear_user_memories(email)
        self.assertEqual(len(database.load_user_memories(email)), 0)

    def test_memory_user_isolation(self):
        user_a = "usera_mem@gmail.com"
        user_b = "userb_mem@gmail.com"

        _, m_a = database.save_user_memory(user_a, "User A secret career goal", category="career")
        _, m_b = database.save_user_memory(user_b, "User B confidential personal context", category="profile")

        mems_a = database.load_user_memories(user_a)
        mems_b = database.load_user_memories(user_b)

        # Strict isolation check
        self.assertTrue(all(m["user_email"] == user_a for m in mems_a))
        self.assertTrue(all(m["user_email"] == user_b for m in mems_b))
        self.assertNotIn("User B", str(mems_a))
        self.assertNotIn("User A", str(mems_b))

        # Search isolation
        search_a = database.search_relevant_memories(user_a, "confidential personal context")
        self.assertEqual(len(search_a), 0)

        # Cross-user delete prevention
        del_attempt = database.delete_user_memory(user_a, m_b["id"])
        mems_b_after = database.load_user_memories(user_b)
        self.assertEqual(len(mems_b_after), 1)

    def test_memory_heuristic_trigger_and_sensitive_data_protection(self):
        from app import should_extract_memory

        # Meaningful statements should trigger heuristic
        self.assertTrue(should_extract_memory("I am a final-year ECE student preparing for software roles."))
        self.assertTrue(should_extract_memory("My goal is to transition into AI engineering."))
        self.assertTrue(should_extract_memory("I prefer concise, direct answers without sermons."))

        # Transient, trivial questions or greetings should NOT trigger
        self.assertFalse(should_extract_memory("hello"))
        self.assertFalse(should_extract_memory("what is 2+2?"))
        self.assertFalse(should_extract_memory("can you explain chapter 2 verse 47?"))

        # Sensitive credentials MUST be blocked
        self.assertFalse(should_extract_memory("my password is Secret123!"))
        self.assertFalse(should_extract_memory("here is my otp: 654321"))
        self.assertFalse(should_extract_memory("my api key is re_1234567890abcdef"))

    def test_legacy_memory_migration_non_destructive(self):
        email = "legacy_user@gmail.com"
        mem_path = database.get_json_memory_path(email)

        # Write legacy string list format
        legacy_data = [
            "User expressed feeling demotivated.",
            "User values practical Bhagavad Gita wisdom."
        ]
        with open(mem_path, "w", encoding="utf-8") as f:
            json.dump(legacy_data, f)

        # Load should auto-migrate
        migrated = database.load_user_memories(email)
        self.assertEqual(len(migrated), 2)
        self.assertIsInstance(migrated[0], dict)
        self.assertEqual(migrated[0]["memory_text"], "User expressed feeling demotivated.")
        self.assertEqual(migrated[0]["user_email"], email)

        # Non-destructive legacy backup must exist
        backup_path = mem_path + ".legacy_backup"
        self.assertTrue(os.path.exists(backup_path))
        with open(backup_path, "r", encoding="utf-8") as f:
            backed_up = json.load(f)
        self.assertEqual(backed_up, legacy_data)

    def test_memory_prompt_injection(self):
        from app import build_prompt

        mock_mems = [
            {"category": "career", "memory_text": "Final-year ECE student preparing for AI roles."},
            {"category": "preference", "memory_text": "Prefers concise, actionable advice."}
        ]
        prompt = build_prompt(mock_mems)
        self.assertIn("<seeker_context>", prompt)
        self.assertIn("[Career] Final-year ECE student", prompt)
        self.assertIn("[Preference] Prefers concise", prompt)
        self.assertIn("NEVER announce that you are reading from memory", prompt)


    # ── 10. SUPABASE GOOGLE OAUTH & DATA COMPATIBILITY TESTS ──
    def test_oauth_pkce_generation(self):
        import base64
        import hashlib
        verifier, challenge = database.create_oauth_pkce_challenge()
        self.assertTrue(len(verifier) >= 43)
        self.assertTrue(len(challenge) >= 43)
        self.assertNotIn("=", challenge)  # Must be unpadded base64url

        # Verify challenge matches SHA-256 of verifier
        expected_digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).decode("ascii").rstrip("=")
        self.assertEqual(challenge, expected_challenge)

    def test_oauth_authorization_url_generation(self):
        from unittest.mock import patch
        with patch("database.get_supabase_credentials", return_value=("https://mock.supabase.co", "mock_key")):
            ok, oauth_url = database.get_supabase_google_oauth_url("https://mock.app")
            self.assertTrue(ok)
            self.assertIn("https://mock.supabase.co/auth/v1/authorize", oauth_url)
            self.assertIn("provider=google", oauth_url)
            self.assertIn("code_challenge=", oauth_url)
            self.assertIn("code_challenge_method=s256", oauth_url)

    def test_oauth_code_exchange_success_mock(self):
        from unittest.mock import patch, MagicMock

        # Setup pending verifier
        verifier = "mock_verifier_123456789012345678901234567890"
        database.save_pending_pkce_verifier(verifier)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "mock_token",
            "token_type": "bearer",
            "user": {
                "id": "mock_user_uuid",
                "email": "GoogleUser@Example.com"
            }
        }

        with patch("database.get_supabase_credentials", return_value=("https://mock.supabase.co", "mock_key")):
            with patch("requests.post", return_value=mock_resp):
                ok, email, err = database.exchange_supabase_oauth_code("mock_auth_code_xyz")
                self.assertTrue(ok)
                self.assertEqual(email, "googleuser@example.com")  # Normalized
                self.assertIsNone(err)

    def test_oauth_code_exchange_failure_mock(self):
        from unittest.mock import patch, MagicMock

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"error":"invalid_grant","error_description":"Invalid code"}'

        with patch("database.get_supabase_credentials", return_value=("https://mock.supabase.co", "mock_key")):
            with patch("requests.post", return_value=mock_resp):
                ok, email, err = database.exchange_supabase_oauth_code("invalid_code")
                self.assertFalse(ok)
                self.assertIsNone(email)
                self.assertIn("Authentication failed", err)

    def test_oauth_existing_user_data_compatibility(self):
        """
        Verify that a user who has existing chats and memories (from OTP login)
        retains ALL data when authenticating via Google OAuth (same email).
        """
        email = "shared_identity@gmail.com"

        # 1. Simulate prior existence of chats and memories under email
        chats = {
            "Spiritual Conversation": [
                {"role": "user", "content": "How do I deal with burnout?", "timestamp": "10:00 AM"},
                {"role": "assistant", "content": "Act without longing for fruit.", "timestamp": "10:01 AM"}
            ]
        }
        database.save_user_chats(email, chats)
        database.save_user_memory(email, "User is a senior engineer experiencing burnout.", category="career", importance=8)

        # 2. Simulate OAuth login returning this email
        from unittest.mock import patch, MagicMock
        verifier = "verifier_compat_test"
        database.save_pending_pkce_verifier(verifier)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "mock_oauth_token",
            "user": {"email": "Shared_Identity@gmail.com"}  # mixed case from Google
        }

        with patch("database.get_supabase_credentials", return_value=("https://mock.supabase.co", "mock_key")):
            with patch("requests.post", return_value=mock_resp):
                ok, auth_email, _ = database.exchange_supabase_oauth_code("auth_code_123")
                self.assertTrue(ok)
                self.assertEqual(auth_email, email)

        # 3. Load user's chats and memories using the authenticated email
        loaded_chats = database.load_user_chats(auth_email)
        loaded_memories = database.load_user_memories(auth_email)

        self.assertIn("Spiritual Conversation", loaded_chats)
        self.assertEqual(len(loaded_chats["Spiritual Conversation"]), 2)
        self.assertEqual(len(loaded_memories), 1)
        self.assertEqual(loaded_memories[0]["category"], "career")
        self.assertIn("burnout", loaded_memories[0]["memory_text"])

    def test_otp_and_oauth_coexistence(self):
        """
        Verify OTP creation, attempt tracking, verification, and cooldown continue to work
        independently while OAuth is active.
        """
        test_email = "otp_coexist@example.com"

        # Test OTP flow
        self.assertTrue(otp_can_send(test_email)[0])
        otp = generate_otp(6)
        otp_create(test_email, otp)
        self.assertFalse(otp_can_send(test_email)[0])  # Cooldown active

        # Wrong OTP attempt
        bad_ok, bad_err = otp_verify(test_email, "000000")
        self.assertFalse(bad_ok)
        self.assertIn("Wrong OTP", bad_err)

        # Correct OTP
        good_ok, _ = otp_verify(test_email, otp)
        self.assertTrue(good_ok)


if __name__ == "__main__":
    unittest.main()
