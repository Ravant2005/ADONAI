"""ADONAI End-to-End Automated Acceptance & Verification Test Suite."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from backend.cyber_range import CyberRangeController
from backend.database import REQUIRED_TABLES, get_connection, init_db
from backend.detection_engine import DeterministicDetectionEngine
from backend.llm_analyst import generate_incident_explanation, validate_explanation_schema
from backend.security import (
    complete_device_pairing,
    create_pairing_challenge,
    redact_secrets,
    revoke_device_pairing,
)
from backend.guardian_watermark import (
    compute_content_hash,
    build_watermark_payload,
    embed_image_watermark,
    extract_image_watermark,
    verify_watermark_integrity,
)
from backend.guardian_blockchain import GuardianBlockchain
from backend.guardian_detector import GuardianDetector
from backend.guardian_web_intel import WebIntelEngine

class TestAdonaiPilotSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.tmp_dir.name) / "test_adonai.db"
        os.environ["ADONAI_DB_PATH"] = str(cls.db_path)
        init_db(cls.db_path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def setUp(self):
        self.conn = get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()

    def test_01_all_24_required_tables_and_1000_simulated_endpoints(self):
        cur = self.conn.cursor()
        for table in REQUIRED_TABLES:
            cur.execute(f"SELECT COUNT(*) as c FROM {table}")
            cnt = cur.fetchone()["c"]
            self.assertGreaterEqual(cnt, 0, f"Table {table} missing or unreadable")
        cur.execute("SELECT COUNT(*) as c FROM SimulatedEndpoint WHERE environment = 'LAB' AND is_physical = 0")
        ep_count = cur.fetchone()["c"]
        self.assertEqual(ep_count, 1000, "Must have exactly 1,000 registered simulated endpoint identities")

    def test_02_authenticated_pairing_and_revocation(self):
        challenge = create_pairing_challenge(self.conn, ttl_seconds=300)
        self.assertEqual(len(challenge["pairing_code"]), 6)
        paired = complete_device_pairing(
            self.conn,
            pairing_code=challenge["pairing_code"],
            device_id="android-test-phone-01",
            device_name="Test Pixel 9",
        )
        self.assertEqual(paired["status"], "ACTIVE")
        self.assertTrue(paired["auth_token"].startswith("adonai_tok_"))

        revoked = revoke_device_pairing(self.conn, "android-test-phone-01")
        self.assertEqual(revoked["status"], "REVOKED_OFFLINE")

    def test_03_secret_redaction_privacy_guard(self):
        raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and password=MySuperSecret123 card 4111-2222-3333-4444"
        cleaned = redact_secrets(raw)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", cleaned)
        self.assertNotIn("MySuperSecret123", cleaned)
        self.assertNotIn("4111-2222-3333-4444", cleaned)
        self.assertIn("[REDACTED_TOKEN]", cleaned)
        self.assertIn("[REDACTED_SECRET]", cleaned)
        self.assertIn("[REDACTED_CARD]", cleaned)

    def test_04_contextual_scam_guard_benign_vs_otp_vs_trusted_compromise(self):
        engine = DeterministicDetectionEngine(self.conn)

        # 1. Benign family message from TRUSTED contact ('Mom') -> 0 false positive
        benign_res = engine.evaluate_event({
            "device_id": "android-pixel8-real-01",
            "environment": "REAL",
            "source_type": "ANDROID_SHARE_SHEET",
            "event_type": "MESSAGE_LINK_ANALYSIS",
            "payload": {
                "url": "https://cooking-recipes.example.org/dosa",
                "message_text": "Here is the family recipe for dinner tonight!",
                "recipient_id": "rec-mom-01",
            },
        })
        self.assertEqual(len(benign_res["detections"]), 0, "Benign trusted contact message must not trigger false positive")

        # 2. OTP scam from unknown sender -> CRITICAL alert
        otp_res = engine.evaluate_event({
            "device_id": "android-pixel8-real-01",
            "environment": "REAL",
            "source_type": "ANDROID_SHARE_SHEET",
            "event_type": "MESSAGE_LINK_ANALYSIS",
            "payload": {
                "message_text": "URGENT: Your bank account will be frozen in 10 minutes. Send me the 6-digit OTP verification code now.",
                "recipient_id": "rec-unknown-03",
            },
        })
        self.assertGreaterEqual(len(otp_res["detections"]), 1)
        self.assertEqual(otp_res["detections"][0]["severity"], "CRITICAL")

        # 3. Compromised trusted contact sending phishing link + OTP lure -> MUST override trust suppression
        comp_res = engine.evaluate_event({
            "device_id": "android-pixel8-real-01",
            "environment": "REAL",
            "source_type": "ANDROID_SHARE_SHEET",
            "event_type": "MESSAGE_LINK_ANALYSIS",
            "payload": {
                "url": "https://urgent-family-wire.example.test/otp-claim",
                "message_text": "I am stuck at the hospital, click https://urgent-family-wire.example.test/otp-claim and send the 6-digit OTP code immediately!",
                "recipient_id": "rec-mom-01",
                "allow_test_fixtures": True,
            },
        })
        self.assertGreaterEqual(len(comp_res["detections"]), 1)
        self.assertEqual(comp_res["detections"][0]["rule_id"], "rule-trust-override-005")
        self.assertTrue(comp_res["detections"][0]["evidence_fields"]["strong_indicator_override"])

    def test_05_deterministic_replay_and_cross_device_correlation(self):
        ctrl = CyberRangeController(self.conn)
        first_run = ctrl.run_scenario("scen-01", target_endpoint_id="sim-ep-0010", is_replay=False)
        self.assertEqual(len(first_run["detection_ids"]), 1)

        replay_run = ctrl.run_scenario("scen-01", target_endpoint_id="sim-ep-0011", is_replay=True)
        self.assertEqual(len(replay_run["detection_ids"]), 1)
        self.assertIn("Correlated with", replay_run["incidents"][0]["why_risky"])

    def test_06_full_10_scenario_evaluation_benchmark(self):
        ctrl = CyberRangeController(self.conn)
        eval_res = ctrl.run_full_evaluation_suite()
        self.assertEqual(eval_res["total_scenarios"], 10)
        self.assertEqual(eval_res["true_positives"], 9)
        self.assertEqual(eval_res["true_negatives"], 1)
        self.assertEqual(eval_res["false_positives"], 0)
        self.assertEqual(eval_res["false_negatives"], 0)
        self.assertEqual(eval_res["precision"], 1.0)
        self.assertEqual(eval_res["recall"], 1.0)
        self.assertEqual(eval_res["false_positive_rate"], 0.0)

    def test_07_local_llm_explanation_and_deterministic_fallback(self):
        exp = generate_incident_explanation(self.conn, "inc-real-001")
        self.assertTrue(exp["schema_valid"])
        self.assertTrue(validate_explanation_schema(exp["structured"]))
        self.assertIn("inc-real-001", exp["structured"]["cited_ids"])
        self.assertIn(exp["generation_mode"], ("LIVE_LOCAL_LLM", "DETERMINISTIC_FALLBACK"))

    def test_08_guardian_watermark_and_blockchain_stage1(self):
        # 1. Create simulated media capture
        test_raw = b"ADONAI GUARDIAN CAMERA CAPTURED RAW TEST IMAGE " * 20
        c_hash = compute_content_hash(test_raw)
        dev_id = "android-pixel8-real-01"
        ts_ms = int(time.time() * 1000)
        wm_payload = build_watermark_payload(dev_id, ts_ms, c_hash)

        # 2. Embed dual-layer watermark
        watermarked_bytes = embed_image_watermark(test_raw, wm_payload)
        self.assertNotEqual(watermarked_bytes, test_raw)

        # 3. Extract and verify watermark payload
        extracted = extract_image_watermark(watermarked_bytes)
        self.assertIsNotNone(extracted)
        v_res = verify_watermark_integrity(extracted, dev_id, c_hash)
        self.assertTrue(v_res["valid"])
        self.assertGreaterEqual(v_res["score"], 0.75)

        # 4. Register to Guardian local blockchain
        chain = GuardianBlockchain(self.conn)
        block_id = chain.register_media(c_hash, dev_id, "IMAGE", wm_payload, {"filename": "test.jpg"})
        self.assertTrue(block_id.startswith("blk-"))

        # 5. Lookup from blockchain
        block_record = chain.lookup_media(c_hash)
        self.assertIsNotNone(block_record)
        self.assertEqual(block_record["media_hash"], c_hash)

        # 6. Verify blockchain integrity
        chain_int = chain.verify_chain_integrity()
        self.assertTrue(chain_int["valid"])
        self.assertGreaterEqual(chain_int["block_count"], 1)

    def test_09_guardian_3stage_verification_and_financial_fraud_analysis(self):
        # Test 10 technology families on unwatermarked AI deepfake audio with financial fraud context
        detector = GuardianDetector()
        web_engine = WebIntelEngine()

        scam_text = "Urgent: Your account is suspended. Transfer Rs 25,000 via UPI immediately to avoid police case."
        audio_stream = b"SYNTHETIC_SPEECH_DATA_STREAM_" * 50

        # Run Stage 2 Web Intel
        intel_res = web_engine.cross_reference("dummy_hash", "AUDIO", scam_text)
        self.assertTrue(intel_res.scheme_detected)

        # Run Stage 3 AI Forensic Multi-Modal Analysis
        forensic_res = detector.analyze_media(audio_stream, "AUDIO", {}, scam_text)
        self.assertIn(forensic_res.verdict, ("LIKELY_AI_GENERATED", "ALMOST_CERTAINLY_FAKE", "UNCERTAIN"))
        self.assertGreaterEqual(len(forensic_res.reasons), 1)
        self.assertIn("frequency_domain", forensic_res.technical_breakdown)
        self.assertIn("signal_processing", forensic_res.technical_breakdown)

        # Test Text perplexity & burstiness analyzer
        text_res = detector.analyze_text(scam_text, "Financial coercion message")
        self.assertIsNotNone(text_res.ai_probability)
        self.assertIn("statistical", text_res.technical_breakdown)

if __name__ == "__main__":
    unittest.main()
