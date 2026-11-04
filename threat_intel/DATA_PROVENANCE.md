# ADONAI — Threat Intelligence Data Provenance & Split Methodology

## 1. Provenance & Separation Rules
- Every indicator in `threat_intel/normalized_iocs.jsonl` and `ThreatIndicator` carries `source_id`, `confidence`, `first_seen`, `last_seen`, `license`, and `is_test_fixture`.
- Safe test fixtures (`threat_intel/test_fixtures.json`) use RFC 2606 (`.test`, `.invalid`) and RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) reserved ranges and are marked `is_test_fixture = 1` (`LAB_AND_TEST_ONLY`).

## 2. Dataset Evaluation & Split Discipline
When evaluating anomaly or lexical classifiers against CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, UNSW-NB15, or Bot-IoT:
- **No Random Row Shuffling Across Campaigns**: Random k-fold splits across flows from the same capture hour or botnet host cause severe temporal and host-identity data leakage.
- **Required Split**: Strict time-window and source-subnet/scenario separation (e.g., CTU-13 scenario-disjoint split; CIC-IDS2017 day-disjoint split).
- **No Binary Execution**: Only flow summaries, Zeek logs, and defanged lexical strings are ingested; malware binaries are excluded.
