# ADONAI Threat Intelligence Data Plan

There is no complete universal cybersecurity dataset. Threat intelligence changes continuously and sources have different access, licensing, quality, and redistribution conditions. Implement updateable connectors; do not claim all threats are included.

| Source | Data | Use | Important handling |
|---|---|---|---|
| MITRE ATT&CK STIX | Tactics, techniques, software, groups, mitigations | Attack taxonomy and mappings | Pin versions; cite STIX IDs |
| CISA KEV | Exploited CVEs | Prioritize known exploited vulnerabilities | Do not equate all CVEs with active attacks |
| NIST NVD | CVE, CVSS, CWE, CPE | Vulnerability context | API limits/key requirements |
| CISA advisories | Threat/vulnerability advisories | Current defensive guidance | Preserve dates and source URLs |
| MISP | Shared IOCs/events | IOC enrichment | Trust/confidence and feed provenance |
| URLhaus | Malicious URLs | URL/domain reputation | Respect API terms |
| PhishTank | Phishing URLs | Phishing detection | Validate feed access and freshness |
| Spamhaus | IP/domain reputation | Network reputation | Follow access/redistribution terms |
| AbuseIPDB | IP reports/reputation | IP enrichment | API key, rate limits, abuse reports are not proof |
| MalwareBazaar | Malware hashes/metadata | Malware intelligence | Do not download/execute binaries by default |
| Have I Been Pwned | Breach/account exposure | User-authorized breach checks | Never upload plaintext passwords |
| SigmaHQ | Detection rules | Event-based detections | Validate log-source compatibility/license |
| YARA rules | File pattern rules | User-selected file/lab scanning | Provenance and false-positive tests |
| Zeek/Suricata rules | Network signatures | Lab/network detection | Check compatibility and license |
| OWASP Top 10 / ASVS | App security risks/controls | Threat taxonomy and guidance | Not an IOC feed |
| MITRE D3FEND | Defensive techniques | Map mitigations | Keep versioned mappings |

Research datasets to evaluate:
- CIC-IDS2017
- CSE-CIC-IDS2018
- CTU-13
- UNSW-NB15
- Bot-IoT
- Stratosphere IPS datasets
- Public phishing URL datasets with explicit licensing and label provenance

For every dataset, record:
- License/terms and allowed use.
- Collection date/time window.
- Feature schema and labels.
- Class imbalance.
- Known labeling errors.
- Train/test split.
- Leakage risks.
- Whether raw PCAPs or binaries are included.
- Safe handling requirements.

Do not train on a dataset and report test performance using a random split if records from the same campaign/host/time period can leak across train and test. Prefer time-separated and source-separated evaluation.

## Safe pilot fixtures
Use reserved example domains such as `example.com`, `.test`, `.invalid`, and reserved IP ranges in isolated tests. Mark every fixture `TEST_ONLY`; do not place it in production IOC tables.
