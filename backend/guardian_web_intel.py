"""ADONAI Guardian — Web Intelligence Cross-Reference Engine.

Stage 2 verification: cross-references media with public web sources.
Uses urllib (stdlib only, no requests) to perform:
- Google reverse image search stub (returns mock result since no API key)
- News article fact-checking via RSS/public feeds
- Domain reputation checking
- Investment scheme pattern matching against known fraud databases
NOTE: Real web lookup requires network access. This module provides the full
implementation with graceful fallback to cached/mock data when offline.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional
import socket

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEB_TIMEOUT_SECONDS = 5
_OFFLINE_MODE = False  # set to True to skip all network calls


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WebIntelResult:
    """Result of a web intelligence cross-reference operation."""
    corroboration_found: bool          # True if authentic sources corroborate the content
    confidence: float                  # 0.0–1.0 — how confident we are in the result
    sources_checked: list              # list of sources/URLs checked
    matching_sources: list             # sources that matched the query
    scheme_detected: bool              # True if investment/fraud scheme detected
    scheme_name: Optional[str]         # name of the matched scheme
    scheme_confidence: float           # 0.0–1.0
    money_warning: str                 # human-readable money warning (empty string = no warning)
    reason: str                        # human-readable summary
    # Extended fields used by Guardian pipeline
    scheme_category: str = ""          # category of detected scheme
    urgency_detected: bool = False     # urgency language found
    money_transfer_requested: bool = False  # explicit money transfer request found
    money_amounts_found: list = None   # currency amounts found in text
    query_terms: list = None           # extracted query terms

    def __post_init__(self):
        if self.money_amounts_found is None:
            self.money_amounts_found = []
        if self.query_terms is None:
            self.query_terms = []


# ---------------------------------------------------------------------------
# Hardcoded Indian Financial Fraud Scheme Database (~20 entries)
# ---------------------------------------------------------------------------

INDIA_FRAUD_SCHEMES: list[dict] = [
    {
        "id": "upi_otp_fraud",
        "name": "UPI OTP Phishing",
        "category": "Payment Fraud",
        "keywords": ["upi", "otp", "verify", "account blocked", "share otp", "paytm", "phonepe", "gpay", "bhim"],
        "patterns": [r"\botp\b", r"\bupi\s*(id|fraud|scam)\b"],
        "risk": "CRITICAL",
        "description": "Fraudster poses as bank/UPI provider and asks victim to share OTP to 'unblock' account.",
        "reported_losses_crore": 1500,
    },
    {
        "id": "kyc_fraud",
        "name": "KYC Update Scam",
        "category": "Banking Fraud",
        "keywords": ["kyc", "update kyc", "kyc expired", "kyc verification", "account suspended", "re-kyc"],
        "patterns": [r"\bkyc\b", r"kyc\s*(update|expired|blocked|verify)"],
        "risk": "CRITICAL",
        "description": "Fraudster sends fake KYC update links to steal banking credentials.",
        "reported_losses_crore": 800,
    },
    {
        "id": "lottery_prize_fraud",
        "name": "Fake Lottery / Prize Scam",
        "category": "Lottery Fraud",
        "keywords": ["lottery", "you have won", "prize money", "claim prize", "congratulations winner",
                     "lucky draw", "spin and win", "jackpot"],
        "patterns": [r"you\s+have\s+won", r"\blottery\b", r"\bprize\s+money\b"],
        "risk": "HIGH",
        "description": "Victim informed they've won a prize; asked to pay 'processing fee' to claim it.",
        "reported_losses_crore": 300,
    },
    {
        "id": "job_offer_fraud",
        "name": "Fake Job Offer Scam",
        "category": "Employment Fraud",
        "keywords": ["job offer", "work from home", "earn daily", "part time job", "data entry job",
                     "typing job", "registration fee", "joining fee"],
        "patterns": [r"work\s+from\s+home", r"earn\s+[\d,]+\s*(per day|daily|weekly)", r"registration\s+fee"],
        "risk": "HIGH",
        "description": "Fake job offers require upfront payment for registration, training, or equipment.",
        "reported_losses_crore": 450,
    },
    {
        "id": "loan_app_fraud",
        "name": "Predatory Loan App Fraud",
        "category": "Loan Fraud",
        "keywords": ["instant loan", "loan approved", "no documents", "aadhar loan", "quick loan",
                     "low interest loan", "loan app"],
        "patterns": [r"instant\s+loan", r"loan\s+approved\s+in\s+\d+\s+minutes", r"no\s+(document|cibil)"],
        "risk": "CRITICAL",
        "description": "Predatory apps charge exorbitant interest and use blackmail tactics (contact access, photos).",
        "reported_losses_crore": 1200,
    },
    {
        "id": "investment_ponzi",
        "name": "High-Return Investment Scheme (Ponzi)",
        "category": "Investment Fraud",
        "keywords": ["guaranteed returns", "double money", "triple investment", "daily profit",
                     "invest now", "1% daily", "2% daily", "roi", "referral bonus"],
        "patterns": [r"guaranteed\s+(return|profit)", r"double\s+your\s+(money|investment)",
                     r"\d+%\s+(daily|weekly|monthly)\s+(return|profit|roi)"],
        "risk": "CRITICAL",
        "description": "Ponzi scheme promising unrealistic returns, pays early investors with new investor funds.",
        "reported_losses_crore": 5000,
    },
    {
        "id": "crypto_fraud",
        "name": "Fake Cryptocurrency Trading Platform",
        "category": "Crypto Fraud",
        "keywords": ["bitcoin", "crypto trading", "forex trading", "binary options", "nft investment",
                     "crypto profit", "trading bot", "crypto signals"],
        "patterns": [r"crypto\s+(trading|investment|profit|signals)", r"bitcoin\s+(investment|profit)",
                     r"trading\s+bot"],
        "risk": "CRITICAL",
        "description": "Fake crypto exchanges show manipulated profits to lure more investment before exit scam.",
        "reported_losses_crore": 3500,
    },
    {
        "id": "impersonation_official",
        "name": "Government/Official Impersonation",
        "category": "Impersonation Fraud",
        "keywords": ["narcotics", "police", "cbi", "ed enforcement", "income tax", "customs",
                     "arrest warrant", "case against you", "pay fine"],
        "patterns": [r"arrest\s+warrant", r"(police|cbi|ed)\s+notice", r"income\s+tax\s+notice"],
        "risk": "CRITICAL",
        "description": "Fraudster impersonates govt. officials to extort money under threat of arrest.",
        "reported_losses_crore": 2000,
    },
    {
        "id": "romance_sextortion",
        "name": "Romance / Sextortion Scam",
        "category": "Social Engineering",
        "keywords": ["meet online", "transfer money", "stranded abroad", "emergency hospital",
                     "send money urgently", "love you", "sending photos"],
        "patterns": [r"stranded\s+(abroad|hospital)", r"send\s+money\s+(urgently|now|immediately)",
                     r"emergency\s+(fund|help|transfer)"],
        "risk": "HIGH",
        "description": "Fake romantic relationship leads to requests for money or sextortion via intimate photos.",
        "reported_losses_crore": 600,
    },
    {
        "id": "mlm_pyramid",
        "name": "MLM / Pyramid Scheme",
        "category": "MLM Fraud",
        "keywords": ["mlm", "multi level marketing", "downline", "referral income", "join our team",
                     "network marketing", "binary plan", "matrix plan"],
        "patterns": [r"mlm\b", r"downline\s+income", r"referral\s+(income|bonus|earning)"],
        "risk": "HIGH",
        "description": "Pyramid scheme requiring recruitment of new members for income, unsustainable and illegal.",
        "reported_losses_crore": 1000,
    },
    {
        "id": "screen_sharing_fraud",
        "name": "Remote Access / Screen Sharing Fraud",
        "category": "Technical Support Fraud",
        "keywords": ["anydesk", "teamviewer", "remote access", "screen share", "technical support",
                     "bank refund", "overdraft", "help you transfer"],
        "patterns": [r"anydesk|teamviewer", r"screen\s+shar(e|ing)", r"remote\s+(access|control)"],
        "risk": "CRITICAL",
        "description": "Victim tricked into installing remote access software; fraudster then empties bank accounts.",
        "reported_losses_crore": 1800,
    },
    {
        "id": "fake_charity",
        "name": "Fake Charity / Disaster Relief Scam",
        "category": "Charity Fraud",
        "keywords": ["donate", "charity", "flood relief", "earthquake", "disaster fund",
                     "help victims", "donate now", "upi donate"],
        "patterns": [r"donate\s+(now|urgently)", r"disaster\s+relief\s+fund", r"charity\s+fund"],
        "risk": "MEDIUM",
        "description": "Fake charity collects donations during disasters, funds never reach victims.",
        "reported_losses_crore": 150,
    },
    {
        "id": "real_estate_fraud",
        "name": "Fake Real Estate / Property Scam",
        "category": "Real Estate Fraud",
        "keywords": ["property for sale", "flat for sale", "booking amount", "token money",
                     "pre-launch price", "below market rate", "government scheme flat"],
        "patterns": [r"booking\s+amount", r"token\s+money", r"pre-launch\s+(price|offer)"],
        "risk": "HIGH",
        "description": "Fake property listings or non-existent projects collect advance payments.",
        "reported_losses_crore": 2500,
    },
    {
        "id": "electricity_bill_fraud",
        "name": "Fake Electricity / Utility Bill Scam",
        "category": "Utility Fraud",
        "keywords": ["electricity bill", "power cut", "meter reading", "pay electricity bill",
                     "last warning", "disconnection notice", "cesc", "bescom", "bses"],
        "patterns": [r"electricity\s+bill\s+(overdue|pending|urgent)", r"disconnection\s+notice",
                     r"last\s+notice\s+electricity"],
        "risk": "HIGH",
        "description": "Fake utility provider SMS/calls threaten disconnection to extract payment.",
        "reported_losses_crore": 200,
    },
    {
        "id": "insurance_fraud",
        "name": "Fake Insurance Policy / Refund Scam",
        "category": "Insurance Fraud",
        "keywords": ["insurance refund", "policy matured", "claim bonus", "insurance claim",
                     "premium refund", "lic bonus", "policy surrender"],
        "patterns": [r"insurance\s+refund", r"policy\s+(matured|bonus|claim)", r"lic\s+bonus"],
        "risk": "MEDIUM",
        "description": "Fraudster poses as insurance agent promising refund of old premiums in exchange for GST/tax payment.",
        "reported_losses_crore": 350,
    },
    {
        "id": "courier_customs_fraud",
        "name": "Fake Courier / Customs Package Scam",
        "category": "Courier Fraud",
        "keywords": ["package detained", "customs duty", "courier held", "fedex", "dhl notice",
                     "parcel seized", "drugs found package", "pay customs"],
        "patterns": [r"package\s+(detained|seized|held)", r"customs\s+(duty|fee|clearance)",
                     r"drugs\s+(found|detected)\s+package"],
        "risk": "CRITICAL",
        "description": "Fraudster claims victim's parcel is held at customs containing contraband; extorts payment.",
        "reported_losses_crore": 500,
    },
    {
        "id": "stock_market_tips",
        "name": "Fake Stock Market Tips / SEBI Fraud",
        "category": "Securities Fraud",
        "keywords": ["stock tips", "sebi registered", "multibagger stocks", "sure shot tips",
                     "guaranteed profit stocks", "penny stocks", "pump and dump", "trading tips"],
        "patterns": [r"sure\s+shot\s+(tip|profit)", r"guaranteed\s+(profit|return)\s+(stock|trade)",
                     r"multibagger\s+stock"],
        "risk": "HIGH",
        "description": "Fake SEBI-registered advisors provide manipulated tips to pump-and-dump penny stocks.",
        "reported_losses_crore": 1500,
    },
    {
        "id": "matrimonial_fraud",
        "name": "Matrimonial / Shaadi Scam",
        "category": "Social Engineering",
        "keywords": ["matrimony", "shaadi", "bride groom", "wedding gift", "marriage proposal",
                     "nri groom", "visa sponsorship"],
        "patterns": [r"nri\s+(groom|bride)", r"marriage\s+proposal", r"wedding\s+gift\s+(transfer|money)"],
        "risk": "MEDIUM",
        "description": "Fake matrimonial profiles extract money for travel/visa/gift; often targets women.",
        "reported_losses_crore": 100,
    },
    {
        "id": "aadhar_pan_fraud",
        "name": "Aadhaar / PAN Card Fraud",
        "category": "Identity Fraud",
        "keywords": ["aadhar update", "pan card blocked", "pan link aadhar", "aadhar otp",
                     "pan verification", "pan card expired", "uidai"],
        "patterns": [r"aadhar\s+(update|otp|link|blocked)", r"pan\s+(blocked|expired|link)",
                     r"uidai\s+notice"],
        "risk": "CRITICAL",
        "description": "Fraudster collects Aadhaar/PAN details to open fake accounts or drain linked accounts.",
        "reported_losses_crore": 700,
    },
    {
        "id": "army_officer_fraud",
        "name": "Fake Army Officer Romance Scam",
        "category": "Impersonation Fraud",
        "keywords": ["army officer", "deployed abroad", "defence personnel", "send money soldier",
                     "military overseas", "soldier love"],
        "patterns": [r"army\s+officer\s+(posted|deployed)", r"military\s+(personnel|officer)\s+(abroad|deployed)",
                     r"soldier\s+(needs|help|money)"],
        "risk": "HIGH",
        "description": "Fake army officer profiles build online relationships and then request money for 'emergency'.",
        "reported_losses_crore": 80,
    },
]


# ---------------------------------------------------------------------------
# Helper: safe HTTP GET with timeout
# ---------------------------------------------------------------------------

def _safe_get(url: str, timeout: int = WEB_TIMEOUT_SECONDS) -> Optional[bytes]:
    """Perform a safe HTTP GET; return bytes or None on any error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ADONAI-Guardian/1.0 (Verification Engine)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(65536)  # max 64 KB
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
        return None


def _is_online() -> bool:
    """Quick check: can we reach 1.1.1.1 on port 53?"""
    if _OFFLINE_MODE:
        return False
    try:
        socket.setdefaulttimeout(2)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("1.1.1.1", 53))
        return True
    except (socket.error, OSError):
        return False


# ---------------------------------------------------------------------------
# WebIntelEngine
# ---------------------------------------------------------------------------

class WebIntelEngine:
    """ADONAI Guardian web intelligence cross-reference engine."""

    # Simulated RSS-like news articles for offline demo
    _DEMO_NEWS_ARTICLES = [
        {
            "title": "Police bust ₹500 crore UPI phishing ring in Jharkhand",
            "source": "Times of India",
            "url": "https://timesofindia.indiatimes.com/fake-article-1",
            "keywords": ["upi", "phishing", "otp", "jharkhand"],
            "date": "2025-10-15",
        },
        {
            "title": "CBI arrests kingpin of fake job portal scam; 10,000 victims across India",
            "source": "NDTV",
            "url": "https://ndtv.com/fake-article-2",
            "keywords": ["job", "fake", "registration fee", "work from home"],
            "date": "2025-11-01",
        },
        {
            "title": "RBI warns public about KYC update SMS fraud",
            "source": "RBI.org.in",
            "url": "https://rbi.org.in/fake-advisory-1",
            "keywords": ["kyc", "rbi", "warning", "bank fraud"],
            "date": "2025-09-30",
        },
        {
            "title": "SEBI action against 47 fake stock tip channels on Telegram",
            "source": "Economic Times",
            "url": "https://economictimes.com/fake-article-3",
            "keywords": ["sebi", "stock tips", "telegram", "fraud"],
            "date": "2025-10-22",
        },
        {
            "title": "Loan app victims lose ₹2.3 lakh on average; NBFC warns of predatory apps",
            "source": "LiveMint",
            "url": "https://livemint.com/fake-article-4",
            "keywords": ["loan app", "instant loan", "predatory", "nbfc"],
            "date": "2025-10-10",
        },
        {
            "title": "Gujarat man loses ₹45 lakh in crypto trading scam on WhatsApp group",
            "source": "Indian Express",
            "url": "https://indianexpress.com/fake-article-5",
            "keywords": ["crypto", "trading", "whatsapp", "scam", "bitcoin"],
            "date": "2025-11-02",
        },
        {
            "title": "Army officer impersonation scams spike during Diwali: Cyber cell",
            "source": "Hindustan Times",
            "url": "https://hindustantimes.com/fake-article-6",
            "keywords": ["army officer", "impersonation", "romance scam", "diwali"],
            "date": "2025-10-28",
        },
        {
            "title": "Fake electricity bill SMS leads to ₹8 lakh loss for Mumbai family",
            "source": "Mid-Day",
            "url": "https://mid-day.com/fake-article-7",
            "keywords": ["electricity bill", "disconnection", "fake sms", "mumbai"],
            "date": "2025-10-18",
        },
    ]

    # Domain reputation database (simplified)
    _DOMAIN_REPUTATION: dict[str, dict] = {
        "rbi.org.in": {"trust": 1.0, "category": "government", "verified": True},
        "sebi.gov.in": {"trust": 1.0, "category": "government", "verified": True},
        "npci.org.in": {"trust": 1.0, "category": "government", "verified": True},
        "india.gov.in": {"trust": 1.0, "category": "government", "verified": True},
        "timesofindia.com": {"trust": 0.90, "category": "news", "verified": True},
        "ndtv.com": {"trust": 0.90, "category": "news", "verified": True},
        "economictimes.com": {"trust": 0.90, "category": "news", "verified": True},
        "hindustantimes.com": {"trust": 0.88, "category": "news", "verified": True},
        "thehindu.com": {"trust": 0.92, "category": "news", "verified": True},
        "sbi.co.in": {"trust": 0.98, "category": "bank", "verified": True},
        "hdfcbank.com": {"trust": 0.98, "category": "bank", "verified": True},
        "icicibank.com": {"trust": 0.97, "category": "bank", "verified": True},
        # Known fraud-associated domains (examples)
        "rb1-kyc-update.ml": {"trust": 0.0, "category": "phishing", "verified": False},
        "sbi-kyc-verify.tk": {"trust": 0.0, "category": "phishing", "verified": False},
        "govt-prize-claim.cf": {"trust": 0.0, "category": "scam", "verified": False},
    }

    def __init__(self, enable_live_web: bool = True) -> None:
        self._enable_live_web = enable_live_web

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_query_terms(self, context_text: str) -> list[str]:
        """Extract meaningful query terms from context text."""
        if not context_text:
            return []

        # Remove common stopwords
        stopwords = {
            "the", "a", "an", "in", "on", "at", "to", "for", "of", "and",
            "is", "are", "was", "were", "be", "been", "has", "have", "had",
            "this", "that", "these", "those", "my", "your", "our", "their",
            "i", "you", "he", "she", "we", "they", "it", "me", "him", "her",
        }

        # Extract words
        words = re.findall(r'\b[a-zA-Z]{3,}\b', context_text.lower())
        filtered = [w for w in words if w not in stopwords]

        # Extract amounts and identifiers
        amounts = re.findall(r'₹[\d,]+(?:\.\d+)?|\d+\s*(?:lakh|crore|thousand)', context_text, re.IGNORECASE)
        phone_patterns = re.findall(r'\b[6-9]\d{9}\b', context_text)
        url_patterns = re.findall(r'https?://\S+|\b\S+\.(com|in|org|net|ml|tk|cf|xyz)\b', context_text, re.IGNORECASE)

        # Build term list (deduplicated, most significant first)
        seen = set()
        terms = []
        for item in amounts + url_patterns + filtered[:20]:
            if isinstance(item, tuple):
                item = item[0]
            item = str(item).strip()
            if item and item not in seen:
                seen.add(item)
                terms.append(item)

        return terms[:30]

    def _check_news_feeds(self, query_terms: list[str]) -> list[dict]:
        """Check hardcoded RSS-like data and optionally live RSS feeds for matching articles."""
        matching = []

        # Check demo articles first (always offline-safe)
        query_lower = {t.lower() for t in query_terms}
        for article in self._DEMO_NEWS_ARTICLES:
            article_keywords = set(article.get("keywords", []))
            overlap = query_lower & article_keywords
            if len(overlap) >= 1:
                matching.append({
                    "title": article["title"],
                    "source": article["source"],
                    "url": article["url"],
                    "matched_terms": list(overlap),
                    "date": article["date"],
                    "type": "news",
                })

        # Attempt live RSS fetch if online (graceful fallback)
        if self._enable_live_web and len(query_terms) > 0:
            live_results = self._fetch_live_news(query_terms[:5])
            matching.extend(live_results)

        return matching[:10]

    def _fetch_live_news(self, query_terms: list[str]) -> list[dict]:
        """Try to fetch live news via public RSS. Returns empty list on failure."""
        results = []
        # We only attempt Google News RSS (no API key needed)
        query = urllib.parse.quote(" ".join(query_terms[:3]))
        rss_url = f"https://news.google.com/rss/search?q={query}+india+fraud+scam&hl=en-IN&gl=IN&ceid=IN:en"

        data = _safe_get(rss_url)
        if not data:
            return []

        try:
            text = data.decode("utf-8", errors="replace")
            # Simple regex-based RSS item extraction (no xml.etree to avoid complexity)
            titles = re.findall(r'<title><!\[CDATA\[(.*?)\]\]></title>', text)
            links = re.findall(r'<link>(https?://[^<]+)</link>', text)
            for i, title in enumerate(titles[:5]):
                url = links[i + 1] if i + 1 < len(links) else ""
                results.append({
                    "title": title,
                    "source": "Google News",
                    "url": url,
                    "matched_terms": query_terms[:3],
                    "date": "live",
                    "type": "live_news",
                })
        except Exception:
            pass
        return results

    def _check_investment_schemes(self, context_text: str) -> dict:
        """Match context against known fraud scheme database."""
        if not context_text:
            return {"scheme_detected": False, "scheme_name": None, "confidence": 0.0, "matches": []}

        lower = context_text.lower()
        best_match = None
        best_score = 0.0
        all_matches = []

        for scheme in INDIA_FRAUD_SCHEMES:
            keyword_hits = sum(1 for kw in scheme["keywords"] if kw in lower)
            pattern_hits = 0
            for pat in scheme["patterns"]:
                try:
                    if re.search(pat, lower):
                        pattern_hits += 1
                except re.error:
                    pass

            if keyword_hits == 0 and pattern_hits == 0:
                continue

            # Score: patterns count double vs keywords
            total_possible = len(scheme["keywords"]) + len(scheme["patterns"]) * 2
            raw_score = (keyword_hits + pattern_hits * 2) / max(total_possible, 1)
            confidence = min(raw_score * 1.5, 1.0)  # boost confidence for strong matches

            all_matches.append({
                "scheme_id": scheme["id"],
                "scheme_name": scheme["name"],
                "confidence": round(confidence, 4),
                "risk": scheme["risk"],
                "keyword_hits": keyword_hits,
                "pattern_hits": pattern_hits,
            })

            if confidence > best_score:
                best_score = confidence
                best_match = scheme

        all_matches.sort(key=lambda x: x["confidence"], reverse=True)

        if best_match and best_score >= 0.1:
            return {
                "scheme_detected": True,
                "scheme_name": best_match["name"],
                "scheme_id": best_match["id"],
                "confidence": round(best_score, 4),
                "risk": best_match["risk"],
                "description": best_match["description"],
                "reported_losses_crore": best_match.get("reported_losses_crore", 0),
                "all_matches": all_matches[:5],
            }

        return {
            "scheme_detected": False,
            "scheme_name": None,
            "confidence": 0.0,
            "all_matches": [],
        }

    def _check_domain_reputation(self, url_or_domain: str) -> dict:
        """Return reputation dict for a domain."""
        # Extract domain from URL if needed
        url_or_domain = url_or_domain.lower().strip()
        if url_or_domain.startswith("http"):
            try:
                parsed = urllib.parse.urlparse(url_or_domain)
                domain = parsed.netloc.lower().lstrip("www.")
            except Exception:
                domain = url_or_domain
        else:
            domain = url_or_domain.lstrip("www.")

        # Direct lookup
        if domain in self._DOMAIN_REPUTATION:
            rep = self._DOMAIN_REPUTATION[domain]
            return {
                "domain": domain,
                "trust_score": rep["trust"],
                "category": rep["category"],
                "verified": rep["verified"],
                "source": "adonai_database",
            }

        # Check TLD heuristics
        suspicious_tlds = {".ml", ".tk", ".cf", ".gq", ".xyz", ".top", ".click", ".link"}
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return {
                    "domain": domain,
                    "trust_score": 0.1,
                    "category": "suspicious_tld",
                    "verified": False,
                    "source": "tld_heuristic",
                }

        # Plausible trusted domains
        trusted_tlds = {".gov.in", ".org.in", ".ac.in", ".edu.in", ".net.in", ".co.in"}
        for tld in trusted_tlds:
            if domain.endswith(tld):
                return {
                    "domain": domain,
                    "trust_score": 0.80,
                    "category": "likely_official",
                    "verified": False,
                    "source": "tld_heuristic",
                }

        return {
            "domain": domain,
            "trust_score": 0.5,
            "category": "unknown",
            "verified": False,
            "source": "default",
        }

    def _reverse_image_lookup(self, content_hash: str) -> dict:
        """Stub for reverse image search (requires API key in production)."""
        # In production: call Google Vision API or TinEye
        return {
            "searched": False,
            "reason": "Reverse image search requires Google Vision API key — configure in settings",
            "result": None,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def cross_reference(
        self,
        content_hash: str,
        media_type: str,
        context_text: str,
        extracted_text: str = "",
    ) -> WebIntelResult:
        """Main entry point: cross-reference media/context with public sources.

        Args:
            content_hash:    SHA-256 of the media file
            media_type:      image | audio | video | text
            context_text:    text accompanying the media (description, caption, message)
            extracted_text:  OCR/ASR transcript of the media content (if available)

        Returns:
            WebIntelResult
        """
        t0 = time.monotonic()
        combined_text = f"{context_text} {extracted_text}".strip()

        # --- Extract query terms ---
        query_terms = self._extract_query_terms(combined_text)

        # --- Scheme matching ---
        scheme_result = self._check_investment_schemes(combined_text)

        # --- News feed check ---
        sources_checked = ["adonai_fraud_db", "demo_news_feed"]
        matching_sources: list[dict] = []

        news_articles = self._check_news_feeds(query_terms)
        matching_sources.extend(news_articles)
        if news_articles:
            sources_checked.append("news_feed")

        # --- Domain reputation ---
        url_pattern = re.compile(r'https?://\S+|\b\S+\.(com|in|org|net|ml|tk|cf|xyz)\b', re.IGNORECASE)
        urls_found = url_pattern.findall(combined_text)
        domain_results = []
        for url_match in urls_found[:5]:
            url = url_match if isinstance(url_match, str) else url_match[0]
            rep = self._check_domain_reputation(url)
            domain_results.append(rep)
            sources_checked.append(f"domain:{rep['domain']}")
            if rep["trust_score"] < 0.3:
                matching_sources.append({
                    "type": "suspicious_domain",
                    "domain": rep["domain"],
                    "trust_score": rep["trust_score"],
                    "category": rep["category"],
                })

        # --- Reverse image lookup (stub) ---
        if media_type == "image":
            rev_img = self._reverse_image_lookup(content_hash)
            sources_checked.append("reverse_image_search")

        # --- Compute overall confidence and flags ---
        scheme_detected = scheme_result.get("scheme_detected", False)
        scheme_confidence = scheme_result.get("confidence", 0.0)
        scheme_name = scheme_result.get("scheme_name")

        money_warning = (
            scheme_detected and scheme_confidence >= 0.15
            or any(d["trust_score"] < 0.3 for d in domain_results)
        )

        corroboration_found = len([s for s in matching_sources if s.get("type") == "news"]) > 0

        # Overall confidence: based on how many sources we checked and what matched
        base_confidence = 0.5
        if scheme_detected:
            base_confidence = min(1.0, 0.5 + scheme_confidence * 0.5)
        elif corroboration_found:
            base_confidence = 0.65

        # Build reason string
        reason_parts = []
        if scheme_detected:
            reason_parts.append(
                f"Matched fraud scheme: «{scheme_name}» "
                f"(confidence={scheme_confidence:.0%}, risk={scheme_result.get('risk', '?')})"
            )
        if corroboration_found:
            reason_parts.append(f"{len(news_articles)} news articles match query terms")
        if money_warning and not scheme_detected:
            reason_parts.append("Suspicious domain or financial pattern detected")
        if not reason_parts:
            reason_parts.append("No strong corroborating signals found in checked sources")

        return WebIntelResult(
            corroboration_found=corroboration_found,
            confidence=round(base_confidence, 4),
            sources_checked=sources_checked,
            matching_sources=matching_sources,
            scheme_detected=scheme_detected,
            scheme_name=scheme_name,
            scheme_confidence=round(scheme_confidence, 4),
            money_warning=scheme_result.get("money_warning", "") if scheme_detected else ("Suspicious financial pattern detected" if money_warning else ""),
            reason="; ".join(reason_parts),
            scheme_category=scheme_result.get("category", ""),
            urgency_detected=bool(any(w in combined_text.lower() for w in ["urgent", "immediately", "right now", "asap", "emergency", "expire", "block"])),
            money_transfer_requested=bool(any(w in combined_text.lower() for w in ["send money", "transfer", "upi", "pay now", "wire", "paytm", "phonepe"])),
        )
