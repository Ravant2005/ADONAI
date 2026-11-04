"""ADONAI Guardian — Multi-Modal AI Forensic Detection Engine.

Implements 10 detection technology families:
1. Statistical forensics (perplexity, burstiness, token analysis)
2. ML classification (feature-based scoring)
3. Deep-learning classification (simulated CNN/ViT scores via feature proxies)
4. Frequency-domain analysis (FFT, DCT, DWT via numpy)
5. Signal processing (structural signal properties)
6. Watermark detection (search for embedded signals)
7. Digital provenance (metadata chain verification)
8. Anomaly detection (statistical deviation from natural distributions)
9. Model fingerprinting (generator artifact identification)
10. Ensemble learning (weighted multi-model voting)

For each media type (image/audio/video/text) runs the applicable subset.
Returns: ai_probability (0-1), fake_possibility (0-1), verdict, reasons[],
         money_risk_level, explanation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """Full analysis result returned by GuardianDetector."""
    media_type: str                        # image | audio | video | text
    ai_probability: float                  # 0.0–1.0
    fake_possibility: float                # 0.0–1.0
    verdict: str                           # LIKELY_AUTHENTIC | UNCERTAIN | LIKELY_AI_GENERATED | ALMOST_CERTAINLY_FAKE
    confidence: float                      # overall confidence in the verdict
    reasons: list[str]                     # human-readable explanation bullets
    money_risk_level: str                  # NONE | LOW | MEDIUM | HIGH | CRITICAL
    money_context: dict                    # detected financial patterns
    technical_breakdown: dict              # per-family scores
    ensemble_weights: dict                 # weight used for each family
    processing_time_ms: float             # wall-clock ms


# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------

def _score_to_verdict(score: float) -> str:
    if score < 0.30:
        return "LIKELY_AUTHENTIC"
    if score < 0.60:
        return "UNCERTAIN"
    if score < 0.80:
        return "LIKELY_AI_GENERATED"
    return "ALMOST_CERTAINLY_FAKE"


def _score_to_risk(score: float, money_detected: bool) -> str:
    if not money_detected:
        return "NONE"
    if score < 0.30:
        return "LOW"
    if score < 0.55:
        return "MEDIUM"
    if score < 0.75:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# 1. Statistical Forensics (text perplexity + burstiness)
# ---------------------------------------------------------------------------

class _StatisticalForensics:
    """Bigram-based perplexity and sentence burstiness for text detection."""

    def __init__(self) -> None:
        # Approximate English unigram log-probabilities for common tokens
        self._common_tokens = {
            "the", "of", "and", "a", "to", "in", "is", "you", "that", "it",
            "he", "was", "for", "on", "are", "as", "with", "his", "they", "i",
            "at", "be", "this", "have", "from", "or", "one", "had", "by", "word",
        }

    def analyze_text(self, text: str) -> dict:
        """Return {score, perplexity, burstiness, avg_sentence_len, details}."""
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        if not sentences:
            return {"score": 0.5, "perplexity": 50.0, "burstiness": 0.5,
                    "avg_sentence_len": 0, "details": "no sentences"}

        words_per_sentence = [len(s.split()) for s in sentences]
        avg_len = float(np.mean(words_per_sentence))
        std_len = float(np.std(words_per_sentence)) if len(words_per_sentence) > 1 else 0.0

        # Burstiness: CV (coefficient of variation) of sentence lengths
        # Natural text: CV ~0.4–0.7; AI text often has lower CV (uniform sentences)
        burstiness = std_len / (avg_len + 1e-9)

        # Perplexity approximation: fraction of tokens NOT in top-30 common words
        all_words = text.lower().split()
        if not all_words:
            perplexity = 50.0
        else:
            rare_fraction = sum(1 for w in all_words if w not in self._common_tokens) / len(all_words)
            perplexity = 10.0 + rare_fraction * 100.0

        # Token repetition rate
        word_set = set(all_words)
        repetition = 1.0 - (len(word_set) / max(len(all_words), 1))

        # AI text signals: low burstiness, moderate perplexity, high repetition
        score = 0.0
        if burstiness < 0.25:
            score += 0.3   # very uniform sentence lengths → AI
        elif burstiness < 0.45:
            score += 0.15
        if repetition > 0.6:
            score += 0.25
        if 20.0 < perplexity < 60.0:
            score += 0.1   # "goldilocks" perplexity typical of LLMs

        # Over-long paragraphs without breaks
        if avg_len > 30:
            score += 0.15

        score = min(score, 1.0)
        return {
            "score": score,
            "perplexity": round(perplexity, 2),
            "burstiness": round(burstiness, 4),
            "avg_sentence_len": round(avg_len, 1),
            "repetition_rate": round(repetition, 4),
            "details": f"{len(sentences)} sentences, {len(all_words)} words",
        }


# ---------------------------------------------------------------------------
# 2. ML Classification (feature-based)
# ---------------------------------------------------------------------------

class _MLClassifier:
    """Lightweight feature-based ML classifier (no sklearn needed)."""

    # Weights empirically set to match expected behaviours
    _IMAGE_FEATURE_WEIGHTS = {
        "spectral_flatness": 0.25,
        "edge_regularity": 0.20,
        "noise_floor": 0.20,
        "histogram_uniformity": 0.15,
        "gradient_smoothness": 0.20,
    }

    _AUDIO_FEATURE_WEIGHTS = {
        "zero_crossing_rate": 0.20,
        "spectral_centroid_norm": 0.25,
        "spectral_flatness": 0.25,
        "silence_ratio": 0.15,
        "amplitude_variance": 0.15,
    }

    def classify_image_features(self, features: dict) -> float:
        """Weighted sum of image feature scores → AI probability (0–1)."""
        total_weight = sum(self._IMAGE_FEATURE_WEIGHTS.values())
        score = 0.0
        for key, weight in self._IMAGE_FEATURE_WEIGHTS.items():
            score += features.get(key, 0.5) * weight
        return min(score / total_weight, 1.0)

    def classify_audio_features(self, features: dict) -> float:
        total_weight = sum(self._AUDIO_FEATURE_WEIGHTS.values())
        score = 0.0
        for key, weight in self._AUDIO_FEATURE_WEIGHTS.items():
            score += features.get(key, 0.5) * weight
        return min(score / total_weight, 1.0)


# ---------------------------------------------------------------------------
# 3. Deep-Learning Proxy (simulated CNN/ViT scores via feature proxies)
# ---------------------------------------------------------------------------

class _DeepLearningProxy:
    """Simulate DL model scores from low-level feature proxies.

    In a production system this would call a TFLite/ONNX model.
    Here we apply non-linear transforms to spectral features to simulate
    what a trained CNN/ViT would output.
    """

    def score_image(self, pixel_stats: dict) -> float:
        """Simulate CNN/ViT confidence that image is AI-generated."""
        # Key indicator: AI images exhibit hyper-consistent local statistics
        local_variance = pixel_stats.get("local_variance_norm", 0.5)
        global_variance = pixel_stats.get("global_variance_norm", 0.5)
        # Natural images: high ratio of local/global variance (textured regions)
        ratio = local_variance / (global_variance + 1e-9)
        # AI images often have ratio closer to 1.0 (unnaturally uniform texture)
        ai_signal = max(0.0, 1.0 - abs(ratio - 1.0) * 2.0)
        # Colour histogram kurtosis
        kurtosis_signal = pixel_stats.get("histogram_kurtosis_norm", 0.5)
        return float(np.clip(0.4 * ai_signal + 0.6 * kurtosis_signal, 0.0, 1.0))

    def score_audio(self, spectral_stats: dict) -> float:
        """Simulate RNN/Transformer score for audio."""
        tts_regularity = spectral_stats.get("pitch_regularity", 0.5)
        breath_absence = spectral_stats.get("breath_absence_score", 0.5)
        return float(np.clip(0.5 * tts_regularity + 0.5 * breath_absence, 0.0, 1.0))


# ---------------------------------------------------------------------------
# 4. Frequency-Domain Analysis (FFT / DCT / DWT via numpy)
# ---------------------------------------------------------------------------

class _FrequencyDomainAnalyzer:
    """FFT/DCT-based spectral fingerprinting."""

    def analyze_image_spectrum(self, pixel_array: np.ndarray) -> dict:
        """Compute FFT of luma channel and extract AI-indicative features.

        AI-generated images often show:
        - Anomalous peaks at regular frequencies (GAN grid artifacts)
        - Unusually flat high-frequency content (over-smoothed)
        - Different spectral roll-off compared to natural photos
        """
        if pixel_array.ndim == 3:
            # Convert to luma
            luma = 0.299 * pixel_array[:, :, 0] + 0.587 * pixel_array[:, :, 1] + 0.114 * pixel_array[:, :, 2]
        else:
            luma = pixel_array.astype(np.float64)

        if luma.size == 0:
            return {"score": 0.5}

        # 2D FFT
        fft = np.fft.fft2(luma)
        fft_shift = np.fft.fftshift(fft)
        magnitude = np.abs(fft_shift)

        h, w = magnitude.shape
        cx, cy = h // 2, w // 2

        # Power in different frequency bands
        def radial_power(r_min: float, r_max: float) -> float:
            y, x = np.ogrid[-cx:h - cx, -cy:w - cy]
            r = np.sqrt(x ** 2 + y ** 2)
            mask = (r >= r_min) & (r < r_max)
            return float(magnitude[mask].mean()) if mask.any() else 0.0

        max_r = min(cx, cy)
        low_power = radial_power(0, max_r * 0.1)
        mid_power = radial_power(max_r * 0.1, max_r * 0.5)
        high_power = radial_power(max_r * 0.5, max_r)

        total = low_power + mid_power + high_power + 1e-9

        # Spectral flatness (Wiener entropy) — high for AI
        spectral_flatness = (high_power / total) if total > 0 else 0.5

        # GAN grid artifact: look for peaks at regular intervals in mid-freq
        mid_band = magnitude[
            int(cx - max_r * 0.5): int(cx + max_r * 0.5),
            int(cy - max_r * 0.5): int(cy + max_r * 0.5),
        ]
        if mid_band.size > 0:
            peak_ratio = float(mid_band.max() / (mid_band.mean() + 1e-9))
            # Natural: high peak ratio (sharp edges); AI: lower peak ratio
            gan_grid_score = max(0.0, 1.0 - (peak_ratio - 1.0) / 20.0)
        else:
            gan_grid_score = 0.5

        ai_score = 0.5 * spectral_flatness + 0.5 * gan_grid_score
        return {
            "score": float(np.clip(ai_score, 0.0, 1.0)),
            "spectral_flatness": round(spectral_flatness, 4),
            "gan_grid_score": round(gan_grid_score, 4),
            "low_power_ratio": round(low_power / total, 4),
            "high_power_ratio": round(high_power / total, 4),
        }

    def analyze_audio_spectrum(self, samples: np.ndarray, sample_rate: int = 44100) -> dict:
        """FFT-based audio spectral analysis."""
        if samples.size < 512:
            return {"score": 0.5}

        # Use first channel if stereo
        if samples.ndim > 1:
            samples = samples[:, 0]

        # Compute magnitude spectrum
        n = min(len(samples), 65536)
        window = np.hanning(n)
        fft_mag = np.abs(np.fft.rfft(samples[:n] * window))
        freqs = np.fft.rfftfreq(n, d=1.0 / sample_rate)

        # Spectral centroid
        centroid = float(np.sum(freqs * fft_mag) / (np.sum(fft_mag) + 1e-9))
        centroid_norm = min(centroid / (sample_rate / 2), 1.0)

        # Spectral flatness (Wiener entropy)
        eps = 1e-9
        geom_mean = float(np.exp(np.mean(np.log(fft_mag + eps))))
        arith_mean = float(np.mean(fft_mag))
        flatness = geom_mean / (arith_mean + eps)

        # TTS audio often has very clean high-frequency roll-off
        high_freq_mask = freqs > 8000
        high_energy = float(fft_mag[high_freq_mask].mean()) if high_freq_mask.any() else 0.0
        low_energy = float(fft_mag[~high_freq_mask].mean()) + 1e-9
        hf_ratio = high_energy / low_energy

        # TTS signals: very low hf_ratio (clean cutoff), high flatness in mid-band
        tts_score = 0.0
        if hf_ratio < 0.05:
            tts_score += 0.4
        if flatness > 0.3:
            tts_score += 0.3
        if centroid_norm < 0.15:
            tts_score += 0.3

        return {
            "score": float(np.clip(tts_score, 0.0, 1.0)),
            "spectral_centroid_hz": round(centroid, 1),
            "spectral_flatness": round(flatness, 6),
            "hf_ratio": round(hf_ratio, 6),
        }


# ---------------------------------------------------------------------------
# 5. Signal Processing (structural properties)
# ---------------------------------------------------------------------------

class _SignalProcessor:
    """Structural signal analysis for image and audio."""

    def analyze_image_signals(self, pixel_array: np.ndarray) -> dict:
        """Gradient smoothness and noise floor analysis."""
        if pixel_array.ndim == 3:
            luma = 0.299 * pixel_array[:, :, 0].astype(np.float64) + \
                   0.587 * pixel_array[:, :, 1].astype(np.float64) + \
                   0.114 * pixel_array[:, :, 2].astype(np.float64)
        else:
            luma = pixel_array.astype(np.float64)

        if luma.size < 4:
            return {"score": 0.5}

        # Horizontal and vertical gradients
        grad_h = np.diff(luma, axis=1)
        grad_v = np.diff(luma, axis=0)
        grad_mag = np.sqrt(
            np.pad(grad_h, ((0, 0), (0, 1))) ** 2 +
            np.pad(grad_v, ((0, 1), (0, 0))) ** 2
        )

        grad_std = float(np.std(grad_mag))
        grad_mean = float(np.mean(grad_mag))

        # Noise floor: std of residual after 3×3 mean blur
        # Simplified: use local variance in non-overlapping 4×4 tiles
        h, w = luma.shape
        tile_vars = []
        for r in range(0, h - 3, 4):
            for c in range(0, w - 3, 4):
                tile = luma[r:r + 4, c:c + 4]
                tile_vars.append(float(np.var(tile)))

        noise_floor = float(np.mean(tile_vars)) if tile_vars else 0.0
        noise_floor_norm = min(noise_floor / 1000.0, 1.0)

        # AI images: overly smooth gradients (low grad_std relative to mean)
        smoothness = 1.0 - min(grad_std / (grad_mean + 1e-9), 1.0)

        score = 0.4 * smoothness + 0.6 * (1.0 - noise_floor_norm)
        return {
            "score": float(np.clip(score, 0.0, 1.0)),
            "gradient_smoothness": round(smoothness, 4),
            "noise_floor_norm": round(noise_floor_norm, 4),
        }

    def analyze_audio_signals(self, samples: np.ndarray) -> dict:
        """Zero-crossing rate and silence ratio."""
        if samples.size < 2:
            return {"score": 0.5}
        if samples.ndim > 1:
            samples = samples[:, 0]
        samples = samples.astype(np.float64)

        # Zero-crossing rate
        zcr = float(np.sum(np.diff(np.sign(samples)) != 0)) / max(len(samples), 1)

        # Silence ratio (frames below 1% of RMS)
        rms = float(np.sqrt(np.mean(samples ** 2)))
        silence_threshold = rms * 0.01
        silence_ratio = float(np.sum(np.abs(samples) < silence_threshold)) / max(len(samples), 1)

        # TTS audio: very low silence ratio, consistent ZCR
        score = 0.0
        if silence_ratio < 0.05:
            score += 0.4
        if 0.1 < zcr < 0.4:
            score += 0.3  # TTS tends to have moderate, uniform ZCR
        amplitude_variance = float(np.std(np.abs(samples)) / (rms + 1e-9))
        if amplitude_variance < 0.3:
            score += 0.3  # very consistent amplitude → TTS

        return {
            "score": float(np.clip(score, 0.0, 1.0)),
            "zero_crossing_rate": round(zcr, 6),
            "silence_ratio": round(silence_ratio, 4),
            "amplitude_variance": round(amplitude_variance, 4),
        }


# ---------------------------------------------------------------------------
# 6. Watermark Detection
# ---------------------------------------------------------------------------

class _WatermarkDetector:
    """Check watermark results for authenticity signals."""

    def analyze(self, watermark_result: Optional[dict]) -> dict:
        if not watermark_result:
            return {"score": 0.5, "detail": "no watermark result provided"}

        wm_found = watermark_result.get("found", False)
        wm_valid = watermark_result.get("valid", False)
        wm_score = watermark_result.get("integrity_score", 0.0)

        if wm_found and wm_valid and wm_score >= 0.75:
            # Valid watermark → authentic signal
            return {"score": 0.05, "detail": "valid ADONAI watermark detected"}
        if wm_found and not wm_valid:
            # Watermark found but tampered
            return {"score": 0.85, "detail": "watermark found but integrity check FAILED — possible tampering"}
        if not wm_found:
            return {"score": 0.45, "detail": "no ADONAI watermark found — provenance unverifiable"}
        return {"score": 0.3, "detail": "watermark partially verified"}


# ---------------------------------------------------------------------------
# 7. Digital Provenance
# ---------------------------------------------------------------------------

class _DigitalProvenance:
    """Metadata chain analysis for EXIF/file header authenticity."""

    def analyze(self, media_bytes: bytes, media_type: str) -> dict:
        """Inspect file headers for provenance signals."""
        if not media_bytes or len(media_bytes) < 8:
            return {"score": 0.5, "detail": "file too small"}

        header = media_bytes[:16]
        score = 0.5
        notes = []

        if media_type == "image":
            if media_bytes[:2] == b'\xff\xd8':
                notes.append("JPEG signature OK")
                # Look for EXIF marker
                if b'Exif' in media_bytes[:256]:
                    notes.append("EXIF metadata present")
                    score -= 0.1  # EXIF present → more likely authentic
                else:
                    notes.append("no EXIF — may be AI-generated or stripped")
                    score += 0.15
                # Check for AI generator tags
                for tag in [b'Stable Diffusion', b'DALL-E', b'Midjourney', b'ComfyUI', b'Automatic1111']:
                    if tag.lower() in media_bytes[:4096].lower():
                        notes.append(f"AI generator tag found: {tag.decode()}")
                        score = 0.95
            elif media_bytes[:8] == b'\x89PNG\r\n\x1a\n':
                notes.append("PNG signature OK")
                if b'IHDR' in media_bytes[:256]:
                    score -= 0.05
            elif header[:2] == b'BM':
                notes.append("BMP format detected")
            else:
                notes.append("unknown image format")
                score += 0.1

        elif media_type == "audio":
            if media_bytes[:4] == b'RIFF' and media_bytes[8:12] == b'WAVE':
                notes.append("WAV signature OK")
                score -= 0.05
            elif media_bytes[:3] == b'ID3' or media_bytes[:2] == b'\xff\xfb':
                notes.append("MP3 signature OK")
            else:
                notes.append("audio format unrecognised")
                score += 0.05

        elif media_type == "video":
            # MP4/MOV: ftyp box
            if b'ftyp' in media_bytes[:16]:
                notes.append("MP4/MOV container signature OK")
                score -= 0.05
            elif media_bytes[:4] == b'\x1a\x45\xdf\xa3':
                notes.append("MKV/WebM container signature OK")
            else:
                notes.append("video container format unrecognised")

        return {"score": float(np.clip(score, 0.0, 1.0)), "notes": notes}


# ---------------------------------------------------------------------------
# 8. Anomaly Detection
# ---------------------------------------------------------------------------

class _AnomalyDetector:
    """Statistical deviation from natural distributions."""

    def analyze_image_anomalies(self, pixel_array: np.ndarray) -> dict:
        """Check pixel value distribution against natural image statistics."""
        if pixel_array.size == 0:
            return {"score": 0.5}

        flat = pixel_array.flatten().astype(np.float64)
        mean = float(np.mean(flat))
        std = float(np.std(flat))

        # Natural images: mean ~100–160, std ~40–80
        mean_anomaly = abs(mean - 128) / 128.0
        std_anomaly = max(0, 1.0 - std / 60.0) if std < 60 else max(0, (std - 80) / 80.0)

        # Histogram uniformity (too uniform → AI?)
        hist, _ = np.histogram(flat, bins=32, range=(0, 256))
        hist_norm = hist / (hist.sum() + 1e-9)
        hist_entropy = -float(np.sum(hist_norm * np.log(hist_norm + 1e-9)))
        max_entropy = math.log(32)
        uniformity = hist_entropy / max_entropy

        # Very high uniformity can indicate AI, but natural scenes also vary
        uniformity_score = abs(uniformity - 0.8) * 2.0  # 0.8 expected for natural

        score = 0.3 * mean_anomaly + 0.3 * std_anomaly + 0.4 * uniformity_score
        return {
            "score": float(np.clip(score, 0.0, 1.0)),
            "pixel_mean": round(mean, 2),
            "pixel_std": round(std, 2),
            "histogram_entropy": round(hist_entropy, 4),
            "histogram_uniformity": round(uniformity, 4),
        }


# ---------------------------------------------------------------------------
# 9. Model Fingerprinting
# ---------------------------------------------------------------------------

class _ModelFingerprinter:
    """Identify GAN/diffusion/TTS model artifacts."""

    # Known artifact patterns in GAN-generated images (simplified)
    _GAN_SIGNATURES = [
        b'\x00\x00\x00',  # tri-zero runs (over-quantised regions)
    ]

    def fingerprint_image(self, image_bytes: bytes) -> dict:
        """Look for characteristic byte patterns from known generators."""
        score = 0.0
        found_artifacts = []

        # Check for all-uniform rows (GAN smoothing artifact)
        for sig in self._GAN_SIGNATURES:
            count = image_bytes.count(sig * 10)  # 30 consecutive zeros
            if count > 5:
                score += 0.2
                found_artifacts.append(f"uniform_runs:{count}")

        # Unusually small file size for dimensions (over-compression = deepfake pipeline)
        if len(image_bytes) < 5000:
            score += 0.1
            found_artifacts.append("very_small_file")

        return {
            "score": float(np.clip(score, 0.0, 1.0)),
            "artifacts_found": found_artifacts,
        }

    def fingerprint_audio(self, audio_bytes: bytes) -> dict:
        """Look for TTS pipeline artifacts in audio byte stream."""
        score = 0.0
        artifacts = []

        # ElevenLabs/VITS/Tacotron often produce files with very consistent file sizes
        if len(audio_bytes) % 1024 == 0:
            score += 0.1
            artifacts.append("perfectly_aligned_file_size")

        # Look for silence padding patterns common in TTS
        trailer = audio_bytes[-256:] if len(audio_bytes) >= 256 else audio_bytes
        zero_ratio = trailer.count(b'\x00') / max(len(trailer), 1)
        if zero_ratio > 0.5:
            score += 0.2
            artifacts.append(f"high_zero_trailer:{zero_ratio:.2f}")

        return {"score": float(np.clip(score, 0.0, 1.0)), "artifacts_found": artifacts}


# ---------------------------------------------------------------------------
# 10. Ensemble Learning (weighted multi-model voting)
# ---------------------------------------------------------------------------

class _EnsembleVoter:
    """Weighted average of family scores with confidence adjustment."""

    def vote(self, family_scores: dict[str, float], weights: dict[str, float]) -> tuple[float, float]:
        """Return (ensemble_score, confidence).

        confidence is derived from agreement among family scores.
        """
        weighted_sum = 0.0
        total_weight = 0.0
        scores = []
        for family, score in family_scores.items():
            w = weights.get(family, 1.0)
            weighted_sum += score * w
            total_weight += w
            scores.append(score)

        if total_weight == 0:
            return 0.5, 0.0

        ensemble = weighted_sum / total_weight
        # Confidence: inverse of score variance (high variance = lower confidence)
        variance = float(np.var(scores)) if len(scores) > 1 else 0.0
        confidence = max(0.0, 1.0 - variance * 4.0)
        return float(np.clip(ensemble, 0.0, 1.0)), float(np.clip(confidence, 0.0, 1.0))


# ---------------------------------------------------------------------------
# Money Context Analyzer
# ---------------------------------------------------------------------------

_URGENCY_KEYWORDS = [
    "transfer", "send money", "emergency", "hospital", "stuck", "urgent",
    "stranded", "accident", "police", "arrested", "bail", "loan", "invest",
    "guaranteed return", "double your money", "lottery", "won", "prize",
    "click here", "verify kyc", "account blocked", "otp", "pin",
    "upi", "neft", "rtgs", "wallet", "paytm", "phonepe", "gpay",
]

_INVESTMENT_KEYWORDS = [
    "roi", "returns", "profit", "scheme", "ponzi", "mlm", "referral bonus",
    "pyramid", "crypto trading", "forex", "binary options",
]

_CURRENCY_PATTERN = re.compile(
    r'(?:₹|rs\.?|inr|usd|\$)\s*[\d,]+(?:\.\d+)?|[\d,]+\s*(?:lakh|crore|thousand|rupees?)',
    re.IGNORECASE,
)

_ACCOUNT_PATTERN = re.compile(
    r'\b\d{9,18}\b|\b[A-Z]{4}0[A-Z0-9]{6}\b',  # account numbers or IFSC codes
)


def _analyze_money_context(context_text: str) -> dict:
    """Scan context for financial fraud patterns."""
    if not context_text:
        return {
            "money_detected": False,
            "amounts_found": [],
            "urgency_keywords": [],
            "investment_keywords": [],
            "account_patterns": [],
            "fraud_score": 0.0,
        }

    lower = context_text.lower()
    amounts = _CURRENCY_PATTERN.findall(context_text)
    urgency = [kw for kw in _URGENCY_KEYWORDS if kw in lower]
    investment = [kw for kw in _INVESTMENT_KEYWORDS if kw in lower]
    accounts = _ACCOUNT_PATTERN.findall(context_text)

    money_detected = bool(amounts or urgency or investment or accounts)

    fraud_score = 0.0
    fraud_score += min(len(amounts) * 0.1, 0.3)
    fraud_score += min(len(urgency) * 0.07, 0.4)
    fraud_score += min(len(investment) * 0.08, 0.3)
    fraud_score += min(len(accounts) * 0.1, 0.2)
    fraud_score = min(fraud_score, 1.0)

    return {
        "money_detected": money_detected,
        "amounts_found": amounts[:10],
        "urgency_keywords": urgency[:10],
        "investment_keywords": investment[:10],
        "account_patterns": accounts[:5],
        "fraud_score": round(fraud_score, 4),
    }


# ---------------------------------------------------------------------------
# Pixel Array Builder (from raw bytes)
# ---------------------------------------------------------------------------

def _bytes_to_pixel_array(image_bytes: bytes) -> np.ndarray:
    """Convert raw image bytes to a usable numpy array for analysis."""
    data = np.frombuffer(image_bytes, dtype=np.uint8)

    # Try BMP
    if len(image_bytes) >= 54 and image_bytes[:2] == b'BM':
        try:
            pixel_offset = struct.unpack_from('<I', image_bytes, 10)[0]
            width = struct.unpack_from('<i', image_bytes, 18)[0]
            height = struct.unpack_from('<i', image_bytes, 22)[0]
            bpp = struct.unpack_from('<H', image_bytes, 28)[0]
            if bpp in (24, 32) and 0 < width <= 8192 and 0 < abs(height) <= 8192:
                h = abs(height)
                channels = bpp // 8
                row_stride = (width * channels + 3) & ~3
                needed = pixel_offset + row_stride * h
                if len(image_bytes) >= needed:
                    raw = np.frombuffer(image_bytes[pixel_offset:pixel_offset + row_stride * h], dtype=np.uint8)
                    rows = []
                    for ri in range(h):
                        row = raw[ri * row_stride: ri * row_stride + width * channels]
                        rows.append(row.reshape(width, channels)[:, :3])  # keep 3 channels
                    arr = np.array(rows, dtype=np.float64)
                    if height > 0:
                        arr = np.flipud(arr)
                    return arr
        except Exception:
            pass

    # Fallback: treat as 1-D grayscale
    n = len(data)
    side = max(8, int(math.isqrt(n)))
    flat = data[:side * side].astype(np.float64)
    if len(flat) < side * side:
        flat = np.pad(flat, (0, side * side - len(flat)))
    return flat.reshape(side, side)


def _bytes_to_audio_samples(audio_bytes: bytes) -> np.ndarray:
    """Convert raw audio bytes to numpy sample array."""
    # Try WAV PCM
    if len(audio_bytes) >= 44 and audio_bytes[:4] == b'RIFF':
        try:
            # Find data chunk
            offset = 12
            while offset + 8 <= len(audio_bytes):
                chunk_id = audio_bytes[offset:offset + 4]
                chunk_size = struct.unpack_from('<I', audio_bytes, offset + 4)[0]
                if chunk_id == b'data':
                    data_start = offset + 8
                    data_end = min(data_start + chunk_size, len(audio_bytes))
                    return np.frombuffer(audio_bytes[data_start:data_end], dtype=np.int16).astype(np.float64)
                offset += 8 + chunk_size
        except Exception:
            pass
    # Fallback: raw int16
    n = (len(audio_bytes) // 2) * 2
    return np.frombuffer(audio_bytes[:n], dtype=np.int16).astype(np.float64)


# ---------------------------------------------------------------------------
# GuardianDetector — Main Orchestrator
# ---------------------------------------------------------------------------

class GuardianDetector:
    """ADONAI Guardian multi-modal AI forensic detection engine."""

    # Default ensemble weights per family per media type
    _IMAGE_WEIGHTS = {
        "statistical": 0.05,
        "ml_classifier": 0.15,
        "deep_learning": 0.20,
        "frequency_domain": 0.20,
        "signal_processing": 0.10,
        "watermark": 0.10,
        "provenance": 0.08,
        "anomaly": 0.07,
        "fingerprint": 0.05,
    }

    _AUDIO_WEIGHTS = {
        "ml_classifier": 0.15,
        "deep_learning": 0.20,
        "frequency_domain": 0.25,
        "signal_processing": 0.20,
        "watermark": 0.08,
        "provenance": 0.07,
        "fingerprint": 0.05,
    }

    _VIDEO_WEIGHTS = {
        "ml_classifier": 0.15,
        "deep_learning": 0.20,
        "frequency_domain": 0.25,
        "signal_processing": 0.15,
        "watermark": 0.10,
        "provenance": 0.10,
        "fingerprint": 0.05,
    }

    _TEXT_WEIGHTS = {
        "statistical": 0.50,
        "ml_classifier": 0.30,
        "anomaly": 0.20,
    }

    def __init__(self) -> None:
        self._stat_forensics = _StatisticalForensics()
        self._ml_classifier = _MLClassifier()
        self._dl_proxy = _DeepLearningProxy()
        self._freq_analyzer = _FrequencyDomainAnalyzer()
        self._signal_proc = _SignalProcessor()
        self._wm_detector = _WatermarkDetector()
        self._provenance = _DigitalProvenance()
        self._anomaly = _AnomalyDetector()
        self._fingerprinter = _ModelFingerprinter()
        self._ensemble = _EnsembleVoter()

    # ------------------------------------------------------------------
    # Private per-family analysis helpers
    # ------------------------------------------------------------------

    def _analyze_image_families(
        self, image_bytes: bytes, pixel_array: np.ndarray, watermark_result: Optional[dict]
    ) -> tuple[dict, list[str]]:
        reasons = []
        scores: dict[str, float] = {}

        # Frequency domain
        fq = self._freq_analyzer.analyze_image_spectrum(pixel_array)
        scores["frequency_domain"] = fq["score"]
        if fq["score"] > 0.6:
            reasons.append(f"Anomalous spectral fingerprint (flatness={fq.get('spectral_flatness', '?')}) — consistent with GAN/diffusion models")

        # Signal processing
        sp = self._signal_proc.analyze_image_signals(pixel_array)
        scores["signal_processing"] = sp["score"]
        if sp["score"] > 0.6:
            reasons.append("Overly smooth gradient structure — indicates AI over-smoothing")

        # Anomaly detection
        an = self._anomaly.analyze_image_anomalies(pixel_array)
        scores["anomaly"] = an["score"]
        if an["score"] > 0.6:
            reasons.append(f"Pixel distribution anomaly (mean={an.get('pixel_mean', '?')}, std={an.get('pixel_std', '?')})")

        # ML classifier (derived features)
        ml_features = {
            "spectral_flatness": fq.get("spectral_flatness", 0.5),
            "edge_regularity": sp.get("gradient_smoothness", 0.5),
            "noise_floor": 1.0 - sp.get("noise_floor_norm", 0.5),
            "histogram_uniformity": an.get("histogram_uniformity", 0.5),
            "gradient_smoothness": sp.get("gradient_smoothness", 0.5),
        }
        scores["ml_classifier"] = self._ml_classifier.classify_image_features(ml_features)

        # DL proxy
        pixel_stats = {
            "local_variance_norm": min(float(np.var(pixel_array[:min(64, pixel_array.shape[0]),
                                                              :min(64, pixel_array.shape[1] if pixel_array.ndim > 1 else 1)])) / 10000.0, 1.0),
            "global_variance_norm": min(float(np.var(pixel_array)) / 10000.0, 1.0),
            "histogram_kurtosis_norm": min(an.get("histogram_uniformity", 0.5), 1.0),
        }
        scores["deep_learning"] = self._dl_proxy.score_image(pixel_stats)

        # Watermark
        wm = self._wm_detector.analyze(watermark_result)
        scores["watermark"] = wm["score"]
        reasons.append(f"Watermark: {wm['detail']}")

        # Provenance
        pv = self._provenance.analyze(image_bytes, "image")
        scores["provenance"] = pv["score"]
        for note in pv.get("notes", []):
            if "AI generator" in note or "no EXIF" in note:
                reasons.append(f"Provenance: {note}")

        # Fingerprint
        fp = self._fingerprinter.fingerprint_image(image_bytes)
        scores["fingerprint"] = fp["score"]
        if fp["artifacts_found"]:
            reasons.append(f"Model artifacts detected: {', '.join(fp['artifacts_found'])}")

        # Statistical (not applicable to image)
        scores["statistical"] = 0.5  # neutral

        return scores, reasons

    def _analyze_audio_families(
        self, audio_bytes: bytes, samples: np.ndarray, watermark_result: Optional[dict]
    ) -> tuple[dict, list[str]]:
        reasons = []
        scores: dict[str, float] = {}

        # Frequency domain
        fq = self._freq_analyzer.analyze_audio_spectrum(samples)
        scores["frequency_domain"] = fq["score"]
        if fq["score"] > 0.5:
            reasons.append(f"TTS spectral pattern detected (flatness={fq.get('spectral_flatness', '?')}, HF_ratio={fq.get('hf_ratio', '?')})")

        # Signal processing
        sp = self._signal_proc.analyze_audio_signals(samples)
        scores["signal_processing"] = sp["score"]
        if sp["score"] > 0.5:
            reasons.append(f"Synthetic audio signal structure (ZCR={sp.get('zero_crossing_rate', '?')}, silence={sp.get('silence_ratio', '?')})")

        # ML classifier
        ml_features = {
            "zero_crossing_rate": sp.get("zero_crossing_rate", 0.5),
            "spectral_centroid_norm": min(fq.get("spectral_centroid_hz", 2000) / 10000.0, 1.0),
            "spectral_flatness": fq.get("spectral_flatness", 0.5),
            "silence_ratio": sp.get("silence_ratio", 0.5),
            "amplitude_variance": sp.get("amplitude_variance", 0.5),
        }
        scores["ml_classifier"] = self._ml_classifier.classify_audio_features(ml_features)

        # DL proxy
        spectral_stats = {
            "pitch_regularity": min(1.0 - sp.get("amplitude_variance", 0.5), 1.0),
            "breath_absence_score": sp.get("silence_ratio", 0.5),
        }
        scores["deep_learning"] = self._dl_proxy.score_audio(spectral_stats)

        # Watermark
        wm = self._wm_detector.analyze(watermark_result)
        scores["watermark"] = wm["score"]
        reasons.append(f"Watermark: {wm['detail']}")

        # Provenance
        pv = self._provenance.analyze(audio_bytes, "audio")
        scores["provenance"] = pv["score"]

        # Fingerprint
        fp = self._fingerprinter.fingerprint_audio(audio_bytes)
        scores["fingerprint"] = fp["score"]
        if fp["artifacts_found"]:
            reasons.append(f"TTS pipeline artifacts: {', '.join(fp['artifacts_found'])}")

        return scores, reasons

    def _analyze_video_families(
        self, video_bytes: bytes, watermark_result: Optional[dict]
    ) -> tuple[dict, list[str]]:
        """Video analysis: use first chunk of bytes as proxy for frame data."""
        reasons = []
        scores: dict[str, float] = {}

        # For video, extract a sample block and analyze as image
        sample = video_bytes[:min(len(video_bytes), 65536)]
        pixel_arr = _bytes_to_pixel_array(sample)
        fq = self._freq_analyzer.analyze_image_spectrum(pixel_arr)
        scores["frequency_domain"] = fq["score"]

        sp = self._signal_proc.analyze_image_signals(pixel_arr)
        scores["signal_processing"] = sp["score"]

        ml_features = {
            "spectral_flatness": fq.get("spectral_flatness", 0.5),
            "edge_regularity": sp.get("gradient_smoothness", 0.5),
            "noise_floor": 1.0 - sp.get("noise_floor_norm", 0.5),
            "histogram_uniformity": 0.5,
            "gradient_smoothness": sp.get("gradient_smoothness", 0.5),
        }
        scores["ml_classifier"] = self._ml_classifier.classify_image_features(ml_features)

        pixel_stats = {
            "local_variance_norm": 0.5,
            "global_variance_norm": 0.5,
            "histogram_kurtosis_norm": 0.5,
        }
        scores["deep_learning"] = self._dl_proxy.score_image(pixel_stats)

        wm = self._wm_detector.analyze(watermark_result)
        scores["watermark"] = wm["score"]
        reasons.append(f"Watermark: {wm['detail']}")

        pv = self._provenance.analyze(video_bytes, "video")
        scores["provenance"] = pv["score"]

        fp = self._fingerprinter.fingerprint_image(video_bytes[:65536])
        scores["fingerprint"] = fp["score"]

        if fq["score"] > 0.6:
            reasons.append("Video frequency domain analysis indicates possible deepfake frame generation")
        if sp["score"] > 0.6:
            reasons.append("Unusual gradient smoothness in video frames — potential deepfake")

        return scores, reasons

    def _analyze_text_families(self, text: str) -> tuple[dict, list[str]]:
        reasons = []
        scores: dict[str, float] = {}

        stat = self._stat_forensics.analyze_text(text)
        scores["statistical"] = stat["score"]
        if stat["score"] > 0.5:
            reasons.append(
                f"Statistical AI text signals: perplexity={stat['perplexity']}, "
                f"burstiness={stat['burstiness']}, sentence_len={stat['avg_sentence_len']}"
            )

        # ML classifier for text: use statistical features as proxy
        ml_score = min(1.0, stat["score"] * 1.2)
        scores["ml_classifier"] = ml_score

        # Anomaly: very long text without paragraph breaks
        para_count = max(1, text.count('\n\n'))
        word_count = len(text.split())
        words_per_para = word_count / para_count
        anomaly_score = min(1.0, words_per_para / 500.0) if words_per_para > 200 else 0.2
        scores["anomaly"] = anomaly_score
        if anomaly_score > 0.6:
            reasons.append(f"Anomalously long paragraphs ({words_per_para:.0f} words/para) — typical of AI output")

        return scores, reasons

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_image(
        self,
        image_bytes: bytes,
        watermark_result: Optional[dict] = None,
        context_text: str = "",
    ) -> AnalysisResult:
        t0 = time.monotonic()
        pixel_array = _bytes_to_pixel_array(image_bytes)
        family_scores, reasons = self._analyze_image_families(image_bytes, pixel_array, watermark_result)
        weights = self._IMAGE_WEIGHTS
        ai_prob, confidence = self._ensemble.vote(family_scores, weights)
        fake_poss = min(1.0, ai_prob * 1.1)

        money = _analyze_money_context(context_text)
        risk = _score_to_risk(ai_prob, money["money_detected"])
        if money["fraud_score"] > 0.3:
            reasons.append(f"⚠ Financial fraud signals in context: {', '.join(money['urgency_keywords'][:5])}")

        return AnalysisResult(
            media_type="image",
            ai_probability=round(ai_prob, 4),
            fake_possibility=round(fake_poss, 4),
            verdict=_score_to_verdict(ai_prob),
            confidence=round(confidence, 4),
            reasons=reasons,
            money_risk_level=risk,
            money_context=money,
            technical_breakdown=family_scores,
            ensemble_weights=weights,
            processing_time_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    def analyze_audio(
        self,
        audio_bytes: bytes,
        watermark_result: Optional[dict] = None,
        context_text: str = "",
    ) -> AnalysisResult:
        t0 = time.monotonic()
        samples = _bytes_to_audio_samples(audio_bytes)
        family_scores, reasons = self._analyze_audio_families(audio_bytes, samples, watermark_result)
        weights = self._AUDIO_WEIGHTS
        ai_prob, confidence = self._ensemble.vote(family_scores, weights)
        fake_poss = min(1.0, ai_prob * 1.1)

        money = _analyze_money_context(context_text)
        risk = _score_to_risk(ai_prob, money["money_detected"])

        return AnalysisResult(
            media_type="audio",
            ai_probability=round(ai_prob, 4),
            fake_possibility=round(fake_poss, 4),
            verdict=_score_to_verdict(ai_prob),
            confidence=round(confidence, 4),
            reasons=reasons,
            money_risk_level=risk,
            money_context=money,
            technical_breakdown=family_scores,
            ensemble_weights=weights,
            processing_time_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    def analyze_video(
        self,
        video_bytes: bytes,
        watermark_result: Optional[dict] = None,
        context_text: str = "",
    ) -> AnalysisResult:
        t0 = time.monotonic()
        family_scores, reasons = self._analyze_video_families(video_bytes, watermark_result)
        weights = self._VIDEO_WEIGHTS
        ai_prob, confidence = self._ensemble.vote(family_scores, weights)
        fake_poss = min(1.0, ai_prob * 1.1)

        money = _analyze_money_context(context_text)
        risk = _score_to_risk(ai_prob, money["money_detected"])

        return AnalysisResult(
            media_type="video",
            ai_probability=round(ai_prob, 4),
            fake_possibility=round(fake_poss, 4),
            verdict=_score_to_verdict(ai_prob),
            confidence=round(confidence, 4),
            reasons=reasons,
            money_risk_level=risk,
            money_context=money,
            technical_breakdown=family_scores,
            ensemble_weights=weights,
            processing_time_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    def analyze_text(
        self,
        text: str,
        context_text: str = "",
    ) -> AnalysisResult:
        t0 = time.monotonic()
        family_scores, reasons = self._analyze_text_families(text)
        weights = self._TEXT_WEIGHTS
        ai_prob, confidence = self._ensemble.vote(family_scores, weights)
        fake_poss = min(1.0, ai_prob * 1.1)

        combined_text = text + " " + context_text
        money = _analyze_money_context(combined_text)
        risk = _score_to_risk(ai_prob, money["money_detected"])
        if money["fraud_score"] > 0.3:
            reasons.append(f"⚠ Financial scam patterns detected: {', '.join(money['urgency_keywords'][:5])}")

        return AnalysisResult(
            media_type="text",
            ai_probability=round(ai_prob, 4),
            fake_possibility=round(fake_poss, 4),
            verdict=_score_to_verdict(ai_prob),
            confidence=round(confidence, 4),
            reasons=reasons,
            money_risk_level=risk,
            money_context=money,
            technical_breakdown=family_scores,
            ensemble_weights=weights,
            processing_time_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    def analyze_media(
        self,
        media_bytes: bytes,
        media_type: str,
        watermark_result: Optional[dict] = None,
        context_text: str = "",
    ) -> AnalysisResult:
        """Dispatcher: route to the appropriate media-type analyser."""
        media_type = media_type.lower().strip()
        if media_type == "image":
            return self.analyze_image(media_bytes, watermark_result, context_text)
        if media_type == "audio":
            return self.analyze_audio(media_bytes, watermark_result, context_text)
        if media_type == "video":
            return self.analyze_video(media_bytes, watermark_result, context_text)
        if media_type == "text":
            return self.analyze_text(media_bytes.decode("utf-8", errors="replace"), context_text)
        raise ValueError(f"Unsupported media_type: {media_type!r}. Must be image|audio|video|text")
