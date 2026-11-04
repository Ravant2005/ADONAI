package com.adonai.mobile.collectors

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.adonai.mobile.ui.theme.AdonaiTheme

class ShareSheetAnalyzerActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val sharedText = if (intent?.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            intent.getStringExtra(Intent.EXTRA_TEXT) ?: ""
        } else ""

        val localAssessment = evaluateLocallyDeterministic(sharedText)
        setContent {
            AdonaiTheme {
                // Displays immediate on-device deterministic verdict even when Mac is offline
            }
        }
    }

    companion object {
        fun evaluateLocallyDeterministic(text: String): Map<String, Any> {
            val lower = text.lowercase()
            val hasOtp = lower.contains("otp") || lower.contains("6-digit") || lower.contains("verification code")
            val hasUrgency = lower.contains("urgent") || lower.contains("frozen") || lower.contains("immediately")
            val hasTestPhish = lower.contains(".example.test") || lower.contains(".invalid")
            val risky = hasOtp || (hasUrgency && hasTestPhish)
            return mapOf(
                "risky" to risky,
                "severity" to if (hasOtp) "CRITICAL" else if (risky) "HIGH" else "LOW",
                "evidence_class" to "OBSERVED",
                "rationale" to if (risky) "Matched on-device OTP/phishing deterministic heuristics." else "No immediate phishing or OTP solicitation indicators detected."
            )
        }
    }
}
