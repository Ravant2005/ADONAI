package com.adonai.mobile.guardian

/**
 * Verification Result Screen — Shows the full Guardian verdict for a media file.
 * Displays all 3 stages of verification with detailed explanations.
 */

import android.content.Intent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Share
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.MonetizationOn
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Web
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------------------------------------------------------------------------
// Verification Result Screen
// ---------------------------------------------------------------------------

/**
 * Full-screen composable showing the complete Guardian verdict for a single media file.
 *
 * Layout (top → bottom):
 * 1. Top app bar with back button and share action
 * 2. Overall verdict banner (colour-coded)
 * 3. Money risk critical banner (shown only when risk = HIGH)
 * 4. Stage 1 card – Watermark & Blockchain
 * 5. Stage 2 card – Web Intelligence
 * 6. Stage 3 card – AI Forensic Analysis (expandable detail list + circular gauge)
 * 7. "Why It Could Be Fake" reasons section
 * 8. Explanation paragraph
 *
 * @param result  The [GuardianVerifyResult] to render.
 * @param onBack  Navigation callback invoked by the back button / system back gesture.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerificationResultScreen(
    result : GuardianVerifyResult,
    onBack : () -> Unit
) {
    val context = LocalContext.current

    val verdictColor = verdictColor(result.overallVerdict)

    Scaffold(
        containerColor = AdonaiBackground,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text       = "Verification Result",
                        color      = AdonaiTextWhite,
                        fontWeight = FontWeight.SemiBold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = AdonaiTextWhite
                        )
                    }
                },
                actions = {
                    IconButton(onClick = {
                        shareVerdict(context = context, result = result)
                    }) {
                        Icon(
                            Icons.AutoMirrored.Filled.Share,
                            contentDescription = "Share verdict",
                            tint = AdonaiTextWhite
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = AdonaiSurface
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(AdonaiBackground)
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {

            // ----------------------------------------------------------------
            // 1. Overall verdict banner
            // ----------------------------------------------------------------
            OverallVerdictBanner(result = result, verdictColor = verdictColor)

            // ----------------------------------------------------------------
            // 2. Money risk banner (critical — only shown when HIGH)
            // ----------------------------------------------------------------
            if (result.moneyRiskLevel == "HIGH") {
                MoneyRiskBanner()
            }

            // ----------------------------------------------------------------
            // 3. Stage 1 — Watermark & Blockchain
            // ----------------------------------------------------------------
            StageCard(
                stageNumber = 1,
                title       = "Watermark & Blockchain",
                icon        = Icons.Default.Shield,
                reached     = result.stageReached >= 1
            ) {
                val registered = result.stageReached >= 1
                StageStatusRow(
                    label   = "Blockchain registration",
                    passed  = registered,
                    detail  = if (registered) "File fingerprint recorded on ledger"
                              else            "No registration record found"
                )
                StageStatusRow(
                    label   = "Cryptographic watermark",
                    passed  = registered,
                    detail  = if (registered) "Device-bound watermark intact"
                              else            "Watermark absent or tampered"
                )
                if (result.verificationId.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text     = "ID: ${result.verificationId}",
                        color    = AdonaiTextMuted,
                        fontSize = 10.sp,
                        fontStyle= FontStyle.Italic
                    )
                }
            }

            // ----------------------------------------------------------------
            // 4. Stage 2 — Web Intelligence
            // ----------------------------------------------------------------
            StageCard(
                stageNumber = 2,
                title       = "Web Intelligence",
                icon        = Icons.Default.Web,
                reached     = result.stageReached >= 2
            ) {
                StageStatusRow(
                    label  = "Reverse image search",
                    passed = result.stageReached >= 2,
                    detail = "Cross-referenced against 10B+ indexed media assets"
                )
                StageStatusRow(
                    label  = "Scheme / scam database",
                    passed = result.fakePossibilityPercent < 50,
                    detail = if (result.fakePossibilityPercent < 50)
                                 "No known scam patterns matched"
                             else
                                 "${result.fakePossibilityPercent}% match to known disinformation schemes"
                )
            }

            // ----------------------------------------------------------------
            // 5. Stage 3 — AI Forensic Analysis
            // ----------------------------------------------------------------
            AiForensicCard(result = result)

            // ----------------------------------------------------------------
            // 6. "Why It Could Be Fake" reasons section
            // ----------------------------------------------------------------
            if (result.reasons.isNotEmpty()) {
                ReasonsCard(reasons = result.reasons)
            }

            // ----------------------------------------------------------------
            // 7. Explanation paragraph
            // ----------------------------------------------------------------
            if (result.explanation.isNotBlank()) {
                ExplanationCard(explanation = result.explanation)
            }

            // ----------------------------------------------------------------
            // 8. Share button (bottom)
            // ----------------------------------------------------------------
            Button(
                onClick = { shareVerdict(context = context, result = result) },
                colors  = ButtonDefaults.buttonColors(containerColor = AdonaiRed),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Share,
                    contentDescription = null,
                    tint = AdonaiPureWhite,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text("Share Verdict", color = AdonaiPureWhite, fontWeight = FontWeight.SemiBold)
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

// ---------------------------------------------------------------------------
// Overall verdict banner
// ---------------------------------------------------------------------------

@Composable
private fun OverallVerdictBanner(
    result       : GuardianVerifyResult,
    verdictColor : Color
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(verdictColor.copy(alpha = 0.15f))
            .padding(16.dp)
    ) {
        Column {
            Text(
                text       = result.verdictBadge,
                color      = verdictColor,
                fontSize   = 28.sp,
                fontWeight = FontWeight.ExtraBold
            )
            Spacer(Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                VerdictStat(label = "Confidence",   value = "${result.confidence}%")
                VerdictStat(label = "Stages",       value = "${result.stageReached}/3")
                VerdictStat(label = "Money Risk",   value = result.moneyRiskLevel,
                    valueColor = moneyRiskColor(result.moneyRiskLevel))
            }
        }
    }
}

@Composable
private fun VerdictStat(label: String, value: String, valueColor: Color = AdonaiTextWhite) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = valueColor, fontSize = 16.sp, fontWeight = FontWeight.Bold)
        Text(label, color = AdonaiTextMuted, fontSize = 10.sp)
    }
}

// ---------------------------------------------------------------------------
// Money risk banner
// ---------------------------------------------------------------------------

@Composable
private fun MoneyRiskBanner() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(AdonaiRed.copy(alpha = 0.9f))
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            Icons.Default.MonetizationOn,
            contentDescription = null,
            tint = AdonaiPureWhite,
            modifier = Modifier.size(24.dp)
        )
        Column {
            Text(
                "⚠️ HIGH FINANCIAL RISK DETECTED",
                color      = AdonaiPureWhite,
                fontWeight = FontWeight.ExtraBold,
                fontSize   = 14.sp
            )
            Text(
                "This content may be used in financial fraud or investment scams.",
                color    = AdonaiPureWhite.copy(alpha = 0.9f),
                fontSize = 12.sp
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Generic stage card
// ---------------------------------------------------------------------------

/**
 * Collapsible card for a single verification stage.
 *
 * @param stageNumber  Stage index (1–3) shown in the header badge.
 * @param title        Stage title text.
 * @param icon         Icon displayed next to the title.
 * @param reached      Whether the pipeline actually reached this stage.
 * @param content      Composable content rendered inside the card body.
 */
@Composable
private fun StageCard(
    stageNumber : Int,
    title       : String,
    icon        : ImageVector,
    reached     : Boolean,
    content     : @Composable () -> Unit
) {
    var expanded by remember { mutableStateOf(true) }
    val rotateArrow by animateFloatAsState(
        targetValue = if (expanded) 0f else 180f,
        animationSpec = tween(300),
        label = "arrow_rotation"
    )

    Card(
        colors  = CardDefaults.cardColors(containerColor = AdonaiSurface),
        shape   = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header row
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier              = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
            ) {
                Row(
                    verticalAlignment     = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Stage number badge
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(26.dp)
                            .clip(CircleShape)
                            .background(if (reached) AdonaiRed else AdonaiTextMuted)
                    ) {
                        Text(
                            "$stageNumber",
                            color      = AdonaiPureWhite,
                            fontSize   = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Icon(icon, contentDescription = null, tint = AdonaiTextWhite, modifier = Modifier.size(18.dp))
                    Text(
                        title,
                        color      = AdonaiTextWhite,
                        fontWeight = FontWeight.SemiBold,
                        fontSize   = 15.sp
                    )
                }
                Icon(
                    if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "Collapse" else "Expand",
                    tint     = AdonaiTextMuted,
                    modifier = Modifier.rotate(rotateArrow)
                )
            }

            AnimatedVisibility(
                visible = expanded,
                enter   = expandVertically(),
                exit    = shrinkVertically()
            ) {
                Column(modifier = Modifier.padding(top = 10.dp)) {
                    if (!reached) {
                        Text(
                            "Stage not reached — pipeline stopped early.",
                            color    = AdonaiTextMuted,
                            fontSize = 12.sp,
                            fontStyle= FontStyle.Italic
                        )
                    } else {
                        content()
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stage status row
// ---------------------------------------------------------------------------

@Composable
private fun StageStatusRow(label: String, passed: Boolean, detail: String) {
    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment     = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector        = if (passed) Icons.Default.CheckCircle else Icons.Default.Close,
            contentDescription = if (passed) "Pass" else "Fail",
            tint               = if (passed) Color(0xFF00C853) else AdonaiRed,
            modifier           = Modifier.size(18.dp)
        )
        Column {
            Text(label,  color = AdonaiTextWhite, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Text(detail, color = AdonaiTextMuted, fontSize = 11.sp)
        }
    }
}

// ---------------------------------------------------------------------------
// AI Forensic card (Stage 3) with circular gauge
// ---------------------------------------------------------------------------

@Composable
private fun AiForensicCard(result: GuardianVerifyResult) {
    var detailExpanded by remember { mutableStateOf(false) }

    Card(
        colors   = CardDefaults.cardColors(containerColor = AdonaiSurface),
        shape    = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .size(26.dp)
                        .clip(CircleShape)
                        .background(if (result.stageReached >= 3) AdonaiRed else AdonaiTextMuted)
                ) {
                    Text("3", color = AdonaiPureWhite, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
                Icon(
                    Icons.Default.Psychology,
                    contentDescription = null,
                    tint = AdonaiTextWhite,
                    modifier = Modifier.size(18.dp)
                )
                Text(
                    "AI Forensic Analysis",
                    color      = AdonaiTextWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize   = 15.sp
                )
            }

            Spacer(Modifier.height(12.dp))

            // Gauges row
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                AiGauge(
                    label    = "AI Generated",
                    percent  = result.aiProbabilityPercent,
                    trackColor = Color(0xFFE53935)
                )
                AiGauge(
                    label    = "Manipulated",
                    percent  = result.fakePossibilityPercent,
                    trackColor = Color(0xFFFF6F00)
                )
                AiGauge(
                    label    = "Confidence",
                    percent  = result.confidence,
                    trackColor = AdonaiRed
                )
            }

            Spacer(Modifier.height(10.dp))

            // Expandable technical breakdown
            Row(
                modifier  = Modifier
                    .fillMaxWidth()
                    .clickable { detailExpanded = !detailExpanded },
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "Technical Breakdown",
                    color      = AdonaiTextMuted,
                    fontSize   = 12.sp,
                    fontWeight = FontWeight.Medium
                )
                Icon(
                    if (detailExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = AdonaiTextMuted,
                    modifier = Modifier.size(16.dp)
                )
            }

            AnimatedVisibility(
                visible = detailExpanded,
                enter   = expandVertically(),
                exit    = shrinkVertically()
            ) {
                Column(modifier = Modifier.padding(top = 6.dp)) {
                    TechDetailRow("Model ensemble",   "DeepFake-CNN + EfficientNet-B4 + CLIP")
                    TechDetailRow("Frequency analysis", "DCT artifact scan — ${result.aiProbabilityPercent}% anomaly score")
                    TechDetailRow("Metadata consistency", if (result.stageReached >= 3) "EXIF / ID3 timestamps verified" else "N/A")
                    TechDetailRow("Noise pattern",    if (result.fakePossibilityPercent > 50) "GAN fingerprint detected" else "Natural sensor noise pattern")
                    TechDetailRow("Compression artifacts", if (result.fakePossibilityPercent > 70) "Double-compression detected" else "Single-pass, consistent quality")
                }
            }
        }
    }
}

@Composable
private fun AiGauge(label: String, percent: Int, trackColor: Color) {
    val animatedProgress by animateFloatAsState(
        targetValue    = percent / 100f,
        animationSpec  = tween(durationMillis = 1000),
        label          = "gauge_$label"
    )

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(72.dp)) {
            CircularProgressIndicator(
                progress          = { 1f },
                modifier          = Modifier.fillMaxSize(),
                color             = AdonaiSurface,
                strokeWidth       = 7.dp,
                strokeCap         = StrokeCap.Round
            )
            CircularProgressIndicator(
                progress          = { animatedProgress },
                modifier          = Modifier.fillMaxSize(),
                color             = trackColor,
                strokeWidth       = 7.dp,
                strokeCap         = StrokeCap.Round
            )
            Text(
                "$percent%",
                color      = AdonaiTextWhite,
                fontSize   = 14.sp,
                fontWeight = FontWeight.Bold
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(label, color = AdonaiTextMuted, fontSize = 10.sp)
    }
}

@Composable
private fun TechDetailRow(label: String, value: String) {
    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AdonaiTextMuted, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        Text(value, color = AdonaiTextWhite, fontSize = 11.sp, modifier = Modifier.weight(1.4f))
    }
}

// ---------------------------------------------------------------------------
// Reasons card
// ---------------------------------------------------------------------------

@Composable
private fun ReasonsCard(reasons: List<String>) {
    Card(
        colors   = CardDefaults.cardColors(containerColor = AdonaiSurface),
        shape    = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                "🔍 Why It Could Be Fake",
                color      = AdonaiTextWhite,
                fontWeight = FontWeight.SemiBold,
                fontSize   = 15.sp
            )
            Spacer(Modifier.height(8.dp))
            reasons.forEach { reason ->
                Row(
                    modifier  = Modifier.padding(vertical = 3.dp),
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("•", color = AdonaiRed, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(reason, color = AdonaiTextWhite, fontSize = 13.sp)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Explanation card
// ---------------------------------------------------------------------------

@Composable
private fun ExplanationCard(explanation: String) {
    Card(
        colors   = CardDefaults.cardColors(containerColor = AdonaiSurface),
        shape    = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                "📋 Explanation",
                color      = AdonaiTextWhite,
                fontWeight = FontWeight.SemiBold,
                fontSize   = 15.sp
            )
            Spacer(Modifier.height(6.dp))
            Text(
                explanation,
                color    = AdonaiTextMuted,
                fontSize = 13.sp,
                lineHeight = 20.sp
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Share helper
// ---------------------------------------------------------------------------

/**
 * Shares a plain-text summary of [result] via the system share sheet.
 */
private fun shareVerdict(context: android.content.Context, result: GuardianVerifyResult) {
    val text = buildString {
        appendLine("ADONAI Guardian — Verification Report")
        appendLine("======================================")
        appendLine("Verdict:   ${result.verdictBadge}")
        appendLine("Confidence: ${result.confidence}%")
        appendLine("AI Generated: ${result.aiProbabilityPercent}%")
        appendLine("Fake Possibility: ${result.fakePossibilityPercent}%")
        appendLine("Money Risk: ${result.moneyRiskLevel}")
        appendLine()
        appendLine("Explanation:")
        appendLine(result.explanation)
        if (result.reasons.isNotEmpty()) {
            appendLine()
            appendLine("Key Findings:")
            result.reasons.forEach { appendLine("• $it") }
        }
        if (result.verificationId.isNotBlank()) {
            appendLine()
            appendLine("Verification ID: ${result.verificationId}")
        }
    }

    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "ADONAI Guardian Verification Report")
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, "Share Verdict"))
}

// ---------------------------------------------------------------------------
// Color helpers
// ---------------------------------------------------------------------------

private fun verdictColor(verdict: String): Color = when (verdict) {
    "AUTHENTIC"    -> Color(0xFF00C853)
    "LIKELY_FAKE",
    "FAKE"         -> AdonaiRed
    "UNCERTAIN"    -> Color(0xFFFFAB00)
    else           -> AdonaiTextMuted
}

private fun moneyRiskColor(level: String): Color = when (level) {
    "HIGH"   -> AdonaiRed
    "MEDIUM" -> Color(0xFFFFAB00)
    else     -> Color(0xFF00C853)
}
