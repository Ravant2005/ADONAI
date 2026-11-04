package com.adonai.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ADONAI White & Red Visual System Tokens
val AdonaiBg = Color(0xFFFFFFFF)
val AdonaiSurface = Color(0xFFFAFAFA)
val AdonaiElevated = Color(0xFFFFF5F5)
val AdonaiPrimaryRed = Color(0xFFE50914)
val AdonaiDeepRed = Color(0xFFB91C1C)
val AdonaiAlertRed = Color(0xFFDC2626)
val AdonaiText = Color(0xFF0F172A)
val AdonaiMuted = Color(0xFF64748B)
val AdonaiBorder = Color(0xFFE2E8F0)

private val AdonaiColorScheme = lightColorScheme(
    primary = AdonaiPrimaryRed,
    secondary = AdonaiDeepRed,
    tertiary = AdonaiAlertRed,
    background = AdonaiBg,
    surface = AdonaiSurface,
    surfaceVariant = AdonaiElevated,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = AdonaiText,
    onSurface = AdonaiText,
    outline = AdonaiBorder
)

@Composable
fun AdonaiTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = AdonaiColorScheme,
        content = content
    )
}
