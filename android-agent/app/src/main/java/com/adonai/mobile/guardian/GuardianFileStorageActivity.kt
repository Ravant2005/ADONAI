package com.adonai.mobile.guardian

/**
 * ADONAI Guardian File Storage & Verification UI
 *
 * Main activity for the ADONAI Guardian media vault.
 * Displays all media on the device and allows users to:
 * 1. View media files
 * 2. Verify authenticity (runs 3-stage pipeline)
 * 3. See verification verdicts with badges
 *
 * Uses Jetpack Compose for UI with the existing AdonaiTheme (red/black).
 */

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AudioFile
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material3.BottomSheetScaffold
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberBottomSheetScaffoldState
import androidx.compose.material3.rememberStandardBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// ADONAI theme colors
// ---------------------------------------------------------------------------

val AdonaiRed        = Color(0xFFE50914)
val AdonaiBackground = Color(0xFFFFFFFF)
val AdonaiSurface    = Color(0xFFF8FAFC)
val AdonaiTextWhite  = Color(0xFF0F172A)
val AdonaiPureWhite  = Color(0xFFFFFFFF)
val AdonaiTextMuted  = Color(0xFF64748B)

// ---------------------------------------------------------------------------
// Domain model for the vault grid
// ---------------------------------------------------------------------------

/**
 * Represents a single media item loaded from [MediaStore].
 *
 * @property uri         Content URI for the file.
 * @property displayName File name shown in the UI.
 * @property mimeType    MIME type string (image/*, video/*, audio/*).
 * @property sizeBytes   File size in bytes.
 */
data class MediaItem(
    val uri         : Uri,
    val displayName : String,
    val mimeType    : String,
    val sizeBytes   : Long
)

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

/**
 * Entry point for the ADONAI Guardian media vault.
 *
 * Presents [GuardianVaultScreen] inside the app's Compose theme.
 * Requires READ_MEDIA_IMAGES / READ_MEDIA_VIDEO / READ_MEDIA_AUDIO permissions.
 */
class GuardianFileStorageActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            GuardianAppTheme {
                GuardianVaultScreen()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal theme wrapper (uses ADONAI colors)
// ---------------------------------------------------------------------------

@Composable
private fun GuardianAppTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MaterialTheme.colorScheme.copy(
            primary    = AdonaiRed,
            background = AdonaiBackground,
            surface    = AdonaiSurface,
            onPrimary  = AdonaiTextWhite,
            onSurface  = AdonaiTextWhite,
        ),
        content = content
    )
}

// ---------------------------------------------------------------------------
// Guardian Vault Screen
// ---------------------------------------------------------------------------

/**
 * Root composable for the Guardian vault.
 *
 * Shows a lazy grid of media files from the device's external storage.
 * Long-pressing a card (or tapping the FAB while one is selected) opens
 * [VerificationResultSheet] with the full Guardian verdict.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun GuardianVaultScreen() {
    val context     = LocalContext.current
    val scope       = rememberCoroutineScope()
    val mediaItems  = remember { mutableStateListOf<MediaItem>() }

    var selectedItem     by remember { mutableStateOf<MediaItem?>(null) }
    var verifyResult     by remember { mutableStateOf<GuardianVerifyResult?>(null) }
    var isVerifying      by remember { mutableStateOf(false) }
    var verificationCache by remember { mutableStateOf<Map<Uri, GuardianVerifyResult>>(emptyMap()) }

    val sheetState = rememberStandardBottomSheetState(
        initialValue = SheetValue.Hidden,
        skipHiddenState = false
    )
    val scaffoldState = rememberBottomSheetScaffoldState(bottomSheetState = sheetState)

    // Load media items from MediaStore on first composition
    LaunchedEffect(Unit) {
        mediaItems.clear()
        mediaItems.addAll(loadMediaFromStore(context))
    }

    // Trigger verification and show sheet
    fun verifySelected(item: MediaItem) {
        selectedItem = item
        isVerifying  = true
        scope.launch {
            val result = GuardianWatermarkSDK.verifyMedia(
                context     = context,
                mediaUri    = item.uri,
                mediaType   = item.mimeType
            )
            verifyResult = result
            verificationCache = verificationCache + (item.uri to result)
            isVerifying  = false
            sheetState.expand()
        }
    }

    BottomSheetScaffold(
        scaffoldState     = scaffoldState,
        sheetPeekHeight   = 0.dp,
        sheetContainerColor = AdonaiSurface,
        containerColor    = AdonaiBackground,
        sheetContent = {
            // ---- Bottom sheet: verification result ----
            if (isVerifying) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(200.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = AdonaiRed)
                        Spacer(Modifier.height(12.dp))
                        Text("Verifying…", color = AdonaiTextWhite)
                    }
                }
            } else {
                verifyResult?.let { result ->
                    VerificationResultSheet(
                        result  = result,
                        onClose = { scope.launch { sheetState.hide() } }
                    )
                }
            }
        },
        floatingActionButton = {
            selectedItem?.let { item ->
                FloatingActionButton(
                    onClick          = { verifySelected(item) },
                    containerColor   = AdonaiRed,
                    contentColor     = AdonaiPureWhite
                ) {
                    Icon(Icons.Default.Shield, contentDescription = "Verify selected file")
                }
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(AdonaiBackground)
                .padding(paddingValues)
        ) {
            // Screen title
            Text(
                text       = "Guardian Vault",
                color      = AdonaiTextWhite,
                fontSize   = 22.sp,
                fontWeight = FontWeight.Bold,
                modifier   = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)
            )

            if (mediaItems.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No media found", color = AdonaiTextMuted)
                }
            } else {
                LazyVerticalGrid(
                    columns         = GridCells.Fixed(3),
                    contentPadding  = PaddingValues(4.dp),
                    verticalArrangement   = Arrangement.spacedBy(4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    modifier        = Modifier.fillMaxSize()
                ) {
                    items(mediaItems, key = { it.uri.toString() }) { item ->
                        val isSelected = selectedItem?.uri == item.uri
                        val cachedResult = verificationCache[item.uri]

                        MediaGridCard(
                            item         = item,
                            isSelected   = isSelected,
                            verifyResult = cachedResult,
                            onClick      = {
                                selectedItem = if (isSelected) null else item
                            },
                            onLongClick  = { verifySelected(item) }
                        )
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Media Grid Card
// ---------------------------------------------------------------------------

/**
 * Single cell in the vault grid.
 *
 * Shows a type icon, file name, and an optional verdict badge if the file
 * has already been verified in this session.
 *
 * @param item         The media item to display.
 * @param isSelected   Whether this card is currently selected.
 * @param verifyResult Cached verification result (null if not yet verified).
 * @param onClick      Tap handler (selects/deselects the card).
 * @param onLongClick  Long-press handler (immediately triggers verification).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MediaGridCard(
    item         : MediaItem,
    isSelected   : Boolean,
    verifyResult : GuardianVerifyResult?,
    onClick      : () -> Unit,
    onLongClick  : () -> Unit
) {
    val borderColor = when {
        isSelected   -> AdonaiRed
        verifyResult != null -> if (verifyResult.overallVerdict == "AUTHENTIC") Color(0xFF00C853)
                                else AdonaiRed
        else         -> AdonaiSurface
    }

    Box(
        modifier = Modifier
            .aspectRatio(1f)
            .clip(RoundedCornerShape(6.dp))
            .background(AdonaiSurface)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(2.dp)
    ) {
        // Type icon
        Icon(
            imageVector        = mediaTypeIcon(item.mimeType),
            contentDescription = item.mimeType,
            tint               = AdonaiTextMuted,
            modifier           = Modifier
                .size(32.dp)
                .align(Alignment.Center)
        )

        // File name label
        Text(
            text      = item.displayName,
            color     = AdonaiTextWhite,
            fontSize  = 8.sp,
            maxLines  = 1,
            overflow  = TextOverflow.Ellipsis,
            modifier  = Modifier
                .align(Alignment.BottomStart)
                .background(Color.Black.copy(alpha = 0.6f))
                .padding(horizontal = 2.dp)
        )

        // Verdict badge (top-right)
        verifyResult?.let { result ->
            Text(
                text     = result.verdictBadge.take(2),   // emoji only
                fontSize = 14.sp,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(2.dp)
            )
        }

        // Selection highlight border
        if (isSelected) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .clip(RoundedCornerShape(6.dp))
                    .background(AdonaiRed.copy(alpha = 0.2f))
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Verification Result Bottom Sheet
// ---------------------------------------------------------------------------

/**
 * Bottom sheet content displaying a compact Guardian verification summary.
 *
 * Shows:
 * - Verdict badge + confidence
 * - AI probability and fake possibility percentages
 * - Money risk level
 * - First three reasons
 * - Explanation paragraph
 *
 * @param result  The [GuardianVerifyResult] to render.
 * @param onClose Callback to dismiss the sheet.
 */
@Composable
fun VerificationResultSheet(
    result  : GuardianVerifyResult,
    onClose : () -> Unit
) {
    val verdictColor = when (result.overallVerdict) {
        "AUTHENTIC"    -> Color(0xFF00C853)
        "LIKELY_FAKE",
        "FAKE"         -> AdonaiRed
        "UNCERTAIN"    -> Color(0xFFFFAB00)
        else           -> AdonaiTextMuted
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(20.dp)
    ) {
        // Verdict badge
        Text(
            text       = result.verdictBadge,
            color      = verdictColor,
            fontSize   = 24.sp,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text     = "Confidence: ${result.confidence}%  |  Stage ${result.stageReached}/3",
            color    = AdonaiTextMuted,
            fontSize = 12.sp
        )

        Spacer(Modifier.height(12.dp))

        // Stats row
        StatRow(label = "AI Probability",    value = "${result.aiProbabilityPercent}%")
        StatRow(label = "Fake Possibility",  value = "${result.fakePossibilityPercent}%")
        StatRow(label = "Money Risk",        value = result.moneyRiskLevel,
            valueColor = if (result.moneyRiskLevel == "HIGH") AdonaiRed else AdonaiTextWhite)

        Spacer(Modifier.height(12.dp))

        // Top reasons
        if (result.reasons.isNotEmpty()) {
            Text("Key Findings", color = AdonaiTextMuted, fontSize = 11.sp)
            result.reasons.take(3).forEach { reason ->
                Text("• $reason", color = AdonaiTextWhite, fontSize = 12.sp,
                    modifier = Modifier.padding(top = 2.dp))
            }
            Spacer(Modifier.height(8.dp))
        }

        // Explanation
        if (result.explanation.isNotBlank()) {
            Text(
                text     = result.explanation,
                color    = AdonaiTextMuted,
                fontSize = 12.sp,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(Modifier.height(16.dp))
        TextButton(onClick = onClose, modifier = Modifier.align(Alignment.End)) {
            Text("Close", color = AdonaiRed)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper composables
// ---------------------------------------------------------------------------

@Composable
private fun StatRow(
    label      : String,
    value      : String,
    valueColor : Color = AdonaiTextWhite
) {
    androidx.compose.foundation.layout.Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AdonaiTextMuted, fontSize = 13.sp)
        Text(value, color = valueColor,      fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
    }
}

// ---------------------------------------------------------------------------
// MediaStore loader
// ---------------------------------------------------------------------------

/**
 * Queries [MediaStore] for all external images, videos, and audio files
 * and returns them as a list of [MediaItem] sorted by date added (newest first).
 */
private suspend fun loadMediaFromStore(context: Context): List<MediaItem> =
    withContext(Dispatchers.IO) {
        val items = mutableListOf<MediaItem>()

        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.MIME_TYPE,
            MediaStore.MediaColumns.SIZE
        )
        val sortOrder = "${MediaStore.MediaColumns.DATE_ADDED} DESC"

        val collections = listOf(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
        )

        for (collection in collections) {
            try {
                context.contentResolver.query(
                    collection, projection, null, null, sortOrder
                )?.use { cursor ->
                    val idCol          = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
                    val nameCol        = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)
                    val mimeCol        = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.MIME_TYPE)
                    val sizeCol        = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE)

                    while (cursor.moveToNext()) {
                        val id    = cursor.getLong(idCol)
                        val name  = cursor.getString(nameCol) ?: "Unknown"
                        val mime  = cursor.getString(mimeCol) ?: "application/octet-stream"
                        val size  = cursor.getLong(sizeCol)
                        val uri   = ContentUris.withAppendedId(collection, id)

                        items.add(MediaItem(uri = uri, displayName = name, mimeType = mime, sizeBytes = size))
                    }
                }
            } catch (e: Exception) {
                Log.e("GuardianVault", "loadMediaFromStore: query failed for $collection", e)
            }
        }

        items
    }

// ---------------------------------------------------------------------------
// Icon helper
// ---------------------------------------------------------------------------

/** Returns an appropriate [ImageVector] icon for the given MIME type. */
private fun mediaTypeIcon(mimeType: String): ImageVector = when {
    mimeType.startsWith("image") -> Icons.Default.Image
    mimeType.startsWith("video") -> Icons.Default.VideoFile
    mimeType.startsWith("audio") -> Icons.Default.AudioFile
    else                         -> Icons.Default.Shield
}
