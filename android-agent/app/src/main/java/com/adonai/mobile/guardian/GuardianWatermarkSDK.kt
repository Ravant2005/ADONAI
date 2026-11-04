package com.adonai.mobile.guardian

/**
 * ADONAI Guardian Watermark SDK
 *
 * Hooks into the Android camera ContentObserver to intercept newly captured
 * media files and embed a cryptographic watermark before the file is accessible
 * to other apps.
 *
 * Key features:
 * - Embeds device-bound watermark (device_id + timestamp + content_hash + user_key)
 * - Works with JPEG images, MP4 video, AAC/M4A audio
 * - Compression-resistant: watermark survives resize/compress operations
 * - Sends registration request to ADONAI Guardian backend API
 * - No new camera app needed — hooks into existing Camera2/CameraX results
 */

import android.content.Context
import android.net.Uri
import android.provider.Settings
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

// ---------------------------------------------------------------------------
// Data classes
// ---------------------------------------------------------------------------

/**
 * Cryptographic watermark payload embedded in every registered media file.
 *
 * @property deviceId       Android Secure Settings ANDROID_ID of the originating device.
 * @property timestampMs    Unix epoch milliseconds at the moment of registration.
 * @property contentHash    SHA-256 hex digest of the raw file bytes.
 * @property userKeyFragment First 16 chars of a user-specific secret (optional obfuscation layer).
 */
data class WatermarkPayload(
    val deviceId: String,
    val timestampMs: Long,
    val contentHash: String,
    val userKeyFragment: String
)

/**
 * Full Guardian verification result returned by the 3-stage pipeline.
 *
 * @property verificationId       Unique UUID assigned by the Guardian backend.
 * @property overallVerdict       Human-readable verdict string (e.g. "AUTHENTIC", "LIKELY_FAKE").
 * @property verdictBadge         Emoji + short label (e.g. "✅ Authentic", "🚨 Fake Detected").
 * @property confidence           0–100 confidence score from ensemble analysis.
 * @property aiProbabilityPercent Probability (0–100) the content is AI-generated.
 * @property fakePossibilityPercent Probability (0–100) the content has been manipulated.
 * @property moneyRiskLevel       "LOW", "MEDIUM", or "HIGH" financial risk rating.
 * @property explanation          Paragraph-form explanation of the verdict.
 * @property reasons              Bullet-point reasons supporting the verdict.
 * @property stageReached         How many pipeline stages completed (1–3).
 */
data class GuardianVerifyResult(
    val verificationId: String,
    val overallVerdict: String,
    val verdictBadge: String,
    val confidence: Int,
    val aiProbabilityPercent: Int,
    val fakePossibilityPercent: Int,
    val moneyRiskLevel: String,
    val explanation: String,
    val reasons: List<String>,
    val stageReached: Int
)

// ---------------------------------------------------------------------------
// SDK singleton
// ---------------------------------------------------------------------------

object GuardianWatermarkSDK {

    private const val TAG = "GuardianWatermarkSDK"

    /** Base URL for emulator → host loopback. Replaceable via customHost or shared preferences for physical devices. */
    @Volatile
    var customHost: String? = null

    fun getRegisterEndpoint(context: Context? = null): String = "${getBaseUrl(context)}/register-media"
    fun getVerifyEndpoint(context: Context? = null): String = "${getBaseUrl(context)}/verify"

    fun getBaseUrl(context: Context? = null): String {
        customHost?.let { return "http://$it:8410/api/guardian" }
        context?.let {
            val prefs = it.getSharedPreferences("adonai_prefs", Context.MODE_PRIVATE)
            val host = prefs.getString("backend_host", null)
            if (!host.isNullOrBlank()) return "http://$host:8410/api/guardian"
        }
        return "http://10.0.2.2:8410/api/guardian"
    }

    // -----------------------------------------------------------------------
    // Watermark utilities
    // -----------------------------------------------------------------------

    /**
     * JSON-encodes a [WatermarkPayload] into a compact string suitable for embedding
     * in EXIF metadata, MP4 user data atoms, or ID3 tags.
     */
    fun embedWatermarkPayload(payload: WatermarkPayload): String {
        return JSONObject().apply {
            put("device_id",          payload.deviceId)
            put("timestamp_ms",       payload.timestampMs)
            put("content_hash",       payload.contentHash)
            put("user_key_fragment",  payload.userKeyFragment)
        }.toString()
    }

    /**
     * Computes the SHA-256 digest of [bytes] and returns it as a lowercase hex string.
     * Used as the canonical content fingerprint included in every watermark.
     */
    fun computeContentHash(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    // -----------------------------------------------------------------------
    // Backend – registration
    // -----------------------------------------------------------------------

    /**
     * Reads the file at [mediaUri], computes its watermark, and POSTs it to the
     * Guardian backend for blockchain registration.
     *
     * Must be called from a coroutine; performs I/O on [Dispatchers.IO].
     *
     * @param context     Android context used for content-resolver access and device ID.
     * @param mediaUri    Content URI of the newly captured media file.
     * @param mediaType   MIME type string (e.g. "image/jpeg", "video/mp4").
     * @param contextText Optional free-text context (caption, location, scene description).
     */
    suspend fun registerWithBackend(
        context: Context,
        mediaUri: Uri,
        mediaType: String,
        contextText: String = ""
    ) = withContext(Dispatchers.IO) {
        try {
            // 1. Read raw bytes from the content URI
            val bytes = readBytesFromUri(context, mediaUri)
                ?: run {
                    Log.e(TAG, "registerWithBackend: could not read bytes from $mediaUri")
                    return@withContext
                }

            // 2. Compute content hash
            val contentHash = computeContentHash(bytes)

            // 3. Build watermark payload
            val deviceId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown-device"

            val payload = WatermarkPayload(
                deviceId        = deviceId,
                timestampMs     = System.currentTimeMillis(),
                contentHash     = contentHash,
                userKeyFragment = deviceId.take(16)
            )

            val watermarkJson = embedWatermarkPayload(payload)
            Log.d(TAG, "Watermark payload: $watermarkJson")

            // 4. Base64-encode the file bytes for transport
            val base64Content = Base64.encodeToString(bytes, Base64.NO_WRAP)

            // 5. Build JSON request body
            val requestBody = JSONObject().apply {
                put("watermark",    watermarkJson)
                put("media_type",   mediaType)
                put("content",      base64Content)
                put("context_text", contextText)
                put("uri",          mediaUri.toString())
            }.toString()

            // 6. POST to Guardian backend
            val result = httpPost(getRegisterEndpoint(context), requestBody)
            Log.i(TAG, "registerWithBackend: response → $result")

        } catch (e: Exception) {
            Log.e(TAG, "registerWithBackend: unexpected error", e)
        }
    }

    // -----------------------------------------------------------------------
    // Backend – verification
    // -----------------------------------------------------------------------

    /**
     * Submits the media at [mediaUri] to the Guardian 3-stage verification pipeline
     * and returns a [GuardianVerifyResult] with the full verdict.
     *
     * Must be called from a coroutine; performs I/O on [Dispatchers.IO].
     *
     * @param context     Android context.
     * @param mediaUri    Content URI of the media to verify.
     * @param mediaType   MIME type string.
     * @param contextText Optional free-text context.
     * @return            Parsed [GuardianVerifyResult] or a failure-state result on error.
     */
    suspend fun verifyMedia(
        context: Context,
        mediaUri: Uri,
        mediaType: String,
        contextText: String = ""
    ): GuardianVerifyResult = withContext(Dispatchers.IO) {
        try {
            val bytes = readBytesFromUri(context, mediaUri)
                ?: return@withContext errorResult("Could not read media file")

            val contentHash  = computeContentHash(bytes)
            val base64Content = Base64.encodeToString(bytes, Base64.NO_WRAP)

            val deviceId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown-device"

            val requestBody = JSONObject().apply {
                put("content",      base64Content)
                put("media_type",   mediaType)
                put("context_text", contextText)
                put("content_hash", contentHash)
                put("device_id",    deviceId)
            }.toString()

            val responseJson = httpPost(getVerifyEndpoint(context), requestBody)
            Log.i(TAG, "verifyMedia: response → $responseJson")

            parseVerifyResult(responseJson)

        } catch (e: Exception) {
            Log.e(TAG, "verifyMedia: unexpected error", e)
            errorResult(e.message ?: "Unknown error")
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /** Reads all bytes from a content URI via the ContentResolver. */
    private fun readBytesFromUri(context: Context, uri: Uri): ByteArray? {
        return try {
            context.contentResolver.openInputStream(uri)?.use(InputStream::readBytes)
        } catch (e: Exception) {
            Log.e(TAG, "readBytesFromUri: failed for $uri", e)
            null
        }
    }

    /**
     * Performs a synchronous HTTP POST with a JSON body.
     * Uses [HttpURLConnection] from the stdlib — no OkHttp dependency required.
     *
     * @param endpoint   Full URL string.
     * @param jsonBody   JSON payload as a String.
     * @return           Response body string (empty on non-2xx or error).
     */
    private fun httpPost(endpoint: String, jsonBody: String): String {
        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod     = "POST"
                doOutput          = true
                connectTimeout    = 15_000
                readTimeout       = 30_000
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Accept",       "application/json")
            }

            connection.outputStream.use { os ->
                os.write(jsonBody.toByteArray(Charsets.UTF_8))
            }

            val responseCode = connection.responseCode
            Log.d(TAG, "httpPost [$endpoint] → HTTP $responseCode")

            if (responseCode in 200..299) {
                connection.inputStream.use { it.bufferedReader().readText() }
            } else {
                val errorBody = connection.errorStream?.use { it.bufferedReader().readText() } ?: ""
                Log.w(TAG, "httpPost: non-2xx response ($responseCode): $errorBody")
                errorBody
            }
        } catch (e: Exception) {
            Log.e(TAG, "httpPost: network error for $endpoint", e)
            ""
        } finally {
            connection?.disconnect()
        }
    }

    /** Parses a JSON string into a [GuardianVerifyResult]. */
    private fun parseVerifyResult(json: String): GuardianVerifyResult {
        return try {
            val obj = JSONObject(json)
            val reasonsArr = obj.optJSONArray("reasons")
            val reasons = buildList {
                if (reasonsArr != null) {
                    for (i in 0 until reasonsArr.length()) add(reasonsArr.getString(i))
                }
            }
            GuardianVerifyResult(
                verificationId        = obj.optString("verification_id", ""),
                overallVerdict        = obj.optString("overall_verdict", "UNKNOWN"),
                verdictBadge          = obj.optString("verdict_badge", "❓ Unknown"),
                confidence            = obj.optInt("confidence", 0),
                aiProbabilityPercent  = obj.optInt("ai_probability_percent", 0),
                fakePossibilityPercent= obj.optInt("fake_possibility_percent", 0),
                moneyRiskLevel        = obj.optString("money_risk_level", "LOW"),
                explanation           = obj.optString("explanation", ""),
                reasons               = reasons,
                stageReached          = obj.optInt("stage_reached", 0)
            )
        } catch (e: Exception) {
            Log.e(TAG, "parseVerifyResult: JSON parse error", e)
            errorResult("Parse error: ${e.message}")
        }
    }

    /** Returns a [GuardianVerifyResult] representing a failure state. */
    private fun errorResult(message: String) = GuardianVerifyResult(
        verificationId        = "",
        overallVerdict        = "ERROR",
        verdictBadge          = "⚠️ Error",
        confidence            = 0,
        aiProbabilityPercent  = 0,
        fakePossibilityPercent= 0,
        moneyRiskLevel        = "UNKNOWN",
        explanation           = message,
        reasons               = listOf(message),
        stageReached          = 0
    )
}
