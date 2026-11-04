package com.adonai.mobile.guardian

/**
 * ADONAI Guardian Camera Observer Service
 *
 * A background service that monitors MediaStore for newly added photos/videos.
 * When a new camera capture is detected, it immediately triggers watermark
 * embedding and blockchain registration via GuardianWatermarkSDK.
 *
 * This runs as a lightweight foreground service with a notification to maintain
 * Android lifecycle compliance. Users must opt in via ADONAI Guardian settings.
 *
 * Uses: MediaStore ContentObserver + CoroutineScope
 */

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service that monitors [MediaStore] for newly captured images, videos, and audio.
 *
 * Lifecycle:
 * - Started via [CameraObserverService.Companion.start]
 * - Stopped via [CameraObserverService.Companion.stop]
 * - Registers [MediaStoreObserver] instances on three MediaStore content URIs.
 * - Each detected new media file is submitted to [GuardianWatermarkSDK.registerWithBackend].
 */
class CameraObserverService : Service() {

    // -----------------------------------------------------------------------
    // Coroutine scope tied to service lifetime
    // -----------------------------------------------------------------------

    private val serviceJob   = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)

    // -----------------------------------------------------------------------
    // Content observers
    // -----------------------------------------------------------------------

    private lateinit var imagesObserver : MediaStoreObserver
    private lateinit var videoObserver  : MediaStoreObserver
    private lateinit var audioObserver  : MediaStoreObserver

    // -----------------------------------------------------------------------
    // Service lifecycle
    // -----------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate: Guardian CameraObserverService starting")

        startForegroundWithNotification()
        registerMediaObservers()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: flags=$flags startId=$startId")
        return START_STICKY   // Restart automatically if killed by the system
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy: unregistering observers and cancelling coroutines")
        unregisterObservers()
        serviceScope.cancel()
        super.onDestroy()
    }

    /** Not a bound service. */
    override fun onBind(intent: Intent?): IBinder? = null

    // -----------------------------------------------------------------------
    // Foreground notification
    // -----------------------------------------------------------------------

    private fun startForegroundWithNotification() {
        createNotificationChannel()

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ADONAI Guardian Active")
            .setContentText("Monitoring new media for watermark registration")
            .setSmallIcon(android.R.drawable.ic_menu_camera)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "ADONAI Guardian",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "ADONAI Guardian media monitoring service"
            }

            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    // -----------------------------------------------------------------------
    // MediaStore observer registration
    // -----------------------------------------------------------------------

    private fun registerMediaObservers() {
        val handler = Handler(Looper.getMainLooper())

        imagesObserver = MediaStoreObserver(
            context   = applicationContext,
            mediaType = "image/jpeg",
            handler   = handler
        )
        videoObserver = MediaStoreObserver(
            context   = applicationContext,
            mediaType = "video/mp4",
            handler   = handler
        )
        audioObserver = MediaStoreObserver(
            context   = applicationContext,
            mediaType = "audio/m4a",
            handler   = handler
        )

        contentResolver.registerContentObserver(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            /* notifyForDescendants = */ true,
            imagesObserver
        )
        contentResolver.registerContentObserver(
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            /* notifyForDescendants = */ true,
            videoObserver
        )
        contentResolver.registerContentObserver(
            MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
            /* notifyForDescendants = */ true,
            audioObserver
        )

        Log.i(TAG, "registerMediaObservers: observers registered for images, video, audio")
    }

    private fun unregisterObservers() {
        if (::imagesObserver.isInitialized) contentResolver.unregisterContentObserver(imagesObserver)
        if (::videoObserver.isInitialized)  contentResolver.unregisterContentObserver(videoObserver)
        if (::audioObserver.isInitialized)  contentResolver.unregisterContentObserver(audioObserver)
    }

    // -----------------------------------------------------------------------
    // Inner class – MediaStore ContentObserver
    // -----------------------------------------------------------------------

    /**
     * Observes a MediaStore content URI and dispatches newly added media files
     * to [GuardianWatermarkSDK.registerWithBackend] for cryptographic watermarking.
     *
     * @param context   Service context used for content-resolver and SDK calls.
     * @param mediaType MIME type expected for files at this URI (passed to the SDK).
     * @param handler   Handler on which [onChange] is invoked (main thread).
     */
    inner class MediaStoreObserver(
        private val context   : Context,
        private val mediaType : String,
        handler               : Handler
    ) : ContentObserver(handler) {

        override fun onChange(selfChange: Boolean, uri: Uri?) {
            super.onChange(selfChange, uri)

            if (uri == null) {
                Log.w(TAG, "MediaStoreObserver.onChange: null URI for $mediaType, skipping")
                return
            }

            Log.d(TAG, "MediaStoreObserver.onChange: detected new $mediaType → $uri")

            // Dispatch watermark registration to the IO-bound coroutine scope.
            serviceScope.launch {
                try {
                    GuardianWatermarkSDK.registerWithBackend(
                        context     = context,
                        mediaUri    = uri,
                        mediaType   = mediaType,
                        contextText = "Auto-registered via CameraObserverService"
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "MediaStoreObserver: registration failed for $uri", e)
                }
            }
        }

        /** Also handle changes without a specific URI (bulk-change notifications). */
        override fun onChange(selfChange: Boolean) {
            super.onChange(selfChange)
            Log.v(TAG, "MediaStoreObserver.onChange (no URI) for $mediaType — skipping")
        }
    }

    // -----------------------------------------------------------------------
    // Companion object — start / stop helpers
    // -----------------------------------------------------------------------

    companion object {
        private const val TAG             = "CameraObserverService"
        private const val CHANNEL_ID      = "adonai_guardian_channel"
        private const val NOTIFICATION_ID = 7700

        /**
         * Starts [CameraObserverService] as a foreground service.
         *
         * Call this after the user enables the Guardian background monitoring toggle
         * in ADONAI settings. Requires the caller to hold
         * `FOREGROUND_SERVICE` and `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` permissions.
         *
         * @param context Any valid Android context (Activity, Application, etc.).
         */
        fun start(context: Context) {
            val intent = Intent(context, CameraObserverService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            Log.i(TAG, "start: CameraObserverService launch requested")
        }

        /**
         * Stops [CameraObserverService].
         *
         * @param context Any valid Android context.
         */
        fun stop(context: Context) {
            val intent = Intent(context, CameraObserverService::class.java)
            context.stopService(intent)
            Log.i(TAG, "stop: CameraObserverService stop requested")
        }
    }
}
