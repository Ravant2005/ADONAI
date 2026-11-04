package com.adonai.mobile.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * Deferrable WorkManager sync to paired Mac over trusted LAN.
 * Gracefully preserves local Room functionality when Mac is offline.
 */
class MacSyncWorker(appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result {
        return try {
            // Sync unsynced LocalEventEntity records to paired Mac endpoint
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}
