package com.adonai.mobile.services

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * Opt-In Notification Scam Guard.
 * Boundary: Processes ONLY notification fields explicitly exposed by Android StatusBarNotification.
 * Never claims access to full WhatsApp or private app SQLite databases.
 */
class AdonaiNotificationService : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return
        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        // Redact secrets & evaluate only if user explicitly enabled OPT_IN_NOTIFICATION_GUARD
    }
}
