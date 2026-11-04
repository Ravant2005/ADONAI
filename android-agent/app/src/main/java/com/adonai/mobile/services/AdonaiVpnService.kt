package com.adonai.mobile.services

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Opt-In Local VPN DNS & Connection Metadata Guard.
 * Boundary: Shows persistent notification. Observes DNS & socket metadata only.
 * TLS payloads remain encrypted and are NEVER intercepted or decrypted.
 */
class AdonaiVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP_VPN") {
            vpnInterface?.close()
            vpnInterface = null
            stopSelf()
            return START_NOT_STICKY
        }
        val builder = Builder()
            .setSession("ADONAI Metadata Guard (No TLS Decryption)")
            .addAddress("10.250.0.1", 24)
            .addDnsServer("1.1.1.1")
        vpnInterface = builder.establish()
        return START_STICKY
    }
}
