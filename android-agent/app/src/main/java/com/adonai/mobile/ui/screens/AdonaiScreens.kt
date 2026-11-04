package com.adonai.mobile.ui.screens

enum class AdonaiMobileScreen(val code: Int, val title: String) {
    ONBOARDING(1, "Onboarding & Capability Boundaries"),
    PERMISSION_CENTER(2, "Permission Center & Revocation"),
    PROTECTION_HOME(3, "Device Protection Home"),
    LIVE_TIMELINE(4, "Live Exposure Timeline"),
    EXPOSURE_DETAILS(5, "App & Permission Exposure"),
    SCAM_SHARE_ANALYSIS(6, "Share-Sheet Scam & Link Guard"),
    INCIDENT_DETAIL(7, "Threat Incident 5-Question Detail"),
    TRUSTED_CONTACTS(8, "Trusted Contacts Context"),
    NETWORK_VPN_SETTINGS(9, "Local VPN Metadata Settings"),
    MAC_PAIRING(10, "Authenticated Mac LAN Pairing"),
    PRIVACY_RETENTION(11, "Privacy & Data Retention Controls"),
    LAB_MODE(12, "Isolated Lab Mode")
}
