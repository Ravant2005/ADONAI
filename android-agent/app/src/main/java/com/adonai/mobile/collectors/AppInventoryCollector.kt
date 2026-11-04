package com.adonai.mobile.collectors

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager

data class AppAuditRecord(
    val packageName: String,
    val appLabel: String,
    val versionName: String,
    val installerSource: String,
    val grantedPermissions: List<String>,
    val riskScore: Double,
    val riskRationale: String
)

class AppInventoryCollector(private val context: Context) {
    fun collectInstalledApps(): List<AppAuditRecord> {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val results = mutableListOf<AppAuditRecord>()

        for (pkg in packages) {
            val granted = mutableListOf<String>()
            val reqPerms = pkg.requestedPermissions
            val flags = pkg.requestedPermissionsFlags
            if (reqPerms != null && flags != null) {
                for (i in reqPerms.indices) {
                    if ((flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                        granted.add(reqPerms[i])
                    }
                }
            }
            val hasSms = granted.any { it.contains("READ_SMS") || it.contains("RECEIVE_SMS") }
            val hasAccess = granted.any { it.contains("BIND_ACCESSIBILITY_SERVICE") }
            val hasOverlay = granted.any { it.contains("SYSTEM_ALERT_WINDOW") }

            var risk = 0.10
            var rationale = "Standard permission footprint."
            if (hasSms && (hasAccess || hasOverlay)) {
                risk = 0.89
                rationale = "HIGH RISK: Holds READ_SMS combined with Accessibility/Overlay permissions."
            }
            val label = pkg.applicationInfo?.let { pm.getApplicationLabel(it).toString() } ?: pkg.packageName
            val version = pkg.versionName ?: "1.0"
            results.add(
                AppAuditRecord(
                    packageName = pkg.packageName,
                    appLabel = label,
                    versionName = version,
                    installerSource = "package_manager_api",
                    grantedPermissions = granted,
                    riskScore = risk,
                    riskRationale = rationale
                )
            )
        }
        return results.sortedByDescending { it.riskScore }
    }
}
