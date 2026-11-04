/*
   ADONAI Curated YARA Ruleset v1.2
   License: BSD-3-Clause
   Usage: On-demand scanning of user-submitted files or isolated lab test artifacts.
*/

rule ADONAI_Suspicious_Android_Manifest_Markers {
    meta:
        author = "ADONAI Threat Intelligence Lab"
        version = "1.2"
        severity = "HIGH"
        technique = "T1404"
        description = "Detects suspicious permission & reflection markers in submitted Android package artifacts"
    strings:
        $perm1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $perm2 = "android.permission.READ_SMS" ascii wide
        $dex1 = "dalvik.system.DexClassLoader" ascii wide
    condition:
        ($perm1 and $perm2) or ($perm1 and $dex1)
}

rule ADONAI_Synthetic_Lab_Test_Artifact {
    meta:
        author = "ADONAI Threat Intelligence Lab"
        version = "1.0"
        severity = "MEDIUM"
        technique = "T1204.002"
        description = "Matches safe synthetic lab test string (EICAR-style benign ADONAI marker)"
    strings:
        $marker = "ADONAI-BENIGN-LAB-TEST-ARTIFACT-DO-NOT-ALERT-PROD" ascii
    condition:
        $marker
}
