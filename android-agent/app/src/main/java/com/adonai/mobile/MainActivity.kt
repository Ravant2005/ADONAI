package com.adonai.mobile

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.adonai.mobile.ui.theme.AdonaiTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AdonaiTheme {
                // Launches ADONAI 12-screen navigation host
            }
        }
    }
}
