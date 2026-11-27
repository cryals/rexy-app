package dev.rexy.r3x

import android.Manifest
import android.app.NativeActivity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : NativeActivity() {
    companion object {
        private const val REQ_VPN_CONSENT = 4001
        private const val REQ_POST_NOTIF = 4002
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        R3xKeystoreStore.init(applicationContext)
        R3xNativeBridge.setDataDir(filesDir.absolutePath)
        R3xNativeBridge.initKeystoreBridge()
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
    }

    fun requestAndStartVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepareIntent, REQ_VPN_CONSENT)
        } else {
            startVpnService()
        }
    }

    fun stopVpnService() {
        val stopIntent = Intent(this, R3xVpnService::class.java).apply {
            action = R3xVpnService.ACTION_STOP
        }
        startService(stopIntent)
    }

    private fun startVpnService() {
        val intent = Intent(this, R3xVpnService::class.java).apply {
            action = R3xVpnService.ACTION_START
        }
        startForegroundService(intent)
    }

    @Deprecated("Required for NativeActivity VPN consent result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_CONSENT && resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    REQ_POST_NOTIF
                )
            }
        }
    }
}
