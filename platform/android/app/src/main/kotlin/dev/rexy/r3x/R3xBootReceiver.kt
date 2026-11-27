package dev.rexy.r3x

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

class R3xBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences("r3x_boot_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("auto_start_vpn", false)) return
        if (VpnService.prepare(context) == null) {
            val svc = Intent(context, R3xVpnService::class.java).apply {
                action = R3xVpnService.ACTION_START
            }
            context.startForegroundService(svc)
        }
    }
}
