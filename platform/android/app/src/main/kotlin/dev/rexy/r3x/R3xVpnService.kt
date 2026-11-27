package dev.rexy.r3x

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor

class R3xVpnService : VpnService() {
    companion object {
        const val ACTION_START = "dev.rexy.r3x.action.START_VPN"
        const val ACTION_STOP = "dev.rexy.r3x.action.STOP_VPN"
        const val CHANNEL_ID = "r3x_vpn_channel"
        const val NOTIFICATION_ID = 1001
        const val EXTRA_DNS_SERVER = "extra_dns_server"
        const val EXTRA_BYPASS_PACKAGES = "extra_bypass_packages"
    }

    private var tunnelInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        registerNetworkMonitor()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            teardownTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildPersistentNotification())
        establishTunnel(
            dnsServer = intent?.getStringExtra(EXTRA_DNS_SERVER) ?: "1.1.1.1",
            bypassPackages = intent?.getStringArrayListExtra(EXTRA_BYPASS_PACKAGES) ?: emptyList()
        )
        return START_STICKY
    }

    private fun establishTunnel(dnsServer: String, bypassPackages: List<String>) {
        if (tunnelInterface != null) return
        val builder = Builder()
            .setSession("R3X")
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(dnsServer)
            .setMtu(1500)

        runCatching { builder.addDisallowedApplication(packageName) }
        for (pkg in bypassPackages) {
            if (pkg.isNotBlank()) {
                runCatching { builder.addDisallowedApplication(pkg) }
            }
        }

        val established = builder.establish()
        if (established != null) {
            tunnelInterface = established
            val fd = established.fd
            R3xNativeBridge.onVpnTunnelEstablished(fd)
        } else {
            R3xNativeBridge.onVpnTunnelRevoked()
            stopSelf()
        }
    }

    private fun teardownTunnel() {
        R3xNativeBridge.onVpnTunnelRevoked()
        tunnelInterface?.runCatching { close() }
        tunnelInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        teardownTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetworkMonitor()
        teardownTunnel()
        super.onDestroy()
    }

    private fun registerNetworkMonitor() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
                R3xNativeBridge.onNetworkChanged(true, metered)
            }

            override fun onLost(network: Network) {
                R3xNativeBridge.onNetworkChanged(false, false)
            }
        }
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(req, cb)
        networkCallback = cb
    }

    private fun unregisterNetworkMonitor() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        networkCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        networkCallback = null
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_description)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildPersistentNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val openPending = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = Intent(this, R3xVpnService::class.java).apply { action = ACTION_STOP }
        val stopPending = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_notification_active))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openPending)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    getString(R.string.vpn_action_disconnect),
                    stopPending
                ).build()
            )
            .build()
    }
}
