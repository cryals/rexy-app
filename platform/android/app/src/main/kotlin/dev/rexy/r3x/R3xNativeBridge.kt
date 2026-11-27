package dev.rexy.r3x

object R3xNativeBridge {
    init {
        System.loadLibrary("r3x_app_lib")
    }

    external fun setDataDir(path: String)
    external fun initKeystoreBridge()
    external fun onVpnTunnelEstablished(tunFd: Int)
    external fun onVpnTunnelRevoked()
    external fun onNetworkChanged(available: Boolean, isMetered: Boolean)
}
