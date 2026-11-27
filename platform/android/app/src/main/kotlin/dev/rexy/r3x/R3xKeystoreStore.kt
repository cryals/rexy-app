package dev.rexy.r3x

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed Android Keystore AES-256-GCM secret storage bridge invoked from Rust via JNI.
 * Refuses plaintext fallback if Keystore is unavailable.
 */
object R3xKeystoreStore {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "dev.rexy.r3x.master_key"
    private const val PREFS_NAME = "r3x_secure_vault"
    private const val GCM_TAG_BITS = 128

    @Volatile
    private var appContext: Context? = null

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
        ks.load(null)
        val existing = ks.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    @JvmStatic
    fun setSecret(key: String, value: String) {
        val ctx = checkNotNull(appContext) { "R3xKeystoreStore not initialized" }
        val secretKey = getOrCreateMasterKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))

        val combined = ByteBuffer.allocate(4 + iv.size + ciphertext.size)
            .putInt(iv.size)
            .put(iv)
            .put(ciphertext)
            .array()

        val encoded = Base64.encodeToString(combined, Base64.NO_WRAP)
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(key, encoded)
            .apply()
    }

    @JvmStatic
    fun getSecret(key: String): String? {
        val ctx = checkNotNull(appContext) { "R3xKeystoreStore not initialized" }
        val encoded = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(key, null) ?: return null
        val bytes = Base64.decode(encoded, Base64.NO_WRAP)
        val buf = ByteBuffer.wrap(bytes)
        val ivLen = buf.int
        require(ivLen in 12..32) { "Invalid Keystore IV length" }
        val iv = ByteArray(ivLen)
        buf.get(iv)
        val ct = ByteArray(buf.remaining())
        buf.get(ct)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        val plain = cipher.doFinal(ct)
        return String(plain, StandardCharsets.UTF_8)
    }

    @JvmStatic
    fun deleteSecret(key: String) {
        val ctx = checkNotNull(appContext) { "R3xKeystoreStore not initialized" }
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
    }
}
