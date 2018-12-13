package de.tutao.tutanota

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.support.annotation.RequiresApi
import de.tutao.tutanota.Utils.base64ToBytes
import de.tutao.tutanota.Utils.bytesToBase64
import kotlinx.coroutines.*
import org.jdeferred.Promise
import org.jdeferred.impl.DeferredObject
import org.json.JSONArray
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

internal class CredentialsHandler(private val mainActivity: MainActivity) {
    private var iv: ByteArray? = null

    suspend fun getCredentials(): List<TutanotaCredentials> {
        val prefString = prefs.getString(CREDENTIALS_PREF_KEY, null)
                ?: return listOf()
        val isEncrypted = prefs.getBoolean(ENCRYPTED_PREF_KEY, false)
        val decryptedString = if (isEncrypted && Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            tryDecrypt(base64ToBytes(prefString))
        } else {
            base64ToBytes(prefString)
        }.toString(Charset.forName("UTF-8"))

        val jsonArray = JSONArray(decryptedString)
        val credentialsArray = mutableListOf<TutanotaCredentials>()
        for (i in 0 until jsonArray.length()) {
            credentialsArray.add(TutanotaCredentials.fromJSON(jsonArray.getJSONObject(i)))
        }
        return credentialsArray
    }

    fun getCredentialsInterop(): Promise<List<TutanotaCredentials>, Any, Any> {
        val deferred = DeferredObject<List<TutanotaCredentials>, Any, Any>()
        GlobalScope.launch {
            val credentials = getCredentials()
            deferred.resolve(credentials)
        }
        return deferred
    }

    fun putCredentialsInterop(encrypted: Boolean, credentials: List<TutanotaCredentials>): Promise<Any, Any, Any> {
        val deferred = DeferredObject<Any, Any, Any>()
        GlobalScope.launch {
            putCredentials(encrypted, credentials)
            deferred.resolve(Unit)
        }
        return deferred
    }

    suspend fun putCredentials(encrypted: Boolean, credentials: List<TutanotaCredentials>) {
        val jsonArray = JSONArray(credentials.map { credential -> credential.toJSON() })
        val stringToStore = if (encrypted && Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            bytesToBase64(tryEncrypt(jsonArray.toString().toByteArray()))
        } else {
            bytesToBase64(jsonArray.toString().toByteArray())
        }
        prefs.edit()
                .putString(CREDENTIALS_PREF_KEY, stringToStore)
                .putBoolean(ENCRYPTED_PREF_KEY, encrypted)
                .apply()
    }

    private val prefs: SharedPreferences =
            PreferenceManager.getDefaultSharedPreferences(this.mainActivity)

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun createKey() {
        // Generate a key to decrypt payment credentials, tokens, etc.
        // This will most likely be a registration step for the user when they are setting up your app.

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder

        keyGenerator.init(KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                // Require that the user has unlocked in the last 30 seconds
                .setUserAuthenticationValidityDurationSeconds(30)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build())

        keyGenerator.generateKey()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    suspend fun tryEncrypt(bytes: ByteArray): ByteArray {
        val cipher = getCipher(null)
        this.iv = cipher.iv
        return cipher.doFinal(bytes)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    suspend fun tryDecrypt(bytes: ByteArray): ByteArray {
        val cipher = getCipher(this.iv)
        return cipher.doFinal(bytes)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private suspend fun getCipher(iv: ByteArray?): Cipher {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            var secretKey: SecretKey? = keyStore.getKey(KEY_NAME, null) as SecretKey?
            if (secretKey == null) {
                this.createKey()
                secretKey = keyStore.getKey(KEY_NAME, null) as SecretKey
            }

            val cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7)
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            }
            return cipher
        } catch (e: UserNotAuthenticatedException) {
            authenticate().await()
            return getCipher(iv)
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun authenticate(): Deferred<Any> {
        val mKeyguardManager = this.mainActivity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        val intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null)
        val deferred = CompletableDeferred<Any>()

        this.mainActivity.startActivityForResult(intent).then { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                deferred.complete(true)
            } else {
                deferred.completeExceptionally(UserNotAuthenticatedException())
            }
        }
        return deferred
    }

    companion object {
        private const val KEY_NAME = "TUTCREDENTIALS"
        private const val CREDENTIALS_PREF_KEY = "credentials"
        private const val ENCRYPTED_PREF_KEY = "encrypted"
    }
}
