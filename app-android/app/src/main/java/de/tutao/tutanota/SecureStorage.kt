package de.tutao.tutanota

import android.app.AlertDialog
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.support.annotation.RequiresApi
import android.util.Log
import de.tutao.tutanota.Utils.bytesToBase64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

typealias StorageId = String

internal class SecureStorage(private val mainActivity: MainActivity) {
    var cancellationSignal: CancellationSignal? = null

    suspend fun get(id: StorageId): String? {
        val prefString = prefs.value.getString(id, null) ?: return null
        return tryDecrypt(Utils.base64ToBytes(prefString)).toString(Charsets.UTF_8)
    }

    suspend fun put(id: StorageId, value: String, authRequired: Boolean, regenerateKey: Boolean) {
        val encryptedData = tryEncrypt(value.toByteArray(), authRequired, regenerateKey)
        prefs.value.edit().putString(id, bytesToBase64(encryptedData)).apply()
    }

    private val prefs = lazy {
        this.mainActivity.getSharedPreferences("SECURE_STORAGE", Context.MODE_PRIVATE)
    }

    private fun createKey(authRequired: Boolean): SecretKey {
        // Generate a key to decrypt payment credentials, tokens, etc.
        // This will most likely be a registration step for the user when they are setting up your app.

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder
        if (atLeastMarshmallow()) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(false)
                    .apply {
                        if (authRequired) {
                            setUserAuthenticationRequired(true)
                            setUserAuthenticationValidityDurationSeconds(10)
                        }
                    }
                    .build())
            return keyGenerator.generateKey()
        } else {
            val keyGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
            @Suppress("DEPRECATION")
            keyGenerator.initialize(KeyPairGeneratorSpec.Builder(mainActivity)
                    .setAlias(KEY_NAME)
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(Date())
                    .setEndDate(Calendar.getInstance().run { add(Calendar.YEAR, 100); time })
                    .setSubject(X500Principal("CN=$KEY_NAME CA Certificate")).build())

            val keyPair = keyGenerator.generateKeyPair()

            val aesKey = generateAesKey()
            val encSymmetricKey = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                    .wrapKey(aesKey, keyPair.public)
            prefs.value.edit()
                    .putString(SYMMETRIC_KEY_PREF_KEY, Utils.bytesToBase64(encSymmetricKey))
                    .apply()

            return aesKey
        }
    }

    suspend fun tryEncrypt(bytes: ByteArray, authRequired: Boolean, regenerateKey: Boolean): ByteArray {
        return try {
            val key = getSymmetricKey(authRequired, regenerateKey)
            CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(bytes, key)
        } catch (e: Exception) {
            if (atLeastMarshmallow() && e is UserNotAuthenticatedException) {
                getAuthentication()
                tryEncrypt(bytes, authRequired, regenerateKey)
            } else {
                // TODO: handle auth failures?
                throw e
            }
        }
    }

    suspend fun tryDecrypt(bytes: ByteArray): ByteArray {
        return try {
            val key = getSymmetricKey(false, false)
            CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(bytes, key)
        } catch (e: Exception) {
            if (atLeastMarshmallow() && e is UserNotAuthenticatedException) {
                getAuthentication()
                tryDecrypt(bytes)
            } else {
                // TODO: handle auth failures?
                throw e
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    suspend fun getAuthentication() {
        cancellationSignal = CancellationSignal()
        withContext(Dispatchers.Main) {
            val authDialog = AlertDialog.Builder(this@SecureStorage.mainActivity)
                    .setCancelable(true)
                    .setMessage("Plz Authenticate")
                    .setNegativeButton(android.R.string.cancel) { dialog, which ->
                        dialog.dismiss()
                        cancellationSignal?.cancel()
                    }
                    .show()
            authenticate().await()
            authDialog.dismiss()
        }
    }


    private fun getKeyPair(): KeyPair {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val publicKey = keyStore.getCertificate(KEY_NAME).publicKey
        val privateKey = keyStore.getKey(KEY_NAME, null) as PrivateKey
        return KeyPair(publicKey, privateKey)
    }

    private suspend fun getSymmetricKey(authRequired: Boolean, regenerateKey: Boolean): SecretKey {
        if (atLeastMarshmallow()) {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if(regenerateKey) {
                return createKey(authRequired)
            }
            return keyStore.getKey(KEY_NAME, null) as SecretKey? ?: return createKey(authRequired)
        } else {
            val encSymmetricKey = prefs.value.getString(SYMMETRIC_KEY_PREF_KEY, null)
                    ?.let { Utils.base64ToBytes(it) }
            if (encSymmetricKey == null) {
                createKey(false)
                return getSymmetricKey(false, false)
            }
            return CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                    .unWrapKey(encSymmetricKey, getKeyPair().private)
        }
    }

    private fun atLeastMarshmallow() = Build.VERSION.SDK_INT > Build.VERSION_CODES.M


    @Suppress("DEPRECATION")
    @RequiresApi(Build.VERSION_CODES.M)
    private fun authenticate(): Deferred<Any> {
        val fingerprintManager = mainActivity.getSystemService(FingerprintManager::class.java)
        val deferred = CompletableDeferred<Any>()
        fingerprintManager.authenticate(
                null,
                cancellationSignal,
                0,
                object : FingerprintManager.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                        deferred.complete(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        deferred.completeExceptionally(FingerprintException())
                    }
                },
                null)
        return deferred
    }

    private fun generateAesKey(): SecretKey = KeyGenerator.getInstance("AES").generateKey()

    companion object {
        private const val KEY_NAME = "TUTCREDENTIALS"
        private const val SYMMETRIC_KEY_PREF_KEY = "symmetricKey"
    }
}

class FingerprintException : Exception()

class CipherWrapper(transformation: String) {
    val cipher: Cipher = Cipher.getInstance(transformation)

    companion object {
        const val TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding"
        const val TRANSFORMATION_SYMMETRIC = "AES/CBC/PKCS7Padding"
        private const val IV_BYTE_SIZE = 16
    }

    fun encrypt(data: ByteArray, key: SecretKey?): ByteArray {
        val iv = ByteArray(IV_BYTE_SIZE)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    fun decrypt(data: ByteArray, key: Key?): ByteArray {
        val iv = data.copyOfRange(0, IV_BYTE_SIZE)
        val msg = data.copyOfRange(IV_BYTE_SIZE, data.size)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        return cipher.doFinal(msg)
    }

    fun wrapKey(keyToBeWrapped: SecretKey, keyToWrapWith: PublicKey): ByteArray {
        cipher.init(Cipher.WRAP_MODE, keyToWrapWith)
        return cipher.wrap(keyToBeWrapped)
    }

    fun unWrapKey(wrappedKeyData: ByteArray, keyToUnWrapWith: PrivateKey): SecretKey {
        cipher.init(Cipher.UNWRAP_MODE, keyToUnWrapWith)
        return cipher.unwrap(wrappedKeyData, "AES", Cipher.SECRET_KEY) as SecretKey
    }
}
