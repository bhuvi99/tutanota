package de.tutao.tutanota

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.support.annotation.RequiresApi
import de.tutao.tutanota.Utils.bytesToBase64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.jdeferred.Promise
import org.jdeferred.impl.DeferredObject
import org.json.JSONArray
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

internal class CredentialsHandler(private val mainActivity: MainActivity) {

    suspend fun getCredentials(): List<TutanotaCredentials> {
        val prefString = prefs.getString(CREDENTIALS_PREF_KEY, null)
                ?: return listOf()
        val decryptedString = tryDecrypt(Utils.base64ToBytes(prefString)).toString(Charsets.UTF_8)

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
        val stringToStore = if (encrypted && atLeastMarshmallow()) {
            bytesToBase64(tryEncrypt(jsonArray.toString().toByteArray()))
        } else {
            bytesToBase64(jsonArray.toString().toByteArray())
        }
        prefs.edit().putString(CREDENTIALS_PREF_KEY, stringToStore).apply()
    }

    private val prefs: SharedPreferences =
            PreferenceManager.getDefaultSharedPreferences(this.mainActivity)

    private fun createKey(): SecretKey {
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
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(10)
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
            prefs.edit()
                    .putString(SYMMETRIC_KEY_PREF_KEY, Utils.bytesToBase64(encSymmetricKey))
                    .apply()

            return aesKey
        }
    }

    suspend fun tryEncrypt(bytes: ByteArray): ByteArray {
        return try {
            val key = getSymmetricKey()
            CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(bytes, key)
        } catch (e: Exception) {
            if (atLeastMarshmallow() && e is UserNotAuthenticatedException) {
                authenticate().join()
                tryEncrypt(bytes)
            } else {
                throw e
            }
        }
    }

    suspend fun tryDecrypt(bytes: ByteArray): ByteArray {
        return try {
            val key = getSymmetricKey()
            CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(bytes, key)
        } catch (e: Exception) {
            if (atLeastMarshmallow() && e is UserNotAuthenticatedException) {
                authenticate().join()
                tryDecrypt(bytes)
            } else {
                throw e
            }
        }
    }


    private fun getKeyPair(): KeyPair {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val publicKey = keyStore.getCertificate(KEY_NAME).publicKey
        val privateKey = keyStore.getKey(KEY_NAME, null) as PrivateKey
        return KeyPair(publicKey, privateKey)
    }

    private suspend fun getSymmetricKey(): SecretKey {
        if (atLeastMarshmallow()) {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            try {
                return keyStore.getKey(KEY_NAME, null) as SecretKey? ?: return createKey()
            } catch (e: UserNotAuthenticatedException) {
                authenticate().await()
                return getSymmetricKey()
            }
        } else {
            val encSymmetricKey = prefs.getString(SYMMETRIC_KEY_PREF_KEY, null)
                    ?.let { Utils.base64ToBytes(it) }
            if (encSymmetricKey == null) {
                createKey()
                return getSymmetricKey()
            }
            return CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                    .unWrapKey(encSymmetricKey, getKeyPair().private)
        }
    }

    private fun atLeastMarshmallow() = Build.VERSION.SDK_INT > Build.VERSION_CODES.M


    @RequiresApi(Build.VERSION_CODES.M)
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

    private fun generateAesKey(): SecretKey = KeyGenerator.getInstance("AES").generateKey()

    companion object {
        private const val KEY_NAME = "TUTCREDENTIALS"
        private const val CREDENTIALS_PREF_KEY = "credentials"
        private const val SYMMETRIC_KEY_PREF_KEY = "symmetricKey"
    }
}

class CipherWrapper(transformation: String) {

    companion object {
        const val TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding"
        const val TRANSFORMATION_SYMMETRIC = "AES/CBC/PKCS7Padding"
        private const val IV_BYTE_SIZE = 16
    }

    val cipher: Cipher = Cipher.getInstance(transformation)

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
