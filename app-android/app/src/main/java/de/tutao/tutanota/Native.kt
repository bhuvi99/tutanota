package de.tutao.tutanota

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import android.webkit.JavascriptInterface
import de.tutao.tutanota.push.PushNotificationService
import de.tutao.tutanota.push.SseStorage
import kotlinx.coroutines.*
import org.jdeferred.Promise
import org.jdeferred.impl.DeferredObject
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

/**
 * Created by mpfau on 4/8/17.
 */
class Native internal constructor(private val activity: MainActivity) {
    private val crypto = Crypto(activity)
    private val files = FileUtil(activity)
    private val contact = Contact(activity)
    private val sseStorage = SseStorage(activity)
    private val secureStorage = SecureStorage(activity)
    private val queue = HashMap<String, kotlinx.coroutines.CompletableDeferred<JSONObject>>()
    private val coroutineScope = CoroutineScope(Dispatchers.Default + Job())

    @Volatile
    var webAppInitialized = DeferredObject<Void, Void, Void>()
        private set


    fun setup() {
        activity.webView.addJavascriptInterface(this, JS_NAME)
    }

    /**
     * Invokes method with args. The returned response is a JSON of the following format:
     *
     * @param msg A request (see WorkerProtocol)
     * @return A promise that resolves to a response or requestError (see WorkerProtocol)
     * @throws JSONException
     */
    @JavascriptInterface
    operator fun invoke(msg: String) {
        coroutineScope.launch {
            try {
                val request = JSONObject(msg)
                if (request.get("type") == "response") {
                    val promise = queue.remove(request.get("id"))
                    promise!!.complete(request)
                } else if (request.getString("type") == "requestError") {
                    val promise = queue.remove(request.get("id"))
                    promise!!.completeExceptionally(Error(request.toString()))
                } else {
                    try {
                        val result = invokeMethod(request.getString("type"), request.getJSONArray("args"))
                        sendResponse(request, result)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed request", e)
                        sendErrorResponse(request, e)
                    }
                }
            } catch (e: JSONException) {
                Log.e("Native", "could not parse msg:$msg", e)
            }
        }
    }

    fun sendRequest(type: JsRequest, args: Array<Any>): Promise<JSONObject, Exception, *> {
        val request = JSONObject()
        val requestId = createRequestId()
        val arguments = JSONArray()
        for (arg in args) {
            arguments.put(arg)
        }
        request.put("id", requestId)
        request.put("type", type.toString())
        request.put("args", arguments)
        this.postMessage(request)
        val d = CompletableDeferred<JSONObject>()
        this.queue[requestId] = d
        return d.toPromise()
    }

    private fun sendResponse(request: JSONObject, value: Any?) {
        val response = JSONObject()
        response.put("id", request.getString("id"))
        response.put("type", "response")
        response.put("value", value)
        postMessage(response)
    }

    private fun sendErrorResponse(request: JSONObject, ex: Exception) {
        val response = JSONObject()
        response.put("id", request.getString("id"))
        response.put("type", "requestError")
        response.put("error", errorToObject(ex))
        postMessage(response)
    }

    private fun postMessage(json: JSONObject) {
        evaluateJs("tutao.nativeApp.handleMessageFromNative('" + escape(json.toString()) + "')")
    }

    private fun evaluateJs(js: String) {
        activity.webView.post {
            activity.webView.evaluateJavascript(js) {
                // no response expected
            }
        }
    }

    private suspend fun invokeMethod(method: String, args: JSONArray): Any? {
        return when (method) {
            "init" -> {
                if (!webAppInitialized.isResolved) {
                    webAppInitialized.resolve(null)
                }
                "android"
            }
            "reload" -> {
                webAppInitialized = DeferredObject()
                queue.clear()
                activity.loadMainPage(args.getString(0))
            }
            "initPushNotifications" -> initPushNotifications()
            "generateRsaKey" -> crypto.generateRsaKey(Utils.base64ToBytes(args.getString(0)))
            "rsaEncrypt" -> crypto.rsaEncrypt(args.getJSONObject(0), Utils.base64ToBytes(args.getString(1)), Utils.base64ToBytes(args.getString(2)))
            "rsaDecrypt" -> crypto.rsaDecrypt(args.getJSONObject(0), Utils.base64ToBytes(args.getString(1)))
            "aesEncryptFile" -> crypto.aesEncryptFile(Utils.base64ToBytes(args.getString(0)), args.getString(1), Utils.base64ToBytes(args.getString(2)))
            "aesDecryptFile" -> {
                val key = Utils.base64ToBytes(args.getString(0))
                val fileUrl = args.getString(1)

                crypto.aesDecryptFile(key, fileUrl)
            }
            "open" -> files.openFile(args.getString(0), args.getString(1)).toDeferred().await()
            "openFileChooser" -> files.openFileChooser().toDeferred().await()
            "deleteFile" -> {
                files.delete(args.getString(0))
                null
            }
            "getName" -> files.getName(args.getString(0))
            "getMimeType" -> files.getMimeType(Uri.parse(args.getString(0)))
            "getSize" -> files.getSize(args.getString(0)).toString()
            "upload" -> files.upload(args.getString(0), args.getString(1), args.getJSONObject(2))
            "download" -> files.download(args.getString(0), args.getString(1), args.getJSONObject(2))
            "clearFileData" -> files.clearFileData()
            "findSuggestions" -> contact.findSuggestions(args.getString(0)).toDeferred().await()
            "openLink" -> openLink(args.getString(0))
            "getPushIdentifier" -> sseStorage.pushIdentifier
            "storePushIdentifierLocally" -> {
                sseStorage.storePushIdentifier(args.getString(0), args.getString(1),
                        args.getString(2))
                true
            }
            "closePushNotifications" -> {
                val addressesArray = args.getJSONArray(0)
                cancelNotifications(addressesArray)
                true
            }
            "readFile" -> Utils.bytesToBase64(Utils.readFile(File(activity.filesDir, args.getString(0))))
            "writeFile" -> {
                val filename = args.getString(0)
                val contentInBase64 = args.getString(1)
                Utils.writeFile(File(activity.filesDir, filename),
                        Utils.base64ToBytes(contentInBase64))
                true
            }
            "changeTheme" -> activity.changeTheme(args.getString(0))
            "saveBlob" -> files.saveBlob(args.getString(0), args.getString(1)).toDeferred().await()
            "putFileIntoDownloads" -> {
                val path = args.getString(0)
                files.putToDownloadFolder(path).toDeferred().await()
            }
            "putIntoSecureStorage" -> secureStorage.put(args.getString(0), args.getString(1), args.getBoolean(2), args.getBoolean(3))
            "getFromSecureStorage" -> secureStorage.get(args.getString(0))
            else -> throw Exception("unsupported method: $method")
        }
    }


    @Throws(JSONException::class)
    private fun cancelNotifications(addressesArray: JSONArray) {
        val notificationManager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        Objects.requireNonNull(notificationManager)

        val emailAddresses = ArrayList<String>(addressesArray.length())
        for (i in 0 until addressesArray.length()) {
            notificationManager.cancel(Math.abs(addressesArray.getString(i).hashCode()))
            emailAddresses.add(addressesArray.getString(i))
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            // Before N summary consumes individual notificaitons and we can only cancel the whole
            // group.
            notificationManager.cancel(PushNotificationService.SUMMARY_NOTIFICATION_ID)
        }
        activity.startService(PushNotificationService.notificationDismissedIntent(activity,
                emailAddresses, "Native", false))
    }

    private fun openLink(uri: String?): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri))
        val pm = activity.packageManager
        val resolved = intent.resolveActivity(pm) != null
        if (resolved) {
            activity.startActivity(intent)
        }
        return resolved
    }

    private fun initPushNotifications() {
        activity.runOnUiThread {
            activity.askBatteryOptinmizationsIfNeeded()
            activity.setupPushNotifications()
        }
    }

    companion object {
        private val JS_NAME = "nativeApp"
        private val TAG = "Native"

        internal val requestId = AtomicInteger()

        internal fun createRequestId(): String {
            return "app" + requestId.getAndIncrement()
        }

        @Throws(JSONException::class)
        private fun errorToObject(e: Exception): JSONObject {
            val error = JSONObject()
            val errorType = e.javaClass.name
            error.put("name", errorType)
            error.put("message", e.message)
            error.put("stack", getStack(e))
            return error
        }

        private fun getStack(e: Exception): String {
            val errors = StringWriter()
            e.printStackTrace(PrintWriter(errors))
            return errors.toString()
        }

        private fun escape(s: String): String {
            return Utils.bytesToBase64(s.toByteArray())
        }
    }
}

private fun <T> Deferred<T>.toPromise(): Promise<T, java.lang.Exception, *> {
    val promise = DeferredObject<T, java.lang.Exception, Any>()

    this.invokeOnCompletion { err ->
        if (err == null) {
            promise.resolve(this.getCompleted())
        } else {
            promise.reject(err as java.lang.Exception)
        }
    }
    return promise
}

private fun <T> Promise<T, Exception, Void>.toDeferred(): Deferred<T> {
    val deferred = CompletableDeferred<T>()
    this.then { res -> deferred.complete(res) }
            .fail { e -> deferred.completeExceptionally(e) }
    return deferred
}


