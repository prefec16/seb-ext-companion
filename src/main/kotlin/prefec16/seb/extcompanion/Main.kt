package prefec16.seb.extcompanion

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import io.javalin.Javalin
import prefec16.seb.config.ConfigExtractor
import prefec16.seb.crypto.Crypto

const val CUSTOM_USER_AGENT_MODE_KEY = "browserUserAgentWinDesktopMode"
const val CUSTOM_USER_AGENT_KEY = "browserUserAgentWinDesktopModeCustom"
const val CUSTOM_USER_AGENT_SUFFIX_KEY = "browserUserAgent"
const val ORIGINATOR_VERSION_KEY = "originatorVersion"
const val BROWSER_EXAM_KEY_SALT_KEY = "examKeySalt"

const val SEB_USERAGENT_VERSION = "SEB/1.0.0.0"
const val DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 $SEB_USERAGENT_VERSION"

@ExperimentalUnsignedTypes
fun main(args: Array<String>) {
    val printHashes = args.toList().contains("--print-hashes")

    val app = Javalin.create {
        it.showJavalinBanner = false
    }.start(9999)

    println("Companion has been started!")

    app.post("/keys") { ctx ->
        ctx.bodyValidator<ConfigKeyBody>().getOrNull()?.let { body ->
            val config = ConfigExtractor.parse(body.config)
            //idk why, but this element will not be serialized to json in the original version
            config.remove(ORIGINATOR_VERSION_KEY)
            val examKeySalt = config.getIfHas(BROWSER_EXAM_KEY_SALT_KEY)?.asJsonPrimitive?.asString

            val configKey = Crypto.computeConfigurationKey(config)
            val browserExamKey = Crypto.computeBrowserExamKey(configKey, examKeySalt)

            println("Config successfully parsed!")
            ctx.status(200).json(
                mapOf(
                    "configKey" to configKey,
                    "browserExamKey" to browserExamKey,
                    "userAgent" to getUserAgent(config)
                )
            )
        }
    }

    app.post("/urlhashes") { ctx ->
        ctx.bodyValidator<CalculateHeadersBody>().getOrNull()?.let { body ->
            val requestHash = Crypto.computeRequestHash(body.url, body.browserExamKey)
            val configKeyHash = Crypto.computeConfigKeyHash(body.url, body.configKey)

            if (printHashes) {
                println("calculated requestHash $requestHash and configKeyHash $configKeyHash for ${body.url}")
            }

            ctx.status(200).json(mapOf("requestHash" to requestHash, "configKeyHash" to configKeyHash))
        }
    }
}

fun getUserAgent(config: JsonObject): String {
    return if (config.getIfHas(CUSTOM_USER_AGENT_MODE_KEY)?.asInt == 1) {
        buildString {
            append(config.get(CUSTOM_USER_AGENT_KEY).asString).append(" ").append(SEB_USERAGENT_VERSION)
            with(config.get(CUSTOM_USER_AGENT_SUFFIX_KEY).asString) {
                if (this.isNotEmpty()) {
                    append(" ").append(this)
                }
            }
        }
    } else DEFAULT_USER_AGENT
}

data class CalculateHeadersBody(val url: String, val browserExamKey: String, val configKey: String)

data class ConfigKeyBody(val config: String)

fun JsonObject.getIfHas(key: String) = if (this.has(key)) this.get(key) else null