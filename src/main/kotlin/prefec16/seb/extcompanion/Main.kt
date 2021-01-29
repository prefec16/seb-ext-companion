package prefec16.seb.extcompanion

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import io.javalin.Javalin
import prefec16.seb.config.ConfigExtractor
import prefec16.seb.crypto.Crypto

const val ORIGINATOR_VERSION_KEY = "originatorVersion"
const val BROWSER_EXAM_KEY_SALT_KEY = "examKeySalt"

@ExperimentalUnsignedTypes
fun main() {
    val app = Javalin.create().start(9999)
    println("Companion has been started!")

    app.post("/keys") { ctx ->
        ctx.bodyValidator<ConfigKeyBody>().getOrNull()?.let { body ->
            val config = ConfigExtractor.parse(body.config)
            //idk why, but this element will not be serialized to json in the original version
            config.remove(ORIGINATOR_VERSION_KEY)
            val examKeySalt = config.getIfHas(BROWSER_EXAM_KEY_SALT_KEY)?.asString?.replace("\"", "")

            val configKey = Crypto.computeConfigurationKey(config)
            val browserExamKey = Crypto.computeBrowserExamKey(configKey, examKeySalt)

            val resp = mapOf("configKey" to configKey, "browserExamKey" to browserExamKey)
            println(resp)
            ctx.status(200).json(resp)
        }
    }

    app.post("/urlhashes") { ctx ->
        ctx.bodyValidator<CalculateHeadersBody>().getOrNull()?.let { body ->
            val requestHash = Crypto.computeRequestHash(body.url, body.browserExamKey)
            val configKeyHash = Crypto.computeConfigKeyHash(body.url, body.configKey)

            println("calculated requestHash $requestHash and configKeyHash $configKeyHash for ${body.url}")
            ctx.status(200).json(mapOf("requestHash" to requestHash, "configKeyHash" to configKeyHash))
        }
    }

}

data class CalculateHeadersBody(val url: String, val browserExamKey: String, val configKey: String)

data class ConfigKeyBody(val config: String)

fun JsonObject.getIfHas(key: String): JsonElement? {
    return if (this.has(key)) this.get(key) else null
}