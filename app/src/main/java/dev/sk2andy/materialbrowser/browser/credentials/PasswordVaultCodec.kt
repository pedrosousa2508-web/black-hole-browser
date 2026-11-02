package dev.sk2andy.materialbrowser.browser.credentials

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/** Binary plaintext schema used only in memory, inside the authenticated encrypted vault envelope. */
internal object PasswordVaultCodec {
    const val MAX_ENTRIES = 5_000
    const val MAX_PLAINTEXT_BYTES = 32 * 1024 * 1024
    private const val MAGIC = 0x42485631 // BHV1

    fun encode(records: List<ImportedPassword>): ByteArray {
        require(records.size <= MAX_ENTRIES)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(MAGIC)
            data.writeInt(records.size)
            records.forEach { entry ->
                require(CredentialPromptRules.matchesHttpsOrigin(entry.origin, entry.origin))
                require(CredentialPromptRules.login(entry.login.username, entry.login.password) != null)
                data.writeUTF(entry.origin)
                data.writeUTF(entry.login.username)
                data.writeUTF(entry.login.password)
            }
        }
        return out.toByteArray().also { require(it.size <= MAX_PLAINTEXT_BYTES) }
    }

    fun decode(bytes: ByteArray): List<ImportedPassword>? = runCatching {
        require(bytes.size in 8..MAX_PLAINTEXT_BYTES)
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == MAGIC)
            val count = input.readInt()
            require(count in 0..MAX_ENTRIES)
            val seen = HashSet<Pair<String, String>>()
            val records = ArrayList<ImportedPassword>(count)
            repeat(count) {
                val origin = input.readUTF()
                val username = input.readUTF()
                val password = input.readUTF()
                require(CredentialPromptRules.matchesHttpsOrigin(origin, origin))
                val login = requireNotNull(CredentialPromptRules.login(username, password))
                require(seen.add(origin to login.username))
                records += ImportedPassword(origin, login)
            }
            require(input.available() == 0)
            records
        }
    }.getOrNull()
}
