package dev.sk2andy.materialbrowser.browser.credentials

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.IDN
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Locale

/**
 * Isolated, read-only CSV import preparation. Does not persist passwords or register Autofill.
 * Imported credentials must only be handed to an encrypted vault after explicit user approval.
 */
internal sealed interface PasswordCsvImportResult {
    data class Parsed(
        val entries: List<ImportedPassword>,
        val skippedRows: Int,
    ) : PasswordCsvImportResult

    data object InvalidFormat : PasswordCsvImportResult
    data object TooLarge : PasswordCsvImportResult
    data object InvalidUtf8 : PasswordCsvImportResult
    data object Unreadable : PasswordCsvImportResult
}

/** Avoid accidental password exposure through generated data-class string representations. */
internal class ImportedPassword(
    val origin: String,
    val login: CredentialLogin,
) {
    override fun toString(): String = "ImportedPassword(<redacted>)"
}

internal object PasswordCsvImportRules {
    const val MAX_FILE_BYTES = 2 * 1024 * 1024
    private const val MAX_RECORDS = 5_000
    private const val MAX_COLUMNS = 48
    private const val MAX_FIELD_CHARS = 16 * 1024
    private const val MAX_URL_CHARS = 8 * 1024

    fun read(input: InputStream): PasswordCsvImportResult {
        val bytes = try {
            input.use { stream ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                var emptyReads = 0
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    if (count == 0) {
                        if (++emptyReads > 3) return PasswordCsvImportResult.Unreadable
                        continue
                    }
                    emptyReads = 0
                    if (count > MAX_FILE_BYTES - output.size()) {
                        return PasswordCsvImportResult.TooLarge
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } catch (_: Exception) {
            return PasswordCsvImportResult.Unreadable
        }
        val source = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            return PasswordCsvImportResult.InvalidUtf8
        }
        return parse(source)
    }

    fun parse(source: String): PasswordCsvImportResult {
        if (source.length > MAX_FILE_BYTES) return PasswordCsvImportResult.TooLarge
        val rows = readRows(source.removePrefix("\uFEFF"))
            ?: return PasswordCsvImportResult.InvalidFormat
        if (rows.isEmpty()) return PasswordCsvImportResult.InvalidFormat
        val headers = rows.first().map { column ->
            column.trim().lowercase(Locale.ROOT).filter(Char::isLetterOrDigit)
        }
        fun column(vararg aliases: String): Int = headers.indexOfFirst { it in aliases }
        val urlIndex = column("url", "origin", "website", "websiteurl", "loginuri", "loginurl")
        val userIndex = column("username", "user", "login", "email", "userid")
        val passwordIndex = column("password", "pass")
        if (urlIndex < 0 || userIndex < 0 || passwordIndex < 0) {
            return PasswordCsvImportResult.InvalidFormat
        }

        val imports = ArrayList<ImportedPassword>()
        val seen = HashSet<Pair<String, String>>()
        var skipped = 0
        for (row in rows.drop(1)) {
            val url = row.getOrNull(urlIndex)
            val username = row.getOrNull(userIndex)
            val password = row.getOrNull(passwordIndex)
            val origin = secureOrigin(url)
            val login = CredentialPromptRules.login(username, password)
            if (origin == null || login == null || !seen.add(origin to login.username)) {
                skipped++
                continue
            }
            imports += ImportedPassword(origin, login)
        }
        return PasswordCsvImportResult.Parsed(entries = imports, skippedRows = skipped)
    }

    private fun secureOrigin(value: String?): String? {
        val raw = value?.trim()?.takeIf { it.length <= MAX_URL_CHARS } ?: return null
        val uri = runCatching { URI(raw) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.isOpaque ||
            uri.rawUserInfo != null || uri.host == null || uri.port > 65535
        ) return null
        val host = runCatching {
            IDN.toASCII(uri.host.trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
                .lowercase(Locale.ROOT)
        }.getOrNull()?.takeIf { it.isNotEmpty() && it.length <= 255 } ?: return null
        val origin = runCatching {
            URI("https", null, host, uri.port, null, null, null).toASCIIString()
        }.getOrNull() ?: return null
        return origin.takeIf { CredentialPromptRules.matchesHttpsOrigin(raw, origin) }
    }

    /** RFC 4180-style double-quoted fields, escaped quotes and multiline cells. */
    private fun readRows(source: String): List<List<String>>? {
        val rows = ArrayList<List<String>>()
        var row = ArrayList<String>()
        val field = StringBuilder()
        var inQuotes = false
        var afterQuote = false
        var index = 0

        fun endField() {
            row.add(field.toString())
            field.setLength(0)
            afterQuote = false
        }

        fun endRow() {
            endField()
            if (row.any(String::isNotBlank)) rows.add(row)
            row = ArrayList()
        }

        while (index < source.length) {
            val ch = source[index]
            if (inQuotes) {
                when {
                    ch == '"' && index + 1 < source.length && source[index + 1] == '"' -> {
                        field.append('"')
                        index++
                    }
                    ch == '"' -> {
                        inQuotes = false
                        afterQuote = true
                    }
                    else -> field.append(ch)
                }
            } else if (afterQuote) {
                when (ch) {
                    ',' -> endField()
                    '\r', '\n' -> {
                        endRow()
                        if (ch == '\r' && index + 1 < source.length && source[index + 1] == '\n') index++
                    }
                    ' ', '\t' -> Unit
                    else -> return null
                }
            } else {
                when (ch) {
                    '"' -> if (field.isEmpty()) inQuotes = true else return null
                    ',' -> endField()
                    '\r', '\n' -> {
                        endRow()
                        if (ch == '\r' && index + 1 < source.length && source[index + 1] == '\n') index++
                    }
                    else -> field.append(ch)
                }
            }
            if (field.length > MAX_FIELD_CHARS || row.size > MAX_COLUMNS ||
                rows.size > MAX_RECORDS + 1
            ) return null
            index++
        }
        if (inQuotes) return null
        if (row.isNotEmpty() || field.isNotEmpty() || afterQuote) endRow()
        if (rows.size > MAX_RECORDS + 1 || rows.any { it.size > MAX_COLUMNS }) return null
        return rows
    }
}
