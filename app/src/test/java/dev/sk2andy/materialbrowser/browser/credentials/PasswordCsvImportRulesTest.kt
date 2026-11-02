package dev.sk2andy.materialbrowser.browser.credentials

import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordCsvImportRulesTest {
    @Test
    fun chromeCsvAcceptsQuotedCommasAndBom() {
        val csv = "\uFEFFname,url,username,password,note\r\n" +
            "Example,https://example.com/login,alice,\"pass,word\",test\r\n"
        val result = PasswordCsvImportRules.parse(csv) as PasswordCsvImportResult.Parsed
        assertEquals(1, result.entries.size)
        assertEquals("https://example.com", result.entries.single().origin)
        assertEquals("alice", result.entries.single().login.username)
        assertEquals("pass,word", result.entries.single().login.password)
    }

    @Test
    fun firefoxCsvSupportsEscapedQuotesAndMultilinePasswords() {
        val csv = buildString {
            append("url,username,password,httpRealm")
            append('\n')
            append("https://example.org/path,bob,")
            append('"')
            append("line1")
            append('\n')
            append("line2 with ")
            append('"')
            append('"')
            append("quote")
            append('"')
            append('"')
            append('"')
            append(',')
        }
        val result = PasswordCsvImportRules.parse(csv) as PasswordCsvImportResult.Parsed
        assertEquals(1, result.entries.size)
        assertEquals("line1\nline2 with \"quote\"", result.entries.single().login.password)
    }

    @Test
    fun rejectsInsecureUrlsUserInfoDuplicatesAndEmptyPasswords() {
        val csv = """
            url,username,password
            https://good.example/login,alice,valid
            https://good.example/other,alice,duplicate
            http://plain.example/,alice,insecure
            https://user:pw@phishing.example/,alice,unsafe
            javascript:alert(1),alice,unsafe
            https://another.example/,bob,
        """.trimIndent()
        val result = PasswordCsvImportRules.parse(csv) as PasswordCsvImportResult.Parsed
        assertEquals(1, result.entries.size)
        assertEquals(5, result.skippedRows)
        assertEquals("https://good.example", result.entries.single().origin)
    }

    @Test
    fun rejectsMissingHeadersAndMalformedQuotes() {
        assertEquals(
            PasswordCsvImportResult.InvalidFormat,
            PasswordCsvImportRules.parse("name,url,password\nx,https://example.com,pw"),
        )
        assertEquals(
            PasswordCsvImportResult.InvalidFormat,
            PasswordCsvImportRules.parse("url,username,password\nhttps://example.com,bob,\"unterminated"),
        )
    }

    @Test
    fun refusesOversizedAndNonUtf8Files() {
        val tooBig = ByteArray(PasswordCsvImportRules.MAX_FILE_BYTES + 1) { 'a'.code.toByte() }
        assertEquals(
            PasswordCsvImportResult.TooLarge,
            PasswordCsvImportRules.read(ByteArrayInputStream(tooBig)),
        )
        assertEquals(
            PasswordCsvImportResult.InvalidUtf8,
            PasswordCsvImportRules.read(ByteArrayInputStream(byteArrayOf(0xC3.toByte(), 0x28))),
        )
    }

    @Test
    fun credentialStringRepresentationsNeverRevealSecrets() {
        val result = PasswordCsvImportRules.parse(
            "url,username,password\nhttps://example.com,private-user,super-secret",
        ) as PasswordCsvImportResult.Parsed
        val entry = result.entries.single()
        assertFalse(entry.toString().contains("super-secret"))
        assertFalse(entry.toString().contains("private-user"))
        assertFalse(entry.login.toString().contains("super-secret"))
        assertTrue(entry.origin.startsWith("https://"))
    }
}
