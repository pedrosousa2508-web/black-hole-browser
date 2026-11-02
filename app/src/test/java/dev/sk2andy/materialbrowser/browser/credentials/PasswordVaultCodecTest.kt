package dev.sk2andy.materialbrowser.browser.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordVaultCodecTest {
    @Test
    fun codecRoundTripsQuotedAndMultilineSecrets() {
        val records = listOf(
            ImportedPassword(
                "https://example.com",
                requireNotNull(CredentialPromptRules.login("alice", "one,\ntwo\"three")),
            ),
        )
        val bytes = PasswordVaultCodec.encode(records)
        val decoded = requireNotNull(PasswordVaultCodec.decode(bytes))
        assertEquals("https://example.com", decoded.single().origin)
        assertEquals("alice", decoded.single().login.username)
        assertEquals("one,\ntwo\"three", decoded.single().login.password)
        assertFalse(decoded.single().toString().contains("one,"))
        assertFalse(decoded.single().login.toString().contains("one,"))
    }

    @Test
    fun codecRefusesCorruptedOrTrailingBytes() {
        val record = ImportedPassword(
            "https://example.com",
            requireNotNull(CredentialPromptRules.login("alice", "test-password")),
        )
        val bytes = PasswordVaultCodec.encode(listOf(record))
        assertNull(PasswordVaultCodec.decode(byteArrayOf(1, 2, 3)))
        assertNull(PasswordVaultCodec.decode(bytes + byteArrayOf(1)))
        assertNull(PasswordVaultCodec.decode(bytes.copyOf(bytes.size - 1)))
        assertTrue(PasswordVaultCodec.decode(bytes) != null)
    }

    @Test
    fun codecRejectsDuplicateCredentials() {
        val item = ImportedPassword(
            "https://example.com",
            requireNotNull(CredentialPromptRules.login("alice", "secret")),
        )
        val bytes = PasswordVaultCodec.encode(listOf(item, item))
        assertNull(PasswordVaultCodec.decode(bytes))
    }
}
