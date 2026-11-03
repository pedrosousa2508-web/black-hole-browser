package dev.sk2andy.materialbrowser.browser.credentials

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** App-private encrypted storage, excluded from Android backup and device transfer. */
/** Account metadata only; its string form never exposes the site or username. */
internal class VaultAccount(val origin: String, val username: String) {
    override fun toString(): String = "VaultAccount(<redacted>)"
}

internal class BlackHolePasswordVault(context: Context) {
    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, "black_hole_passwords_v1.enc"))

    internal sealed interface ImportResult {
        data class Saved(val added: Int, val duplicates: Int, val total: Int) : ImportResult
        data object LimitReached : ImportResult
        data object StorageError : ImportResult
    }

    /**
     * Imports only explicit user-approved rows. Existing (origin, username) pairs are NEVER
     * replaced by CSV, and read/decrypt errors NEVER overwrite the existing encrypted vault.
     */
    fun importApproved(rows: List<ImportedPassword>): ImportResult = synchronized(STORAGE_LOCK) {
        if (rows.isEmpty()) return ImportResult.Saved(0, 0, 0)
        return try {
            val existing = load() ?: return ImportResult.StorageError
            val known = existing.mapTo(HashSet()) { it.origin to it.login.username }
            val additions = ArrayList<ImportedPassword>()
            var duplicates = 0
            for (entry in rows) {
                if (!CredentialPromptRules.matchesHttpsOrigin(entry.origin, entry.origin) ||
                    CredentialPromptRules.login(entry.login.username, entry.login.password) == null
                ) return ImportResult.StorageError
                if (!known.add(entry.origin to entry.login.username)) {
                    duplicates++
                } else {
                    additions += entry
                }
            }
            if (existing.size + additions.size > PasswordVaultCodec.MAX_ENTRIES) {
                return ImportResult.LimitReached
            }
            if (additions.isNotEmpty()) save(existing + additions)
            ImportResult.Saved(additions.size, duplicates, existing.size + additions.size)
        } catch (_: Exception) {
            // No logs here: CSV contents and crypto/IO exceptions may contain sensitive data.
            ImportResult.StorageError
        }
    }

    /** This API must be called only after a fresh Android BiometricPrompt authorization. */
    fun listAccounts(): List<VaultAccount>? = synchronized(STORAGE_LOCK) {
        try {
            load()?.map { VaultAccount(it.origin, it.login.username) }
        } catch (_: Exception) {
            null
        }
    }

    /** A separate fresh authorization is required before the UI invokes this method. */
    fun revealPassword(account: VaultAccount): String? = synchronized(STORAGE_LOCK) {
        try {
            load()?.firstOrNull {
                it.origin == account.origin && it.login.username == account.username
            }?.login?.password
        } catch (_: Exception) {
            null
        }
    }

    internal sealed interface DeleteResult {
        data object Deleted : DeleteResult
        data object NotFound : DeleteResult
        data object StorageError : DeleteResult
    }

    /** Only called after a separate biometric/lock-screen prompt and explicit confirmation. */
    fun deleteAccount(account: VaultAccount): DeleteResult = synchronized(STORAGE_LOCK) {
        try {
            val existing = load() ?: return@synchronized DeleteResult.StorageError
            val remaining = existing.filterNot {
                it.origin == account.origin && it.login.username == account.username
            }
            if (remaining.size == existing.size) return@synchronized DeleteResult.NotFound
            save(remaining)
            DeleteResult.Deleted
        } catch (_: Exception) {
            DeleteResult.StorageError
        }
    }

    /** Atomic replacement; callers already own STORAGE_LOCK. */
    private fun save(records: List<ImportedPassword>) {
        val plaintext = PasswordVaultCodec.encode(records)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            require(iv.size == 12)
            val envelope = HEADER + iv + ciphertext
            val output = file.startWrite()
            try {
                output.write(envelope)
                file.finishWrite(output)
            } catch (error: Exception) {
                file.failWrite(output)
                throw error
            }
        } finally {
            plaintext.fill(0)
        }
    }

    /** Null means unreadable/corrupt ciphertext. Never interpret it as an empty vault. */
    private fun load(): List<ImportedPassword>? {
        // AtomicFile may keep the previous valid vault as .bak during an interrupted write.
        // Never overwrite it by assuming an absent base file means an empty vault.
        val base = file.baseFile
        if (!base.exists() &&
            !File(base.path + ".bak").exists() &&
            !File(base.path + ".new").exists()
        ) return emptyList()
        val encrypted = file.openRead().use { input ->
            val bytes = input.readBytes()
            require(bytes.size in (HEADER.size + 12 + 16)..PasswordVaultCodec.MAX_PLAINTEXT_BYTES)
            bytes
        }
        require(encrypted.copyOfRange(0, HEADER.size).contentEquals(HEADER))
        val iv = encrypted.copyOfRange(HEADER.size, HEADER.size + 12)
        val ciphertext = encrypted.copyOfRange(HEADER.size + 12, encrypted.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        val plaintext = cipher.doFinal(ciphertext)
        return try {
            PasswordVaultCodec.decode(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        val HEADER = byteArrayOf(0x42, 0x48, 0x50, 0x57, 0x01) // BHPW + version 1
        const val KEY_ALIAS = "black_hole_password_vault_v1"
        val STORAGE_LOCK = Any()
    }
}
