package dev.sk2andy.materialbrowser.ui

import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import dev.sk2andy.materialbrowser.R
import dev.sk2andy.materialbrowser.browser.credentials.BlackHolePasswordVault
import dev.sk2andy.materialbrowser.browser.credentials.VaultAccount
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Experimental local-only vault manager. The AES key is not biometric-bound; Android
 * authentication is a mandatory UI gate for each read/reveal/delete interaction.
 * No system Autofill credential provider is registered by this screen.
 */
@Composable
internal fun PasswordVaultManagerAction() {
    val context = LocalContext.current
    val activity = remember(context) { findVaultActivity(context) }
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var unlocked by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    var accounts by remember { mutableStateOf<List<VaultAccount>>(emptyList()) }
    var selected by remember { mutableStateOf<VaultAccount?>(null) }
    var password by remember { mutableStateOf<String?>(null) }
    var deleteConfirmation by remember { mutableStateOf(false) }
    var errorText by remember { mutableIntStateOf(0) }
    var token by remember { mutableIntStateOf(0) }

    fun lock() {
        token++
        password = null
        accounts = emptyList()
        selected = null
        unlocked = false
        deleteConfirmation = false
        open = false
        working = false
    }

    fun authenticate(action: () -> Unit) {
        val target = activity
        if (target == null || !canAuthenticateVault(target)) {
            errorText = R.string.bh_vault_auth_unavailable
            return
        }
        val requestToken = ++token
        errorText = 0
        authenticateVault(target) { success ->
            if (requestToken != token || !open) return@authenticateVault
            if (!target.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                lock()
                return@authenticateVault
            }
            if (success) action() else errorText = R.string.bh_vault_auth_failed
        }
    }

    DisposableEffect(activity, open) {
        if (activity == null || !open) {
            onDispose { }
        } else {
            val wasSecure = activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP || event == Lifecycle.Event.ON_DESTROY) lock()
            }
            activity.lifecycle.addObserver(observer)
            onDispose {
                activity.lifecycle.removeObserver(observer)
                if (!wasSecure) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }

    Surface(
        onClick = {
            if (!working) {
                open = true
                unlocked = false
                password = null
                selected = null
                accounts = emptyList()
                authenticate {
                    working = true
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            BlackHolePasswordVault(context).listAccounts()
                        }
                        if (open) {
                            if (result != null) {
                                accounts = result
                                unlocked = true
                            } else errorText = R.string.bh_vault_error
                        }
                        working = false
                    }
                }
            }
        },
        modifier = Modifier.fillMaxWidth()
            .testTag("black_hole_manage_passwords")
            .sizeIn(minHeight = 48.dp),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) {
            Text(stringResource(R.string.bh_vault_manage), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(R.string.bh_vault_manage_desc),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    if (open) {
        AlertDialog(
            onDismissRequest = { if (!working) lock() },
            title = { Text(stringResource(R.string.bh_vault_title)) },
            text = {
                Column {
                    if (errorText != 0) {
                        Text(stringResource(errorText), color = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.height(8.dp))
                    }
                    when {
                        !unlocked -> Text(stringResource(R.string.bh_vault_unlocking))
                        accounts.isEmpty() -> Text(stringResource(R.string.bh_vault_empty))
                        else -> {
                            LazyColumn(Modifier.heightIn(max = 300.dp)) {
                                items(accounts, key = { it.origin + "\u0000" + it.username }) { item ->
                                    Surface(
                                        modifier = Modifier.fillMaxWidth()
                                            .clickable {
                                                selected = item
                                                password = null
                                                errorText = 0
                                            },
                                        color = if (item === selected) {
                                            MaterialTheme.colorScheme.primaryContainer
                                        } else MaterialTheme.colorScheme.surfaceContainerLow,
                                    ) {
                                        Column(Modifier.padding(10.dp)) {
                                            Text(item.origin, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                            Text(
                                                item.username,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis,
                                            )
                                        }
                                    }
                                    Spacer(Modifier.height(4.dp))
                                }
                            }
                        }
                    }
                    val account = selected
                    if (unlocked && account != null) {
                        Spacer(Modifier.height(12.dp))
                        if (password != null) {
                            Text(password.orEmpty(), style = MaterialTheme.typography.bodyMedium)
                        }
                        TextButton(
                            enabled = !working,
                            onClick = {
                                if (password != null) password = null
                                else authenticate {
                                    working = true
                                    scope.launch {
                                        val result = withContext(Dispatchers.IO) {
                                            BlackHolePasswordVault(context).revealPassword(account)
                                        }
                                        if (open && selected === account) {
                                            if (result != null) password = result
                                            else errorText = R.string.bh_vault_reveal_failed
                                        }
                                        working = false
                                    }
                                }
                            },
                        ) {
                            Text(stringResource(if (password == null) R.string.bh_vault_reveal else R.string.bh_vault_hide))
                        }
                        TextButton(enabled = !working, onClick = {
                            password = null
                            deleteConfirmation = true
                        }) { Text(stringResource(R.string.bh_vault_delete)) }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { lock() }) {
                    Text(stringResource(R.string.bh_vault_close))
                }
            },
        )
    }

    if (open && deleteConfirmation && selected != null) {
        val account = selected!!
        AlertDialog(
            onDismissRequest = { deleteConfirmation = false },
            title = { Text(stringResource(R.string.bh_vault_delete_title)) },
            text = { Text(stringResource(R.string.bh_vault_delete_body)) },
            confirmButton = {
                TextButton(enabled = !working, onClick = {
                    deleteConfirmation = false
                    authenticate {
                        working = true
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                val vault = BlackHolePasswordVault(context)
                                val deleted = vault.deleteAccount(account)
                                val updated = if (deleted == BlackHolePasswordVault.DeleteResult.Deleted) {
                                    vault.listAccounts()
                                } else null
                                deleted to updated
                            }
                            if (open) {
                                if (result.first == BlackHolePasswordVault.DeleteResult.Deleted &&
                                    result.second != null
                                ) {
                                    accounts = result.second!!
                                    selected = null
                                    password = null
                                    errorText = R.string.bh_vault_delete_success
                                } else errorText = R.string.bh_vault_delete_failed
                            }
                            working = false
                        }
                    }
                }) { Text(stringResource(R.string.bh_vault_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmation = false }) {
                    Text(stringResource(R.string.bh_vault_cancel))
                }
            },
        )
    }
}

private tailrec fun findVaultActivity(context: Context): AppCompatActivity? = when (context) {
    is AppCompatActivity -> context
    is ContextWrapper -> {
        val base = context.baseContext
        if (base === context) null else findVaultActivity(base)
    }
    else -> null
}

private const val VAULT_AUTHENTICATORS =
    BiometricManager.Authenticators.BIOMETRIC_STRONG or
    BiometricManager.Authenticators.DEVICE_CREDENTIAL

private fun canAuthenticateVault(activity: AppCompatActivity): Boolean =
    BiometricManager.from(activity).canAuthenticate(VAULT_AUTHENTICATORS) ==
        BiometricManager.BIOMETRIC_SUCCESS

private fun authenticateVault(activity: AppCompatActivity, onResult: (Boolean) -> Unit) {
    val prompt = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onResult(true)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onResult(false)
            }
        },
    )
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.bh_vault_auth_title))
            .setSubtitle(activity.getString(R.string.bh_vault_auth_subtitle))
            .setAllowedAuthenticators(VAULT_AUTHENTICATORS)
            .build(),
    )
}
