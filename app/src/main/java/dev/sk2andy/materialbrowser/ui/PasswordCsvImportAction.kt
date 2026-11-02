package dev.sk2andy.materialbrowser.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.unit.dp
import dev.sk2andy.materialbrowser.R
import dev.sk2andy.materialbrowser.browser.credentials.BlackHolePasswordVault
import dev.sk2andy.materialbrowser.browser.credentials.PasswordCsvImportResult
import dev.sk2andy.materialbrowser.browser.credentials.PasswordCsvImportRules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Files are selected by the system SAF picker; no blanket storage permissions are needed. */
@Composable
internal fun PasswordCsvImportAction() {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    var processing by remember { mutableStateOf(false) }
    var pending by remember { mutableStateOf<PasswordCsvImportResult.Parsed?>(null) }
    var feedbackId by remember { mutableIntStateOf(0) }
    var savedCount by remember { mutableIntStateOf(0) }
    var skippedCount by remember { mutableIntStateOf(0) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !processing) {
            processing = true
            feedbackId = 0
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    try {
                        val stream = context.contentResolver.openInputStream(uri)
                            ?: return@withContext PasswordCsvImportResult.Unreadable
                        PasswordCsvImportRules.read(stream)
                    } catch (_: Exception) {
                        PasswordCsvImportResult.Unreadable
                    }
                }
                when (result) {
                    is PasswordCsvImportResult.Parsed -> {
                        if (result.entries.isEmpty()) feedbackId = R.string.password_csv_no_valid
                        else pending = result
                    }
                    PasswordCsvImportResult.InvalidFormat ->
                        feedbackId = R.string.password_csv_invalid_format
                    PasswordCsvImportResult.InvalidUtf8 ->
                        feedbackId = R.string.password_csv_invalid_utf8
                    PasswordCsvImportResult.TooLarge ->
                        feedbackId = R.string.password_csv_too_large
                    PasswordCsvImportResult.Unreadable ->
                        feedbackId = R.string.password_csv_unreadable
                }
                processing = false
            }
        }
    }

    Surface(
        onClick = {
            if (!processing && pending == null) {
                picker.launch(arrayOf("text/*", "application/csv", "application/octet-stream"))
            }
        },
        modifier = Modifier.fillMaxWidth()
            .testTag("black_hole_import_password_csv")
            .sizeIn(minHeight = 48.dp),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) {
            Text(
                stringResource(R.string.password_csv_action),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                stringResource(
                    if (processing) R.string.password_csv_processing
                    else R.string.password_csv_summary,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    if (feedbackId != 0) {
        Text(
            stringResource(feedbackId),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
    }
    if (savedCount > 0 || skippedCount > 0) {
        Text(
            stringResource(R.string.password_csv_import_result, savedCount, skippedCount),
            style = MaterialTheme.typography.bodySmall,
        )
    }
    val preview = pending
    if (preview != null) {
        AlertDialog(
            onDismissRequest = { if (!processing) pending = null },
            title = { Text(stringResource(R.string.password_csv_confirm_title)) },
            text = {
                Text(
                    stringResource(
                        R.string.password_csv_confirm_summary,
                        preview.entries.size,
                        preview.skippedRows,
                    ),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (!processing) {
                            processing = true
                            scope.launch {
                                val outcome = withContext(Dispatchers.IO) {
                                    BlackHolePasswordVault(context).importApproved(preview.entries)
                                }
                                when (outcome) {
                                    is BlackHolePasswordVault.ImportResult.Saved -> {
                                        savedCount = outcome.added
                                        skippedCount = outcome.duplicates + preview.skippedRows
                                        feedbackId = R.string.password_csv_imported_notice
                                    }
                                    BlackHolePasswordVault.ImportResult.LimitReached ->
                                        feedbackId = R.string.password_csv_limit
                                    BlackHolePasswordVault.ImportResult.StorageError ->
                                        feedbackId = R.string.password_csv_storage_error
                                }
                                pending = null
                                processing = false
                            }
                        }
                    },
                    enabled = !processing,
                ) { Text(stringResource(R.string.password_csv_import_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { pending = null }, enabled = !processing) {
                    Text(stringResource(R.string.password_csv_cancel))
                }
            },
        )
    }
}
