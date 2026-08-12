package com.example.cryptomsg

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.cryptomsg.crypto.CryptoManager
import com.example.cryptomsg.ui.theme.CryptoMsgTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CryptoMsgTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    CryptoScreen()
                }
            }
        }
    }
}

@Composable
fun CryptoScreen() {
    val clipboardManager = LocalClipboardManager.current

    var message by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var keyVisible by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    fun clearError() {
        errorMessage = null
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = "CryptoMsg",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 4.dp)
        )
        Text(
            text = "Chiffrement AES-256-GCM local, aucune connexion internet requise.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            modifier = Modifier.padding(bottom = 16.dp)
        )

        OutlinedTextField(
            value = message,
            onValueChange = {
                message = it
                clearError()
            },
            label = { Text("Message") },
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 120.dp),
            minLines = 4,
            maxLines = 8
        )

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = secretKey,
            onValueChange = {
                secretKey = it
                clearError()
            },
            label = { Text("Clé secrète") },
            singleLine = true,
            visualTransformation = if (keyVisible) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { keyVisible = !keyVisible }) {
                    Icon(
                        imageVector = if (keyVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (keyVisible) "Masquer la clé" else "Afficher la clé"
                    )
                }
            },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(8.dp))

        TextButton(onClick = {
            secretKey = CryptoManager.generateRandomPassphrase()
            keyVisible = true
            clearError()
        }) {
            Text("Générer une clé aléatoire")
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = {
                    clearError()
                    if (secretKey.isEmpty()) {
                        errorMessage = "Veuillez saisir une clé secrète."
                        return@Button
                    }
                    try {
                        result = CryptoManager.encrypt(message, secretKey.toCharArray())
                    } catch (e: Exception) {
                        errorMessage = "Erreur de chiffrement : ${e.message ?: "inconnue"}"
                    }
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Chiffrer")
            }

            Button(
                onClick = {
                    clearError()
                    if (secretKey.isEmpty()) {
                        errorMessage = "Veuillez saisir une clé secrète."
                        return@Button
                    }
                    val decryptResult = CryptoManager.decrypt(message, secretKey.toCharArray())
                    decryptResult.fold(
                        onSuccess = { result = it },
                        onFailure = {
                            result = ""
                            errorMessage = it.message
                                ?: "Impossible de déchiffrer : clé incorrecte ou message invalide."
                        }
                    )
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Déchiffrer")
            }
        }

        errorMessage?.let {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        Text(text = "Résultat", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(6.dp))

        OutlinedTextField(
            value = result,
            onValueChange = { /* lecture seule */ },
            readOnly = true,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 120.dp),
            minLines = 4,
            maxLines = 8
        )

        Spacer(modifier = Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = { clipboardManager.setText(AnnotatedString(result)) },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Copier")
            }

            OutlinedButton(
                onClick = {
                    val pasted = clipboardManager.getText()?.text ?: ""
                    message = pasted
                    clearError()
                },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Coller")
            }

            OutlinedButton(
                onClick = {
                    message = ""
                    secretKey = ""
                    result = ""
                    errorMessage = null
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Effacer")
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}
