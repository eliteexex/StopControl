package com.example.cryptomsg.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoManagerTest {

    // 1. "Bonjour" -> chiffrement -> déchiffrement = "Bonjour"
    @Test
    fun `chiffrement puis dechiffrement restitue le message simple`() {
        val original = "Bonjour"
        val encrypted = CryptoManager.encrypt(original, "cle-secrete-test".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "cle-secrete-test".toCharArray())
        assertTrue(decrypted.isSuccess)
        assertEquals(original, decrypted.getOrNull())
    }

    // 2. Phrase contenant des accents
    @Test
    fun `message avec accents francais`() {
        val original = "Éàçüîôë – très élégant, n'est-ce pas ?"
        val encrypted = CryptoManager.encrypt(original, "clé-été-çà".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "clé-été-çà".toCharArray())
        assertEquals(original, decrypted.getOrNull())
    }

    // 3. Phrase contenant des emojis
    @Test
    fun `message avec emojis`() {
        val original = "Salut 👋 comment ça va 😄🔥🚀 ?"
        val encrypted = CryptoManager.encrypt(original, "emoji-key-123".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "emoji-key-123".toCharArray())
        assertEquals(original, decrypted.getOrNull())
    }

    // 4. Plusieurs lignes
    @Test
    fun `message multiligne`() {
        val original = "Ligne 1\nLigne 2\r\nLigne 3\n\nLigne finale"
        val encrypted = CryptoManager.encrypt(original, "multi-line-key".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "multi-line-key".toCharArray())
        assertEquals(original, decrypted.getOrNull())
    }

    // 5. Chaîne vide
    @Test
    fun `chaine vide`() {
        val original = ""
        val encrypted = CryptoManager.encrypt(original, "empty-string-key".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "empty-string-key".toCharArray())
        assertTrue(decrypted.isSuccess)
        assertEquals(original, decrypted.getOrNull())
    }

    // 6. Clé incorrecte
    @Test
    fun `cle incorrecte echoue proprement avec le bon message`() {
        val encrypted = CryptoManager.encrypt("Message secret", "bonne-cle".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "mauvaise-cle".toCharArray())
        assertTrue(decrypted.isFailure)
        assertEquals(
            "Impossible de déchiffrer : clé incorrecte ou message invalide.",
            decrypted.exceptionOrNull()?.message
        )
    }

    // 7. Message chiffré volontairement modifié
    @Test
    fun `message chiffre modifie est detecte`() {
        val encrypted = CryptoManager.encrypt("Message important", "integrity-key".toCharArray())
        val lastChar = encrypted.last()
        val replacement = if (lastChar.code == 0x2800) '\u2801' else '\u2800'
        val tampered = encrypted.dropLast(1) + replacement

        val decrypted = CryptoManager.decrypt(tampered, "integrity-key".toCharArray())
        assertTrue(decrypted.isFailure)
    }

    // 8. Deux chiffrements du même message avec la même clé -> résultats différents
    @Test
    fun `deux chiffrements du meme message sont differents mais se dechiffrent correctement`() {
        val message = "Message identique"
        val encrypted1 = CryptoManager.encrypt(message, "same-key-twice".toCharArray())
        val encrypted2 = CryptoManager.encrypt(message, "same-key-twice".toCharArray())

        assertNotEquals(encrypted1, encrypted2)
        assertEquals(message, CryptoManager.decrypt(encrypted1, "same-key-twice".toCharArray()).getOrNull())
        assertEquals(message, CryptoManager.decrypt(encrypted2, "same-key-twice".toCharArray()).getOrNull())
    }

    // 9. Message long
    @Test
    fun `message long`() {
        val original = "Ceci est une phrase répétée plusieurs fois pour simuler un message long. ".repeat(200)
        val encrypted = CryptoManager.encrypt(original, "long-message-key".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "long-message-key".toCharArray())
        assertEquals(original, decrypted.getOrNull())
    }

    // 10. Caractères Unicode variés
    @Test
    fun `caracteres unicode varies`() {
        val original = "日本語 中文 العربية русский ελληνικά ✓★♥☯ 𝔘𝔫𝔦𝔠𝔬𝔡𝔢"
        val encrypted = CryptoManager.encrypt(original, "unicode-key".toCharArray())
        val decrypted = CryptoManager.decrypt(encrypted, "unicode-key".toCharArray())
        assertEquals(original, decrypted.getOrNull())
    }

    // Vérification supplémentaire : un message trop court / mal formé est rejeté proprement
    @Test
    fun `message invalide non genere par l-application est rejete`() {
        val decrypted = CryptoManager.decrypt("abc", "peu-importe".toCharArray())
        assertTrue(decrypted.isFailure)
        assertEquals(
            "Impossible de déchiffrer : clé incorrecte ou message invalide.",
            decrypted.exceptionOrNull()?.message
        )
    }
}
