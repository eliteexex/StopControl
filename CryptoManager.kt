package com.example.cryptomsg.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Moteur de chiffrement/déchiffrement de messages entre deux personnes
 * partageant une même clé secrète (phrase de passe).
 *
 * Primitives utilisées (aucun algorithme "maison") :
 *  - Dérivation de clé : PBKDF2-HMAC-SHA256, sel aléatoire, 310 000 itérations
 *    (recommandation OWASP 2023 pour PBKDF2-HMAC-SHA256), clé dérivée 256 bits.
 *  - Chiffrement authentifié : AES-256-GCM, avec IV/nonce aléatoire de 96 bits
 *    (taille recommandée pour GCM) et tag d'authentification de 128 bits.
 *
 * Format binaire produit (avant encodage en alphabet personnalisé) :
 *
 *   [version:1] [itérations:4] [sel:16] [IV:12] [ciphertext + tag GCM]
 *
 * Le champ "itérations" est stocké dans le message afin de permettre une
 * évolution future des paramètres sans casser la compatibilité de lecture
 * des anciens messages. Le champ "version" permet de reconnaître les
 * messages produits par cette version de l'application et de rejeter
 * proprement tout ce qui ne correspond pas à un format connu.
 */
object CryptoManager {

    private const val FORMAT_VERSION: Byte = 1
    private const val SALT_LENGTH = 16          // octets
    private const val IV_LENGTH = 12             // octets (recommandé pour AES-GCM)
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val KEY_LENGTH_BITS = 256
    private const val DEFAULT_ITERATIONS = 310_000

    private const val HEADER_LENGTH = 1 + 4 + SALT_LENGTH + IV_LENGTH

    private val secureRandom = SecureRandom()

    class DecryptionException(message: String) : Exception(message)

    /**
     * Chiffre [plaintext] avec la clé dérivée de [passphrase].
     * [passphrase] est effacé (mis à zéro) avant le retour de la fonction.
     */
    fun encrypt(plaintext: String, passphrase: CharArray): String {
        require(passphrase.isNotEmpty()) { "La clé secrète ne peut pas être vide." }

        val salt = ByteArray(SALT_LENGTH).also { secureRandom.nextBytes(it) }
        val iv = ByteArray(IV_LENGTH).also { secureRandom.nextBytes(it) }
        var plaintextBytes: ByteArray? = null

        try {
            val key = deriveKey(passphrase, salt, DEFAULT_ITERATIONS)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))

            plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
            val ciphertext = cipher.doFinal(plaintextBytes)

            val payload = ByteArray(HEADER_LENGTH + ciphertext.size)
            var offset = 0
            payload[offset] = FORMAT_VERSION; offset += 1
            intToBytes(DEFAULT_ITERATIONS).copyInto(payload, offset); offset += 4
            salt.copyInto(payload, offset); offset += SALT_LENGTH
            iv.copyInto(payload, offset); offset += IV_LENGTH
            ciphertext.copyInto(payload, offset)

            val encoded = BrailleCodec.encode(payload)
            payload.fill(0)
            return encoded
        } finally {
            plaintextBytes?.fill(0)
            passphrase.fill('\u0000')
        }
    }

    /**
     * Tente de déchiffrer [cipherText] avec la clé dérivée de [passphrase].
     * [passphrase] est effacé (mis à zéro) avant le retour de la fonction.
     *
     * Ne renvoie jamais de résultat partiel : soit un succès avec le texte
     * clair intégral, soit un échec avec un message d'erreur générique.
     */
    fun decrypt(cipherText: String, passphrase: CharArray): Result<String> {
        try {
            require(passphrase.isNotEmpty()) { "La clé secrète ne peut pas être vide." }

            if (cipherText.isEmpty()) {
                return Result.failure(invalidMessage())
            }

            val payload = try {
                BrailleCodec.decode(cipherText)
            } catch (e: Exception) {
                return Result.failure(invalidMessage())
            }

            if (payload.size < HEADER_LENGTH) {
                return Result.failure(invalidMessage())
            }

            var offset = 0
            val version = payload[offset]; offset += 1
            if (version != FORMAT_VERSION) {
                return Result.failure(invalidMessage())
            }

            val iterations = bytesToInt(payload.copyOfRange(offset, offset + 4)); offset += 4
            if (iterations <= 0) {
                return Result.failure(invalidMessage())
            }

            val salt = payload.copyOfRange(offset, offset + SALT_LENGTH); offset += SALT_LENGTH
            val iv = payload.copyOfRange(offset, offset + IV_LENGTH); offset += IV_LENGTH
            val ciphertext = payload.copyOfRange(offset, payload.size)
            payload.fill(0)

            return try {
                val key = deriveKey(passphrase, salt, iterations)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
                val plainBytes = cipher.doFinal(ciphertext)
                val text = plainBytes.toString(Charsets.UTF_8)
                plainBytes.fill(0)
                Result.success(text)
            } catch (e: Exception) {
                // Inclut notamment javax.crypto.AEADBadTagException, levée par GCM
                // quand la clé est incorrecte OU que le message a été modifié :
                // volontairement, on ne distingue pas les deux cas.
                Result.failure(invalidMessage())
            }
        } catch (e: Exception) {
            return Result.failure(invalidMessage())
        } finally {
            passphrase.fill('\u0000')
        }
    }

    /** Génère une phrase secrète aléatoire forte à l'aide de SecureRandom. */
    fun generateRandomPassphrase(length: Int = 24): String {
        val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+"
        val sb = StringBuilder(length)
        repeat(length) {
            sb.append(alphabet[secureRandom.nextInt(alphabet.length)])
        }
        return sb.toString()
    }

    private fun invalidMessage() =
        DecryptionException("Impossible de déchiffrer : clé incorrecte ou message invalide.")

    private fun deriveKey(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(passphrase, salt, iterations, KEY_LENGTH_BITS)
        try {
            val secretKey = factory.generateSecret(spec)
            val keyBytes = secretKey.encoded
            val keySpec = SecretKeySpec(keyBytes, "AES")
            keyBytes.fill(0)
            return keySpec
        } finally {
            spec.clearPassword()
        }
    }

    private fun intToBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun bytesToInt(bytes: ByteArray): Int =
        ((bytes[0].toInt() and 0xFF) shl 24) or
        ((bytes[1].toInt() and 0xFF) shl 16) or
        ((bytes[2].toInt() and 0xFF) shl 8) or
        (bytes[3].toInt() and 0xFF)
}
