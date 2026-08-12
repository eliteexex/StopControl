package com.example.cryptomsg.crypto

/**
 * Encode/décode des octets bruts vers/depuis un alphabet Unicode "personnalisé"
 * composé de caractères spéciaux, afin que le texte chiffré ait l'apparence
 * d'un texte incompréhensible (ex : "⠓⠛⠭⠶⠩...").
 *
 * Choix technique : le bloc Unicode "Braille Patterns" (U+2800 à U+28FF)
 * contient exactement 256 points de code, tous assignés dans la norme
 * Unicode, aucun n'étant un caractère de contrôle, d'espacement ou de
 * substitution (surrogate). Cela permet un mapping direct et bijectif
 * 1 octet <-> 1 caractère, garantissant un encodage/décodage strictement
 * réversible, sans aucune perte ni ambiguïté, quel que soit le contenu
 * binaire (y compris des octets nuls).
 *
 * Ce codec n'apporte AUCUNE sécurité par lui-même : il s'applique après
 * un chiffrement authentifié (voir CryptoManager) et sert uniquement à
 * l'habillage visuel du résultat.
 */
object BrailleCodec {

    private const val BASE = 0x2800 // U+2800 = premier caractère du bloc Braille Patterns

    fun encode(data: ByteArray): String {
        val builder = StringBuilder(data.size)
        for (byte in data) {
            val unsignedValue = byte.toInt() and 0xFF
            builder.append((BASE + unsignedValue).toChar())
        }
        return builder.toString()
    }

    /**
     * @throws IllegalArgumentException si la chaîne contient un caractère
     * en dehors de l'alphabet attendu (message invalide ou corrompu).
     */
    fun decode(text: String): ByteArray {
        // On tolère les espaces/retours à la ligne qu'une messagerie pourrait
        // ajouter lors du copier-coller (aucun caractère du bloc Braille
        // Patterns n'est lui-même considéré comme un espace par Unicode,
        // donc ce filtrage ne peut pas supprimer de données valides).
        val cleaned = text.filterNot { it.isWhitespace() }

        val bytes = ByteArray(cleaned.length)
        for (index in cleaned.indices) {
            val codePoint = cleaned[index].code
            val value = codePoint - BASE
            if (value < 0 || value > 255) {
                throw IllegalArgumentException("Caractère hors de l'alphabet attendu.")
            }
            bytes[index] = value.toByte()
        }
        return bytes
    }
}
