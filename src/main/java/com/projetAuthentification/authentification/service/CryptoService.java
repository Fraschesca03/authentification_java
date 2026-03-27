package com.projetAuthentification.authentification.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * CryptoService — AES-256-GCM
 *   GCM : même texte = chiffré différent à chaque fois (sécurisé)
 * Seules encrypt() et decrypt() changent.
 * computeHmac() et compareHmacConstantTime() restent identiques.
 */
@Service
public class CryptoService {

    @Value("${app.master-key}")
    private String masterKey;

    // 12 octets = taille pour l'IV en GCM
    private static final int IV_SIZE  = 12;

    // 128 bits = taille maximale du Tag GCM (le plus sécurisé)
    private static final int TAG_SIZE = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    // Chiffrement AES-GCM
    /**
     * Chiffre un texte avec AES-256-GCM.
     *
     * Différences avec ECB :
     *   - Génère un IV aléatoire à chaque appel → même texte = résultat différent
     *   - cipher.init() reçoit un GCMParameterSpec en plus (contient l'IV)
     *   - Le résultat = IV (12 octets) + données chiffrées + Tag (16 octets)
     *   - On stocke IV + données ensemble car on a besoin de l'IV pour déchiffrer
     */
    public String encrypt(String plainText) throws Exception {
        // Générer IV aléatoire
        byte[] iv = new byte[IV_SIZE];
        SECURE_RANDOM.nextBytes(iv);

        // Chiffrer
        SecretKeySpec key = buildKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        byte[] ciphertext = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Format imposé : v1:Base64(iv):Base64(ciphertext)
        return "v1:" + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
        // → "v1:k5dZya0y6qo=:xK9mP2qR7vL4nS8oT3..."
    }

    // Déchiffrement AES-GCM
    /**
     * Déchiffre un texte chiffré avec AES-256-GCM.
     *
     * Opération inverse exacte de encrypt() :
     *   1. Base64 decode → combined
     *   2. Extraire IV (12 premiers octets)
     *   3. Extraire données (le reste)
     *   4. Déchiffrer avec le même IV
     *
     * Protection bonus GCM : si les données ont été modifiées en base,
     * Java lance AEADBadTagException automatiquement.
     * ECB n'a pas cette protection — il déchiffre silencieusement des données corrompues.
     */
    public String decrypt(String encryptedText) throws Exception {
        // Découper les 3 parties séparées par ":"
        // "v1:k5dZya0y6qo=:xK9mP2..." → ["v1", "k5dZya0y6qo=", "xK9mP2..."]
        String[] parts = encryptedText.split(":");
        if (parts.length != 3 || !parts[0].equals("v1")) {
            throw new IllegalArgumentException("Format de chiffrement invalide");
        }

        // Décoder IV et ciphertext depuis Base64
        byte[] iv         = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        // Déchiffrer
        SecretKeySpec key = buildKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        byte[] decrypted = cipher.doFinal(ciphertext);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // Ces deux méthodes ne changent pas entre ECB et GCM
    /**
     * Calcule le HMAC-SHA256 — inchangé par rapport à ECB.
     */
    public String computeHmac(String secret, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /**
     * Comparaison en temps constant — inchangée par rapport à ECB.
     */
    public boolean compareHmacConstantTime(String hmac1, String hmac2) {
        return MessageDigest.isEqual(
                hmac1.getBytes(StandardCharsets.UTF_8),
                hmac2.getBytes(StandardCharsets.UTF_8)
        );
    }

    // Méthode privée
    /**
     * Construit une clé AES-256 de 32 octets depuis la SMK.
     */
    private SecretKeySpec buildKey() {
        byte[] keyBytes = Arrays.copyOf(
                masterKey.getBytes(StandardCharsets.UTF_8), 32);
        return new SecretKeySpec(keyBytes, "AES");
    }
}