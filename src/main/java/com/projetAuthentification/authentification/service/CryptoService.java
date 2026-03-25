package com.projetAuthentification.authentification.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * <h2>CryptoService</h2>
 *
 * Service responsable de toutes les opérations cryptographiques du TP3 :
 * <ul>
 *   <li>Chiffrement AES du mot de passe (pour le stocker en base)</li>
 *   <li>Déchiffrement AES du mot de passe (pour recalculer le HMAC)</li>
 *   <li>Calcul du HMAC-SHA256 (signature du message)</li>
 *   <li>Comparaison en temps constant (anti timing-attack)</li>
 * </ul>
 *
 * <h3>Pourquoi un service dédié ?</h3>
 * Regrouper toute la cryptographie dans un seul endroit permet de :
 * - Tester facilement chaque opération isolément
 * - Remplacer l'algorithme sans toucher au reste du code
 * - Avoir une seule source de vérité pour les paramètres crypto
 *
 * <h3>Limite pédagogique importante :</h3>
 * Ce service utilise AES en mode ECB (Electronic Code Book).
 * ECB est simple mais imparfait : deux mots de passe identiques
 * produiront le même chiffré. En production on utiliserait AES-GCM
 * avec un IV (vecteur d'initialisation) aléatoire par chiffrement.
 */
@Service
public class CryptoService {


    @Value("${app.smk}")
    private String smk;
    /**
     * La Server Master Key lue depuis application.properties.
     *
     * @Value("${app.smk}") dit à Spring :
     * "injecte la valeur de app.smk dans la variable smk au démarrage"

    // Chiffrement AES
    /**
     * Chiffre un texte en clair avec AES-256 et la SMK.
     * Utilisé dans AuthService.register() pour chiffrer le mot de passe
     * avant de le stocker en base de données.
     * Étapes internes :
     *   1. Convertit la SMK en clé AES de 32 octets (Arrays.copyOf)
     *   2. Initialise le cipher AES en mode ENCRYPT
     *   3. Chiffre les octets du texte
     *   4. Encode le résultat en Base64 pour pouvoir le stocker en String
     *
     * @param plainText le mot de passe en clair
     * @return le mot de passe chiffré, encodé en Base64
     * @throws Exception si la clé est invalide ou l'algorithme indisponible
     */

    public String encrypt(String plainText) throws Exception {
        // buildKey() transforme la SMK (String) en objet SecretKeySpec (32 octets)
        SecretKeySpec key = buildKey();

        // Cipher est la classe Java qui fait le chiffrement
        // "AES/ECB/PKCS5Padding" = algorithme AES, mode ECB, rembourrage PKCS5
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        // ENCRYPT_MODE : chiffrer (l'inverse serait DECRYPT_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // doFinal() fait le chiffrement et retourne des octets bruts
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Base64 convertit les octets bruts en String lisible et transportable
        // Sans Base64, les octets chiffrés contiennent des caractères non imprimables
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Déchiffre un texte chiffré en Base64 avec AES-256 et la SMK.
     *
     * Utilisé dans AuthService.login() pour retrouver le mot de passe en clair
     * afin de pouvoir recalculer le HMAC côté serveur.

     * C'est l'opération INVERSE de encrypt() :
     *   encrypt("MonMotDePasse") → "8fGhJ2kL9mN..."
     *   decrypt("8fGhJ2kL9mN...") → "MonMotDePasse"
     *
     * @param encryptedText le mot de passe chiffré en Base64 (venant de la base)
     * @return le mot de passe en clair
     * @throws Exception si la SMK a changé ou les données sont corrompues
     */
    public String decrypt(String encryptedText) throws Exception {
        SecretKeySpec key = buildKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        // DECRYPT_MODE = on va déchiffrer
        cipher.init(Cipher.DECRYPT_MODE, key);

        // D'abord on décode le Base64 pour retrouver les octets chiffrés
        byte[] decoded = Base64.getDecoder().decode(encryptedText);

        // Puis on déchiffre ces octets pour retrouver le texte original
        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }

    // ── Calcul HMAC ──────────────────────────────────────────────────────────

    /**
     * Calcule le HMAC-SHA256 d'un message avec une clé secrète.
     *
     * C'est la fonction centrale du protocole TP3.
     * Elle est appelée :
     *   - Côté client  : avec clé = mot de passe saisi par l'utilisateur
     *   - Côté serveur : avec clé = mot de passe déchiffré depuis la base
     *
     * Si les deux clés sont identiques (bon mot de passe),
     * les deux HMAC seront identiques → authentification réussie.
     *
     * Fonctionnement interne :
     *   HMAC-SHA256 applique SHA256 deux fois en mélangeant la clé :
     *   HMAC(k, m) = SHA256((k XOR opad) || SHA256((k XOR ipad) || m))
     *   (Tu n'as pas à comprendre cette formule, Java la gère pour toi)
     *
     * @param secret  la clé secrète (mot de passe)
     * @param message le message à signer (email:nonce:timestamp)
     * @return la signature HMAC encodée en Base64
     * @throws Exception si l'algorithme HmacSHA256 est indisponible
     */
    public String computeHmac(String secret, String message) throws Exception {
        // Mac est la classe Java pour les Message Authentication Codes
        Mac mac = Mac.getInstance("HmacSHA256");

        // SecretKeySpec encapsule la clé brute dans un objet Java cryptographique
        // On convertit le mot de passe en octets UTF-8 pour en faire une clé
        SecretKeySpec keySpec = new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
        );

        // init() configure le Mac avec la clé
        mac.init(keySpec);

        // doFinal() calcule la signature HMAC sur le message
        // Le résultat est 32 octets bruts (256 bits)
        byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // On encode en Base64 pour obtenir une String transportable dans le JSON
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    // ── Comparaison sécurisée ────────────────────────────────────────────────

    /**
     * Compare deux signatures HMAC en temps constant.
     *
     * <h3>Pourquoi ne pas utiliser hmac1.equals(hmac2) ?</h3>
     * La méthode equals() s'arrête dès qu'elle trouve une différence.
     * Si le premier caractère est différent, elle retourne false immédiatement.
     * Si les 31 premiers caractères sont identiques, elle prend plus de temps.
     * Un attaquant peut mesurer ces différences de temps pour deviner
     * caractère par caractère la signature valide (timing attack).
     *
     * <h3>Comment MessageDigest.isEqual() résout ça ?</h3>
     * Cette méthode compare toujours les DEUX tableaux jusqu'au bout,
     * peu importe à quel caractère ils diffèrent. Le temps est donc
     * constant → aucune information ne peut être déduite du temps de réponse.
     *
     * @param hmac1 première signature (reçue du client)
     * @param hmac2 deuxième signature (calculée par le serveur)
     * @return true si les deux signatures sont identiques
     */
    public boolean compareHmacConstantTime(String hmac1, String hmac2) {
        // On convertit en octets car MessageDigest.isEqual() travaille sur des octets
        return MessageDigest.isEqual(
            hmac1.getBytes(StandardCharsets.UTF_8),
            hmac2.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ── Méthode privée utilitaire ────────────────────────────────────────────

    /**
     * Construit une clé AES-256 à partir de la SMK.
     *
     * AES-256 exige exactement 32 octets (256 bits).
     * Arrays.copyOf gère les deux cas :
     *   - SMK trop courte (<32 octets) : complète avec des zéros
     *   - SMK trop longue (>32 octets) : tronque à 32 octets
     *
     * @return la clé AES prête à l'emploi
     */
    private SecretKeySpec buildKey() {
        // Convertit la String SMK en tableau d'octets
        byte[] keyBytes = smk.getBytes(StandardCharsets.UTF_8);

        // Force exactement 32 octets pour AES-256
        // (copyOf tronque si trop long, complète avec 0x00 si trop court)
        keyBytes = Arrays.copyOf(keyBytes, 32);

        // SecretKeySpec encapsule ces octets en une clé utilisable par le Cipher
        return new SecretKeySpec(keyBytes, "AES");
    }
}