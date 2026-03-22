package com.projetAuthentification.authentification.dto;

/**
 * <h2>LoginRequest</h2>
 *
 * DTO (Data Transfer Object) qui représente le corps JSON
 * envoyé par le client lors d'une tentative de connexion.
 *
 * <h3>Avant (TP2) le JSON ressemblait à :</h3>
 * <pre>
 * {
 *   "email"    : "alice@gmail.com",
 *   "password" : "MonMotDePasse123!"   ← le mot de passe voyageait sur le réseau
 * }
 * </pre>
 *
 * <h3>Maintenant (TP3) le JSON ressemble à :</h3>
 * <pre>
 * {
 *   "email"     : "alice@gmail.com",
 *   "nonce"     : "a3f7c2d1-8b4e-47f6-9c1a-3e5d7f8b9012",
 *   "timestamp" : 1711234567,
 *   "hmac"      : "xK9mP2qR7vL4nS8oT3..."
 * }
 * </pre>
 *
 * Le mot de passe n'apparaît PLUS dans ce JSON.
 * À la place on a une preuve cryptographique (hmac) que l'on
 * connaît le mot de passe, sans l'avoir envoyé.
 *
 * <h3>Pourquoi un DTO plutôt qu'une Map ?</h3>
 * Dans le TP2 on utilisait Map<String, String> body dans le contrôleur.
 * C'est fonctionnel mais fragile : si on oublie une clé, on obtient null
 * sans aucun message d'erreur clair. Un DTO typé est plus robuste et
 * plus lisible.
 */
public class LoginRequest {

    // L'email de l'utilisateur qui veut se connecter
    private String email;

    // UUID aléatoire généré par le client — utilisé une seule fois
    // Exemple : "a3f7c2d1-8b4e-47f6-9c1a-3e5d7f8b9012"
    private String nonce;

    // Secondes depuis le 1er janvier 1970 (Unix Epoch)
    // Exemple : 1711234567
    private long timestamp;

    // La signature HMAC-SHA256 encodée en Base64
    // Prouve que le client connaît le mot de passe sans l'envoyer
    // Exemple : "xK9mP2qR7vL4nS8oT3uQ6wE1rY5..."
    private String hmac;

    // ── Getters et Setters ───────────────────────────────────────────────────
    // Spring (Jackson) a besoin des getters pour sérialiser
    // et des setters pour désérialiser le JSON entrant

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getHmac() { return hmac; }
    public void setHmac(String hmac) { this.hmac = hmac; }
}