package com.projetAuthentification.authentification.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * <h2>Entité AuthNonce</h2>
 *
 * Représente un nonce utilisé dans le protocole d'authentification HMAC.
 *
 * <h3>C'est quoi un nonce ici ?</h3>
 * Un nonce (Number Used Once) est une chaîne aléatoire unique générée par
 * le client pour chaque tentative de connexion. Le serveur la stocke ici
 * pour s'assurer qu'elle ne sera JAMAIS réutilisée.
 *
 * <h3>Pourquoi cette table existe ?</h3>
 * Sans cette table, un attaquant qui intercepte ta requête de login
 * (email + nonce + timestamp + hmac) pourrait la renvoyer identique
 * au serveur et se connecter à ta place. C'est une "replay attack".
 * En stockant chaque nonce consommé, le serveur peut détecter et rejeter
 * toute tentative de réutilisation.
 *
 * <h3>Structure de la table auth_nonce :</h3>
 * - id          : identifiant auto-généré
 * - user_id     : référence vers l'utilisateur concerné
 * - nonce       : la valeur UUID unique
 * - expires_at  : date d'expiration (now + 2 minutes)
 * - consumed    : true si ce nonce a déjà été utilisé
 * - created_at  : date de création
 *
 * <h3>Contrainte unique :</h3>
 * La paire (user_id, nonce) est unique en base — un même nonce
 * ne peut apparaître qu'une seule fois par utilisateur.
 */
@Entity
@Table(
    name = "auth_nonce",
    uniqueConstraints = {
        // Cette contrainte SQL garantit qu'un même nonce ne peut pas être enregistré deux fois pour le même utilisateur
        @UniqueConstraint(columnNames = {"user_id", "nonce"})
    }
)
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Lien vers l'utilisateur propriétaire de ce nonce
    // @ManyToOne = plusieurs nonces peuvent appartenir à un même utilisateur
    // @JoinColumn = en base, cette colonne s'appelle "user_id"
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // La valeur du nonce — un UUID comme "a3f7c2d1-8b4e-47f6-9c1a-3e5d7f8b9012"
    @Column(nullable = false)
    private String nonce;

    // Date/heure d'expiration : now + 120 secondes
    // Après cette date, le nonce peut être supprimé par le scheduler
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    // true = ce nonce a déjà été utilisé pour une connexion
    // Un nonce consommé est immédiatement rejeté s'il est réutilisé
    @Column(nullable = false)
    private boolean consumed = false;

    // Date de création — utile pour le débogage et les logs
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    // ── Getters et Setters ───────────────────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}