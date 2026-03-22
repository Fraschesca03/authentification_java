package com.projetAuthentification.authentification.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * <h2>Entité User</h2>
 *
 * Représente un utilisateur dans le système.
 *
 * <h3>Changement TP3 vs TP2 :</h3>
 * Dans le TP2, le mot de passe était stocké avec BCrypt (hash non réversible).
 * BCrypt est excellent pour la sécurité MAIS le serveur ne peut plus retrouver
 * le mot de passe en clair — ce qui est impossible avec le protocole HMAC.
 *
 * Dans le TP3, on passe à un chiffrement AES RÉVERSIBLE :
 *   - Le mot de passe est chiffré avec la Server Master Key (SMK)
 *   - Le serveur peut le déchiffrer quand il a besoin de recalculer le HMAC
 *   - Le champ s'appelle maintenant "password_encrypted" en base
 *
 * <h3>Avertissement pédagogique :</h3>
 * Stocker un mot de passe réversible est un compromis accepté ici
 * UNIQUEMENT pour apprendre le protocole HMAC. En production réelle,
 * on utiliserait des protocoles comme SRP (Secure Remote Password)
 * qui évitent complètement ce problème.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Email unique — sert d'identifiant de connexion
    @Column(unique = true, nullable = false)
    private String email;

    // ── CHANGEMENT TP3 ───────────────────────────────────────────────────────
    // Avant (TP2) : private String passwordHash;
    //   → BCrypt, non réversible, impossible de retrouver le mot de passe
    // Maintenant (TP3) : private String passwordEncrypted;
    //   → AES chiffré avec la SMK, réversible via CryptoService.decrypt()
    //   → Nécessaire pour que le serveur puisse recalculer le HMAC
    @Column(name = "password_encrypted", nullable = false)
    private String passwordEncrypted;

    // Nom de l'utilisateur (ajouté en TP2)
    @Column(nullable = false)
    private String nom;

    // Prénom de l'utilisateur (ajouté en TP2)
    @Column(nullable = false)
    private String prenom;

    // Compteur de tentatives de connexion échouées (protection brute-force TP2)
    @Column(nullable = false)
    private int failedAttempts = 0;

    // Date/heure jusqu'à laquelle le compte est verrouillé (protection TP2)
    private LocalDateTime lockUntil;

    // Date de création du compte
    private LocalDateTime createdAt = LocalDateTime.now();

    // ── Getters et Setters ───────────────────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le mot de passe chiffré AES stocké en base.
     * Ce n'est PAS le mot de passe en clair.
     * Pour obtenir le mot de passe en clair, utiliser CryptoService.decrypt()
     */
    public String getPasswordEncrypted() { return passwordEncrypted; }
    public void setPasswordEncrypted(String passwordEncrypted) {
        this.passwordEncrypted = passwordEncrypted;
    }

    public String getNom() { return nom; }
    public void setNom(String nom) { this.nom = nom; }

    public String getPrenom() { return prenom; }
    public void setPrenom(String prenom) { this.prenom = prenom; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}