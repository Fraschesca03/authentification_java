package com.projetAuthentification.authentification.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité User — alignée sur le modèle Laravel SkillHub.
 *
 * IMPORTANT : cette entité partage la MÊME table users que Laravel.
 * Les champs correspondent à la migration Laravel create_users_table.
 *
 * Le champ `password` contient le mot de passe chiffré AES-GCM (réversible)
 * pour permettre le protocole HMAC de login du TP3.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    // Colonne "password" pour être compatible avec le schéma Laravel
    // Contient le chiffré AES-GCM (TP4), pas le plain text
    @Column(nullable = false, length = 500)
    private String password;

    @Column(nullable = false)
    private String nom;

    // Rôle : "apprenant" ou "formateur"
    @Column(nullable = false)
    private String role = "apprenant";

    // Champs optionnels présents côté Laravel
    @Column(nullable = true)
    private String photo;

    @Column(nullable = true, columnDefinition = "TEXT")
    private String bio;

    // Protection brute-force (TP2 — conservé)
    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();

    // ── Getters et Setters ───────────────────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le mot de passe chiffré AES-GCM (pas le plain text).
     * Utiliser CryptoService.decrypt() pour obtenir le plain text.
     */
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    // Alias pour compatibilité avec le code existant qui utilise getPasswordEncrypted
    public String getPasswordEncrypted() { return password; }
    public void setPasswordEncrypted(String value) { this.password = value; }

    public String getNom() { return nom; }
    public void setNom(String nom) { this.nom = nom; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public String getPhoto() { return photo; }
    public void setPhoto(String photo) { this.photo = photo; }

    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int v) { this.failedAttempts = v; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime v) { this.lockUntil = v; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime v) { this.createdAt = v; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime v) { this.updatedAt = v; }
}