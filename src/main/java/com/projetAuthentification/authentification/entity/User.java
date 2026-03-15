package com.projetAuthentification.authentification.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * <h2>Entité User</h2>
 * Représente un utilisateur dans le système.
 * <p>
 * Cette entité contient les informations de base d'un utilisateur :
 * <ul>
 *     <li>id : identifiant unique généré automatiquement</li>
 *     <li>email : adresse email unique de l'utilisateur</li>
 *     <li>passwordClear : mot de passe stocké en clair (volontairement dangereux)</li>
 *     <li>createdAt : date de création de l'utilisateur</li>
 * </ul>
 * <p>
 * <strong>Attention :</strong> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production. Les mots de passe sont stockés en clair
 * et il n'y a aucune sécurité réelle sur les données.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordClear; // mot de passe en clair

    @Column(nullable = true)
    private String passwordHash;

    private LocalDateTime createdAt = LocalDateTime.now();

    // ----------------- Getters et setters -----------------

    /**
     * Retourne l'identifiant unique de l'utilisateur.
     * @return ID de l'utilisateur
     */
    public Long getId() { return id; }

    /**
     * Définit l'identifiant unique de l'utilisateur.
     * @param id ID à définir
     */
    public void setId(Long id) { this.id = id; }

    /**
     * Retourne l'adresse email de l'utilisateur.
     * @return email de l'utilisateur
     */
    public String getEmail() { return email; }

    /**
     * Définit l'adresse email de l'utilisateur.
     * @param email de l'utilisateur
     */
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le mot de passe en clair.
     * @return mdp de l'utilisateur
     */
    public String getPasswordClear() { return passwordClear; }

    /**
     * Définit le mot de passe en clair.
     * <p>
     * <strong>Attention :</strong> le mot de passe est stocké en clair,
     * ce qui est dangereux et non recommandé pour une application réelle.
     * @param passwordClear de l'utilisateur
     */
    public void setPasswordClear(String passwordClear) { this.passwordClear = passwordClear; }

    /**
     * Retourne le mot de passe hashé.
     * @return mdp  hashé de l'utilisateur
     */
    public String getPasswordHash() { return passwordHash; }

    /**
            * Définit le mot de passe en hashé.
     * <p>
     * <strong>Attention :</strong> le mot de passe est stocké en clair,
     * ce qui est dangereux et non recommandé pour une application réelle.
     * @param passwordClear de l'utilisateur
     */
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    /**
     * Retourne la date de création de l'utilisateur.
     * @return createdAt de l'utilisateur
     */
    public LocalDateTime getCreatedAt() { return createdAt; }

    /**
     * Définit la date de création de l'utilisateur.
     * @param createdAt de l'utilisateur
     */
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}