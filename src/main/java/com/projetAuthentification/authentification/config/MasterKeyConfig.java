package com.projetAuthentification.authentification.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.PostConstruct;

/**
 * Vérifie que APP_MASTER_KEY est présente au démarrage.
 * Si absente : l'application refuse de démarrer.
 *
 * @PostConstruct = exécuté juste après que Spring
 * ait injecté toutes les dépendances
 */
@Configuration
public class MasterKeyConfig {

    @Value("${app.master-key}")
    private String masterKey;

    @PostConstruct
    public void validateMasterKey() {
        if (masterKey == null || masterKey.isBlank()) {
            throw new IllegalStateException(
                    "APP_MASTER_KEY est absente ou vide. " +
                            "L'application ne peut pas démarrer sans la Master Key. " +
                            "Définissez la variable d'environnement APP_MASTER_KEY."
            );
        }
        if (masterKey.length() < 32) {
            throw new IllegalStateException(
                    "APP_MASTER_KEY doit faire au moins 32 caractères pour AES-256."
            );
        }
    }
}