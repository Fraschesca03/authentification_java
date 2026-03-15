package com.projetAuthentification.authentification.validator;

import java.util.regex.Pattern;

/**
 * Validator pour vérifier qu'un mot de passe respecte la politique définie.
 * <p>
 * Politique TP2 :
 * - Minimum 12 caractères
 * - Au moins 1 majuscule
 * - Au moins 1 minuscule
 * - Au moins 1 chiffre
 * - Au moins 1 caractère spécial
 */
public class PasswordPolicyValidator {

    // Regex correspondant à la politique
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\w\\s]).{12,}$");

    /**
     * Vérifie si le mot de passe respecte la politique.
     *
     * @param password mot de passe à vérifier
     * @return true si conforme, false sinon
     */
    public static boolean isValid(String password) {
        if (password == null) return false;
        return PASSWORD_PATTERN.matcher(password).matches();
    }
}