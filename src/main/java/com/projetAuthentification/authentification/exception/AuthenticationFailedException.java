package com.projetAuthentification.authentification.exception;

/**
 * Exception levée lorsque la connexion échoue
 * Exemple : email inconnu ou mot de passe incorrect
 */
public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(String message) {
        super(message);
    }
}