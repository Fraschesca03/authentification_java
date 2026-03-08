package com.projetAuthentification.authentification.exception;

/**
 * Exception levée lorsqu'une entrée utilisateur est invalide (ex : email vide, mot de passe trop court).
 * <p>
 * Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production.
 */

public class InvalidInputException extends RuntimeException {
    public InvalidInputException(String message) { super(message); }
}