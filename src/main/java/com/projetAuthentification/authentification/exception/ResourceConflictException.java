package com.projetAuthentification.authentification.exception;

/**
 * Exception levée lorsqu'une ressource entre en conflit (ex : email déjà utilisé).
 * <p>
 * Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production.
 */

public class ResourceConflictException extends RuntimeException {
    public ResourceConflictException(String message) { super(message); }
}