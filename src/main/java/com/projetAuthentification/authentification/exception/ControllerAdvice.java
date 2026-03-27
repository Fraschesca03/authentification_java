package com.projetAuthentification.authentification.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * <h2>GlobalExceptionHandler</h2>
 * Gestion centralisée des exceptions pour l'API REST.
 * <p>
 * Cette classe intercepte les exceptions personnalisées et retourne
 * des réponses JSON structurées contenant :
 * <ul>
 *     <li>timestamp : date et heure de l'erreur</li>
 *     <li>status : code HTTP</li>
 *     <li>error : type d'erreur</li>
 *     <li>message : message explicatif</li>
 * </ul>
 * <p>
 * <strong>Attention :</strong> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production. Elle sert uniquement de démonstration pour TP1.
 */


@RestControllerAdvice
public class ControllerAdvice {
    private static final String TIMESTAMP = "timestamp";
    private static final String STATUS = "status";
    private static final String ERROR = "error";
    private static final String MESSAGE = "message";
    /**
     * Gestion des erreurs liées aux entrées invalides.
     *
     * @param ex InvalidInputException
     * @return ResponseEntity avec status 400 et détails de l'erreur
     */
    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(InvalidInputException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                        TIMESTAMP, LocalDateTime.now(),
                        STATUS, 400,

                        ERROR, "Bad Request",
                        MESSAGE, ex.getMessage()
                ));
    }
    /**
     * Gestion des conflits liés aux ressources (par exemple email déjà existant).
     *
     * @param ex ResourceConflictException
     * @return ResponseEntity avec status 409 et détails de l'erreur
     */
    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(ResourceConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of(
                        TIMESTAMP, LocalDateTime.now(),
                        STATUS, 409,
                        ERROR, "Conflict",
                        MESSAGE, ex.getMessage()
                ));
    }
    /**
     * Gestion des erreurs d'authentification.
     *
     * @param ex AuthenticationFailedException
     * @return ResponseEntity avec status 401 et détails de l'erreur
     */
    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleAuthFailed(AuthenticationFailedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                        TIMESTAMP, LocalDateTime.now(),
                        STATUS, 401,
                        ERROR, "Unauthorized",
                        MESSAGE, ex.getMessage()
                ));
    }
}