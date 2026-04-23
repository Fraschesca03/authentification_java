package com.projetAuthentification.authentification.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * Service d'émission et vérification de JWT signés HS256.
 *
 * Le JWT_SECRET est PARTAGÉ avec Laravel (SkillHub) pour permettre
 * à Laravel de vérifier les JWT émis par ce service d'authentification
 * sans appel réseau supplémentaire.
 *
 * Format compatible tymon/jwt-auth (Laravel) :
 * Claims : sub (user_id), iat, nbf, exp, jti, email, role, nom, iss
 * Algorithme : HS256
 *
 * Le JWT_SECRET doit faire au MINIMUM 32 caractères (256 bits) pour HS256.
 */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.ttl-minutes:60}")
    private long ttlMinutes;

    /**
     * Construit la clé HMAC à partir du secret partagé.
     * Lancer une exception claire si le secret est trop court.
     */
    private SecretKey getKey() {
        if (jwtSecret == null || jwtSecret.length() < 32) {
            throw new IllegalStateException(
                    "JWT_SECRET doit faire au moins 32 caracteres pour HS256. " +
                            "Configure la variable d'environnement JWT_SECRET."
            );
        }
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Émet un JWT HS256 signé avec le secret partagé.
     *
     * @param userId id de l'utilisateur (sera le claim "sub")
     * @param email  email de l'utilisateur
     * @param role   role (apprenant / formateur)
     * @param nom    nom complet
     * @return le JWT encodé en string
     */
    public String emit(Long userId, String email, String role, String nom) {
        long now = System.currentTimeMillis();
        long exp = now + ttlMinutes * 60 * 1000;

        return Jwts.builder()
                .subject(String.valueOf(userId))   // sub: user ID (string pour tymon)
                .claim("email", email)
                .claim("role",  role)
                .claim("nom",   nom)
                .id(UUID.randomUUID().toString())  // jti: JWT ID
                .issuedAt(new Date(now))           // iat
                .notBefore(new Date(now))          // nbf
                .expiration(new Date(exp))         // exp
                .issuer("skillhub-auth")           // iss
                .signWith(getKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Surcharge à 3 arguments (compatibilité avec login qui n'a pas le nom sous la main).
     */
    public String emit(Long userId, String email, String role) {
        return emit(userId, email, role, null);
    }

    /**
     * Parse et vérifie un JWT.
     * Lève une exception si signature invalide, expiré, ou malformé.
     *
     * @param token le JWT à vérifier
     * @return les claims extraits
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}