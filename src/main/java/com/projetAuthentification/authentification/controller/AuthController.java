package com.projetAuthentification.authentification.controller;

import com.projetAuthentification.authentification.dto.LoginRequest;
import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.service.AuthService;
import org.springframework.web.bind.annotation.*;
import com.projetAuthentification.authentification.dto.ChangePasswordRequest;
import java.util.Map;

/**
 * AuthController — TP3
 *
 * Changements vs TP2 :
 * - login() recoit maintenant un LoginRequest (DTO) au lieu de Map<String,String>
 *   car le timestamp est un long numerique et pas une String
 * - register() : inchange dans le principe
 * - me()       : inchange
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:5173")
public class AuthController {

    private static final String EMAIL_KEY    = "email";
    private static final String PASSWORD_KEY = "password";

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * POST /api/auth/register
     * Body : { "nom":"...", "prenom":"...", "email":"...", "password":"..." }
     */
    @PostMapping("/auth/register")
    public User register(@RequestBody Map<String, String> body) {
        String email    = body.get(EMAIL_KEY);
        String password = body.get(PASSWORD_KEY);
        String nom      = body.get("nom");
        String prenom   = body.get("prenom");
        return authService.register(email, password, nom, prenom);
    }

    /**
     * POST /api/auth/login — PROTOCOLE HMAC (TP3)
     * Body : { "email":"...", "nonce":"...", "timestamp":1711234567, "hmac":"..." }
     *
     * CHANGEMENT TP3 : on recoit un LoginRequest (DTO) et non plus
     * une Map<String,String>, car timestamp est un long numerique.
     * Le mot de passe N'EST PLUS dans ce JSON.
     *
     * @return { "accessToken":"...", "expiresAt":"..." }
     */
    @PostMapping("/auth/login")
    public Map<String, String> login(@RequestBody LoginRequest request) {
        return authService.login(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp(),
                request.getHmac()
        );
    }

    /**
     * GET /api/me
     * Header : Authorization: <accessToken>
     * Inchange vs TP2.
     */
    @GetMapping("/me")
    public Map<String, String> me(@RequestHeader("Authorization") String token) {
        User user = authService.getUserFromToken(token);
        return Map.of(EMAIL_KEY, user.getEmail());
    }

    /**
     * PUT /api/auth/change-password
     * Body JSON :
     * {
     *   "email": "toto@auth.com",
     *   "oldPassword": "pwd1234",
     *   "newPassword": "TotoNouveauMdpd123!",
     *   "confirmPassword": "TotoNouveauMdpd123!"
     * }
     *
     * @return message de succès
     */
    @PutMapping("/auth/change-password")
    public Map<String, String> changePassword(@RequestBody ChangePasswordRequest request) {

        authService.changePassword(
                request.getEmail(),
                request.getOldPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        return Map.of("message", "Mot de passe change avec succes");
    }
}