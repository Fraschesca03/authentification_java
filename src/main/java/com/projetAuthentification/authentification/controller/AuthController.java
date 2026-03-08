package com.projetAuthentification.authentification.controller;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.exception.ResourceConflictException;
import com.projetAuthentification.authentification.service.AuthService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * <h2>AuthController</h2>
 * Contrôleur REST pour la gestion de l'authentification.
 * <p>
 * Cette classe contient les endpoints pour :
 * <ul>
 *     <li>Inscription d'un nouvel utilisateur (/api/auth/register)</li>
 *     <li>Connexion d'un utilisateur (/api/auth/login)</li>
 *     <li>Récupération des informations de l'utilisateur connecté (/api/auth/me)</li>
 * </ul>
 * <p>
 * <strong> Attention :</strong> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production. Les mots de passe sont stockés en clair
 * et les mécanismes de sécurité sont minimalistes.
 */

@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    /**
     * Endpoint pour inscrire un nouvel utilisateur.
     *
     * @param body Map contenant :
     *             <ul>
     *                 <li>email : l'adresse email de l'utilisateur</li>
     *                 <li>password : le mot de passe</li>
     *             </ul>
     * @return User : l'utilisateur créé
     * @throws InvalidInputException       si l'email est vide ou le mot de passe trop court
     * @throws ResourceConflictException   si l'email existe déjà
     */


    @PostMapping("/auth/register")
    public User register(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        return authService.register(email, password);
    }



    /**
     * Endpoint pour connecter un utilisateur existant.
     *
     * @param body Map contenant :
     *             <ul>
     *                 <li>email : l'adresse email de l'utilisateur</li>
     *                 <li>password : le mot de passe</li>
     *             </ul>
     * @return Map&lt;String, String&gt; : message indiquant le succès de la connexion et le token
     * @throws AuthenticationFailedException si l'email est inconnu ou le mot de passe incorrect
     */


    @PostMapping("/auth/login")
    public Map<String, String> login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");

        // Retourne le token pour l'accès à /api/me
        String token = authService.login(email, password);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Connexion réussie");
        response.put("token", token);
        return response;
    }

    /**
     * Endpoint pour récupérer les informations de l'utilisateur connecté.
     *
     * @param token Token d'authentification envoyé dans l'en-tête "Authorization"
     * @return Map&lt;String, String&gt; contenant l'email de l'utilisateur
     * @throws AuthenticationFailedException si le token est invalide ou expiré
     */

    @GetMapping("/me")
    public Map<String, String> me(@RequestHeader("Authorization") String token) {
        // Vérifie le token et récupère l'utilisateur
        User user = authService.getUserFromToken(token);
        return Map.of("email", user.getEmail());
    }
}