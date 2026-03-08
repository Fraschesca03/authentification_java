package com.projetAuthentification.authentification.controller;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.service.AuthService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/auth/register")
    public User register(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        return authService.register(email, password);
    }

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

    @GetMapping("/me")
    public Map<String, String> me(@RequestHeader("Authorization") String token) {
        // Vérifie le token et récupère l'utilisateur
        User user = authService.getUserFromToken(token);
        return Map.of("email", user.getEmail());
    }
}