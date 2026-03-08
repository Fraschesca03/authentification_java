package com.projetAuthentification.authentification.controller;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.service.AuthService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) { this.authService = authService; }

    @PostMapping("/register")
    public User register(@RequestBody Map<String, String> body) {
        return authService.register(body.get("email"), body.get("password"));
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> body) {
        authService.login(body.get("email"), body.get("password")); // Vérifie email + mdp
        return Map.of("message", "Connexion réussie");
    }

}