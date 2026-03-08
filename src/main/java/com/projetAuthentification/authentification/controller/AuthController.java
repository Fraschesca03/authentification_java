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

    /**
     * Endpoint pour l'inscription
     * @param body JSON avec "email" et "password"
     * @return utilisateur créé
     */
    @PostMapping("/register")
    public User register(@RequestBody Map<String, String> body) {
        return authService.register(body.get("email"), body.get("password"));
    }
}