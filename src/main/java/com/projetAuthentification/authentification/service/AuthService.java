package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.*;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthService {

    private final UserRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public AuthService(UserRepository userRepository) { this.userRepository = userRepository; }

    public User register(String email, String password) {
        if (email == null || email.isBlank()) {
            logger.warn("Inscription échouée : email vide");
            throw new InvalidInputException("Email vide");
        }
        if (password == null || password.length() < 4) {
            logger.warn("Inscription échouée : mot de passe trop court pour {}", email);
            throw new InvalidInputException("Mot de passe trop court");
        }
        if (userRepository.existsByEmail(email)) {
            logger.warn("Inscription échouée : email déjà utilisé {}", email);
            throw new ResourceConflictException("Email déjà utilisé");
        }

        User user = new User();
        user.setEmail(email);
        user.setPasswordClear(password);
        userRepository.save(user);
        logger.info("Inscription réussie pour {}", email);
        return user;
    }
    public User login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Connexion échouée : email inconnu {}", email);
                    return new AuthenticationFailedException("Email inconnu");
                });
        if (!user.getPasswordClear().equals(password)) {
            logger.warn("Connexion échouée : mot de passe incorrect pour {}", email);
            throw new AuthenticationFailedException("Mot de passe incorrect");
        }

        logger.info("Connexion réussie pour {}", email);
        return user;
    }

}