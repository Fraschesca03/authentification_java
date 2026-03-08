package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.*;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) { this.userRepository = userRepository; }

    public User register(String email, String password) {
        if (email == null || email.isBlank())
            throw new InvalidInputException("Email vide");
        if (password == null || password.length() < 4)
            throw new InvalidInputException("Mot de passe trop court");
        if (userRepository.existsByEmail(email))
            throw new ResourceConflictException("Email déjà utilisé");

        User user = new User();
        user.setEmail(email);
        user.setPasswordClear(password); // volontairement dangereux
        return userRepository.save(user);
    }
}