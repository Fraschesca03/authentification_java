package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.exception.ResourceConflictException;
import com.projetAuthentification.authentification.repository.UserRepository;
import com.projetAuthentification.authentification.validator.PasswordPolicyValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private UserRepository userRepository;
    private AuthService authService;
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setup() {
        userRepository = Mockito.mock(UserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder(); // on simule le hash réel
        authService = new AuthService(userRepository);
    }

    // ------------------- Inscription -------------------
    @Test
    void registerSuccess() {
        String rawPassword = "StrongPass1!@#";

        when(userRepository.existsByEmail("toto@example.com")).thenReturn(false);

        User savedUser = new User();
        savedUser.setEmail("toto@example.com");
        savedUser.setPasswordHash(passwordEncoder.encode(rawPassword)); // simule le hash
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        User user = authService.register("toto@example.com", rawPassword);

        assertEquals("toto@example.com", user.getEmail());
        assertTrue(passwordEncoder.matches(rawPassword, user.getPasswordHash())); // vérifier le hash
    }

    @Test
    void registerInvalidPasswordThrows() {
        String badPassword = "short1!A"; // pas assez long ou policy invalide

        when(userRepository.existsByEmail("toto@example.com")).thenReturn(false);

        InvalidInputException ex = assertThrows(InvalidInputException.class,
                () -> authService.register("toto@example.com", badPassword));

        assertEquals("Mot de passe non conforme à la politique", ex.getMessage());
    }

    @Test
    void registerEmailExistsThrows() {
        when(userRepository.existsByEmail("toto@example.com")).thenReturn(true);

        ResourceConflictException ex = assertThrows(ResourceConflictException.class,
                () -> authService.register("toto@example.com", "StrongPass1!@#"));

        assertEquals("Email déjà utilisé", ex.getMessage());
    }

    // ------------------- Connexion -------------------
    @Test
    void loginSuccess() {
        String rawPassword = "StrongPass1!@#";
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordHash(passwordEncoder.encode(rawPassword));

        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        String token = authService.login("toto@example.com", rawPassword);
        assertNotNull(token);
    }

    @Test
    void loginWrongPasswordThrows() {
        String rawPassword = "StrongPass1!@#";
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordHash(passwordEncoder.encode(rawPassword));

        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> authService.login("toto@example.com", "WrongPassword!1"));

        assertEquals("Mot de passe incorrect", ex.getMessage());
    }

    @Test
    void loginUnknownEmailThrows() {
        when(userRepository.findByEmail("inconnu@example.com")).thenReturn(Optional.empty());

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> authService.login("inconnu@example.com", "StrongPass1!@#"));

        assertEquals("Email inconnu", ex.getMessage());
    }

    // ------------------- Token / Route protégée -------------------
    @Test
    void getUserFromTokenSuccess() {
        String rawPassword = "StrongPass1!@#";
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        String token = authService.login("toto@example.com", rawPassword);
        User fromToken = authService.getUserFromToken(token);

        assertEquals("toto@example.com", fromToken.getEmail());
    }

    @Test
    void getUserFromTokenInvalidThrows() {
        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> authService.getUserFromToken("invalide"));
        assertEquals("Token invalide ou expiré", ex.getMessage());
    }
}