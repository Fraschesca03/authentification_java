package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.exception.ResourceConflictException;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private UserRepository userRepository;
    private AuthService authService;

    @BeforeEach
    void setup() {
        userRepository = Mockito.mock(UserRepository.class);
        authService = new AuthService(userRepository);
    }

    // ------------------- Inscription -------------------
    @Test
    void registerSuccess() {
        when(userRepository.existsByEmail("toto@example.com")).thenReturn(false);
        User savedUser = new User();
        savedUser.setEmail("toto@example.com");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        User user = authService.register("toto@example.com", "pwd1234");

        assertEquals("toto@example.com", user.getEmail());
    }

    @Test
    void registerEmptyEmailThrows() {
        InvalidInputException ex = assertThrows(InvalidInputException.class,
                () -> authService.register("", "pwd1234"));
        assertEquals("Email vide", ex.getMessage());
    }

    @Test
    void registerShortPasswordThrows() {
        InvalidInputException ex = assertThrows(InvalidInputException.class,
                () -> authService.register("toto@example.com", "abc"));
        assertEquals("Mot de passe trop court", ex.getMessage());
    }

    @Test
    void registerEmailExistsThrows() {
        when(userRepository.existsByEmail("toto@example.com")).thenReturn(true);
        ResourceConflictException ex = assertThrows(ResourceConflictException.class,
                () -> authService.register("toto@example.com", "pwd1234"));
        assertEquals("Email déjà utilisé", ex.getMessage());
    }

    // ------------------- Connexion -------------------
    @Test
    void loginSuccess() {
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordClear("pwd1234");

        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        String token = authService.login("toto@example.com", "pwd1234");

        assertNotNull(token);
    }

    @Test
    void loginWrongPasswordThrows() {
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordClear("pwd1234");

        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> authService.login("toto@example.com", "wrongpwd"));
        assertEquals("Mot de passe incorrect", ex.getMessage());
    }

    @Test
    void loginUnknownEmailThrows() {
        when(userRepository.findByEmail("inconnu@example.com")).thenReturn(Optional.empty());

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> authService.login("inconnu@example.com", "pwd1234"));
        assertEquals("Email inconnu", ex.getMessage());
    }

    // ------------------- Token / Route protégée -------------------
    @Test
    void getUserFromTokenSuccess() {
        User user = new User();
        user.setEmail("toto@example.com");
        user.setPasswordClear("pwd1234");
        when(userRepository.findByEmail("toto@example.com")).thenReturn(Optional.of(user));

        String token = authService.login("toto@example.com", "pwd1234");
        // le token est stocké automatiquement dans AuthService

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