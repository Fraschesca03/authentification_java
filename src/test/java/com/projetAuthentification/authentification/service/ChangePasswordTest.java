package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.repository.AuthNonceRepository;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChangePasswordTest {

    @Mock private UserRepository      userRepository;
    @Mock private AuthNonceRepository authNonceRepository;
    @Mock private CryptoService       cryptoService;

    @InjectMocks
    private AuthService authService;

    private static final String EMAIL        = "alice@gmail.com";
    private static final String OLD_PASSWORD = "AncienMdp123!";
    private static final String NEW_PASSWORD = "NouveauMdp456@";

    private User userValide;

    @BeforeEach
    void setUp() {
        userValide = new User();
        userValide.setEmail(EMAIL);
        userValide.setPasswordEncrypted("ancienChiffre==");

        ReflectionTestUtils.setField(authService, "timestampWindow", 60L);
        ReflectionTestUtils.setField(authService, "nonceTtl",        120L);
        ReflectionTestUtils.setField(authService, "tokenTtl",        15L);
    }

    // Test 1 : Changement de mot de passe réussi
    @Test
    @DisplayName("Changement OK : tous les parametres corrects")
    void changePasswordOk() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);
        when(cryptoService.encrypt(NEW_PASSWORD)).thenReturn("nouveauChiffre==");
        when(userRepository.save(any())).thenReturn(userValide);

        assertThatNoException().isThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD));

        // Vérifier que save() a été appelé avec le nouveau mot de passe chiffré
        verify(userRepository, times(1)).save(any(User.class));
    }

    // Test 2 : Ancien mot de passe incorrect
    @Test
    @DisplayName("Changement KO : ancien mot de passe incorrect")
    void changePasswordKo_ancienMdpIncorrect() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, "MauvaisAncien!", NEW_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(AuthenticationFailedException.class)
                .hasMessageContaining("incorrect");
    }

    // Test 3 : Confirmation différente du nouveau mot de passe
    @Test
    @DisplayName("Changement KO : confirmation differente du nouveau mot de passe")
    void changePasswordKo_confirmationDifferente() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, "AutreConfirm123@"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("correspondent pas");
    }

    // Test 4 : Nouveau mot de passe trop faible
    @Test
    @DisplayName("Changement KO : nouveau mot de passe trop faible")
    void changePasswordKo_nouveauMdpTropFaible() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, "faible", "faible"))
                .isInstanceOf(InvalidInputException.class);
    }

    // Test 5 : Utilisateur inexistant
    @Test
    @DisplayName("Changement KO : utilisateur inexistant")
    void changePasswordKo_utilisateurInexistant() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(AuthenticationFailedException.class);
    }
}