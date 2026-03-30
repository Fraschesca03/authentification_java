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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChangePasswordTest {

    @Mock private UserRepository userRepository;
    @Mock private AuthNonceRepository authNonceRepository;
    @Mock private CryptoService cryptoService;

    @InjectMocks
    private AuthService authService;

    private static final String EMAIL = "alice@gmail.com";
    private static final String OLD_PASSWORD = "AncienMdp123!";
    private static final String NEW_PASSWORD = "NouveauMdp456@";

    private User userValide;

    @BeforeEach
    void setUp() {
        userValide = new User();
        userValide.setEmail(EMAIL);
        userValide.setPasswordEncrypted("ancienChiffre==");

        ReflectionTestUtils.setField(authService, "timestampWindow", 60L);
        ReflectionTestUtils.setField(authService, "nonceTtl", 120L);
        ReflectionTestUtils.setField(authService, "tokenTtl", 15L);
    }

    // succès complet
    @Test
    @DisplayName("Changement OK : tous les parametres corrects")
    void changePasswordOk() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);
        when(cryptoService.encrypt(NEW_PASSWORD)).thenReturn("nouveauChiffre==");

        assertThatNoException().isThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD));

        // Vérifier le vrai changement
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User savedUser = captor.getValue();
        assertThat(savedUser.getPasswordEncrypted()).isEqualTo("nouveauChiffre==");
    }

    // ancien mot de passe incorrect
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

    // confirmation différente
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

    // mot de passe faible
    @Test
    @DisplayName("Changement KO : nouveau mot de passe trop faible")
    void changePasswordKo_nouveauMdpTropFaible() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, "faible", "faible"))
                .isInstanceOf(InvalidInputException.class);
    }

    // utilisateur inexistant
    @Test
    @DisplayName("Changement KO : utilisateur inexistant")
    void changePasswordKo_utilisateurInexistant() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    // erreur de déchiffrement
    @Test
    @DisplayName("Changement KO : erreur lors du dechiffrement")
    void changePasswordKo_erreurDecrypt() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenThrow(new RuntimeException());

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(AuthenticationFailedException.class)
                .hasMessageContaining("Erreur interne");
    }

    // erreur de chiffrement
    @Test
    @DisplayName("Changement KO : erreur lors du chiffrement")
    void changePasswordKo_erreurEncrypt() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(cryptoService.decrypt("ancienChiffre==")).thenReturn(OLD_PASSWORD);
        when(cryptoService.encrypt(NEW_PASSWORD)).thenThrow(new RuntimeException());

        assertThatThrownBy(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Erreur interne");
    }
}