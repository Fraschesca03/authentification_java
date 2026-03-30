package com.projetAuthentification.authentification.exception;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ExceptionTest {

    @Test
    void authenticationFailedException_message() {
        AuthenticationFailedException ex =
                new AuthenticationFailedException("Acces refuse");
        assertThat(ex.getMessage()).isEqualTo("Acces refuse");
    }

    @Test
    void invalidInputException_message() {
        InvalidInputException ex =
                new InvalidInputException("Champ invalide");
        assertThat(ex.getMessage()).isEqualTo("Champ invalide");
    }

    @Test
    void resourceConflictException_message() {
        ResourceConflictException ex =
                new ResourceConflictException("Email deja utilise");
        assertThat(ex.getMessage()).isEqualTo("Email deja utilise");
    }
}