package com.projetAuthentification.authentification.validator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordPolicyValidatorTest {

    @Test
    void validPasswordShouldPass() {
        String password = "Password1234!?";
        assertTrue(PasswordPolicyValidator.isValid("Abcdef123!@#")); // valide
    }

    @Test
    void motDePasseInvalide_tropCourt() {
        assertFalse(PasswordPolicyValidator.isValid("Abc1!")); // trop court
    }

    @Test
    void motDePasseInvalide_sansMajuscule() {
        assertFalse(PasswordPolicyValidator.isValid("abcdef123!@#"));
    }

    @Test
    void motDePasseInvalide_sansMinuscule() {
        assertFalse(PasswordPolicyValidator.isValid("ABCDEF123!@#"));
    }

    @Test
    void motDePasseInvalide_sansChiffre() {
        assertFalse(PasswordPolicyValidator.isValid("Abcdefgh!@#"));
    }

    @Test
    void motDePasseInvalide_sansSpecial() {
        assertFalse(PasswordPolicyValidator.isValid("Abcdefgh1234"));
    }

    @Test
    void motDePasseNull() {
        assertFalse(PasswordPolicyValidator.isValid(null));
    }
}