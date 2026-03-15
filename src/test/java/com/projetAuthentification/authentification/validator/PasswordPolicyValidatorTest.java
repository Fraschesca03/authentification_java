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
    void shortPasswordShouldFail() {
        assertFalse(PasswordPolicyValidator.isValid("Abc1!")); // trop court
    }

    @Test
    void missingUpperCaseShouldFail() {
        assertFalse(PasswordPolicyValidator.isValid("abcdef123!@#"));
    }

    @Test
    void missingLowerCaseShouldFail() {
        assertFalse(PasswordPolicyValidator.isValid("ABCDEF123!@#"));
    }

    @Test
    void missingDigitShouldFail() {
        assertFalse(PasswordPolicyValidator.isValid("Abcdefgh!@#"));
    }

    @Test
    void missingSpecialCharShouldFail() {
        assertFalse(PasswordPolicyValidator.isValid("Abcdefgh1234"));
    }
}