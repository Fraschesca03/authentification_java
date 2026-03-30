package com.projetAuthentification.authentification.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.*;

class MasterKeyConfigTest {

    @Test
    @DisplayName("Demarrage KO si APP_MASTER_KEY absente")
    void masterKeyAbsente_lancerException() {
        MasterKeyConfig config = new MasterKeyConfig();
        ReflectionTestUtils.setField(config, "masterKey", "");
        assertThatThrownBy(config::validateMasterKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_MASTER_KEY");
    }

    @Test
    @DisplayName("Demarrage KO si APP_MASTER_KEY trop courte")
    void masterKeyTropCourte_lancerException() {
        MasterKeyConfig config = new MasterKeyConfig();
        ReflectionTestUtils.setField(config, "masterKey", "tropCourte");
        assertThatThrownBy(config::validateMasterKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32");
    }

    @Test
    @DisplayName("Demarrage OK si APP_MASTER_KEY valide")
    void masterKeyValide_pasException() {
        MasterKeyConfig config = new MasterKeyConfig();
        ReflectionTestUtils.setField(config, "masterKey",
                "UneCleSuperSecreteDeMinimum32Car!!");
        assertThatNoException().isThrownBy(config::validateMasterKey);
    }
}