package com.projetAuthentification.authentification;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Test de démarrage du contexte Spring.
 * Vérifie que l'application démarre correctement.
 *
 * @TestPropertySource injecte application-test.properties
 * qui fournit APP_MASTER_KEY fictive + base H2 en mémoire.
 * Sans ça, Spring cherche APP_MASTER_KEY dans l'environnement
 * et plante si elle n'est pas définie.
 */
@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.properties")
class AuthentificationApplicationTests {

	@Test
	void contextLoads() {
		// Ce test vérifie juste que Spring Boot démarre sans erreur
		// Si MasterKeyConfig, CryptoService, AuthService etc.
		// ont des problèmes de configuration : ce test échoue
	}
}