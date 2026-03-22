package com.projetAuthentification.authentification;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Classe principale Spring Boot.
 *
 * Changement TP3 : ajout de @EnableScheduling
 *
 * Sans cette annotation, le @Scheduled(fixedDelay=60_000) dans AuthService
 * ne s'exécuterait jamais — Spring ignorerait silencieusement les méthodes
 * annotées @Scheduled.
 *
 * EnableScheduling dit à Spring : "active le moteur de tâches planifiées,
 * cherche tous les @Scheduled dans l'application et exécute-les."
 */
@SpringBootApplication
@EnableScheduling
public class AuthentificationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthentificationApplication.class, args);
	}
}