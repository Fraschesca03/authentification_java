package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordMigration implements CommandLineRunner {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public PasswordMigration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) {
        System.out.println("Début de la migration des mots de passe...");

        for (User user : userRepository.findAll()) {
            if (user.getPasswordClear() != null && user.getPasswordHash() == null) {
                user.setPasswordHash(passwordEncoder.encode(user.getPasswordClear()));
                userRepository.save(user);
                System.out.println("Mot de passe migré pour : " + user.getEmail());
            }
        }

        System.out.println("Migration terminée !");
    }
}