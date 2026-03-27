package com.projetAuthentification.authentification.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests obligatoires TP4 sur la Master Key et le chiffrement.
 *
 * @SpringBootTest charge le contexte Spring complet
 * @TestPropertySource utilise application-test.properties
 * qui injecte une Master Key fictive et une base H2 en mémoire
 */
@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.properties")
class MasterKeyTest {

    @Autowired
    private CryptoService cryptoService;

    // Test 1 : chiffrement puis déchiffrement retourne le texte original
    @Test
    @DisplayName("Encrypt puis decrypt retourne le texte original")
    void encryptDecryptOk() throws Exception {
        String original = "MonMotDePasse123!";
        String chiffre  = cryptoService.encrypt(original);
        String retour   = cryptoService.decrypt(chiffre);
        assertThat(retour).isEqualTo(original);
    }

    // Test 2 : le mot de passe chiffré est différent du mot de passe clair
    @Test
    @DisplayName("Le chiffre est different du clair")
    void chiffreEstDifferentDuClair() throws Exception {
        String original = "MonMotDePasse123!";
        String chiffre  = cryptoService.encrypt(original);
        assertThat(chiffre).isNotEqualTo(original);
    }

    // Test 3 : le format respecte v1:Base64(iv):Base64(ciphertext)
    @Test
    @DisplayName("Format de stockage correct : v1:iv:ciphertext")
    void formatChiffreEstCorrect() throws Exception {
        String chiffre = cryptoService.encrypt("test");
        assertThat(chiffre).startsWith("v1:");
        assertThat(chiffre.split(":")).hasSize(3);
    }

    // Test 4 : déchiffrement échoue si ciphertext modifié
    @Test
    @DisplayName("Dechiffrement KO si ciphertext modifie")
    void dechiffrementKoSiModifie() throws Exception {
        String chiffre = cryptoService.encrypt("MonMotDePasse123!");
        // On modifie la dernière partie (le ciphertext)
        String[] parts   = chiffre.split(":");
        String   modifie = parts[0] + ":" + parts[1] + ":" + parts[2] + "XXXX";
        assertThatThrownBy(() -> cryptoService.decrypt(modifie))
                .isInstanceOf(Exception.class);
    }

    // Test 5 : deux chiffrements du même texte = résultats différents (IV aléatoire)
    @Test
    @DisplayName("Deux chiffrements du meme texte donnent des resultats differents")
    void deuxChiffrementsDifferents() throws Exception {
        String texte    = "MonMotDePasse123!";
        String chiffre1 = cryptoService.encrypt(texte);
        String chiffre2 = cryptoService.encrypt(texte);
        assertThat(chiffre1).isNotEqualTo(chiffre2);
    }
}