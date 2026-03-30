package com.projetAuthentification.authentification.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
class AuthControllerTest {

    // MockMvc simule des requêtes HTTP sans démarrer un vrai serveur
    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Register OK : tous les champs valides")
    void registerOk() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                {
                  "nom": "Dupont",
                  "prenom": "Alice",
                  "email": "alice.controller@test.com",
                  "password": "MonMotDePasse123!"
                }
                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice.controller@test.com"));
    }

    @Test
    @DisplayName("Register KO : email deja utilise")
    void registerKo_emailDejaUtilise() throws Exception {
        // Premier enregistrement
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                {
                  "nom": "Dupont",
                  "prenom": "Bob",
                  "email": "bob.double@test.com",
                  "password": "MonMotDePasse123!"
                }
                """))
                .andExpect(status().isOk());

        // Deuxième enregistrement avec le même email → 409
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                {
                  "nom": "Dupont",
                  "prenom": "Bob",
                  "email": "bob.double@test.com",
                  "password": "MonMotDePasse123!"
                }
                """))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("Acces /api/me sans token : KO")
    void meKo_sansToken() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isBadRequest());
    }
}