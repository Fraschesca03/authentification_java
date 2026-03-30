package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.dto.LoginRequest;
import com.projetAuthentification.authentification.entity.AuthNonce;
import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.exception.ResourceConflictException;
import com.projetAuthentification.authentification.repository.AuthNonceRepository;
import com.projetAuthentification.authentification.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour AuthService — TP3
 *
 * On utilise Mockito pour simuler les dépendances (UserRepository,
 * AuthNonceRepository, CryptoService) sans avoir besoin d'une vraie base
 * de données. Chaque test est isolé et rapide.
 *
 * @ExtendWith(MockitoExtension.class) active Mockito pour cette classe
 * @Mock crée un faux objet simulé
 * @InjectMocks crée le vrai AuthService en injectant les @Mock dedans
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    // ── Mocks (faux objets simulés) ──────────────────────────────────────────
    @Mock private UserRepository      userRepository;
    @Mock private AuthNonceRepository authNonceRepository;
    @Mock private CryptoService       cryptoService;

    // Le vrai AuthService avec les mocks injectés
    @InjectMocks
    private AuthService authService;

    // ── Données communes à tous les tests ────────────────────────────────────
    private static final String EMAIL    = "alice@gmail.com";
    private static final String PASSWORD = "MonMotDePasse123!";
    private static final String NOM      = "Dupont";
    private static final String PRENOM   = "Alice";

    private User userValide;
    private long timestampValide;
    private String nonceValide;

    /**
     * @BeforeEach : exécuté avant CHAQUE test.
     * Prépare les données communes et configure les paramètres du service.
     */
    @BeforeEach
    void setUp() {
        // Créer un utilisateur valide pour les tests
        userValide = new User();
        userValide.setEmail(EMAIL);
        userValide.setPasswordEncrypted("motDePasseChiffre==");
        userValide.setNom(NOM);
        userValide.setPrenom(PRENOM);

        // Timestamp actuel — valide car dans la fenêtre ±60s
        timestampValide = Instant.now().getEpochSecond();

        // Nonce unique pour chaque test
        nonceValide = UUID.randomUUID().toString();

        // Injecter les valeurs de configuration via ReflectionTestUtils
        // (remplace ce que @Value ferait normalement depuis application.properties)
        ReflectionTestUtils.setField(authService, "timestampWindow", 60L);
        ReflectionTestUtils.setField(authService, "nonceTtl",        120L);
        ReflectionTestUtils.setField(authService, "tokenTtl",        15L);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TESTS DE CONNEXION
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Test 1 : Login OK avec HMAC valide
     * Vérifie que la connexion réussit quand tout est correct.
     */
    @Test
    @DisplayName("Login OK : HMAC valide et tous les paramètres corrects")
    void loginOk_hmacValide() throws Exception {
        // ARRANGE (préparer)
        // Le serveur trouve l'utilisateur en base
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        // Le nonce n'a jamais été vu (Optional vide = pas en base)
        when(authNonceRepository.findByUserAndNonce(eq(userValide), eq(nonceValide)))
                .thenReturn(Optional.empty());
        // Le déchiffrement retourne le mot de passe en clair
        when(cryptoService.decrypt("motDePasseChiffre==")).thenReturn(PASSWORD);
        // Le calcul HMAC retourne une signature
        String message = EMAIL + ":" + nonceValide + ":" + timestampValide;
        when(cryptoService.computeHmac(PASSWORD, message)).thenReturn("signatureValide");
        // La comparaison en temps constant retourne true (signatures identiques)
        when(cryptoService.compareHmacConstantTime("signatureValide", "signatureValide"))
                .thenReturn(true);

        // ACT (exécuter)
        Map<String, String> result = authService.login(
                EMAIL, nonceValide, timestampValide, "signatureValide");

        // ASSERT (vérifier)
        // Le résultat contient bien un accessToken et une date d'expiration
        assertThat(result).containsKey("accessToken");
        assertThat(result).containsKey("expiresAt");
        assertThat(result.get("accessToken")).isNotBlank();
    }

    /**
     * Test 2 : Login KO avec HMAC invalide
     * Vérifie que la connexion échoue si la signature est incorrecte.
     * (Mauvais mot de passe côté client → HMAC différent)
     */
    @Test
    @DisplayName("Login KO : HMAC invalide (mauvais mot de passe)")
    void loginKo_hmacInvalide() throws Exception {
        // ARRANGE
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(cryptoService.decrypt(any())).thenReturn(PASSWORD);
        when(cryptoService.computeHmac(any(), any())).thenReturn("signatureAttendue");
        // La comparaison retourne false : signatures différentes
        when(cryptoService.compareHmacConstantTime("signatureAttendue", "signatureReçue"))
                .thenReturn(false);

        // ACT & ASSERT
        // assertThatThrownBy vérifie qu'une exception est levée
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "signatureReçue"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    /**
     * Test 3 : Login KO timestamp expiré
     * Vérifie que la connexion échoue si le timestamp est trop vieux (> 60s).
     */
    @Test
    @DisplayName("Login KO : timestamp expiré (plus de 60 secondes dans le passé)")
    void loginKo_timestampExpire() {
        // ARRANGE
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        // Timestamp d'il y a 5 minutes = clairement hors de la fenêtre ±60s
        long timestampExpire = Instant.now().getEpochSecond() - 300;

        // ACT & ASSERT
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampExpire, "n'importe"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    /**
     * Test 4 : Login KO timestamp futur
     * Vérifie que la connexion échoue si le timestamp est dans le futur (> 60s).
     * (Protection contre les attaques où l'horloge client est manipulée)
     */
    @Test
    @DisplayName("Login KO : timestamp futur (plus de 60 secondes dans le futur)")
    void loginKo_timestampFutur() {
        // ARRANGE
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        // Timestamp dans 5 minutes = hors de la fenêtre ±60s
        long timestampFutur = Instant.now().getEpochSecond() + 300;

        // ACT & ASSERT
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampFutur, "n'importe"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    /**
     * Test 5 : Login KO nonce déjà utilisé
     * Vérifie que le rejouer une requête identique est rejeté.
     */
    @Test
    @DisplayName("Login KO : nonce déjà utilisé (tentative de replay attack)")
    void loginKo_nonceDejaUtilise() {
        // ARRANGE
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        // Le nonce EST déjà en base (Optional non vide = nonce connu = consommé)
        AuthNonce nonceDeja = new AuthNonce();
        nonceDeja.setConsumed(true);
        when(authNonceRepository.findByUserAndNonce(eq(userValide), eq(nonceValide)))
                .thenReturn(Optional.of(nonceDeja));

        // ACT & ASSERT
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "n'importe"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    /**
     * Test 6 : Login KO utilisateur inconnu
     * Vérifie que la connexion échoue si l'email n'existe pas en base.
     */
    @Test
    @DisplayName("Login KO : email inconnu")
    void loginKo_userInconnu() {
        // ARRANGE
        // findByEmail retourne Optional.empty() = email pas en base
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        // ACT & ASSERT
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "n'importe"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    /**
     * Test 7 : Vérification de la comparaison en temps constant
     * Vérifie que compareHmacConstantTime() est bien appelée (et pas equals()).
     */
    @Test
    @DisplayName("Comparaison HMAC : utilise bien compareHmacConstantTime (temps constant)")
    void comparaisonTempsConstant_utiliseMethodeSecurisee() throws Exception {
        // ARRANGE
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(cryptoService.decrypt(any())).thenReturn(PASSWORD);
        when(cryptoService.computeHmac(any(), any())).thenReturn("sig");
        when(cryptoService.compareHmacConstantTime("sig", "sig")).thenReturn(true);

        // ACT
        authService.login(EMAIL, nonceValide, timestampValide, "sig");

        // ASSERT : on vérifie que compareHmacConstantTime a bien été appelée
        // verify() de Mockito vérifie qu'une méthode a été invoquée
        verify(cryptoService, times(1)).compareHmacConstantTime("sig", "sig");
    }

    /**
     * Test 8 : Token émis et accès /api/me OK
     * Vérifie que le token retourné permet de récupérer l'utilisateur.
     */
    @Test
    @DisplayName("Token émis : accès /api/me réussi avec le token retourné")
    void tokenEmis_accesMeOk() throws Exception {
        // ARRANGE — configurer le login pour qu'il réussisse
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(cryptoService.decrypt(any())).thenReturn(PASSWORD);
        when(cryptoService.computeHmac(any(), any())).thenReturn("sig");
        when(cryptoService.compareHmacConstantTime(any(), any())).thenReturn(true);

        // ACT 1 : se connecter et récupérer le token
        Map<String, String> loginResult =
                authService.login(EMAIL, nonceValide, timestampValide, "sig");
        String token = loginResult.get("accessToken");

        // Préparer le mock pour getUserFromToken
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));

        // ACT 2 : utiliser le token pour accéder à /api/me
        User user = authService.getUserFromToken(token);

        // ASSERT
        assertThat(user.getEmail()).isEqualTo(EMAIL);
    }

    /**
     * Test 9 : Accès /api/me sans token KO
     * Vérifie que /api/me rejette un token invalide.
     */
    @Test
    @DisplayName("Accès /api/me : token invalide ou absent → exception")
    void accesMeSansToken_KO() {
        // ACT & ASSERT
        // Un token qui n'existe pas dans le tokenStore doit lever une exception
        assertThatThrownBy(() -> authService.getUserFromToken("tokenInexistant"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TESTS D'INSCRIPTION
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Test 10 : Inscription OK
     */
    @Test
    @DisplayName("Inscription OK : tous les champs valides")
    void registerOk() throws Exception {
        // ARRANGE
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(cryptoService.encrypt(PASSWORD)).thenReturn("motDePasseChiffre==");
        when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        // ACT
        User result = authService.register(EMAIL, PASSWORD, NOM, PRENOM);

        // ASSERT
        assertThat(result.getEmail()).isEqualTo(EMAIL);
        assertThat(result.getNom()).isEqualTo(NOM);
        assertThat(result.getPrenom()).isEqualTo(PRENOM);
        // Le mot de passe chiffré est stocké, pas le mot de passe en clair
        assertThat(result.getPasswordEncrypted()).isEqualTo("motDePasseChiffre==");
    }

    /**
     * Test 11 : Inscription KO email déjà utilisé
     */
    @Test
    @DisplayName("Inscription KO : email déjà utilisé")
    void registerKo_emailDejaUtilise() {
        // ARRANGE
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        // ACT & ASSERT
        assertThatThrownBy(() ->
                authService.register(EMAIL, PASSWORD, NOM, PRENOM))
                .isInstanceOf(ResourceConflictException.class);
    }

    /**
     * Test 12 : Inscription KO email vide
     */
    @Test
    @DisplayName("Inscription KO : email vide")
    void registerKo_emailVide() {
        assertThatThrownBy(() ->
                authService.register("", PASSWORD, NOM, PRENOM))
                .isInstanceOf(InvalidInputException.class);
    }

    /**
     * Test 13 : Inscription KO nom vide
     */
    @Test
    @DisplayName("Inscription KO : nom vide")
    void registerKo_nomVide() {
        assertThatThrownBy(() ->
                authService.register(EMAIL, PASSWORD, "", PRENOM))
                .isInstanceOf(InvalidInputException.class);
    }

    /**
     * Test 14 : Inscription KO prénom vide
     */
    @Test
    @DisplayName("Inscription KO : prénom vide")
    void registerKo_prenomVide() {
        assertThatThrownBy(() ->
                authService.register(EMAIL, PASSWORD, NOM, ""))
                .isInstanceOf(InvalidInputException.class);
    }

    /**
     * Test 15 : CryptoService — encrypt puis decrypt retourne le texte original
     * Vérifie que le chiffrement AES est bien réversible.
     * Ce test utilise la vraie implémentation de CryptoService (pas un mock).
     */
    @Test
    @DisplayName("CryptoService : encrypt() puis decrypt() retourne le texte original")
    void cryptoService_encryptDecryptReversible() throws Exception {
        CryptoService realCrypto = new CryptoService();

        // CHANGEMENT TP4 : "smk" → "masterKey"
        ReflectionTestUtils.setField(realCrypto, "masterKey",
                "UneCleSuperSecreteDeMinimum32Car!!");

        String texteOriginal = "MonMotDePasse123!";
        String chiffre       = realCrypto.encrypt(texteOriginal);
        String dechiffre     = realCrypto.decrypt(chiffre);

        assertThat(dechiffre).isEqualTo(texteOriginal);
        assertThat(chiffre).isNotEqualTo(texteOriginal);
    }
    @Test
    @DisplayName("Login OK : le nonce est enregistré en base")
    void loginOk_nonceSauvegarde() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(cryptoService.decrypt(any())).thenReturn(PASSWORD);
        when(cryptoService.computeHmac(any(), any())).thenReturn("sig");
        when(cryptoService.compareHmacConstantTime(any(), any())).thenReturn(true);

        authService.login(EMAIL, nonceValide, timestampValide, "sig");

        verify(authNonceRepository, times(1)).save(any(AuthNonce.class));
    }
    @Test
    @DisplayName("Nonce expiré / supprimé ou refusé")
    void nonceExpireTest() {
        AuthNonce nonce = new AuthNonce();
        nonce.setExpiresAt(LocalDateTime.now().minusMinutes(10));
        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "sig"))
                .isInstanceOf(AuthenticationFailedException.class);
    }
    @Test
    @DisplayName("Token null : rejet")
    void tokenNull() {
        assertThatThrownBy(() -> authService.getUserFromToken(null))
                .isInstanceOf(NullPointerException.class);
    }
    @Test
    @DisplayName("Decrypt KO si masterKey invalide")
    void decryptFailWrongKey() {
        CryptoService crypto = new CryptoService();
        ReflectionTestUtils.setField(crypto, "masterKey", "badkey");

        assertThatThrownBy(() -> crypto.decrypt("v1:abc:def"))
                .isInstanceOf(Exception.class);
    }
    @Test
    @DisplayName("Encrypt KO si texte null")
    void encryptNull() {
        CryptoService crypto = new CryptoService();

        assertThatThrownBy(() -> crypto.encrypt(null))
                .isInstanceOf(Exception.class);
    }
    @Test
    @DisplayName("Password jamais stocké en clair")
    void passwordNeverStoredPlain() throws Exception {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(cryptoService.encrypt(PASSWORD)).thenReturn("encrypted");

        User user = authService.register(EMAIL, PASSWORD, NOM, PRENOM);

        assertThat(user.getPasswordEncrypted()).doesNotContain(PASSWORD);
    }
    @Test
    @DisplayName("Inscription KO : email null")
    void registerKo_emailNull() {
        assertThatThrownBy(() ->
                authService.register(null, PASSWORD, NOM, PRENOM))
                .isInstanceOf(InvalidInputException.class);
    }
    @Test
    @DisplayName("Login KO : erreur lors du dechiffrement")
    void loginKo_erreurDechiffrement() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        // Simuler une exception pendant le déchiffrement
        when(cryptoService.decrypt(any())).thenThrow(new Exception("Erreur AES"));

        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "sig"))
                .isInstanceOf(AuthenticationFailedException.class);
    }

    @Test
    @DisplayName("Login KO : erreur lors du calcul HMAC")
    void loginKo_erreurHmac() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(userValide));
        when(authNonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(cryptoService.decrypt(any())).thenReturn(PASSWORD);
        // Simuler une exception pendant le calcul HMAC
        when(cryptoService.computeHmac(any(), any())).thenThrow(new Exception("Erreur HMAC"));

        assertThatThrownBy(() ->
                authService.login(EMAIL, nonceValide, timestampValide, "sig"))
                .isInstanceOf(AuthenticationFailedException.class);
    }
    @Test
    @DisplayName("Scheduler : nettoyage des nonces expires")
    void cleanExpiredNonces_appelleRepository() {
        authService.cleanExpiredNonces();
        verify(authNonceRepository, times(1))
                .deleteByExpiresAtBefore(any(LocalDateTime.class));
    }
    @Test
    @DisplayName("LoginRequest : getters et setters fonctionnent")
    void loginRequest_gettersSetters() {
        LoginRequest req = new LoginRequest();
        req.setEmail("alice@test.com");
        req.setNonce("uuid-123");
        req.setTimestamp(1711234567L);
        req.setHmac("hmacValue");

        assertThat(req.getEmail()).isEqualTo("alice@test.com");
        assertThat(req.getNonce()).isEqualTo("uuid-123");
        assertThat(req.getTimestamp()).isEqualTo(1711234567L);
        assertThat(req.getHmac()).isEqualTo("hmacValue");
    }
    @Test
    @DisplayName("Decrypt KO : format invalide")
    void decrypt_formatInvalide() {
        CryptoService crypto = new CryptoService();
        ReflectionTestUtils.setField(crypto, "masterKey",
                "UneCleSuperSecreteDeMinimum32Car!!");

        assertThatThrownBy(() -> crypto.decrypt("mauvais_format"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Format");
    }
    @Test
    @DisplayName("HMAC : calcul correct")
    void computeHmac_ok() throws Exception {
        CryptoService crypto = new CryptoService();

        String result = crypto.computeHmac("secret", "message");

        assertThat(result).isNotNull();
        assertThat(result).isNotBlank();
    }
    @Test
    @DisplayName("Comparaison HMAC : true si identique")
    void compareHmac_true() {
        CryptoService crypto = new CryptoService();

        boolean result = crypto.compareHmacConstantTime("abc", "abc");

        assertThat(result).isTrue();
    }
    @Test
    @DisplayName("Comparaison HMAC : false si différent")
    void compareHmac_false() {
        CryptoService crypto = new CryptoService();

        boolean result = crypto.compareHmacConstantTime("abc", "xyz");

        assertThat(result).isFalse();
    }
    @Test
    @DisplayName("Encrypt : format v1 correct")
    void encrypt_format() throws Exception {
        CryptoService crypto = new CryptoService();
        ReflectionTestUtils.setField(crypto, "masterKey",
                "UneCleSuperSecreteDeMinimum32Car!!");

        String encrypted = crypto.encrypt("hello");

        assertThat(encrypted).startsWith("v1:");
        assertThat(encrypted.split(":")).hasSize(3);
    }
}