package com.projetAuthentification.authentification.service;

import com.projetAuthentification.authentification.entity.AuthNonce;
import com.projetAuthentification.authentification.entity.User;
import com.projetAuthentification.authentification.exception.AuthenticationFailedException;
import com.projetAuthentification.authentification.exception.InvalidInputException;
import com.projetAuthentification.authentification.exception.ResourceConflictException;
import com.projetAuthentification.authentification.repository.AuthNonceRepository;
import com.projetAuthentification.authentification.repository.UserRepository;
import com.projetAuthentification.authentification.validator.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <h2>AuthService — TP3</h2>
 *
 * Service principal d'authentification implémentant le protocole HMAC-SSO.
 *
 * <h3>Protocole d'authentification (résumé) :</h3>
 * <pre>
 * CLIENT                                    SERVEUR
 * nonce     = UUID.randomUUID()
 * timestamp = Instant.now().epochSecond
 * message   = email + ":" + nonce + ":" + timestamp
 * hmac      = HMAC-SHA256(password, message)
 *   POST /api/auth/login { email, nonce, timestamp, hmac }
 *                                            1. email existe ?
 *                                            2. timestamp dans +-60s ?
 *                                            3. nonce jamais vu ?
 *                                            4. dechiffrer password (AES)
 *                                            5. recalculer hmac
 *                                            6. comparer en temps constant
 *                                            7. consommer nonce
 *                                            8. emettre accessToken
 *   RETOUR { accessToken, expiresAt }
 * </pre>
 *
 * <h3>Changements vs TP2 :</h3>
 * - register() : BCryptPasswordEncoder remplace par CryptoService.encrypt() (AES)
 * - login()    : comparaison hash remplace par verification HMAC
 * - Nouveau    : gestion des nonces anti-rejeu
 * - Nouveau    : scheduler de nettoyage des nonces expires
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    // Dependances injectees par Spring
    private final UserRepository      userRepository;
    private final AuthNonceRepository authNonceRepository;
    private final CryptoService       cryptoService;

    // Stocke en memoire les tokens actifs : token UUID -> email
    // ConcurrentHashMap est thread-safe (plusieurs requetes simultanees)
    private final ConcurrentHashMap<String, String> tokenStore = new ConcurrentHashMap<>();

    // Parametres lus depuis application.properties
    // La syntaxe :60 signifie "valeur par defaut = 60 si la propriete n'existe pas"
    @Value("${app.auth.timestamp-window:60}")
    private long timestampWindow;

    @Value("${app.auth.nonce-ttl:120}")
    private long nonceTtl;

    @Value("${app.auth.token-ttl:15}")
    private long tokenTtl;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository authNonceRepository,
                       CryptoService cryptoService) {
        this.userRepository      = userRepository;
        this.authNonceRepository = authNonceRepository;
        this.cryptoService       = cryptoService;
    }

    // ── INSCRIPTION ──────────────────────────────────────────────────────────

    /**
     * Inscrit un nouvel utilisateur.
     *
     * Changement TP3 vs TP2 :
     *   TP2 : passwordEncoder.encode(password) = BCrypt (non reversible)
     *   TP3 : cryptoService.encrypt(password)  = AES (reversible avec SMK)
     *
     * Pourquoi ce changement ?
     * Le protocole HMAC necessite que le serveur retrouve le mot de passe
     * en clair pour recalculer la signature. BCrypt rend ca impossible.
     *
     * @param email    email de l'utilisateur
     * @param password mot de passe en clair (sera chiffre AES avant stockage)
     * @param nom      nom de famille
     * @param prenom   prenom
     * @return l'utilisateur cree
     */
    public User register(String email, String password, String nom, String prenom) {
        if (email == null || email.isBlank()) {
            logger.warn("Inscription echouee : email vide");
            throw new InvalidInputException("Email vide");
        }
        if (nom == null || nom.isBlank()) {
            throw new InvalidInputException("Nom vide");
        }
        if (prenom == null || prenom.isBlank()) {
            throw new InvalidInputException("Prenom vide");
        }
        if (!PasswordPolicyValidator.isValid(password)) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir 12 caracteres avec 1 maj, " +
                            "1 minuscule, 1 chiffre et 1 caractere special");
        }
        if (userRepository.existsByEmail(email)) {
            logger.warn("Inscription echouee : email deja utilise {}", email);
            throw new ResourceConflictException("Email deja utilise");
        }

        try {
            User user = new User();
            user.setEmail(email);
            user.setNom(nom);
            user.setPrenom(prenom);
            // CHANGEMENT TP3 : encrypt() au lieu de BCrypt encode()
            // encrypt() chiffre le mot de passe avec AES + SMK
            // Le resultat est une String Base64 stockee en base
            user.setPasswordEncrypted(cryptoService.encrypt(password));
            userRepository.save(user);
            logger.info("Inscription reussie pour {}", email);
            return user;
        } catch (Exception e) {
            logger.error("Erreur de chiffrement lors de l inscription", e);
            throw new RuntimeException("Erreur interne lors de l inscription");
        }
    }

    // ── CONNEXION (protocole HMAC) ────────────────────────────────────────────

    /**
     * Authentifie un utilisateur via le protocole HMAC-SSO.
     *
     * Les verifications sont faites dans cet ordre precis :
     * 1. Email existe
     * 2. Timestamp dans la fenetre +-60s
     * 3. Nonce jamais vu
     * 4. Dechiffrer le mot de passe
     * 5. Recalculer et comparer le HMAC en temps constant
     * 6. Consommer le nonce
     * 7. Emettre l'access token
     *
     * @param email      email de l'utilisateur
     * @param nonce      UUID unique genere par le client
     * @param timestamp  secondes Unix envoyees par le client
     * @param hmacRecu   signature HMAC envoyee par le client
     * @return Map avec "accessToken" et "expiresAt"
     */
    public Map<String, String> login(String email, String nonce,
                                     long timestamp, String hmacRecu) {

        // Etape 1 : Email existe ?
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Connexion echouee : email inconnu {}", email);
                    // On dit "Acces refuse" plutot que "Email inconnu"
                    // pour ne pas reveler si l email existe en base
                    return new AuthenticationFailedException("Acces refuse");
                });

        // Etape 2 : Timestamp dans la fenetre +-60 secondes ?
        // Instant.now().getEpochSecond() = heure actuelle du serveur en secondes Unix
        long maintenant = Instant.now().getEpochSecond();
        // Math.abs() calcule la valeur absolue de la difference
        // Exemple : maintenant=1000, timestamp=950 -> abs(50) < 60 -> OK
        // Exemple : maintenant=1000, timestamp=800 -> abs(200) > 60 -> KO
        if (Math.abs(maintenant - timestamp) > timestampWindow) {
            logger.warn("Connexion echouee : timestamp invalide pour {}", email);
            throw new AuthenticationFailedException("Acces refuse");
        }

        // Etape 3 : Nonce jamais vu ?
        // findByUserAndNonce retourne un Optional
        // ifPresent = "si on trouve ce nonce en base, executer ce bloc"
        // Si le nonce est deja en base = tentative de rejeu = refus
        authNonceRepository.findByUserAndNonce(user, nonce).ifPresent(n -> {
            logger.warn("Connexion echouee : nonce reutilise pour {}", email);
            throw new AuthenticationFailedException("Acces refuse");
        });

        // Etape 4 : Dechiffrer le mot de passe
        // On retrouve le mot de passe en clair grace au dechiffrement AES + SMK
        // C'est la cle qui va servir a recalculer le HMAC
        String motDePasseClair;
        try {
            motDePasseClair = cryptoService.decrypt(user.getPasswordEncrypted());
        } catch (Exception e) {
            logger.error("Erreur de dechiffrement pour {}", email, e);
            throw new AuthenticationFailedException("Erreur interne");
        }

        // Etape 5 : Recalculer et comparer le HMAC
        // On reconstruit exactement le meme message que le client a signe
        String message = email + ":" + nonce + ":" + timestamp;

        String hmacAttendu;
        try {
            // computeHmac() calcule HMAC-SHA256(motDePasseClair, message)
            // Si le client a utilise le bon mot de passe, les deux HMAC seront identiques
            hmacAttendu = cryptoService.computeHmac(motDePasseClair, message);
        } catch (Exception e) {
            logger.error("Erreur de calcul HMAC pour {}", email, e);
            throw new AuthenticationFailedException("Erreur interne");
        }

        // Comparaison en temps constant — OBLIGATOIRE contre les timing attacks
        // compareHmacConstantTime() prend toujours le meme temps, peu importe
        // a quel caractere les deux signatures different
        if (!cryptoService.compareHmacConstantTime(hmacAttendu, hmacRecu)) {
            logger.warn("Connexion echouee : HMAC invalide pour {}", email);
            throw new AuthenticationFailedException("Acces refuse");
        }

        // Etape 6 : Consommer le nonce
        // On enregistre ce nonce en base avec consumed=true
        // Toute tentative de reutilisation sera bloquee a l etape 3
        AuthNonce authNonce = new AuthNonce();
        authNonce.setUser(user);
        authNonce.setNonce(nonce);
        authNonce.setExpiresAt(LocalDateTime.now().plusSeconds(nonceTtl));
        authNonce.setConsumed(true);
        authNonceRepository.save(authNonce);

        // Etape 7 : Emettre l'access token
        // UUID aleatoire comme token — imprévisible et unique
        String accessToken = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(tokenTtl);

        // On stocke en memoire : token -> email (pour /api/me)
        tokenStore.put(accessToken, email);

        logger.info("Connexion reussie pour {}", email);

        return Map.of(
                "accessToken", accessToken,
                "expiresAt",   expiresAt.toString()
        );
    }

    // ── RECUPERATION UTILISATEUR ─────────────────────────────────────────────

    /**
     * Recupere l'utilisateur correspondant a un access token.
     * Utilise par le endpoint GET /api/me.
     *
     * @param token l'access token recu dans le header Authorization
     * @return l'utilisateur correspondant
     */
    public User getUserFromToken(String token) {
        String email = tokenStore.get(token);
        if (email == null) {
            throw new AuthenticationFailedException("Token invalide ou expire");
        }
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("Utilisateur introuvable"));
    }

    // ── NETTOYAGE AUTOMATIQUE DES NONCES EXPIRES ─────────────────────────────

    /**
     * Supprime automatiquement les nonces expires de la base.
     *
     * @Scheduled(fixedDelay = 60_000) = executer toutes les 60 secondes
     *
     * Sans ce nettoyage, la table auth_nonce grossit indefiniment.
     * Les nonces expires ne servent plus a rien car le timestamp
     * les rend de toute facon inutilisables.
     *
     * Necessite @EnableScheduling sur AuthentificationApplication.java
     */
    @Scheduled(fixedDelay = 60_000)
    public void cleanExpiredNonces() {
        authNonceRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        logger.debug("Nettoyage des nonces expires effectue");
    }
}