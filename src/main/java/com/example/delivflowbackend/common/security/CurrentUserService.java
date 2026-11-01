package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.exception.UserDisabledException;
import com.example.delivflowbackend.common.util.EmailUtils;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * The single place that turns the authenticated Keycloak token into an application user:
 *
 *   JWT "iss" + "sub"  ->  users.(keycloak_issuer, keycloak_subject)  ->  User
 *   OIDC id token "iss" + "sub" -> users.(keycloak_issuer, keycloak_subject) -> User
 *
 * The row is created on the first authenticated request and is never written again
 * afterwards, so an authenticated request does not trigger database writes (the
 * status DISABLED check is a read-only guard that rejects disabled users with 403).
 *
 * The unique constraint on users(keycloak_issuer, keycloak_subject) keeps the table
 * consistent if the very first requests of a new user arrive in parallel.
 *
 * Authentication mechanism is irrelevant here: both the session-based OIDC login
 * ({@code oauth2Login()}) and the Bearer-token JWT resource server path identify
 * users by the same OIDC pair (issuer, subject).
 */
@Component
@RequiredArgsConstructor
public class CurrentUserService {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_NAME = "name";
    private static final String CLAIM_EMAIL_VERIFIED = "email_verified";

    private final IUserRepository userRepository;

    public User getCurrentUser() {
        Jwt jwt = currentToken();
        return loadOrCreate(jwt);
    }

    /**
     * Find (or create on first login) the application user for the given Keycloak
     * JWT. Rejects a DISABLED account with {@link UserDisabledException}.
     */
    public User loadOrCreate(Jwt jwt) {
        String issuer = jwt.getIssuer().toString();
        String subject = jwt.getSubject();
        return loadOrCreate(issuer, subject,
                jwt.getClaimAsString(CLAIM_EMAIL),
                jwt.getClaimAsString(CLAIM_NAME),
                jwt.getClaimAsBoolean(CLAIM_EMAIL_VERIFIED));
    }

    /**
     * Find (or create on first login) the application user for the given OIDC
     * user (session-based login). Rejects a DISABLED account with
     * {@link UserDisabledException}.
     */
    public User loadOrCreate(OidcUser oidcUser) {
        OidcIdToken idToken = oidcUser.getIdToken();
        String issuer = idToken.getIssuer().toString();
        String subject = idToken.getSubject();
        return loadOrCreate(issuer, subject,
                oidcUser.getClaimAsString(CLAIM_EMAIL),
                oidcUser.getClaimAsString(CLAIM_NAME),
                oidcUser.getClaimAsBoolean(CLAIM_EMAIL_VERIFIED));
    }

    private User loadOrCreate(String issuer, String subject, String email, String name, Boolean emailVerified) {
        if (subject == null) {
            throw new IllegalStateException("Keycloak token has no subject (sub)");
        }

        try {
            return userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, subject)
                    .map(user -> {
                        if (user.getStatus() == UserStatus.DISABLED) {
                            throw new UserDisabledException("Account is disabled");
                        }
                        return user;
                    })
                    .orElseGet(() -> userRepository.save(createFromToken(issuer, subject, email, name, emailVerified)));
        } catch (DataIntegrityViolationException exception) {
            // concurrent first-login: another request created the row first
            return userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, subject)
                    .orElseThrow(() -> exception);
        }
    }

    // first authenticated request of a Keycloak user: create the matching application user
    private User createFromToken(String issuer, String subject, String email, String name, Boolean emailVerified) {
        User user = new User();
        user.setKeycloakIssuer(issuer);
        user.setKeycloakSubject(subject);
        user.setEmail(EmailUtils.normalizeEmail(email));
        user.setDisplayName(name);
        user.setEmailVerified(emailVerified != null ? emailVerified : false);
        user.setStatus(UserStatus.ACTIVE);
        user.setLastLoginAt(Instant.now());
        return user;
    }

    private Jwt currentToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            throw new IllegalStateException("No Keycloak token in the security context");
        }
        return jwt;
    }
}