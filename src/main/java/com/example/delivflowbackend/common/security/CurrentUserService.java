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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * The single place that turns the authenticated Keycloak token into an application user:
 *
 *   JWT "iss" + "sub"  ->  users.(keycloak_issuer, keycloak_subject)  ->  User
 *
 * The row is created on the first authenticated request and is never written again
 * afterwards, so an authenticated request does not trigger database writes (the
 * status DISABLED check is a read-only guard that rejects disabled users with 403).
 *
 * The unique constraint on users(keycloak_issuer, keycloak_subject) keeps the table
 * consistent if the very first requests of a new user arrive in parallel.
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
     * token. Rejects a DISABLED account with {@link UserDisabledException}.
     */
    public User loadOrCreate(Jwt jwt) {
        String issuer = jwt.getIssuer().toString();
        String subject = jwt.getSubject();
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
                    .orElseGet(() -> userRepository.save(createFromToken(jwt)));
        } catch (DataIntegrityViolationException exception) {
            // concurrent first-login: another request created the row first
            return userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, subject)
                    .orElseThrow(() -> exception);
        }
    }

    // first authenticated request of a Keycloak user: create the matching application user
    private User createFromToken(Jwt jwt) {
        String email = jwt.getClaimAsString(CLAIM_EMAIL);
        String normalizedEmail = EmailUtils.normalizeEmail(email);

        User user = new User();
        user.setKeycloakIssuer(jwt.getIssuer().toString());
        user.setKeycloakSubject(jwt.getSubject());
        user.setEmail(normalizedEmail);
        user.setDisplayName(jwt.getClaimAsString(CLAIM_NAME));
        Boolean emailVerified = jwt.getClaimAsBoolean(CLAIM_EMAIL_VERIFIED);
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