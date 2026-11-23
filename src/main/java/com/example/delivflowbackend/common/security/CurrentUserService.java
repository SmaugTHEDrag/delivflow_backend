package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.util.EmailUtils;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CurrentUserService {

    private final IUserRepository userRepository;

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            throw new AccessDeniedException("A valid Keycloak access token is required");
        }
        return requireLocalUser(jwt);
    }

    @Transactional
    public User updateCurrentUserProfile(String firstName, String lastName, String avatarUrl) {
        User user = getCurrentUser();
        if (firstName != null) {
            user.setFirstName(firstName.trim());
        }
        if (lastName != null) {
            user.setLastName(lastName.trim());
        }
        if (avatarUrl != null) {
            user.setAvatarUrl(avatarUrl);
        }
        return userRepository.save(user);
    }

    public User requireLocalUser(Jwt jwt) {
        return requireLocalUser(
                jwt == null ? null : jwt.getSubject(),
                jwt == null ? null : jwt.getClaimAsString("email"),
                jwt == null ? null : jwt.getClaimAsString("preferred_username"),
                jwt == null ? null : jwt.getClaimAsString("given_name"),
                jwt == null ? null : jwt.getClaimAsString("family_name"),
                jwt == null ? null : jwt.getClaimAsBoolean("email_verified"));
    }

    public User requireLocalUser(OidcUser oidcUser) {
        return requireLocalUser(
                oidcUser == null ? null : oidcUser.getSubject(),
                oidcUser == null ? null : oidcUser.getClaimAsString("email"),
                oidcUser == null ? null : oidcUser.getClaimAsString("preferred_username"),
                oidcUser == null ? null : oidcUser.getClaimAsString("given_name"),
                oidcUser == null ? null : oidcUser.getClaimAsString("family_name"),
                oidcUser == null ? null : oidcUser.getClaimAsBoolean("email_verified"));
    }

    private User requireLocalUser(
            String subject,
            String email,
            String preferredUsername,
            String givenName,
            String familyName,
            Boolean tokenEmailVerified) {

        if (subject == null || subject.isBlank()) {
            throw new AccessDeniedException("The access token has no subject");
        }
        if (subject.length() > 255) {
            throw new AccessDeniedException("The access token subject is invalid");
        }

        // Look up by Keycloak subject (the OIDC "sub" claim) — the stable identity mapping.
        // We never auto-link by email; a matching email with a different keycloak_id is a
        // distinct identity and must not be merged.
        Optional<User> existing = userRepository.findByKeycloakId(subject);
        if (existing.isPresent()) {
            User user = existing.get();
            if (user.getStatus() == UserStatus.DISABLED
                    || !Boolean.TRUE.equals(tokenEmailVerified)
                    || (user.getStatus() != UserStatus.ACTIVE
                    && user.getStatus() != UserStatus.PENDING_VERIFICATION)) {
                throw new AccessDeniedException("An active, verified account is required");
            }
            if (user.getStatus() == UserStatus.PENDING_VERIFICATION) {
                user.setEmailVerified(true);
                user.setStatus(UserStatus.ACTIVE);
                return userRepository.save(user);
            }
            if (!Boolean.TRUE.equals(user.getEmailVerified())) {
                throw new AccessDeniedException("An active, verified account is required");
            }
            return user;
        }

        if (!Boolean.TRUE.equals(tokenEmailVerified)) {
            throw new AccessDeniedException("An active, verified account is required");
        }
        return createLocalUser(subject, email, preferredUsername, givenName, familyName);
    }

    /**
     * Creates a local application profile for a Keycloak-authenticated identity that has no
     * local profile yet. Used by social login (e.g. Google via Keycloak Identity Provider) and
     * by any first-time Keycloak login.
     *
     * The Keycloak subject ({@code sub}) is stored as {@code keycloak_id}. Email is normalized
     * (lowercase, trimmed) before saving. The email claim is trusted because it comes from a
     * Keycloak-issued JWT, not from the client.
     */
    private User createLocalUser(
            String subject,
            String email,
            String preferredUsername,
            String givenName,
            String familyName) {

        String normalizedEmail = normalizeOrBlank(email);
        if (normalizedEmail.isBlank() || normalizedEmail.length() > 320) {
            throw new AccessDeniedException("A verified email address is required");
        }
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new AccessDeniedException("A local profile already exists for this email");
        }

        User user = User.builder()
                .keycloakId(subject)
                .username(determineUsername(preferredUsername, normalizedEmail, subject))
                .email(normalizedEmail)
                .firstName(givenName != null ? givenName.trim() : null)
                .lastName(familyName != null ? familyName.trim() : null)
                .emailVerified(true)
                .status(UserStatus.ACTIVE)
                .build();

        try {
            return userRepository.save(user);
        } catch (DataIntegrityViolationException ex) {
            Optional<User> raceWinner = userRepository.findByKeycloakId(subject);
            if (raceWinner.isPresent()) {
                return raceWinner.get();
            }
            throw new AccessDeniedException("Unable to synchronize local profile", ex);
        }
    }

    private String determineUsername(String preferredUsername, String email, String subject) {
        String candidate;
        if (preferredUsername != null && !preferredUsername.isBlank()) {
            candidate = preferredUsername.trim();
        } else {
            int at = email.indexOf('@');
            candidate = at > 0 ? email.substring(0, at) : email;
        }
        if (candidate.isBlank()) {
            candidate = subjectFallback(subject);
        }

        Optional<User> collision = userRepository.findByUsernameIgnoreCase(candidate);
        if (collision.isEmpty()) {
            return candidate.length() <= 320 ? candidate : candidate.substring(0, 320);
        }
        String suffix = "_" + subject;
        int candidateLength = Math.min(candidate.length(), 320 - suffix.length());
        if (candidateLength < 0) {
            candidateLength = 0;
        }
        return candidate.substring(0, candidateLength) + suffix;
    }

    private String subjectFallback(String subject) {
        return "kc_" + (subject != null ? subject : "unknown");
    }

    private String normalizeOrBlank(String email) {
        String normalized = EmailUtils.normalizeEmail(email);
        return normalized != null ? normalized : "";
    }
}
