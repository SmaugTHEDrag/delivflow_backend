package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.common.util.EmailUtils;
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

import java.util.Map;

@Component
@RequiredArgsConstructor
public class CurrentUserService {

    private static final int MAX_SUBJECT_LENGTH = 255;
    private static final int MAX_EMAIL_LENGTH = 320;
    private static final int MAX_NAME_LENGTH = 160;

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
        return requireLocalUser(jwt == null ? null : jwt.getSubject(),
                jwt == null ? null : jwt.getClaims());
    }

    public User requireLocalUser(OidcUser oidcUser) {
        return requireLocalUser(oidcUser == null ? null : oidcUser.getSubject(),
                oidcUser == null ? null : oidcUser.getClaims());
    }

    private User requireLocalUser(String subject, Map<String, Object> claims) {
        if (subject == null || subject.isBlank() || subject.length() > MAX_SUBJECT_LENGTH) {
            throw new AccessDeniedException("The access token has no subject");
        }

        Boolean tokenEmailVerified = booleanClaim(claims, "email_verified");
        User user = userRepository.findByKeycloakId(subject).orElse(null);
        if (user != null) {
            return requireActiveVerifiedUser(user, tokenEmailVerified);
        }
        if (!Boolean.TRUE.equals(tokenEmailVerified)) {
            throw new AccessDeniedException("An active, verified account is required");
        }

        String email = EmailUtils.normalizeEmail(stringClaim(claims, "email"));
        if (email == null || email.isBlank() || email.length() > MAX_EMAIL_LENGTH) {
            throw new AccessDeniedException("A verified email address is required");
        }

        String username = normalizedClaim(claims, "preferred_username");
        if (username == null) {
            username = email;
        }
        String firstName = normalizedClaim(claims, "given_name");
        String lastName = normalizedClaim(claims, "family_name");
        if (username.length() > MAX_EMAIL_LENGTH
                || tooLong(firstName, MAX_NAME_LENGTH)
                || tooLong(lastName, MAX_NAME_LENGTH)) {
            throw new AccessDeniedException("The access token contains invalid profile claims");
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new AccessDeniedException("A local profile already exists for this email");
        }

        User newUser = new User();
        newUser.setKeycloakId(subject);
        newUser.setUsername(username);
        newUser.setEmail(email);
        newUser.setFirstName(firstName);
        newUser.setLastName(lastName);
        newUser.setEmailVerified(true);
        newUser.setStatus(UserStatus.ACTIVE);

        try {
            return userRepository.save(newUser);
        } catch (DataIntegrityViolationException duplicate) {
            User winningProfile = userRepository.findByKeycloakId(subject).orElse(null);
            if (winningProfile != null) {
                return requireActiveVerifiedUser(winningProfile, tokenEmailVerified);
            }
            if (userRepository.findByEmail(email).isPresent()) {
                throw new AccessDeniedException("A local profile already exists for this email", duplicate);
            }
            throw duplicate;
        }
    }

    private User requireActiveVerifiedUser(User user, Boolean tokenEmailVerified) {
        if (user.getStatus() != UserStatus.ACTIVE
                || !Boolean.TRUE.equals(user.getEmailVerified())
                || !Boolean.TRUE.equals(tokenEmailVerified)) {
            throw new AccessDeniedException("An active, verified account is required");
        }
        return user;
    }

    private String normalizedClaim(Map<String, Object> claims, String name) {
        String value = stringClaim(claims, name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private String stringClaim(Map<String, Object> claims, String name) {
        if (claims == null || !(claims.get(name) instanceof String value)) {
            return null;
        }
        return value;
    }

    private Boolean booleanClaim(Map<String, Object> claims, String name) {
        if (claims == null || !(claims.get(name) instanceof Boolean value)) {
            return null;
        }
        return value;
    }

    private boolean tooLong(String value, int maximumLength) {
        return value != null && value.length() > maximumLength;
    }
}
