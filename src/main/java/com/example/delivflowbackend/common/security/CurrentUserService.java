package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

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

    public User requireLocalUser(Jwt jwt) {
        return requireLocalUser(
                jwt == null ? null : jwt.getSubject(),
                jwt == null ? null : jwt.getClaimAsBoolean("email_verified"));
    }

    public User requireLocalUser(OidcUser oidcUser) {
        return requireLocalUser(
                oidcUser == null ? null : oidcUser.getSubject(),
                oidcUser == null ? null : oidcUser.getClaimAsBoolean("email_verified"));
    }

    private User requireLocalUser(String subject, Boolean tokenEmailVerified) {
        if (subject == null || subject.isBlank()) {
            throw new AccessDeniedException("The access token has no subject");
        }
        User user = userRepository.findByKeycloakId(subject)
                .orElseThrow(() -> new AccessDeniedException("No local profile exists for this identity"));
        if (user.getStatus() != UserStatus.ACTIVE
                || !Boolean.TRUE.equals(user.getEmailVerified())
                || !Boolean.TRUE.equals(tokenEmailVerified)) {
            throw new AccessDeniedException("An active, verified account is required");
        }
        return user;
    }
}
