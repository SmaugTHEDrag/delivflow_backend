package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.exception.UserDisabledException;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * The application user is resolved from the Keycloak token's OIDC identity pair
 * (issuer + sub). Created on first login, never updated afterwards, and a
 * DISABLED account is rejected.
 */
@ExtendWith(MockitoExtension.class)
class CurrentUserServiceTest {

    @Mock
    private IUserRepository userRepository;

    @InjectMocks
    private CurrentUserService currentUserService;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private Jwt token(String issuer, String subject) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer(issuer)
                .subject(subject)
                .claim("email", "Alice@Example.COM")
                .claim("name", "Alice Doe")
                .claim("email_verified", true)
                .build();
    }

    private void authenticate(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, List.of(), jwt.getSubject()));
    }

    @Test
    void existingUserIsLoadedByIssuerAndSubjectAndNotUpdated() {
        String issuer = "http://localhost:8180/realms/delivflow";
        authenticate(token(issuer, "kc-123"));
        User existing = new User();
        existing.setId(UUID.randomUUID());
        existing.setKeycloakIssuer(issuer);
        existing.setKeycloakSubject("kc-123");
        existing.setEmail("alice@example.com");
        existing.setStatus(UserStatus.ACTIVE);
        when(userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, "kc-123"))
                .thenReturn(Optional.of(existing));

        assertThat(currentUserService.getCurrentUser()).isSameAs(existing);
        verify(userRepository, never()).save(any());
        // existing row is not rewritten
        assertThat(existing.getEmail()).isEqualTo("alice@example.com");
    }

    @Test
    void unknownUserIsCreatedFromTheTokenWithNormalizedLowercaseEmail() {
        String issuer = "http://localhost:8180/realms/delivflow";
        authenticate(token(issuer, "kc-123"));
        when(userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, "kc-123"))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User created = currentUserService.getCurrentUser();

        assertThat(created.getKeycloakIssuer()).isEqualTo(issuer);
        assertThat(created.getKeycloakSubject()).isEqualTo("kc-123");
        // email is normalized: trim + toLowerCase
        assertThat(created.getEmail()).isEqualTo("alice@example.com");
        assertThat(created.getDisplayName()).isEqualTo("Alice Doe");
        assertThat(created.getEmailVerified()).isTrue();
        assertThat(created.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(created.getLastLoginAt()).isNotNull();
    }

    @Test
    void secondLoginFindsTheSameUserByIssuerAndSubject() {
        String issuer = "http://localhost:8180/realms/delivflow";
        authenticate(token(issuer, "kc-123"));
        User existing = new User();
        existing.setId(UUID.randomUUID());
        existing.setKeycloakIssuer(issuer);
        existing.setKeycloakSubject("kc-123");
        existing.setEmail("bob@example.com");
        existing.setStatus(UserStatus.ACTIVE);
        when(userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, "kc-123"))
                .thenReturn(Optional.of(existing));

        User first = currentUserService.getCurrentUser();
        User second = currentUserService.getCurrentUser();

        assertThat(first).isSameAs(existing);
        assertThat(second).isSameAs(existing);
        assertThat(existing.getEmail()).isEqualTo("bob@example.com"); // unchanged
    }

    @Test
    void disabledUserIsRejected() {
        String issuer = "http://localhost:8180/realms/delivflow";
        authenticate(token(issuer, "kc-disabled"));
        User disabled = new User();
        disabled.setKeycloakIssuer(issuer);
        disabled.setKeycloakSubject("kc-disabled");
        disabled.setStatus(UserStatus.DISABLED);
        when(userRepository.findByKeycloakIssuerAndKeycloakSubject(issuer, "kc-disabled"))
                .thenReturn(Optional.of(disabled));

        assertThatThrownBy(() -> currentUserService.getCurrentUser())
                .isInstanceOf(UserDisabledException.class);
    }

    @Test
    void missingTokenFailsLoudly() {
        assertThatThrownBy(() -> currentUserService.getCurrentUser())
                .isInstanceOf(IllegalStateException.class);
    }
}