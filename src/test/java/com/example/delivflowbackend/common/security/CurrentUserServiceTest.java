package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

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

    @Test
    void resolvesActiveLocalUserByJwtSubject() {
        Jwt jwt = token("kc-subject", true);
        User user = activeUser("kc-subject");
        when(userRepository.findByKeycloakId("kc-subject")).thenReturn(Optional.of(user));

        assertThat(currentUserService.requireLocalUser(jwt)).isSameAs(user);
        verify(userRepository).findByKeycloakId("kc-subject");
        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsJwtWithNoLinkedLocalProfile() {
        when(userRepository.findByKeycloakId("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> currentUserService.requireLocalUser(token("unknown", true)))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void rejectsDisabledOrUnverifiedProfilesAndUnverifiedJwt() {
        User disabled = activeUser("disabled");
        disabled.setStatus(UserStatus.DISABLED);
        when(userRepository.findByKeycloakId("disabled")).thenReturn(Optional.of(disabled));
        assertThatThrownBy(() -> currentUserService.requireLocalUser(token("disabled", true)))
                .isInstanceOf(AccessDeniedException.class);

        User unverified = activeUser("unverified");
        unverified.setEmailVerified(false);
        when(userRepository.findByKeycloakId("unverified")).thenReturn(Optional.of(unverified));
        assertThatThrownBy(() -> currentUserService.requireLocalUser(token("unverified", true)))
                .isInstanceOf(AccessDeniedException.class);

        User verified = activeUser("jwt-unverified");
        when(userRepository.findByKeycloakId("jwt-unverified")).thenReturn(Optional.of(verified));
        assertThatThrownBy(() -> currentUserService.requireLocalUser(token("jwt-unverified", false)))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void currentUserComesFromSecurityContextNotAClientSuppliedId() {
        Jwt jwt = token("subject-from-token", true);
        User user = activeUser("subject-from-token");
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, List.of(), "frontend-user-id"));
        when(userRepository.findByKeycloakId("subject-from-token")).thenReturn(Optional.of(user));

        assertThat(currentUserService.getCurrentUser()).isSameAs(user);
        verify(userRepository).findByKeycloakId("subject-from-token");
        verify(userRepository, never()).findById(any());
    }

    @Test
    void missingAuthenticationIsRejected() {
        assertThatThrownBy(() -> currentUserService.getCurrentUser())
                .isInstanceOf(AccessDeniedException.class);
    }

    private Jwt token(String subject, boolean emailVerified) {
        return Jwt.withTokenValue("jwt")
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/delivflow")
                .subject(subject)
                .claim("email_verified", emailVerified)
                .build();
    }

    private User activeUser(String keycloakId) {
        User user = new User();
        user.setKeycloakId(keycloakId);
        user.setEmail("user@example.com");
        user.setUsername("user");
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }
}
