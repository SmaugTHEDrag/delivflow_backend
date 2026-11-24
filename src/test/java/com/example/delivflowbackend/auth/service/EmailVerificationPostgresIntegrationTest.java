package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@EnabledIfEnvironmentVariable(named = "DELIVFLOW_TEST_POSTGRES_URL", matches = "jdbc:postgresql:.*")
class EmailVerificationPostgresIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private IUserRepository userRepository;

    @MockitoBean
    private KeycloakAuthService keycloakAuthService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @DynamicPropertySource
    static void configurePostgres(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> System.getenv("DELIVFLOW_TEST_POSTGRES_URL"));
        registry.add("spring.datasource.username", () -> System.getenv("DELIVFLOW_TEST_POSTGRES_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DELIVFLOW_TEST_POSTGRES_PASSWORD"));
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
    }

    @Test
    void reconciliationPersistsVerifiedEligibleProfilesWithoutReactivatingDisabledUsers() {
        String suffix = UUID.randomUUID().toString();
        User activeUnverified = user(
                "active-" + suffix, "active-" + suffix + "@example.com", UserStatus.ACTIVE, false);
        User pendingVerified = user(
                "pending-" + suffix, "pending-" + suffix + "@example.com",
                UserStatus.PENDING_VERIFICATION, true);
        User disabledUnverified = user(
                "disabled-" + suffix, "disabled-" + suffix + "@example.com", UserStatus.DISABLED, false);
        disabledUnverified.setDeactivatedAt(Instant.now());

        List<User> users = userRepository.saveAllAndFlush(
                List.of(activeUnverified, pendingVerified, disabledUnverified));
        String activeId = users.get(0).getKeycloakId();
        String pendingId = users.get(1).getKeycloakId();
        String disabledId = users.get(2).getKeycloakId();
        try {
            when(keycloakAuthService.isEmailVerifiedInKeycloak(activeId)).thenReturn(true);
            when(keycloakAuthService.isEmailVerifiedInKeycloak(pendingId)).thenReturn(true);

            authService.reconcilePendingEmailVerifications();

            User synchronizedActive = userRepository.findByKeycloakId(activeId).orElseThrow();
            assertThat(synchronizedActive.getEmailVerified()).isTrue();
            assertThat(synchronizedActive.getStatus()).isEqualTo(UserStatus.ACTIVE);

            User synchronizedPending = userRepository.findByKeycloakId(pendingId).orElseThrow();
            assertThat(synchronizedPending.getEmailVerified()).isTrue();
            assertThat(synchronizedPending.getStatus()).isEqualTo(UserStatus.ACTIVE);

            User unchangedDisabled = userRepository.findByKeycloakId(disabledId).orElseThrow();
            assertThat(unchangedDisabled.getEmailVerified()).isFalse();
            assertThat(unchangedDisabled.getStatus()).isEqualTo(UserStatus.DISABLED);
            verify(keycloakAuthService, never()).isEmailVerifiedInKeycloak(disabledId);
        } finally {
            userRepository.deleteAllByIdInBatch(users.stream().map(User::getId).toList());
        }
    }

    private User user(String keycloakId, String email, UserStatus status, boolean emailVerified) {
        User user = new User();
        user.setKeycloakId(keycloakId);
        user.setUsername(keycloakId);
        user.setEmail(email);
        user.setStatus(status);
        user.setEmailVerified(emailVerified);
        return user;
    }
}
