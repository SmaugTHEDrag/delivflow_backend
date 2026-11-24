package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.dto.AuthResponse;
import com.example.delivflowbackend.auth.dto.AuthTokenResponse;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.LoginRequest;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.dto.UserResponse;
import com.example.delivflowbackend.common.exception.BadCredentialsException;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceLoginTest {

    private static final String ISSUER = "http://localhost:8180/realms/delivflow";
    private static final String SUBJECT = "kc-user-id";

    @Mock
    private KeycloakAuthService keycloakAuthService;
    @Mock
    private IUserRepository userRepository;
    @Mock
    private RateLimiter rateLimiter;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(keycloakAuthService, userRepository,
                new RefreshTokenCookieService(true, "Lax"), rateLimiter);
    }

    @Test
    void registrationPersistsUsernameAndSeparateNamesWithoutPassword() {
        RegisterRequest request = new RegisterRequest(
                "thainguyen", "Thai@Example.com", "StrongPassword123!", "Thai", "Nguyen");
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsernameIgnoreCase("thainguyen")).thenReturn(Optional.empty());
        when(keycloakAuthService.register(request))
                .thenReturn(new KeycloakAuthService.CreatedUserIdentity(SUBJECT, ISSUER));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ResponseEntity<?> result = authService.register(request);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        ArgumentCaptor<User> profile = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(profile.capture());
        assertThat(profile.getValue().getKeycloakId()).isEqualTo(SUBJECT);
        assertThat(profile.getValue().getUsername()).isEqualTo("thainguyen");
        assertThat(profile.getValue().getEmail()).isEqualTo("thai@example.com");
        assertThat(profile.getValue().getFirstName()).isEqualTo("Thai");
        assertThat(profile.getValue().getLastName()).isEqualTo("Nguyen");
        assertThat(profile.getValue().getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(profile.getValue().getEmailVerified()).isFalse();
        assertThat(java.util.Arrays.stream(User.class.getDeclaredFields())
                .map(java.lang.reflect.Field::getName)).doesNotContain("password");
        verify(keycloakAuthService).sendVerificationEmail(SUBJECT);
    }

    @Test
    void registrationRejectsDuplicateUsername() {
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsernameIgnoreCase("thainguyen")).thenReturn(Optional.of(new User()));

        ResponseEntity<?> result = authService.register(registerRequest());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        verifyNoInteractions(keycloakAuthService);
    }

    @Test
    void registrationRejectsDuplicateEmail() {
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.of(new User()));

        ResponseEntity<?> result = authService.register(registerRequest());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        verifyNoInteractions(keycloakAuthService);
    }

    @Test
    void registrationRetryForPendingUserResendsWithoutCreatingAnotherUser() {
        User pending = pendingUser();
        when(userRepository.findByEmail(pending.getEmail())).thenReturn(Optional.of(pending));
        when(rateLimiter.checkVerificationResendRate(pending.getEmail(), "unknown")).thenReturn(true);

        ResponseEntity<?> result = authService.register(registerRequest());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(keycloakAuthService).sendVerificationEmail(SUBJECT);
        verify(keycloakAuthService, never()).register(any(RegisterRequest.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void localProfileFailureDeletesTheCreatedKeycloakUser() {
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsernameIgnoreCase("thainguyen")).thenReturn(Optional.empty());
        when(keycloakAuthService.register(any(RegisterRequest.class)))
                .thenReturn(new KeycloakAuthService.CreatedUserIdentity(SUBJECT, ISSUER));
        doThrow(new IllegalStateException("database unavailable"))
                .when(userRepository).save(any(User.class));

        assertThat(authService.register(registerRequest()).getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);

        verify(keycloakAuthService).deleteUser(SUBJECT);
        verify(keycloakAuthService, never()).sendVerificationEmail(any());
    }

    @Test
    void verificationEmailFailureLeavesPendingProfileAndReturnsRetryableError() {
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsernameIgnoreCase("thainguyen")).thenReturn(Optional.empty());
        when(keycloakAuthService.register(any(RegisterRequest.class)))
                .thenReturn(new KeycloakAuthService.CreatedUserIdentity(SUBJECT, ISSUER));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doThrow(new KeycloakIntegrationException("SMTP unavailable"))
                .when(keycloakAuthService).sendVerificationEmail(SUBJECT);

        ResponseEntity<?> result = authService.register(registerRequest());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(((AuthResponse) result.getBody()).message()).contains("pending verification").contains("retry");
        ArgumentCaptor<User> profile = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(profile.capture());
        assertThat(profile.getValue().getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(profile.getValue().getEmailVerified()).isFalse();
    }

    @Test
    void resendVerificationIsSafeToRepeat() {
        User pending = pendingUser();
        when(userRepository.findByEmail(pending.getEmail())).thenReturn(Optional.of(pending));
        when(rateLimiter.checkVerificationResendRate(pending.getEmail(), "unknown")).thenReturn(true);

        assertThat(authService.resendVerification(pending.getEmail()).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(authService.resendVerification(pending.getEmail()).getStatusCode()).isEqualTo(HttpStatus.OK);

        verify(keycloakAuthService, times(2)).sendVerificationEmail(SUBJECT);
        verify(keycloakAuthService, never()).register(any(RegisterRequest.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void verificationSyncReactivatesOnceOnlyAfterKeycloakConfirmsIt() {
        User pending = pendingUser();
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(pending));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT)).thenReturn(true);

        assertThat(authService.synchronizeEmailVerification(SUBJECT)).isTrue();
        assertThat(authService.synchronizeEmailVerification(SUBJECT)).isTrue();

        assertThat(pending.getEmailVerified()).isTrue();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(userRepository, times(1)).save(pending);
        verify(keycloakAuthService, times(2)).isEmailVerifiedInKeycloak(SUBJECT);
    }

    @Test
    void verificationSyncDoesNotTrustAnUnverifiedKeycloakUserOrSave() {
        User pending = pendingUser();
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(pending));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT)).thenReturn(false);

        assertThat(authService.synchronizeEmailVerification(SUBJECT)).isFalse();

        assertThat(pending.getEmailVerified()).isFalse();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void verificationSyncLeavesDisabledUserUnchanged() {
        User disabled = pendingUser();
        disabled.setStatus(UserStatus.DISABLED);
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(disabled));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT)).thenReturn(true);

        assertThat(authService.synchronizeEmailVerification(SUBJECT)).isFalse();

        assertThat(disabled.getEmailVerified()).isFalse();
        assertThat(disabled.getStatus()).isEqualTo(UserStatus.DISABLED);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void verificationSyncCanRetryAfterKeycloakIsTemporarilyUnavailable() {
        User pending = pendingUser();
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(pending));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT))
                .thenThrow(new KeycloakIntegrationException("internal Keycloak failure"))
                .thenReturn(true);

        assertThatThrownBy(() -> authService.synchronizeEmailVerification(SUBJECT))
                .isInstanceOf(KeycloakIntegrationException.class);
        assertThat(pending.getEmailVerified()).isFalse();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        verify(userRepository, never()).save(any(User.class));

        assertThat(authService.synchronizeEmailVerification(SUBJECT)).isTrue();
        assertThat(pending.getEmailVerified()).isTrue();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(userRepository).save(pending);
    }

    @Test
    void reconciliationFindsVerifiedUsersWhenSyncRequestsWereLost() {
        User pending = pendingUser();
        when(userRepository.findAllEligibleForEmailVerificationReconciliation(
                UserStatus.PENDING_VERIFICATION, UserStatus.ACTIVE))
                .thenReturn(List.of(pending));
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(pending));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT)).thenReturn(true);

        authService.reconcilePendingEmailVerifications();

        assertThat(pending.getEmailVerified()).isTrue();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(userRepository).save(pending);
    }

    @Test
    void reconciliationRepairsActiveUnverifiedAndPendingAlreadyVerifiedProfiles() {
        User activeUnverified = pendingUser();
        activeUnverified.setKeycloakId("active-unverified-id");
        activeUnverified.setEmail("active-unverified@example.com");
        activeUnverified.setStatus(UserStatus.ACTIVE);

        User pendingVerified = pendingUser();
        pendingVerified.setKeycloakId("pending-verified-id");
        pendingVerified.setEmail("pending-verified@example.com");
        pendingVerified.setEmailVerified(true);

        when(userRepository.findAllEligibleForEmailVerificationReconciliation(
                UserStatus.PENDING_VERIFICATION, UserStatus.ACTIVE))
                .thenReturn(List.of(activeUnverified, pendingVerified));
        when(userRepository.findByKeycloakId("active-unverified-id"))
                .thenReturn(Optional.of(activeUnverified));
        when(userRepository.findByKeycloakId("pending-verified-id"))
                .thenReturn(Optional.of(pendingVerified));
        when(keycloakAuthService.isEmailVerifiedInKeycloak("active-unverified-id")).thenReturn(true);
        when(keycloakAuthService.isEmailVerifiedInKeycloak("pending-verified-id")).thenReturn(true);

        authService.reconcilePendingEmailVerifications();

        assertThat(activeUnverified.getEmailVerified()).isTrue();
        assertThat(activeUnverified.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(pendingVerified.getEmailVerified()).isTrue();
        assertThat(pendingVerified.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(userRepository).save(activeUnverified);
        verify(userRepository).save(pendingVerified);
    }

    @Test
    void pendingUserCannotLogInBeforeKeycloakVerification() {
        User pending = pendingUser();
        when(userRepository.findByEmail(pending.getEmail())).thenReturn(Optional.of(pending));
        when(rateLimiter.checkLoginRate(pending.getEmail(), "unknown")).thenReturn(true);
        when(keycloakAuthService.authenticateUserPassword("thainguyen", "StrongPassword123!"))
                .thenReturn(tokens("access-value", "refresh-value"));
        when(keycloakAuthService.getIdentityFromAccessToken("access-value"))
                .thenReturn(new KeycloakAuthService.AuthenticatedIdentity(ISSUER, SUBJECT, false));

        assertThat(authService.login(new LoginRequest(pending.getEmail(), "StrongPassword123!"))
                .getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(pending.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void pendingUserIsActivatedForLoginOnlyAfterAdminApiConfirmsVerification() {
        User pending = pendingUser();
        when(userRepository.findByEmail(pending.getEmail())).thenReturn(Optional.of(pending));
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(pending));
        when(rateLimiter.checkLoginRate(pending.getEmail(), "unknown")).thenReturn(true);
        when(keycloakAuthService.authenticateUserPassword("thainguyen", "StrongPassword123!"))
                .thenReturn(tokens("access-value", "refresh-value"));
        when(keycloakAuthService.getIdentityFromAccessToken("access-value"))
                .thenReturn(new KeycloakAuthService.AuthenticatedIdentity(ISSUER, SUBJECT, true));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT)).thenReturn(true);

        ResponseEntity<?> result = authService.login(
                new LoginRequest(pending.getEmail(), "StrongPassword123!"));

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(pending.getEmailVerified()).isTrue();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(keycloakAuthService).isEmailVerifiedInKeycloak(SUBJECT);
    }

    @Test
    void adminApiFailureDoesNotActivatePendingUserDuringLogin() {
        User pending = pendingUser();
        when(userRepository.findByEmail(pending.getEmail())).thenReturn(Optional.of(pending));
        when(rateLimiter.checkLoginRate(pending.getEmail(), "unknown")).thenReturn(true);
        when(keycloakAuthService.authenticateUserPassword("thainguyen", "StrongPassword123!"))
                .thenReturn(tokens("access-value", "refresh-value"));
        when(keycloakAuthService.getIdentityFromAccessToken("access-value"))
                .thenReturn(new KeycloakAuthService.AuthenticatedIdentity(ISSUER, SUBJECT, true));
        when(keycloakAuthService.isEmailVerifiedInKeycloak(SUBJECT))
                .thenThrow(new KeycloakIntegrationException("Keycloak unavailable"));

        ResponseEntity<?> result = authService.login(
                new LoginRequest(pending.getEmail(), "StrongPassword123!"));

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(pending.getEmailVerified()).isFalse();
        assertThat(pending.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void registrationReportsKeycloakDuplicateConflict() {
        when(userRepository.findByEmail("thai@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsernameIgnoreCase("thainguyen")).thenReturn(Optional.empty());
        when(keycloakAuthService.register(any(RegisterRequest.class)))
                .thenThrow(new UserAlreadyExistsException("duplicate"));

        assertThat(authService.register(registerRequest()).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void successfulLoginReturnsAccessTokenAndSetsSecureRefreshCookie() {
        User user = activeUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(rateLimiter.checkLoginRate(user.getEmail(), "unknown")).thenReturn(true);
        when(keycloakAuthService.authenticateUserPassword("thainguyen", "StrongPassword123!"))
                .thenReturn(tokens("access-value", "refresh-value"));
        when(keycloakAuthService.getIdentityFromAccessToken("access-value"))
                .thenReturn(new KeycloakAuthService.AuthenticatedIdentity(ISSUER, SUBJECT, true));

        ResponseEntity<?> result = authService.login(
                new LoginRequest("thai@example.com", "StrongPassword123!"));

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuthTokenResponse response = (AuthTokenResponse) result.getBody();
        assertThat(response.data().accessToken()).isEqualTo("access-value");
        assertThat(response.data().tokenType()).isEqualTo("Bearer");
        assertThat(response.data().expiresIn()).isEqualTo(300);
        assertThat(response.data().user().getUsername()).isEqualTo("thainguyen");
        assertThat(response.data().user().getFirstName()).isEqualTo("Thai");
        assertThat(result.getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .contains("HttpOnly", "Secure", "SameSite=Lax", "Path=/api/auth", "Max-Age=1200")
                .contains("refresh-value");
        assertThat(response.toString()).doesNotContain("refresh-value");
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(keycloakAuthService).authenticateUserPassword("thainguyen", "StrongPassword123!");
    }

    @Test
    void invalidLoginReturnsUnauthorized() {
        User user = activeUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(rateLimiter.checkLoginRate(user.getEmail(), "unknown")).thenReturn(true);
        when(keycloakAuthService.authenticateUserPassword("thainguyen", "wrong"))
                .thenThrow(new BadCredentialsException("bad credentials"));

        assertThat(authService.login(new LoginRequest(user.getEmail(), "wrong")).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void successfulRefreshRotatesHttpOnlyCookieAndReturnsAccessTokenOnly() {
        when(keycloakAuthService.refreshUserTokens("old-refresh")).thenReturn(tokens("new-access", "new-refresh"));
        when(keycloakAuthService.getIdentityFromAccessToken("new-access"))
                .thenReturn(new KeycloakAuthService.AuthenticatedIdentity(ISSUER, SUBJECT, true));
        when(userRepository.findByKeycloakId(SUBJECT)).thenReturn(Optional.of(activeUser()));

        ResponseEntity<?> result = authService.refresh("old-refresh");

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuthTokenResponse response = (AuthTokenResponse) result.getBody();
        assertThat(response.data().accessToken()).isEqualTo("new-access");
        assertThat(response.data().expiresIn()).isEqualTo(300);
        assertThat(result.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).contains("new-refresh", "HttpOnly", "Secure");
        assertThat(response.toString()).doesNotContain("new-refresh");
    }

    @Test
    void expiredRefreshTokenIsRejected() {
        when(keycloakAuthService.refreshUserTokens("expired"))
                .thenThrow(new BadCredentialsException("expired"));

        assertThat(authService.refresh("expired").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void successfulLogoutRevokesSessionAndExpiresCookie() {
        ResponseEntity<?> result = authService.logout("current-refresh");

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .contains("Max-Age=0", "HttpOnly", "Secure")
                .contains("DELIVFLOW_REFRESH=");
        verify(keycloakAuthService).logoutUser("current-refresh");
    }

    private RegisterRequest registerRequest() {
        return new RegisterRequest("thainguyen", "thai@example.com",
                "StrongPassword123!", "Thai", "Nguyen");
    }

    private User activeUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setKeycloakId(SUBJECT);
        user.setUsername("thainguyen");
        user.setEmail("thai@example.com");
        user.setFirstName("Thai");
        user.setLastName("Nguyen");
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    private User pendingUser() {
        User user = activeUser();
        user.setEmailVerified(false);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        return user;
    }

    private KeycloakTokenResponse tokens(String access, String refresh) {
        return new KeycloakTokenResponse(access, refresh, 300L, 1200L, "Bearer");
    }
}
