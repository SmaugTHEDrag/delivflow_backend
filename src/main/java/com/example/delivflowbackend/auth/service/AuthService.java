package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.dto.AuthResponse;
import com.example.delivflowbackend.auth.dto.AuthTokenResponse;
import com.example.delivflowbackend.auth.dto.ForgotPasswordRequest;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.LoginRequest;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.dto.ResetPasswordRequest;
import com.example.delivflowbackend.auth.dto.UserResponse;
import com.example.delivflowbackend.common.exception.BadCredentialsException;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import com.example.delivflowbackend.common.util.EmailUtils;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String UNKNOWN_CLIENT_ADDRESS = "unknown";
    private static final String VERIFICATION_RESEND_ACKNOWLEDGEMENT =
            "If the account exists and requires verification, a verification email may be sent.";
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.{8,128}$)(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*$");

    private final KeycloakAuthService keycloakAuthService;
    private final IUserRepository userRepository;
    private final RefreshTokenCookieService refreshTokenCookieService;
    private final RateLimiter rateLimiter;

    private UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId() == null ? null : user.getId().toString())
                .keycloakId(user.getKeycloakId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(java.util.stream.Stream.of(user.getFirstName(), user.getLastName())
                        .filter(Objects::nonNull)
                        .collect(java.util.stream.Collectors.joining(" ")))
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .emailVerified(Boolean.TRUE.equals(user.getEmailVerified()))
                .status(user.getStatus())
                .build();
    }

    public ResponseEntity<?> register(RegisterRequest request) {
        return register(request, UNKNOWN_CLIENT_ADDRESS);
    }

    public ResponseEntity<?> register(RegisterRequest request, String remoteAddress) {
        if (request == null || request.getEmail() == null || request.getEmail().isBlank()
                || request.getUsername() == null || request.getUsername().isBlank()
                || request.getFirstName() == null || request.getFirstName().isBlank()
                || request.getLastName() == null || request.getLastName().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(AuthResponse.failure("Username, email, first name, and last name are required"));
        }
        String username = request.getUsername().trim();
        String firstName = request.getFirstName().trim();
        String lastName = request.getLastName().trim();
        String email = EmailUtils.normalizeEmail(request.getEmail());
        if (!PASSWORD_PATTERN.matcher(request.getPassword() == null ? "" : request.getPassword()).matches()
                || username.length() < 3 || username.length() > 100
                || firstName.length() > 160 || lastName.length() > 160
                || email == null || email.length() > 320) {
            return ResponseEntity.badRequest()
                    .body(AuthResponse.failure("Registration details or password do not meet the requirements"));
        }

        User existing = userRepository.findByEmail(email).orElse(null);
        if (existing != null) {
            if (existing.getStatus() == UserStatus.PENDING_VERIFICATION
                    && !Boolean.TRUE.equals(existing.getEmailVerified())
                    && existing.getKeycloakId() != null
                    && existing.getUsername().equalsIgnoreCase(username)) {
                if (!rateLimiter.checkVerificationResendRate(email, remoteAddress)) {
                    return verificationResendAcknowledgement();
                }
                if (!canSendVerificationEmail(existing)) {
                    return verificationResendAcknowledgement();
                }
                sendVerificationEmail(existing);
                return verificationResendAcknowledgement();
            }
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(AuthResponse.failure("The username or email is already in use"));
        }
        if (userRepository.findByUsernameIgnoreCase(username).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(AuthResponse.failure("The username or email is already in use"));
        }

        KeycloakAuthService.CreatedUserIdentity identity;
        try {
            identity = keycloakAuthService.register(request);
        } catch (UserAlreadyExistsException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(AuthResponse.failure("The username or email is already in use"));
        } catch (KeycloakIntegrationException ex) {
            log.error("Registration failed because Keycloak is unavailable");
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(AuthResponse.failure("Registration is temporarily unavailable"));
        }

        User user = new User();
        user.setKeycloakId(identity.keycloakId());
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmailVerified(false);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        try {
            userRepository.save(user);
        } catch (RuntimeException persistenceFailure) {
            log.error("Could not persist the PostgreSQL profile for Keycloak user {}",
                    identity.keycloakId(), persistenceFailure);
            try {
                keycloakAuthService.deleteUser(identity.keycloakId());
            } catch (RuntimeException cleanupFailure) {
                log.error("Could not clean up Keycloak user {}", identity.keycloakId(), cleanupFailure);
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.failure("Registration could not be completed"));
        }

        ResponseEntity<?> emailResponse = sendVerificationEmail(user);
        if (!emailResponse.getStatusCode().is2xxSuccessful()) {
            return emailResponse;
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(AuthResponse.success(
                "Registration successful. Check your email to verify your account.", null));
    }

    public ResponseEntity<?> resendVerification(String email) {
        return resendVerification(email, UNKNOWN_CLIENT_ADDRESS);
    }

    public ResponseEntity<?> resendVerification(String email, String remoteAddress) {
        String normalizedEmail = EmailUtils.normalizeEmail(email);
        if (normalizedEmail == null || normalizedEmail.isBlank()
                || normalizedEmail.length() > 320
                || !rateLimiter.checkVerificationResendRate(normalizedEmail, remoteAddress)) {
            return verificationResendAcknowledgement();
        }
        User user = userRepository.findByEmail(normalizedEmail).orElse(null);
        if (user == null || user.getStatus() != UserStatus.PENDING_VERIFICATION
                || Boolean.TRUE.equals(user.getEmailVerified()) || user.getKeycloakId() == null) {
            return verificationResendAcknowledgement();
        }
        if (canSendVerificationEmail(user)) {
            sendVerificationEmail(user);
        }
        return verificationResendAcknowledgement();
    }

    private boolean canSendVerificationEmail(User user) {
        try {
            if (keycloakAuthService.isEmailVerifiedInKeycloak(user.getKeycloakId())) {
                synchronizeEmailVerification(user.getKeycloakId(), true);
                return false;
            }
            return true;
        } catch (KeycloakIntegrationException ex) {
            log.warn("Could not verify current Keycloak email state for user {}", user.getKeycloakId());
            return false;
        }
    }

    private ResponseEntity<?> verificationResendAcknowledgement() {
        return ResponseEntity.ok(AuthResponse.success(VERIFICATION_RESEND_ACKNOWLEDGEMENT, null));
    }

    private ResponseEntity<?> sendVerificationEmail(User user) {
        try {
            keycloakAuthService.sendVerificationEmail(user.getKeycloakId());
            return ResponseEntity.ok(AuthResponse.success(
                    "Verification email sent. Check your inbox.", null));
        } catch (KeycloakIntegrationException emailFailure) {
            log.warn("Verification email delivery failed for Keycloak user {}",
                    user.getKeycloakId(), emailFailure);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(AuthResponse.failure(
                    "Verification email could not be sent. Your account is pending verification; please retry."));
        }
    }

    @Transactional
    public boolean synchronizeEmailVerification(String keycloakId) {
        return synchronizeEmailVerification(
                keycloakId, keycloakAuthService.isEmailVerifiedInKeycloak(keycloakId));
    }

    private boolean synchronizeEmailVerification(String keycloakId, boolean keycloakVerified) {
        User user = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new com.example.delivflowbackend.common.exception.UserNotFoundException(
                        "No local profile exists for this identity"));
        if (!keycloakVerified || user.getStatus() == UserStatus.DISABLED) {
            return false;
        }

        boolean changed = false;
        if (!Boolean.TRUE.equals(user.getEmailVerified())) {
            user.setEmailVerified(true);
            changed = true;
        }
        if (user.getStatus() == UserStatus.PENDING_VERIFICATION) {
            user.setStatus(UserStatus.ACTIVE);
            changed = true;
        }
        if (changed) {
            userRepository.save(user);
        }
        return true;
    }

    @Scheduled(
            fixedDelayString = "${app.keycloak.email-verification.reconciliation-interval-ms:300000}",
            initialDelayString = "${app.keycloak.email-verification.reconciliation-interval-ms:300000}")
    public void reconcilePendingEmailVerifications() {
        List<User> eligibleUsers = userRepository.findAllEligibleForEmailVerificationReconciliation(
                UserStatus.PENDING_VERIFICATION, UserStatus.ACTIVE);
        for (User user : eligibleUsers) {
            try {
                synchronizeEmailVerification(user.getKeycloakId());
            } catch (KeycloakIntegrationException ex) {
                log.warn("Email-verification reconciliation failed for Keycloak user {}",
                        user.getKeycloakId(), ex);
            }
        }
    }

    @Transactional
    public ResponseEntity<?> login(LoginRequest request) {
        return login(request, UNKNOWN_CLIENT_ADDRESS);
    }

    @Transactional
    public ResponseEntity<?> login(LoginRequest request, String remoteAddress) {
        if (request == null || request.email() == null || request.password() == null) {
            return unauthorized("Invalid email or password");
        }
        String email = EmailUtils.normalizeEmail(request.email());
        if (email == null || email.isBlank() || email.length() > 320) {
            return unauthorized("Invalid email or password");
        }
        if (!rateLimiter.checkLoginRate(email, remoteAddress)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(AuthResponse.failure("Invalid email or password"));
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getKeycloakId() == null || user.getUsername() == null
                || user.getStatus() == UserStatus.DISABLED
                || (user.getStatus() != UserStatus.ACTIVE
                && user.getStatus() != UserStatus.PENDING_VERIFICATION)) {
            return unauthorized("Invalid email or password");
        }

        try {
            KeycloakTokenResponse tokens =
                    keycloakAuthService.authenticateUserPassword(user.getUsername(), request.password());
            KeycloakAuthService.AuthenticatedIdentity identity =
                    keycloakAuthService.getIdentityFromAccessToken(tokens.accessToken());
            if (!Objects.equals(user.getKeycloakId(), identity.subject())
                    || !Boolean.TRUE.equals(identity.emailVerified())) {
                return unauthorized("Invalid email or password");
            }

            if (user.getStatus() == UserStatus.PENDING_VERIFICATION
                    || !Boolean.TRUE.equals(user.getEmailVerified())) {
                if (!synchronizeEmailVerification(user.getKeycloakId())) {
                    return unauthorized("Invalid email or password");
                }
            }
            if (user.getStatus() != UserStatus.ACTIVE || !Boolean.TRUE.equals(user.getEmailVerified())) {
                return unauthorized("Invalid email or password");
            }
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
            rateLimiter.resetLoginRate(email, remoteAddress);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookieService.issue(
                            tokens.refreshToken(), tokens.refreshExpiresIn()).toString())
                    .body(AuthTokenResponse.success(
                            "Login successful", tokens.toTokenResponse(), toUserResponse(user)));
        } catch (BadCredentialsException ex) {
            return unauthorized("Invalid email or password");
        } catch (KeycloakIntegrationException ex) {
            log.error("Keycloak integration error during login");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(AuthResponse.failure("Authentication is temporarily unavailable"));
        }
    }

    public ResponseEntity<?> refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return unauthorized("Invalid or expired refresh token");
        }
        try {
            KeycloakTokenResponse tokens = keycloakAuthService.refreshUserTokens(refreshToken);
            KeycloakAuthService.AuthenticatedIdentity identity =
                    keycloakAuthService.getIdentityFromAccessToken(tokens.accessToken());
            User user = userRepository.findByKeycloakId(identity.subject()).orElse(null);
            if (user == null || user.getStatus() != UserStatus.ACTIVE
                    || !Boolean.TRUE.equals(user.getEmailVerified())
                    || !Boolean.TRUE.equals(identity.emailVerified())) {
                return unauthorized("Invalid or expired refresh token");
            }
            String nextRefreshToken = tokens.refreshToken() == null || tokens.refreshToken().isBlank()
                    ? refreshToken : tokens.refreshToken();
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookieService.issue(
                            nextRefreshToken, tokens.refreshExpiresIn()).toString())
                    .body(AuthTokenResponse.success(
                            "Token refreshed successfully", tokens.toTokenResponse(), null));
        } catch (BadCredentialsException ex) {
            return unauthorized("Invalid or expired refresh token");
        } catch (KeycloakIntegrationException ex) {
            log.error("Keycloak integration error during token refresh");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(AuthResponse.failure("Authentication is temporarily unavailable"));
        }
    }

    @Transactional
    public ResponseEntity<?> logout(String refreshToken) {
        try {
            keycloakAuthService.logoutUser(refreshToken);
        } catch (KeycloakIntegrationException ex) {
            log.warn("Keycloak logout could not be completed");
            SecurityContextHolder.clearContext();
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookieService.clear().toString())
                    .body(AuthResponse.failure("Logout could not be completed"));
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieService.clear().toString())
                .body(AuthResponse.success("Logout successful", null));
    }

    @Transactional
    public ResponseEntity<?> forgotPassword(ForgotPasswordRequest request) {
        return ResponseEntity.ok(AuthResponse.of(true,
                "If the account exists, password reset instructions will be sent.", null));
    }

    @Transactional
    public ResponseEntity<?> resetPassword(ResetPasswordRequest request) {
        return ResponseEntity.badRequest().body(AuthResponse.of(false, "Not yet implemented", null));
    }

    private ResponseEntity<?> unauthorized(String message) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponse.failure(message));
    }
}
