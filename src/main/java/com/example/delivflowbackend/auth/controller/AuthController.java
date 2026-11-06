package com.example.delivflowbackend.auth.controller;

import com.example.delivflowbackend.auth.dto.CsrfTokenResponse;
import com.example.delivflowbackend.auth.dto.LoginRequest;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.service.AuthService;
import com.example.delivflowbackend.auth.service.RefreshTokenCookieService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final CookieCsrfTokenRepository csrfTokenRepository;

    @Operation(summary = "Register a new customer account")
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @Operation(summary = "Resend the Keycloak email-verification link")
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@RequestParam String email) {
        return authService.resendVerification(email);
    }

    @Operation(summary = "Synchronize a verified Keycloak email into the local profile")
    @PutMapping("/email-verification/sync/{keycloakId}")
    public ResponseEntity<Void> synchronizeEmailVerification(@PathVariable String keycloakId) {
        return authService.synchronizeEmailVerification(keycloakId)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.accepted().build();
    }

    @Operation(summary = "Login with email and password")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @Operation(summary = "Exchange the refresh-token cookie for a new access token")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @CookieValue(name = RefreshTokenCookieService.COOKIE_NAME, required = false) String refreshToken) {
        return authService.refresh(refreshToken);
    }

    @Operation(summary = "Obtain the CSRF token for cookie-authenticated requests")
    @GetMapping("/csrf")
    public CsrfTokenResponse csrf(
            CsrfToken csrfToken,
            HttpServletRequest request,
            HttpServletResponse response) {
        csrfTokenRepository.saveToken(csrfToken, request, response);
        return new CsrfTokenResponse(csrfToken.getToken(), csrfToken.getHeaderName());
    }

    @Operation(summary = "Get current authenticated user profile")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        return authService.me(authentication);
    }

    @Operation(summary = "Revoke the refresh token and clear its cookie")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = RefreshTokenCookieService.COOKIE_NAME, required = false) String refreshToken) {
        return authService.logout(refreshToken);
    }
}
