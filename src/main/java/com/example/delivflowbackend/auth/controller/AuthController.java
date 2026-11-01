package com.example.delivflowbackend.auth.controller;

import com.example.delivflowbackend.auth.dto.AuthError;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.service.KeycloakAuthService;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Public authentication endpoints (permitAll). Browser-based login uses Spring
 * Security's OIDC Authorization Code Flow and redirects to Keycloak
 * ({@code /oauth2/authorization/keycloak}); this controller only exposes the
 * server-to-server user registration backed by the Keycloak Admin API.
 */
@RestController
@RequestMapping("api/auth")
@Tag(name = "Auth API", description = "User registration via the Keycloak Admin API")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakAuthService keycloakAuthService;

    @Operation(summary = "Register a new customer account",
            description = "Creates the user in Keycloak through the Admin API. Roles are membership-based " +
                          "and are not assigned here.")
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            keycloakAuthService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "Account created"));
        } catch (UserAlreadyExistsException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(AuthError.of(ex.getMessage()));
        } catch (KeycloakIntegrationException ex) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(AuthError.of(ex.getMessage()));
        }
    }
}