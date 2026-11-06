package com.example.delivflowbackend.auth.dto;

/** Raw Keycloak token endpoint response (snake_case). Internal to the backend
 *  only - KeycloakAuthService maps it to the camelCase TokenResponse. */
public record TokenResponse(
        String accessToken,
        String refreshToken,
        Long expiresIn,
        Long refreshExpiresIn,
        String tokenType) {
}