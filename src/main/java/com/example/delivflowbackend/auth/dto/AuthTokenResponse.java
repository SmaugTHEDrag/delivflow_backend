package com.example.delivflowbackend.auth.dto;

/**
 * Login and refresh response. The refresh token is deliberately absent.
 */
public record AuthTokenResponse(
        boolean success,
        String message,
        AuthTokenData data) {

    public static AuthTokenResponse success(String message, TokenResponse tokens, UserResponse user) {
        return new AuthTokenResponse(true, message,
                new AuthTokenData(tokens.accessToken(), tokens.tokenType(), tokens.expiresIn(), user));
    }
}
