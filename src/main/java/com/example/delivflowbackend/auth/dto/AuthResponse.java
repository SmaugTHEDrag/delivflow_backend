package com.example.delivflowbackend.auth.dto;

/**
 * Response returned by auth endpoints (register, login, me).
 */
public record AuthResponse(
        boolean success,
        String message,
        UserResponse data
) {
    public static AuthResponse success(String message, UserResponse data) {
        return new AuthResponse(true, message, data);
    }

    public static AuthResponse failure(String message) {
        return new AuthResponse(false, message, null);
    }

    public static AuthResponse of(boolean success, String message, UserResponse data) {
        return new AuthResponse(success, message, data);
    }
}