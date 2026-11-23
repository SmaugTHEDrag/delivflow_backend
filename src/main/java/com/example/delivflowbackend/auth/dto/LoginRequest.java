package com.example.delivflowbackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/auth/login request.
 * Email is normalized (trimmed + lowercased) before authentication.
 */
public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Size(max = 320, message = "Email must not be longer than 320 characters")
        String email,

        @NotBlank(message = "Password is required")
        String password
) {
}