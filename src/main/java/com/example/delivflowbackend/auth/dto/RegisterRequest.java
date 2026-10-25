package com.example.delivflowbackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/auth/register request.
 * There is deliberately NO username field: DelivFlow identifies users by the
 * Keycloak (issuer, subject) pair and does not store a username column. Roles
 * are membership-based (workspace_members / project_members), so the backend
 * does not assign any realm role here.
 */
public record RegisterRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String password,

        @Size(max = 160, message = "Display name must not be longer than 160 characters")
        String displayName) {
}