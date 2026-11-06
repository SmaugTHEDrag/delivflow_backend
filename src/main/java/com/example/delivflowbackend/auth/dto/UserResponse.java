package com.example.delivflowbackend.auth.dto;

import com.example.delivflowbackend.user.entity.UserStatus;
import lombok.Builder;
import lombok.Data;

/**
 * Response returned by GET /api/auth/me.
 */
@Data
@Builder
public class UserResponse {
    private String id;
    private String keycloakId;
    private String username;
    private String email;
    private String fullName;
    private String firstName;
    private String lastName;
    private boolean emailVerified;
    private UserStatus status;
}