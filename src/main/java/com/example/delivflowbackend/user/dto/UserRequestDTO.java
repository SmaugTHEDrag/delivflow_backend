package com.example.delivflowbackend.user.dto;

import com.example.delivflowbackend.user.entity.UserStatus;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Application profile data an admin may change.
 * Identity (keycloak_issuer / keycloak_subject) and email verification live in
 * Keycloak and are never updated through this endpoint.
 */
@Data
public class UserRequestDTO {

    @NotBlank(message = "Email does not blank")
    @Email(message = "Email is valid")
    private String email;

    @Size(max = 160, message = "Display name must not be longer than 160 characters")
    private String displayName;

    @Size(max = 500, message = "Avatar URL must not be longer than 500 characters")
    private String avatarUrl;

    @NotBlank(message = "Status cannot be blank")
    @Pattern(regexp = "ACTIVE|DISABLED", message = "Status must be either ACTIVE or DISABLED")
    private String status;
}