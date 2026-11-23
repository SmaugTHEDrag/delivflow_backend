package com.example.delivflowbackend.user.dto;

import jakarta.validation.constraints.Size;

public record UpdateMyProfileRequest(
        @Size(max = 160, message = "First name must not be longer than 160 characters")
        String firstName,

        @Size(max = 160, message = "Last name must not be longer than 160 characters")
        String lastName,

        @Size(max = 500, message = "Avatar URL must not be longer than 500 characters")
        String avatarUrl
) {
}
