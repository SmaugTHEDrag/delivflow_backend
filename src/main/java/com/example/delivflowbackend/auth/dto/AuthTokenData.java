package com.example.delivflowbackend.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthTokenData(
        String accessToken,
        String tokenType,
        Long expiresIn,
        UserResponse user) {
}
