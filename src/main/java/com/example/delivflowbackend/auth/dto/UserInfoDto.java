package com.example.delivflowbackend.auth.dto;

/**
 * Safe view of the authenticated user returned by {@code GET /api/me}.
 * Only OIDC claims are exposed: no access token, refresh token, ID token,
 * client secret or other credentials are ever returned.
 */
public record UserInfoDto(
        String sub,
        String username,
        String email,
        Boolean emailVerified,
        String name
) {}