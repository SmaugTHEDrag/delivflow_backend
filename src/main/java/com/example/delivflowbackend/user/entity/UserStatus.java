package com.example.delivflowbackend.user.entity;

/**
 * Application user status, mirrored by the PostgreSQL {@code user_status} enum
 * ({@code ACTIVE}, {@code DISABLED}).
 *
 * Users are never hard-deleted when their Keycloak account is disabled: the row is
 * marked {@code DISABLED} (and {@code deactivated_at} is set) so audit references
 * stay intact.
 */
public enum UserStatus {
    ACTIVE,
    DISABLED
}