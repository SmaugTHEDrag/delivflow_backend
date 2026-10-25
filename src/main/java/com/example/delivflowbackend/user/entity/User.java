package com.example.delivflowbackend.user.entity;

import jakarta.persistence.*;
import java.util.UUID;
import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.type.SqlTypes;
import org.hibernate.annotations.JdbcTypeCode;

/**
 * Application user profile.
 *
 * Authentication (password, login, tokens) belongs to Keycloak; this table only
 * stores application-level profile data. The link to Keycloak is the OIDC pair
 * ({@code keycloak_issuer}, {@code keycloak_subject}) -- the JWT "iss" and "sub"
 * claims. The subject is treated as opaque text, not assumed to be a UUID.
 *
 * Columns match {@code delivflow.sql} (Flyway {@code V1__init_delivflow.sql}):
 * {@code users} table.
 */
@Entity
@Table(
        name = "users",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_users_oidc_identity",
                columnNames = {"keycloak_issuer", "keycloak_subject"}
        )
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "keycloak_issuer", nullable = false, length = 512)
    private String keycloakIssuer;

    @Column(name = "keycloak_subject", nullable = false, length = 255)
    private String keycloakSubject;

    @Column(name = "email", length = 320)
    private String email;

    @Column(name = "display_name", length = 160)
    private String displayName;

    @Column(name = "avatar_url", columnDefinition = "TEXT")
    private String avatarUrl;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    @Column(name = "status", nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "deactivated_at")
    private Instant deactivatedAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private Instant createdAt;

    /**
     * Maintained by the database trigger {@code trg_users_updated_at}; the
     * application never writes this column (hence {@code insertable = false,
     * updatable = false}).
     */
    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;
}