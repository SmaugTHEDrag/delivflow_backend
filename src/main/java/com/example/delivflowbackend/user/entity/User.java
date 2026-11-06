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
 * Authentication (password and tokens) belongs to Keycloak; this table stores
 * the application profile and the Keycloak subject used to identify it.
 *
 * The table is managed by Flyway; see the migration history for the legacy
 * profile backfill.
 */
@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_users_keycloak_id", columnNames = {"keycloak_id"}),
                @UniqueConstraint(name = "uq_users_email", columnNames = {"email"})
        }
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

    @Column(name = "keycloak_id", nullable = false, length = 255)
    private String keycloakId;

    @Column(name = "username", nullable = false, length = 320)
    private String username;

    @Column(name = "email", nullable = false, length = 320)
    private String email;

    @Column(name = "first_name", length = 160)
    private String firstName;

    @Column(name = "last_name", length = 160)
    private String lastName;

    @Column(name = "avatar_url", columnDefinition = "TEXT")
    private String avatarUrl;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    @Column(name = "status", nullable = false, columnDefinition = "user_status")
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