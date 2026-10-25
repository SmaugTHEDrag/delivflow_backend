package com.example.delivflowbackend.user.dto;

import com.example.delivflowbackend.user.entity.UserStatus;
import java.util.UUID;
import java.time.Instant;
import lombok.Data;

@Data
public class UserDTO {
    private UUID id;
    private String email;
    private String displayName;
    private String avatarUrl;
    private Boolean emailVerified;
    private UserStatus status;
    private Instant lastLoginAt;
    private Instant createdAt;
    private Instant updatedAt;
}