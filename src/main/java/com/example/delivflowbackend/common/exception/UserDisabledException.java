package com.example.delivflowbackend.common.exception;

import org.springframework.security.access.AccessDeniedException;

/**
 * Thrown when an authenticated request comes from a user whose application
 * account is DISABLED (status = DISABLED). Answered with 403.
 */
public class UserDisabledException extends AccessDeniedException {

    public UserDisabledException(String message) {
        super(message);
    }
}