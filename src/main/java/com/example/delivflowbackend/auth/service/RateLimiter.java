package com.example.delivflowbackend.auth.service;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.Instant;
import java.time.Duration;

/**
 * Simple in-memory rate limiter for login attempts.
 * <p>
 * In production, replace with a distributed rate limiter (Redis, etc.).
 * </p>
 */
@Component
public class RateLimiter {

    private final ConcurrentHashMap<String, AtomicInteger> attemptMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> lockMap = new ConcurrentHashMap<>();

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(30);

    /**
     * Check if the user is within the login attempt limit.
     *
     * @param email the user's email (normalized)
     * @return true if within limits, false if rate limited
     */
    public synchronized boolean checkLoginRate(String email) {
        Instant now = Instant.now();

        // Check if there's a lock on this email
        Instant lockUntil = lockMap.get(email);
        if (lockUntil != null && now.isBefore(lockUntil)) {
            return false; // Still locked
        }

        // Reset lock if past the lock duration
        if (lockUntil != null && now.isAfter(lockUntil)) {
            lockMap.remove(email);
        }

        // Get or create the attempt counter
        AtomicInteger attempts = attemptMap.computeIfAbsent(email, k -> new AtomicInteger());

        if (attempts.incrementAndGet() > MAX_ATTEMPTS) {
            // Lock the account for LOCK_DURATION
            lockMap.put(email, now.plus(LOCK_DURATION));
            // Reset the counter after locking
            attemptMap.remove(email);
            return false;
        }

        return attempts.get() <= MAX_ATTEMPTS;
    }

    /** Reset the rate limiter counter for a user (e.g., after successful login). */
    public synchronized void resetLoginRate(String email) {
        attemptMap.remove(email);
        lockMap.remove(email);
    }
}