package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.common.util.EmailUtils;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Instance-local throttling for authentication requests. Production deployments
 * with multiple backend instances must also configure rate limiting at the edge.
 */
@Component
public class RateLimiter {

    static final int MAX_TRACKED_KEYS = 10_000;

    private static final int LOGIN_IP_LIMIT = 30;
    private static final int LOGIN_ACCOUNT_IP_LIMIT = 5;
    private static final int RESEND_IP_LIMIT = 10;
    private static final int RESEND_EMAIL_LIMIT = 3;
    private static final Duration LOGIN_IP_WINDOW = Duration.ofMinutes(15);
    private static final Duration LOGIN_ACCOUNT_IP_WINDOW = Duration.ofMinutes(30);
    private static final Duration RESEND_IP_WINDOW = Duration.ofMinutes(10);
    private static final Duration RESEND_EMAIL_WINDOW = Duration.ofHours(1);
    private static final Duration CLEANUP_INTERVAL = Duration.ofMinutes(1);
    private static final String UNKNOWN_ADDRESS = "unknown";

    private final Clock clock;
    private final LinkedHashMap<String, Bucket> buckets = new LinkedHashMap<>();
    private Instant nextCleanup = Instant.MIN;

    public RateLimiter() {
        this(Clock.systemUTC());
    }

    RateLimiter(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    public synchronized boolean checkLoginRate(String email, String remoteAddress) {
        Instant now = clock.instant();
        cleanupExpired(now);
        String ip = normalizeAddress(remoteAddress);
        boolean ipAllowed = consume("login-ip:" + ip, LOGIN_IP_LIMIT, LOGIN_IP_WINDOW, now);
        boolean accountIpAllowed = consume(
                "login-account-ip:" + ip + ":" + emailKey(email),
                LOGIN_ACCOUNT_IP_LIMIT,
                LOGIN_ACCOUNT_IP_WINDOW,
                now);
        return ipAllowed && accountIpAllowed;
    }

    public synchronized boolean checkVerificationResendRate(String email, String remoteAddress) {
        Instant now = clock.instant();
        cleanupExpired(now);
        String ip = normalizeAddress(remoteAddress);
        boolean ipAllowed = consume("resend-ip:" + ip, RESEND_IP_LIMIT, RESEND_IP_WINDOW, now);
        boolean emailAllowed = consume(
                "resend-email:" + emailKey(email), RESEND_EMAIL_LIMIT, RESEND_EMAIL_WINDOW, now);
        return ipAllowed && emailAllowed;
    }

    public synchronized void resetLoginRate(String email, String remoteAddress) {
        buckets.remove("login-account-ip:" + normalizeAddress(remoteAddress) + ":" + emailKey(email));
    }

    synchronized int trackedKeyCount() {
        return buckets.size();
    }

    private boolean consume(String key, int limit, Duration window, Instant now) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= MAX_TRACKED_KEYS) {
                return false;
            }
            bucket = new Bucket(now.plus(window));
            buckets.put(key, bucket);
        } else if (!now.isBefore(bucket.windowEndsAt)) {
            bucket.reset(now.plus(window));
        }

        if (bucket.attempts >= limit) {
            return false;
        }
        bucket.attempts++;
        return true;
    }

    private void cleanupExpired(Instant now) {
        if (now.isBefore(nextCleanup)) {
            return;
        }
        Iterator<Map.Entry<String, Bucket>> iterator = buckets.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!now.isBefore(iterator.next().getValue().windowEndsAt)) {
                iterator.remove();
            }
        }
        nextCleanup = now.plus(CLEANUP_INTERVAL);
    }

    private String emailKey(String email) {
        String normalized = EmailUtils.normalizeEmail(email);
        if (normalized == null) {
            normalized = "";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private String normalizeAddress(String remoteAddress) {
        if (remoteAddress == null || remoteAddress.isBlank()) {
            return UNKNOWN_ADDRESS;
        }
        String address = remoteAddress.trim();
        return address.length() <= 64 ? address : address.substring(0, 64);
    }

    private static final class Bucket {
        private Instant windowEndsAt;
        private int attempts;

        private Bucket(Instant windowEndsAt) {
            this.windowEndsAt = windowEndsAt;
        }

        private void reset(Instant nextWindowEndsAt) {
            windowEndsAt = nextWindowEndsAt;
            attempts = 0;
        }
    }
}
