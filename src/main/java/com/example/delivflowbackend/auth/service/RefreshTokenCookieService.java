package com.example.delivflowbackend.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RefreshTokenCookieService {

    public static final String COOKIE_NAME = "DELIVFLOW_REFRESH";

    private final boolean secure;
    private final String sameSite;

    public RefreshTokenCookieService(
            @Value("${app.auth.refresh-cookie.secure:true}") boolean secure,
            @Value("${app.auth.refresh-cookie.same-site:Lax}") String sameSite) {
        this.secure = secure;
        this.sameSite = sameSite;
    }

    public ResponseCookie issue(String token, Long maxAgeSeconds) {
        ResponseCookie.ResponseCookieBuilder cookie = ResponseCookie.from(COOKIE_NAME, token)
                .httpOnly(true)
                .secure(secure)
                .path("/api/auth")
                .sameSite(sameSite);
        if (maxAgeSeconds != null && maxAgeSeconds >= 0) {
            cookie.maxAge(Duration.ofSeconds(maxAgeSeconds));
        }
        return cookie.build();
    }

    public ResponseCookie clear() {
        return ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(secure)
                .path("/api/auth")
                .sameSite(sameSite)
                .maxAge(Duration.ZERO)
                .build();
    }
}
