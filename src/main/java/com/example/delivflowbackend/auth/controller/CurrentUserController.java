package com.example.delivflowbackend.auth.controller;

import com.example.delivflowbackend.auth.dto.UserInfoDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

/**
 * Current user endpoint for the OIDC login session.
 *
 * Returns only safe OIDC claims (subject, username, email, email verification,
 * display name). Never returns access tokens, refresh tokens, ID tokens or
 * client secrets. Unauthenticated requests are answered with 401 by the security
 * filter chain (API requests are not redirected to the login page).
 */
@RestController
@RequestMapping("/api/me")
@RequiredArgsConstructor
public class CurrentUserController {

    @GetMapping
    public UserInfoDto currentUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            return map(oidcUser);
        }
        if (principal instanceof Jwt jwt) {
            return map(jwt);
        }
        throw new IllegalStateException("Unexpected authentication principal: " + principal.getClass().getName());
    }

    private UserInfoDto map(OidcUser oidcUser) {
        OidcIdToken idToken = oidcUser.getIdToken();
        return map(
                idToken != null ? idToken.getSubject() : null,
                oidcUser.getClaimAsString("preferred_username"),
                oidcUser.getClaimAsString("name"),
                oidcUser.getClaimAsString("email"),
                oidcUser.getClaimAsBoolean("email_verified"));
    }

    private UserInfoDto map(Jwt jwt) {
        return map(
                jwt.getSubject(),
                jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("name"),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsBoolean("email_verified"));
    }

    private UserInfoDto map(String sub, String preferredUsername, String name, String email, Boolean emailVerified) {
        String username = preferredUsername != null ? preferredUsername : (name != null ? name : sub);
        return new UserInfoDto(sub, username, email, emailVerified, name);
    }
}