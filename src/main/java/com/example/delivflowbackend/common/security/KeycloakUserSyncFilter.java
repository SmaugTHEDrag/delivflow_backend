package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.exception.UserDisabledException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Syncs the authenticated Keycloak subject to an application user
 * on every request, after the bearer token has been validated.
 *
 * Runs after BearerTokenAuthenticationFilter so the SecurityContext
 * already holds the authentication (Jwt for the Bearer-token path,
 * OidcUser for the session-based OIDC login path).
 *
 * Both paths identify users by the same OIDC pair (issuer, subject).
 * A DISABLED user is rejected here (403).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class KeycloakUserSyncFilter extends OncePerRequestFilter {

    private final CurrentUserService currentUserService;

    // Jackson 3 - Spring Boot 4
    private final JsonMapper jsonMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws IOException, ServletException {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            try {
                if (authentication.getPrincipal() instanceof Jwt jwt) {
                    // Bearer-token path
                    currentUserService.loadOrCreate(jwt);
                } else if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                    // Session-based OIDC login path
                    currentUserService.loadOrCreate(oidcUser);
                }

                // Ensures the application user exists and is not DISABLED
            } catch (UserDisabledException e) {

                writeError(
                        response,
                        HttpServletResponse.SC_FORBIDDEN,
                        e.getMessage()
                );
                return;

            } catch (Exception e) {

                log.error(
                        "Error syncing user from Keycloak token",
                        e
                );
            }
        }

        filterChain.doFilter(request, response);
    }

    private void writeError(
            HttpServletResponse response,
            int status,
            String message
    ) throws IOException {

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        jsonMapper.writeValue(
                response.getWriter(),
                Map.of("message", message)
        );
    }
}