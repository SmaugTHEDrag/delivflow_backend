package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.user.repository.IUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.MediaType;

/**
 * Syncs the authenticated Keycloak subject to an application user on every
 * request, after the bearer token has been validated.
 *
 * Runs after BearerTokenAuthenticationFilter so the SecurityContext already
 * holds the Jwt. A DISABLED user is rejected here (403) so that authorization
 * checks effectively run on every request, independent of filter ordering.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class KeycloakUserSyncFilter extends OncePerRequestFilter {

    private final CurrentUserService currentUserService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            try {
                // ensures the application user exists and is not DISABLED
                currentUserService.loadOrCreate(jwt);
            } catch (Exception e) {
                if (e instanceof com.example.delivflowbackend.common.exception.UserDisabledException) {
                    writeError(response, HttpServletResponse.SC_FORBIDDEN, e.getMessage());
                    return;
                }
                log.error("Error syncing user from Keycloak JWT: {}", e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), Map.of("message", message));
    }
}