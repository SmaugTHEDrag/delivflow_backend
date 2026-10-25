package com.example.delivflowbackend.common.config;

import com.example.delivflowbackend.common.security.KeycloakUserSyncFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Resource server configuration.
 *
 * Authentication is delegated to Keycloak: the frontends POST credentials to
 * /api/auth/* (a public proxy to Keycloak's token/admin endpoints) and all
 * other APIs carry the resulting Bearer JWT, which this application validates
 * against the realm's JWKS. There is no custom JWT code.
 *
 * The KeycloakUserSyncFilter runs after the bearer token filter to sync the
 * authenticated Keycloak subject to an application user (issuer + sub) and to
 * reject requests from DISABLED users.
 */
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;
    private final KeycloakUserSyncFilter keycloakUserSyncFilter;
    private final ObjectMapper objectMapper;

    // Explicit frontend origins, e.g. "http://localhost:3000,https://app.example.com"
    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Stateless Bearer-token API: no server session, therefore no CSRF token.
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Public authentication endpoints (backend proxies Keycloak;
                        // no redirect flow - the frontends only call these).
                        .requestMatchers(HttpMethod.POST,
                                "/api/auth/login", "/api/auth/refresh",
                                "/api/auth/logout", "/api/auth/register").permitAll()
                        // Public, read-only content (DelivFlow has no public blog/book/review
                        // module; add here if such read-only endpoints are introduced).
                        // Uptime check and API documentation
                        .requestMatchers("/api/ping", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // Everything else (users, ...) requires a Keycloak token.
                        // Role-based gating (e.g. ADMIN) is enforced at the controller
                        // level via @PreAuthorize; membership-based authorization is
                        // enforced in the service layer.
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtAuthenticationConverter))
                )
                // Spring Security rejects the request before any controller runs:
                // answer with the same JSON shape as GlobalExceptionHandler.
                .addFilterAfter(keycloakUserSyncFilter, BearerTokenAuthenticationFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) ->
                                writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentication required"))
                        .accessDeniedHandler((request, response, exception) ->
                                writeError(response, HttpServletResponse.SC_FORBIDDEN, "Access denied"))
                )
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private void writeError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), Map.of("message", message));
    }
}