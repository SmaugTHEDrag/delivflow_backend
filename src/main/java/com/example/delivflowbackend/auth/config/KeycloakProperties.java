package com.example.delivflowbackend.auth.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Keycloak connection settings for the backend's service-account client,
 * read from environment-driven properties only (never hardcoded).
 * See application.yaml for the property names.
 *
 * The backend client is confidential: client authentication is enabled,
 * Direct Access Grants and Implicit Flow are disabled. It is used only for
 * server-to-server Admin API calls (user registration). Browser-based user
 * login uses the OIDC Authorization Code Flow managed by Spring Security and
 * is configured under {@code spring.security.oauth2.client.registration.keycloak}.
 */
@Getter
@Component
public class KeycloakProperties {

    private final String baseUrl;        // e.g. http://localhost:8180
    private final String realm;          // e.g. delivflow
    private final String backendClientId;// service-account client used for the Admin API
    private final String backendClientSecret;

    public KeycloakProperties(
            @Value("${app.keycloak.base-url}") String baseUrl,
            @Value("${app.keycloak.realm}") String realm,
            @Value("${app.keycloak.backend-client-id}") String backendClientId,
            @Value("${app.keycloak.backend-client-secret:}") String backendClientSecret) {
        this.baseUrl = baseUrl;
        this.realm = realm;
        this.backendClientId = backendClientId;
        this.backendClientSecret = backendClientSecret;
    }

    /** Token endpoint, e.g. http://localhost:8180/realms/delivflow/protocol/openid-connect/token */
    public String getTokenEndpoint() {
        return baseUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    /** Admin REST root, e.g. http://localhost:8180/admin/realms */
    public String getAdminRealmsUrl() {
        return baseUrl + "/admin/realms";
    }
}