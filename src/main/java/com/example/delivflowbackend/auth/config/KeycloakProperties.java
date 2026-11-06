package com.example.delivflowbackend.auth.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Keycloak connection settings for the backend's service-account client,
 * read from environment-driven properties only (never hardcoded).
 * See application.yaml for the property names.
 *
 * The backend client credentials are used only for Keycloak Admin API and
 * token endpoint requests. The client secret is never sent to the frontend.
 */
@Getter
@Component
public class KeycloakProperties {

    private final String baseUrl;        // e.g. http://localhost:8180
    private final String realm;          // e.g. delivflow
    private final String issuerUri;
    private final String backendClientId;// service-account client used for the Admin API
    private final String backendClientSecret;
    private final boolean directAccessGrantEnabled;
    private final String emailVerificationClientId;
    private final String emailVerificationRedirectUri;
    private final int emailVerificationLifespanSeconds;

    public KeycloakProperties(
            @Value("${app.keycloak.base-url}") String baseUrl,
            @Value("${app.keycloak.realm}") String realm,
            @Value("${app.keycloak.issuer-uri}") String issuerUri,
            @Value("${app.keycloak.backend-client-id}") String backendClientId,
            @Value("${app.keycloak.backend-client-secret:}") String backendClientSecret,
            @Value("${app.keycloak.direct-access-grant.enabled:true}") boolean directAccessGrantEnabled,
            @Value("${app.keycloak.email-verification.client-id}") String emailVerificationClientId,
            @Value("${app.keycloak.email-verification.redirect-uri}") String emailVerificationRedirectUri,
            @Value("${app.keycloak.email-verification.lifespan-seconds}") int emailVerificationLifespanSeconds) {
        this.baseUrl = baseUrl;
        this.realm = realm;
        this.issuerUri = issuerUri;
        this.backendClientId = backendClientId;
        this.backendClientSecret = backendClientSecret;
        this.directAccessGrantEnabled = directAccessGrantEnabled;
        this.emailVerificationClientId = emailVerificationClientId;
        this.emailVerificationRedirectUri = emailVerificationRedirectUri;
        this.emailVerificationLifespanSeconds = emailVerificationLifespanSeconds;
    }

    /** Token endpoint, e.g. http://localhost:8180/realms/delivflow/protocol/openid-connect/token */
    public String getTokenEndpoint() {
        return baseUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    /** Keycloak OIDC logout endpoint used to revoke the refresh-token session. */
    public String getLogoutEndpoint() {
        return baseUrl + "/realms/" + realm + "/protocol/openid-connect/logout";
    }

    /** Admin REST root, e.g. http://localhost:8180/admin/realms */
    public String getAdminRealmsUrl() {
        return baseUrl + "/admin/realms";
    }
}