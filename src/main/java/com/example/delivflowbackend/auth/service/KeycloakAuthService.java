package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.config.KeycloakProperties;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import com.example.delivflowbackend.common.util.EmailUtils;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.List;
import java.util.Map;

/**
 * Backend-to-Keycloak intermediary for server-to-server Admin API operations.
 * The frontends never talk to Keycloak directly; they only call
 * {@code /api/auth/register}, and this service creates the user in Keycloak
 * through the Admin API using the backend's confidential service-account
 * client (client authentication enabled, Direct Access Grants and Implicit
 * Flow disabled).
 *
 * Browser-based user login is handled by Spring Security's OIDC Authorization
 * Code Flow (session-based), not by this service.
 *
 * Roles are membership-based in DelivFlow (workspace_members.role /
 * project_members.role), so registration does NOT assign any realm role.
 *
 * Keycloak error bodies are logged but NEVER forwarded to clients - the
 * frontends only see the generic messages defined here.
 */
@Service
public class KeycloakAuthService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthService.class);

    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";

    private static final ParameterizedTypeReference<List<Map<String, Object>>> USER_LIST =
            new ParameterizedTypeReference<>() {
            };

    private final KeycloakProperties properties;
    private final IUserRepository userRepository;
    private final RestClient restClient = RestClient.create();

    public KeycloakAuthService(KeycloakProperties properties, IUserRepository userRepository) {
        this.properties = properties;
        this.userRepository = userRepository;
    }

    // ------------------------------------------------------------------
    // Keycloak Admin API plumbing (service account)
    // ------------------------------------------------------------------
    /**
     * Create a user in Keycloak through the Admin API (service account).
     * No realm role is assigned - roles in DelivFlow are membership-based.
     */
    public void register(RegisterRequest request) {
        String adminToken = getAdminToken();
        String email = EmailUtils.normalizeEmail(request.email());
        String username = email; // Keycloak requires a username; use the (unique) email

        if (userExists(adminToken, "username", username)) {
            throw new UserAlreadyExistsException("User already exists: " + username);
        }

        Map<String, Object> userRepresentation = Map.of(
                "username", username,
                "email", email,
                "firstName", request.displayName() == null ? "" : request.displayName(),
                "lastName", "",
                "enabled", true,
                "emailVerified", false,
                "credentials", List.of(
                        Map.of("type", "password", "value", request.password(), "temporary", false)
                ),
                "requiredActions", List.of("VERIFY_EMAIL")
        );

        try {
            restClient.post()
                    .uri(properties.getAdminRealmsUrl() + "/{realm}/users", properties.getRealm())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(userRepresentation)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientResponseException ex) {
            if (ex.getStatusCode().value() == 409) {
                throw new UserAlreadyExistsException("User already exists: " + username);
            }
            log.error("Keycloak user creation failed with status {}: {}", ex.getStatusCode().value(),
                    ex.getResponseBodyAsString());
            throw new KeycloakIntegrationException("User registration is temporarily unavailable");
        } catch (RuntimeException ex) {
            log.error("Keycloak user creation failed: {}", ex.getMessage());
            throw new KeycloakIntegrationException("User registration is temporarily unavailable", ex);
        }

        // Send a verification email through the Keycloak Admin API.
        try {
            String userId = findUserId(adminToken, username);
            if (userId != null) {
                sendVerificationEmail(adminToken, userId);
            }
        } catch (RuntimeException ex) {
            log.error("Failed to trigger Keycloak verification email for '{}': {}", username, ex.getMessage());
        }
    }
    /** Obtain an admin access token using the backend service-account client. */
    private String getAdminToken() {
        MultiValueMap<String, String> form = grantType(GRANT_TYPE_CLIENT_CREDENTIALS);
        form.add("client_id", properties.getBackendClientId());
        form.add("client_secret", properties.getBackendClientSecret());
        try {
            KeycloakTokenResponse response = restClient.post()
                    .uri(properties.getTokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(KeycloakTokenResponse.class);
            if (response == null || response.accessToken() == null) {
                throw new KeycloakIntegrationException("Keycloak admin token has no access_token");
            }
            return response.accessToken();
        } catch (RestClientResponseException ex) {
            log.error("Keycloak admin token request failed with status {}: {}",
                    ex.getStatusCode().value(), ex.getResponseBodyAsString());
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable");
        } catch (RuntimeException ex) {
            log.error("Keycloak admin token request failed: {}", ex.getMessage());
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable", ex);
        }
    }

    /** Check whether a Keycloak user exists for the given attribute/value. */
    private boolean userExists(String adminToken, String attribute, String value) {
        List<Map<String, Object>> users = restClient.get()
                .uri(properties.getAdminRealmsUrl() + "/{realm}/users"
                        + "?{attribute}={value}&exact=true",
                        properties.getRealm(), attribute, value)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .body(USER_LIST);
        return users != null && !users.isEmpty();
    }

    /** Lookup the Keycloak id of a user by username (exact match). */
    private String findUserId(String adminToken, String username) {
        List<Map<String, Object>> users = restClient.get()
                .uri(properties.getAdminRealmsUrl() + "/{realm}/users"
                        + "?username={value}&exact=true",
                        properties.getRealm(), username)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .body(USER_LIST);
        if (users == null || users.isEmpty()) {
            return null;
        }
        Object id = users.get(0).get("id");
        return id == null ? null : String.valueOf(id);
    }

    /** Send a verification email through the Keycloak Admin API. */
    private void sendVerificationEmail(String adminToken, String userId) {
        try {
            restClient.put()
                    .uri(properties.getAdminRealmsUrl()
                                    + "/{realm}/users/{userId}/send-verify-email",
                            properties.getRealm(), userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException ex) {
            log.error("Failed to send Keycloak verification email for user '{}': {}", userId, ex.getMessage());
        }
    }

    private static MultiValueMap<String, String> grantType(String grantType) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", grantType);
        return form;
    }
}