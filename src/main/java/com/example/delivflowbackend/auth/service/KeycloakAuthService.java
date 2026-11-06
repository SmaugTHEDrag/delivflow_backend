package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.config.KeycloakProperties;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.common.exception.BadCredentialsException;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import com.example.delivflowbackend.common.util.EmailUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
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
 * User login and refresh use the backend-to-Keycloak token endpoint. The
 * frontend receives only the short-lived access token; refresh credentials stay
 * in an HttpOnly cookie.
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
    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();

    private static final ParameterizedTypeReference<List<Map<String, Object>>> USER_LIST =
            new ParameterizedTypeReference<>() {
            };
    private static final ParameterizedTypeReference<Map<String, Object>> USER_REPRESENTATION =
            new ParameterizedTypeReference<>() {
            };

    private final KeycloakProperties properties;
    private final JwtDecoder jwtDecoder;
    private final RestClient restClient;

    @Autowired
    public KeycloakAuthService(KeycloakProperties properties, JwtDecoder jwtDecoder) {
        this(properties, jwtDecoder, RestClient.create());
    }

    public KeycloakAuthService(KeycloakProperties properties,
                               JwtDecoder jwtDecoder,
                               RestClient restClient) {
        this.properties = properties;
        this.jwtDecoder = jwtDecoder;
        this.restClient = restClient;
    }

    public record CreatedUserIdentity(String keycloakId, String issuer) {
    }

    public record AuthenticatedIdentity(String issuer, String subject, Boolean emailVerified) {
    }

    // ------------------------------------------------------------------
    // Keycloak Admin API plumbing (service account)
    // ------------------------------------------------------------------
    /**
     * Create a user in Keycloak through the Admin API (service account).
     * No realm role is assigned - roles in DelivFlow are membership-based.
     */
    public CreatedUserIdentity register(RegisterRequest request) {
        String adminToken = getAdminToken();
        String email = EmailUtils.normalizeEmail(request.getEmail());
        String username = request.getUsername().trim();

        try {
            if (userExists(adminToken, "username", username) || userExists(adminToken, "email", email)) {
                throw new UserAlreadyExistsException("User already exists: " + username);
            }
        } catch (UserAlreadyExistsException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            log.error("Keycloak user lookup failed during registration", ex);
            throw new KeycloakIntegrationException("User registration is temporarily unavailable", ex);
        }

        Map<String, Object> userRepresentation = Map.of(
                "username", username,
                "email", email,
                "firstName", request.getFirstName().trim(),
                "lastName", request.getLastName().trim(),
                "enabled", true,
                "emailVerified", false,
                "credentials", List.of(
                        Map.of("type", "password", "value", request.getPassword(), "temporary", false)
                ),
                "requiredActions", List.of("VERIFY_EMAIL")
        );

        ResponseEntity<Void> createResponse;
        try {
            createResponse = restClient.post()
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
            log.error("Keycloak user creation failed with status {}", ex.getStatusCode().value());
            throw new KeycloakIntegrationException("User registration is temporarily unavailable");
        } catch (RuntimeException ex) {
            log.error("Keycloak user creation failed: {}", ex.getMessage());
            throw new KeycloakIntegrationException("User registration is temporarily unavailable", ex);
        }

        String userId = userIdFromLocation(createResponse.getHeaders().getLocation());
        if (userId == null) {
            try {
                userId = findUserId(adminToken, username);
            } catch (RuntimeException ex) {
                log.error("Keycloak user was created but its ID could not be retrieved", ex);
                throw new KeycloakIntegrationException(
                        "The created Keycloak user ID could not be retrieved", ex);
            }
        }
        if (userId == null || userId.isBlank()) {
            log.error("Keycloak user was created but the Admin API did not return its ID");
            throw new KeycloakIntegrationException("The created Keycloak user ID could not be retrieved");
        }

        return new CreatedUserIdentity(userId, properties.getIssuerUri());
    }

    /** Authenticate the user directly against Keycloak using the confidential backend client. */
    public KeycloakTokenResponse authenticateUserPassword(String username, String password) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new BadCredentialsException("Invalid email or password");
        }

        if (!properties.isDirectAccessGrantEnabled()) {
            throw new KeycloakIntegrationException(
                    "Password-based login is disabled. Set KEYCLOAK_DIRECT_ACCESS_GRANT_ENABLED=true "
                            + "(app.keycloak.direct-access-grant.enabled) and enable Direct Access Grants "
                            + "for Keycloak client '" + properties.getBackendClientId() + "'.");
        }
        if (properties.getBackendClientSecret() == null || properties.getBackendClientSecret().isBlank()) {
            throw new KeycloakIntegrationException(
                    "Keycloak backend client secret is not configured; set KEYCLOAK_BACKEND_CLIENT_SECRET "
                            + "for client '" + properties.getBackendClientId() + "'.");
        }

        MultiValueMap<String, String> form = grantType("password");
        form.add("client_id", properties.getBackendClientId());
        form.add("client_secret", properties.getBackendClientSecret());
        form.add("username", username);
        form.add("password", password);
        form.add("scope", "openid email");

        try {
            KeycloakTokenResponse response = restClient.post()
                    .uri(properties.getTokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(KeycloakTokenResponse.class);

            if (response == null || response.accessToken() == null || response.accessToken().isBlank()
                    || response.refreshToken() == null || response.refreshToken().isBlank()
                    || response.expiresIn() == null) {
                throw new KeycloakIntegrationException("Keycloak login response was incomplete");
            }

            return response;
        } catch (RestClientResponseException ex) {
            KeycloakErrorResponse error = parseKeycloakError(ex);
            String description = sanitizeErrorDescription(error.description(), username);
            log.warn("Keycloak password grant rejected: status={} error={} description={}",
                    ex.getStatusCode().value(), error.error(), description);

            if (ex.getStatusCode().is4xxClientError()) {
                if ("invalid_grant".equals(error.error())) {
                    String normalizedDescription = description.toLowerCase(java.util.Locale.ROOT);
                    if (normalizedDescription.contains("not fully set up")
                            || normalizedDescription.contains("required action")
                            || normalizedDescription.contains("verify email")) {
                        throw new BadCredentialsException("Keycloak account has outstanding required actions");
                    }
                    if (normalizedDescription.contains("account is disabled")
                            || normalizedDescription.contains("user is disabled")
                            || normalizedDescription.contains("temporarily disabled")) {
                        throw new BadCredentialsException("Keycloak account is disabled");
                    }
                    if (normalizedDescription.contains("invalid user credentials")
                            || normalizedDescription.contains("invalid credentials")) {
                        throw new BadCredentialsException("Invalid email or password");
                    }
                }
                throw new KeycloakIntegrationException(
                        "Keycloak rejected the password grant (error=" + error.error() + ")");
            }
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable");
        } catch (RuntimeException ex) {
            log.error("Keycloak password grant failed");
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable", ex);
        }
    }

    /** Exchange a valid refresh token for a rotated Keycloak token pair. */
    public KeycloakTokenResponse refreshUserTokens(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        requireBackendClientSecret();

        MultiValueMap<String, String> form = grantType("refresh_token");
        form.add("client_id", properties.getBackendClientId());
        form.add("client_secret", properties.getBackendClientSecret());
        form.add("refresh_token", refreshToken);
        try {
            KeycloakTokenResponse response = restClient.post()
                    .uri(properties.getTokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(KeycloakTokenResponse.class);
            if (response == null || response.accessToken() == null || response.accessToken().isBlank()
                    || response.expiresIn() == null) {
                throw new KeycloakIntegrationException("Keycloak refresh response was incomplete");
            }
            return response;
        } catch (RestClientResponseException ex) {
            KeycloakErrorResponse error = parseKeycloakError(ex);
            if (ex.getStatusCode().is4xxClientError() && "invalid_grant".equals(error.error())) {
                throw new BadCredentialsException("Invalid or expired refresh token");
            }
            log.warn("Keycloak token refresh failed with status {} and error={}",
                    ex.getStatusCode().value(), error.error());
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable");
        } catch (BadCredentialsException | KeycloakIntegrationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            log.warn("Keycloak token refresh failed");
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable", ex);
        }
    }

    /** Revoke the supplied refresh token at Keycloak. */
    public void logoutUser(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }
        try {
            requireBackendClientSecret();
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("client_id", properties.getBackendClientId());
            form.add("client_secret", properties.getBackendClientSecret());
            form.add("refresh_token", refreshToken);
            restClient.post()
                    .uri(properties.getLogoutEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientResponseException ex) {
            if (ex.getStatusCode().value() == 400) {
                log.info("Keycloak refresh session was already invalidated");
                return;
            }
            throw new KeycloakIntegrationException("Keycloak logout is temporarily unavailable", ex);
        } catch (RuntimeException ex) {
            throw new KeycloakIntegrationException("Keycloak logout is temporarily unavailable", ex);
        }
    }

    private void requireBackendClientSecret() {
        if (properties.getBackendClientSecret() == null || properties.getBackendClientSecret().isBlank()) {
            throw new KeycloakIntegrationException("Keycloak backend client secret is not configured");
        }
    }

    private KeycloakErrorResponse parseKeycloakError(RestClientResponseException exception) {
        try {
            JsonNode response = JSON_MAPPER.readTree(exception.getResponseBodyAsString());
            return new KeycloakErrorResponse(
                    nodeText(response.get("error")),
                    nodeText(response.get("error_description")));
        } catch (JacksonException parseFailure) {
            return new KeycloakErrorResponse("unparseable_response", null);
        }
    }

    private String sanitizeErrorDescription(String description, String email) {
        if (description == null || description.isBlank()) {
            return "not provided";
        }
        String sanitized = description
                .replaceAll("(?i)(password|client_secret|access_token|refresh_token)\\s*[:=]\\s*[^\\s,;]+",
                        "$1=[redacted]")
                .replaceAll("[\\r\\n\\t]", " ");
        if (email != null && !email.isBlank()) {
            sanitized = sanitized.replace(email, "[email]");
        }
        return sanitized.length() <= 256 ? sanitized : sanitized.substring(0, 256);
    }

    private String nodeText(JsonNode node) {
        return node == null || node.isNull() ? "not provided" : node.asString();
    }

    private record KeycloakErrorResponse(String error, String description) {
    }

    public String getSubjectFromAccessToken(String accessToken) {
        return getIdentityFromAccessToken(accessToken).subject();
    }

    public AuthenticatedIdentity getIdentityFromAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new BadCredentialsException("Invalid email or password");
        }

        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String subject = jwt.getSubject();
            String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            if (issuer == null || issuer.isBlank() || subject == null || subject.isBlank()) {
                throw new BadCredentialsException("Invalid email or password");
            }
            return new AuthenticatedIdentity(issuer, subject, jwt.getClaimAsBoolean("email_verified"));
        } catch (JwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    /** Request a Keycloak verification email after the local profile is committed. */
    public void sendVerificationEmail(String userId) {
        String adminToken = getAdminToken();
        try {
            restClient.put()
                    .uri(properties.getAdminRealmsUrl()
                                    + "/{realm}/users/{userId}/execute-actions-email"
                                    + "?client_id={clientId}&redirect_uri={redirectUri}&lifespan={lifespan}",
                            properties.getRealm(),
                            userId,
                            properties.getEmailVerificationClientId(),
                            properties.getEmailVerificationRedirectUri(),
                            properties.getEmailVerificationLifespanSeconds())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(List.of("VERIFY_EMAIL"))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientResponseException ex) {
            log.warn("Keycloak verification email request failed with status {} for user {}",
                    ex.getStatusCode().value(), userId);
            throw new KeycloakIntegrationException("Verification email could not be sent", ex);
        } catch (RuntimeException ex) {
            log.warn("Keycloak verification email request failed for user {}", userId, ex);
            throw new KeycloakIntegrationException("Verification email could not be sent", ex);
        }
    }

    /** Read verification state from Keycloak; caller-supplied state is never trusted. */
    public boolean isEmailVerifiedInKeycloak(String userId) {
        String adminToken = getAdminToken();
        try {
            Map<String, Object> user = restClient.get()
                    .uri(properties.getAdminRealmsUrl() + "/{realm}/users/{userId}",
                            properties.getRealm(), userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .body(USER_REPRESENTATION);
            if (user == null) {
                throw new KeycloakIntegrationException("Keycloak user state could not be retrieved");
            }
            return Boolean.TRUE.equals(user.get("emailVerified"));
        } catch (KeycloakIntegrationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            log.warn("Keycloak verification state lookup failed for user {}", userId, ex);
            throw new KeycloakIntegrationException("Keycloak verification state could not be retrieved", ex);
        }
    }

    /** Compensating action when PostgreSQL cannot persist a newly created user. */
    public void deleteUser(String userId) {
        String adminToken = getAdminToken();
        try {
            restClient.delete()
                    .uri(properties.getAdminRealmsUrl() + "/{realm}/users/{userId}",
                            properties.getRealm(), userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException ex) {
            throw new KeycloakIntegrationException("Keycloak user cleanup failed", ex);
        }
    }

    /** Obtain an admin access token using the backend service-account client. */
    private String getAdminToken() {
        requireBackendClientSecret();
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
            if (response == null || response.accessToken() == null || response.accessToken().isBlank()) {
                throw new KeycloakIntegrationException("Keycloak admin token has no access_token");
            }
            return response.accessToken();
        } catch (RestClientResponseException ex) {
            log.error("Keycloak admin token request failed with status {}", ex.getStatusCode().value());
            throw new KeycloakIntegrationException("Authentication is temporarily unavailable");
        } catch (RuntimeException ex) {
            log.error("Keycloak admin token request failed");
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

    private String userIdFromLocation(URI location) {
        if (location == null || location.getPath() == null) {
            return null;
        }
        String path = location.getPath();
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return null;
        }
        return path.substring(lastSlash + 1);
    }

    private static MultiValueMap<String, String> grantType(String grantType) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", grantType);
        return form;
    }
}