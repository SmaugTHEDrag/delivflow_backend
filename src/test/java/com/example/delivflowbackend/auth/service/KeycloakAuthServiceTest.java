package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.config.KeycloakProperties;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.common.exception.BadCredentialsException;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.common.exception.UserAlreadyExistsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.hamcrest.Matchers.containsString;

@ExtendWith(OutputCaptureExtension.class)
class KeycloakAuthServiceTest {

    private static final String BASE_URL = "http://keycloak";
    private static final String REALM = "delivflow";
    private static final String ISSUER = BASE_URL + "/realms/" + REALM;
    private static final String ADMIN_TOKEN_URL =
            ISSUER + "/protocol/openid-connect/token";
    private static final String LOGOUT_URL =
            ISSUER + "/protocol/openid-connect/logout";
    private static final String USERS_URL = BASE_URL + "/admin/realms/" + REALM + "/users";

    @Test
    void registerCreatesKeycloakUserAndReturnsActualAdminUserId() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build());

        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"admin-token\"}", MediaType.APPLICATION_JSON));
        server.expect(userSearch("username"))
                .andRespond(MockRestResponseCreators.withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(userSearch("email"))
                .andRespond(MockRestResponseCreators.withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(requestTo(USERS_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().json("""
                        {
                          "username": "thainguyen",
                          "email": "alice@example.com",
                          "firstName": "Thai",
                          "lastName": "Nguyen",
                          "enabled": true,
                          "emailVerified": false,
                          "credentials": [{"type": "password", "temporary": false}],
                          "requiredActions": ["VERIFY_EMAIL"]
                        }
                        """, false))
                .andRespond(MockRestResponseCreators.withStatus(HttpStatus.CREATED)
                        .location(URI.create(USERS_URL + "/actual-keycloak-id")));

        KeycloakAuthService.CreatedUserIdentity identity = service.register(
                new RegisterRequest("thainguyen", " Alice@Example.COM ", "StrongPassword123!", "Thai", "Nguyen"));

        assertThat(identity.keycloakId()).isEqualTo("actual-keycloak-id");
        assertThat(identity.issuer()).isEqualTo(ISSUER);
        server.verify();
    }

    @Test
    void registerRejectsAnExistingKeycloakEmailBeforeCreatingUser() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build());

        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"admin-token\"}", MediaType.APPLICATION_JSON));
        server.expect(userSearch("username"))
                .andRespond(MockRestResponseCreators.withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(userSearch("email"))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "[{\"id\":\"existing-id\",\"email\":\"alice@example.com\"}]",
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> service.register(
                new RegisterRequest("thainguyen", "Alice@Example.COM", "StrongPassword123!", "Thai", "Nguyen")))
                .isInstanceOf(UserAlreadyExistsException.class);
        server.verify();
    }

    @Test
    void verificationEmailUsesAdminEndpointAndSurfacesFailureForTheCallerToHandle() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build());

        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"admin-token\"}", MediaType.APPLICATION_JSON));
        server.expect(request -> {
                    var uri = request.getURI();
                    var query = UriComponentsBuilder.fromUri(uri).build().getQueryParams();
                    assertThat(uri.getPath()).isEqualTo(
                            "/admin/realms/" + REALM + "/users/user-id/execute-actions-email");
                    assertThat(query.getFirst("client_id")).isEqualTo("frontend-client");
                    assertThat(URLDecoder.decode(
                            query.getFirst("redirect_uri"), StandardCharsets.UTF_8))
                            .isEqualTo("http://localhost:3000/login");
                    assertThat(query.getFirst("lifespan")).isEqualTo("86400");
                })
                .andExpect(method(HttpMethod.PUT))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("[\"VERIFY_EMAIL\"]"))
                .andRespond(MockRestResponseCreators.withServerError());

        assertThatThrownBy(() -> service.sendVerificationEmail("user-id"))
                .isInstanceOf(KeycloakIntegrationException.class);
        server.verify();
    }

    @Test
    void verificationSyncReadsTheCurrentKeycloakUserState() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build());

        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"admin-token\"}", MediaType.APPLICATION_JSON));
        server.expect(requestTo(USERS_URL + "/user-id"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"id\":\"user-id\",\"emailVerified\":true}", MediaType.APPLICATION_JSON));

        assertThat(service.isEmailVerifiedInKeycloak("user-id")).isTrue();
        server.verify();
    }

    @Test
    void enabledDirectAccessGrantPostsPasswordGrantUsingBackendClientCredentials() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);

        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("grant_type=password")))
                .andExpect(content().string(containsString("client_id=backend-client")))
                .andExpect(content().string(containsString("client_secret=client-secret")))
                .andExpect(content().string(containsString("username=thainguyen")))
                .andExpect(content().string(containsString("password=correct-password")))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"access-token\",\"refresh_token\":\"refresh-token\","
                                + "\"expires_in\":300,\"token_type\":\"Bearer\"}",
                        MediaType.APPLICATION_JSON));

        var response = service.authenticateUserPassword("thainguyen", "correct-password");

        assertThat(response.accessToken()).isEqualTo("access-token");
        server.verify();
    }

    @Test
    void disabledDirectAccessGrantFailsBeforeCallingKeycloak() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), false);

        assertThatThrownBy(() -> service.authenticateUserPassword("alice@example.com", "correct-password"))
                .isInstanceOf(KeycloakIntegrationException.class)
                .hasMessageContaining("KEYCLOAK_DIRECT_ACCESS_GRANT_ENABLED=true")
                .hasMessageContaining("app.keycloak.direct-access-grant.enabled")
                .hasMessageContaining("Keycloak client 'backend-client'");
        server.verify();
    }

    @Test
    void refreshExchangesRefreshTokenAndReturnsRotatedPair() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("grant_type=refresh_token")))
                .andExpect(content().string(containsString("refresh_token=old-refresh")))
                .andExpect(content().string(containsString("client_secret=client-secret")))
                .andRespond(MockRestResponseCreators.withSuccess(
                        "{\"access_token\":\"new-access\",\"refresh_token\":\"new-refresh\","
                                + "\"expires_in\":240,\"refresh_expires_in\":600,\"token_type\":\"Bearer\"}",
                        MediaType.APPLICATION_JSON));

        KeycloakTokenResponse response = service.refreshUserTokens("old-refresh");

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isEqualTo("new-refresh");
        server.verify();
    }

    @Test
    void refreshMapsExpiredRefreshTokenToGenericCredentialFailure() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_grant\",\"error_description\":\"Token expired\"}"));

        assertThatThrownBy(() -> service.refreshUserTokens("expired"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid or expired refresh token");
        server.verify();
    }

    @Test
    void logoutPostsRefreshTokenToKeycloakLogoutEndpoint() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(LOGOUT_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("refresh_token=current-refresh")))
                .andExpect(content().string(containsString("client_secret=client-secret")))
                .andRespond(MockRestResponseCreators.withSuccess());

        service.logoutUser("current-refresh");
        server.verify();
    }

    @Test
    void missingBackendClientSecretFailsWithConfigurationErrorBeforeCallingKeycloak() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true, "");

        assertThatThrownBy(() -> service.authenticateUserPassword("alice@example.com", "password"))
                .isInstanceOf(KeycloakIntegrationException.class)
                .hasMessageContaining("KEYCLOAK_BACKEND_CLIENT_SECRET")
                .hasMessageContaining("backend-client");
        server.verify();
    }

    @Test
    void invalidCredentialsAreLoggedAsInvalidGrantNotAsClientConfigurationFailure(CapturedOutput output) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("""
                                {"error":"invalid_grant","error_description":"Invalid user credentials"}
                                """));

        assertThatThrownBy(() -> service.authenticateUserPassword("alice@example.com", "wrong"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid email or password");
        assertThat(output.getAll())
                .contains("status=400")
                .contains("error=invalid_grant")
                .contains("description=Invalid user credentials");
        server.verify();
    }

    @Test
    void invalidClientIsNotMisreportedAsInvalidUserCredentials(CapturedOutput output) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withStatus(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("""
                                {"error":"invalid_client","error_description":"Client authentication failed"}
                                """));

        assertThatThrownBy(() -> service.authenticateUserPassword("alice@example.com", "password"))
                .isInstanceOf(KeycloakIntegrationException.class)
                .hasMessageContaining("error=invalid_client");
        assertThat(output.getAll())
                .contains("status=401")
                .contains("error=invalid_client")
                .contains("Client authentication failed")
                .doesNotContain("Invalid email or password");
        server.verify();
    }

    @Test
    void requiredActionIsDistinguishedFromWrongPasswordAndSensitiveTextIsRedacted(CapturedOutput output) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        KeycloakAuthService service = service(builder.build(), true);
        server.expect(requestTo(ADMIN_TOKEN_URL))
                .andRespond(MockRestResponseCreators.withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("""
                                {"error":"invalid_grant","error_description":"Account is not fully set up: VERIFY_EMAIL; access_token=secret-value"}
                                """));

        assertThatThrownBy(() -> service.authenticateUserPassword("alice@example.com", "password"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("outstanding required actions");
        assertThat(output.getAll())
                .contains("error=invalid_grant")
                .contains("not fully set up")
                .doesNotContain("secret-value")
                .doesNotContain("alice@example.com");
        server.verify();
    }

    private KeycloakAuthService service(RestClient restClient) {
        return service(restClient, true);
    }

    private KeycloakAuthService service(RestClient restClient, boolean directAccessGrantEnabled) {
        return service(restClient, directAccessGrantEnabled, "client-secret");
    }

    private KeycloakAuthService service(
            RestClient restClient,
            boolean directAccessGrantEnabled,
            String backendClientSecret) {
        KeycloakProperties properties = new KeycloakProperties(
                BASE_URL, REALM, ISSUER, "backend-client", backendClientSecret, directAccessGrantEnabled,
                "frontend-client", "http://localhost:3000/login", 86400);
        return new KeycloakAuthService(properties, token -> {
            throw new UnsupportedOperationException("JWT decoding is not used by these tests");
        }, restClient);
    }

    private RequestMatcher userSearch(String attribute) {
        return request -> {
            assertThat(request.getMethod()).isEqualTo(HttpMethod.GET);
            assertThat(request.getURI().getPath()).isEqualTo("/admin/realms/" + REALM + "/users");
            assertThat(request.getURI().getQuery()).contains(attribute + "=");
            assertThat(request.getURI().getQuery())
                    .contains(attribute.equals("username") ? "thainguyen" : "alice");
        };
    }
}
