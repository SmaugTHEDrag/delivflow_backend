package com.example.delivflowbackend.security;

import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.dto.AuthTokenResponse;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.LoginRequest;
import com.example.delivflowbackend.auth.dto.UserResponse;
import com.example.delivflowbackend.auth.service.AuthService;
import com.example.delivflowbackend.common.security.CurrentUserService;
import com.example.delivflowbackend.common.exception.KeycloakIntegrationException;
import com.example.delivflowbackend.user.entity.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.ActiveProfiles;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Authorization behavior of the resource server and authenticated profile routes.
 * The KeycloakUserSyncFilter is mocked so tests do not hit the user repository.
 */
@SpringBootTest(
    properties = {
        "spring.datasource.password=dummy",
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=none"
    }
)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private CurrentUserService currentUserService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void configureInvalidTokenDecoder() {
        when(jwtDecoder.decode("invalid-token")).thenThrow(new BadJwtException("Invalid JWT signature"));
        when(jwtDecoder.decode("expired-token")).thenThrow(new BadJwtException("JWT has expired"));
    }

    @Test
    void registerDoesNotRequireAuthenticationOrCsrfToken() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenReturn(ResponseEntity.status(201).build());

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"newuser\",\"email\":\"new@example.com\","
                                + "\"password\":\"Password123!\",\"firstName\":\"New\",\"lastName\":\"User\"}"))
            .andExpect(status().isCreated());
    }

    @Test
    void registrationRejectsWeakPasswordBeforeCallingService() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"weakuser\",\"email\":\"weak@example.com\","
                                + "\"password\":\"password\",\"firstName\":\"Weak\",\"lastName\":\"Password\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginReturnsAccessTokenAndProfileWithoutRefreshTokenInJson() throws Exception {
        ResponseEntity<?> loginResponse = ResponseEntity.ok(
                AuthTokenResponse.success("Login successful",
                        new KeycloakTokenResponse("access-value", "refresh-value", 300L, 1800L, "Bearer")
                                .toTokenResponse(),
                        UserResponse.builder().email("person@example.com").username("person")
                                .firstName("Person").lastName("User").build()));
        org.mockito.Mockito.doReturn(loginResponse).when(authService).login(any(LoginRequest.class));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"person@example.com\",\"password\":\"StrongPassword123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("access-value"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.expiresIn").value(300))
                .andExpect(jsonPath("$.data.user.email").value("person@example.com"))
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist());
    }

    @Test
    void csrfBootstrapReturnsCookieCsrfTokenForFrontendHeader() throws Exception {
        mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.headerName").value("X-CSRF-TOKEN"));
    }

    @Test
    void logoutRequiresCsrfTokenEvenForBearerAuthenticatedRequests() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("browser")))
                .andExpect(status().isForbidden());
    }

    @Test
    void refreshRequiresCsrfProtectionForHttpOnlyCookieRequests() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new jakarta.servlet.http.Cookie("DELIVFLOW_REFRESH", "refresh-value")))
                .andExpect(status().isForbidden());
    }

    @Test
    void verificationSyncRequiresAnAuthenticatedCaller() throws Exception {
        mockMvc.perform(put("/api/auth/email-verification/sync/keycloak-user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void verifiedEmailSyncReturnsNoContent() throws Exception {
        when(authService.synchronizeEmailVerification("caller-user")).thenReturn(true);

        mockMvc.perform(put("/api/auth/email-verification/sync/caller-user")
                        .with(jwt().jwt(token -> token.subject("caller-user"))))
                .andExpect(status().isNoContent());

        verify(authService).synchronizeEmailVerification("caller-user");
    }

    @Test
    void unverifiedEmailSyncReturnsAccepted() throws Exception {
        when(authService.synchronizeEmailVerification("caller-user")).thenReturn(false);

        mockMvc.perform(put("/api/auth/email-verification/sync/caller-user")
                        .with(jwt().jwt(token -> token.subject("caller-user"))))
                .andExpect(status().isAccepted());
    }

    @Test
    void keycloakSyncOutageReturnsGenericServiceUnavailable() throws Exception {
        when(authService.synchronizeEmailVerification("caller-user"))
                .thenThrow(new KeycloakIntegrationException("internal infrastructure details"));

        mockMvc.perform(put("/api/auth/email-verification/sync/caller-user")
                        .with(jwt().jwt(token -> token.subject("caller-user"))))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message")
                        .value("Email verification synchronization is temporarily unavailable"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .content().string(org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("internal infrastructure details"))));
    }

        @Test
        void verificationSyncCannotTargetAnotherKeycloakUser() throws Exception {
                mockMvc.perform(put("/api/auth/email-verification/sync/another-user")
                                                .with(jwt().jwt(token -> token.subject("caller-user"))))
                                .andExpect(status().isForbidden());
        }

    @Test
    void currentUserProfileReadAndUpdateRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(patch("/api/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"firstName\":\"New\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void currentUserCanReadAndUpdateOnlyEditableProfileFields() throws Exception {
        User user = new User();
        user.setKeycloakId("current-subject");
        user.setUsername("original-user");
        user.setEmail("original@example.com");
        user.setEmailVerified(true);
        user.setFirstName("Updated");
        user.setLastName("Name");
        user.setAvatarUrl("https://example.com/avatar.png");
        when(currentUserService.getCurrentUser()).thenReturn(user);
        when(currentUserService.updateCurrentUserProfile(
                "Updated", "Name", "https://example.com/avatar.png")).thenReturn(user);

        mockMvc.perform(get("/api/me").with(jwt().jwt(token -> token.subject("current-subject"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("current-subject"))
                .andExpect(jsonPath("$.firstName").value("Updated"))
                .andExpect(jsonPath("$.lastName").value("Name"))
                .andExpect(jsonPath("$.avatarUrl").value("https://example.com/avatar.png"));

        mockMvc.perform(patch("/api/me")
                        .with(jwt().jwt(token -> token.subject("current-subject")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"firstName\":\"Updated\",\"lastName\":\"Name\","
                                + "\"avatarUrl\":\"https://example.com/avatar.png\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("original-user"))
                .andExpect(jsonPath("$.email").value("original@example.com"))
                .andExpect(jsonPath("$.firstName").value("Updated"))
                .andExpect(jsonPath("$.lastName").value("Name"));

        mockMvc.perform(patch("/api/me")
                        .with(jwt().jwt(token -> token.subject("current-subject")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"changed-user\",\"email\":\"changed@example.com\"}"))
                .andExpect(status().isBadRequest());
        org.mockito.Mockito.verify(currentUserService).updateCurrentUserProfile(
                "Updated", "Name", "https://example.com/avatar.png");
    }

    @Test
    void deprecatedAuthMeRouteDelegatesProfileLookupToCurrentUserService() throws Exception {
        User user = new User();
        user.setKeycloakId("current-subject");
        user.setUsername("original-user");
        user.setEmail("original@example.com");
        user.setEmailVerified(true);
        user.setFirstName("Current");
        user.setLastName("User");
        when(currentUserService.requireLocalUser(any(Jwt.class))).thenReturn(user);

        mockMvc.perform(get("/api/auth/me")
                        .with(jwt().jwt(token -> token.subject("current-subject")
                                .claim("email_verified", true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.keycloakId").value("current-subject"))
                .andExpect(jsonPath("$.data.email").value("original@example.com"));
    }

    @Test
    void refreshReadsHttpOnlyCookieAndReturnsRotatedCookieWithCsrf() throws Exception {
        ResponseEntity<?> refreshResponse = ResponseEntity.ok()
                .header("Set-Cookie", "DELIVFLOW_REFRESH=new-refresh; Path=/api/auth; HttpOnly; Secure")
                .body(AuthTokenResponse.success("Token refreshed successfully",
                        new KeycloakTokenResponse("new-access", "new-refresh", 300L, 1200L, "Bearer")
                                .toTokenResponse(),
                        null));
        org.mockito.Mockito.doReturn(refreshResponse).when(authService).refresh("old-refresh");

        mockMvc.perform(post("/api/auth/refresh")
                .cookie(new jakarta.servlet.http.Cookie("DELIVFLOW_REFRESH", "old-refresh"))
                .with(csrf().asHeader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("new-access"))
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist());
        org.mockito.Mockito.verify(authService).refresh("old-refresh");
    }

    @Test
    void invalidJwtIsRejectedByResourceServer() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredAccessTokenIsRejectedByResourceServer() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer expired-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void swaggerDoesNotRequireBearerTokenForRegister() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/auth/register'].post.security").doesNotExist())
                .andExpect(jsonPath("$.paths['/api/users']").doesNotExist())
                .andExpect(jsonPath("$.paths['/api/auth/me'].get.deprecated").value(true))
                .andExpect(jsonPath("$.paths['/api/me'].get.security[0].bearerAuth").exists())
                .andExpect(jsonPath("$.paths['/api/me'].patch.security[0].bearerAuth").exists());
    }

}
