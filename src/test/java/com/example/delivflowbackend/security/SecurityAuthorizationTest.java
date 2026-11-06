package com.example.delivflowbackend.security;

import com.example.delivflowbackend.auth.dto.RegisterRequest;
import com.example.delivflowbackend.auth.dto.AuthTokenResponse;
import com.example.delivflowbackend.auth.dto.KeycloakTokenResponse;
import com.example.delivflowbackend.auth.dto.LoginRequest;
import com.example.delivflowbackend.auth.dto.UserResponse;
import com.example.delivflowbackend.auth.service.AuthService;
import com.example.delivflowbackend.common.exception.ResourceNotFoundException;
import com.example.delivflowbackend.common.security.CurrentUserService;
import com.example.delivflowbackend.user.controller.UserController;
import com.example.delivflowbackend.user.dto.UserPageResponse;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.service.IUserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Authorization behaviour of the resource server:
 * 401 without a token, 403 for a role that is not allowed, public reads stay open.
 *
 * The realm-role -> ROLE_* mapping itself is covered by converter logic; here the
 * authorities are supplied directly. The KeycloakUserSyncFilter is mocked so it does
 * not hit the user repository during these authorization tests.
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
    private IUserService userService;

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
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredAccessTokenIsRejectedByResourceServer() throws Exception {
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer expired-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void swaggerDoesNotRequireBearerTokenForRegister() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/auth/register'].post.security").doesNotExist())
                .andExpect(jsonPath("$.paths['/api/users'].get.security[0].bearerAuth").exists());
    }

    @Test
    void usersEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void usersEndpointRequiresAdminRole() throws Exception {
        mockMvc.perform(get("/api/users").with(customer()))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanCallUsersEndpoint() throws Exception {
        when(userService.getAllUsers(any(), any())).thenReturn(new UserPageResponse());
        mockMvc.perform(get("/api/users").with(admin()))
                .andExpect(status().isOk());
    }

    @Test
    void userByIdRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/users/1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateUserRequiresAuthentication() throws Exception {
        mockMvc.perform(put("/api/users/1")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.com\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disableUserRequiresAuthentication() throws Exception {
        mockMvc.perform(delete("/api/users/1").with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missingResourceReturnsConsistentErrorBody() throws Exception {
        UUID unknownId = UUID.fromString("11111111-1111-1111-1111-111111111111");
        when(userService.getUserById(unknownId)).thenThrow(new ResourceNotFoundException("User not found"));
        mockMvc.perform(get("/api/users/{id}", unknownId).with(admin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found"));
    }

    private static RequestPostProcessor customer() {
        return jwt()
                .jwt(builder -> builder
                        .issuer("http://localhost:8080/realms/test")
                        .subject("kc-customer"))
                .authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"));
    }

    private static RequestPostProcessor admin() {
        return jwt()
                .jwt(builder -> builder
                        .issuer("http://localhost:8080/realms/test")
                        .subject("kc-admin"))
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}
