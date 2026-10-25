package com.example.delivflowbackend.security;

import com.example.delivflowbackend.common.config.KeycloakJwtAuthenticationConverter;
import com.example.delivflowbackend.common.config.SecurityConfig;
import com.example.delivflowbackend.common.security.KeycloakUserSyncFilter;
import com.example.delivflowbackend.common.exception.ResourceNotFoundException;
import com.example.delivflowbackend.user.controller.UserController;
import com.example.delivflowbackend.user.dto.UserPageResponse;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.service.IUserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
@WebMvcTest(
        controllers = UserController.class,
        properties = "app.cors.allowed-origins=http://localhost:3000"
)
@Import({SecurityConfig.class, KeycloakJwtAuthenticationConverter.class})
class SecurityAuthorizationTest {

    @TestConfiguration
    static class StubJwtDecoderConfiguration {
        // Keycloak is not running during tests; Spring Security only needs a decoder bean.
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> {
                throw new UnsupportedOperationException("JWT decoding is not exercised in this test");
            };
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IUserService userService;

    // Mocked so the filter chain does not sync users against the repository in these tests
    @MockBean
    private KeycloakUserSyncFilter keycloakUserSyncFilter;

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
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.com\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disableUserRequiresAuthentication() throws Exception {
        mockMvc.perform(delete("/api/users/1"))
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
                .jwt(builder -> builder.subject("kc-customer"))
                .authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"));
    }

    private static RequestPostProcessor admin() {
        return jwt()
                .jwt(builder -> builder.subject("kc-admin"))
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}