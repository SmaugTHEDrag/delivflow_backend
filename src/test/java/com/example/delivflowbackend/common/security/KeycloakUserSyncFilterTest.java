package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.exception.UserDisabledException;
import com.example.delivflowbackend.user.entity.User;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeycloakUserSyncFilterTest {

    @Mock
    private CurrentUserService currentUserService;

    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    private KeycloakUserSyncFilter filter;

    @BeforeEach
    void setUp() {
        filter = new KeycloakUserSyncFilter(currentUserService, jsonMapper);
    }

    @Test
    void activeUserLetsTheChainProceed() throws Exception {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:8180/realms/delivflow")
                .subject("kc-active")
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(jwt, "token", List.of()));
        when(currentUserService.requireLocalUser(jwt)).thenReturn(new User());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        verify(currentUserService).requireLocalUser(jwt);
        SecurityContextHolder.clearContext();
    }

    @Test
    void disabledUserIsRejectedWith403AndChainIsNotInvoked() throws Exception {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:8180/realms/delivflow")
                .subject("kc-disabled")
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(jwt, "token", List.of()));
        when(currentUserService.requireLocalUser(jwt))
                .thenThrow(new UserDisabledException("Account is disabled"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getContentAsString()).contains("Account is disabled");
        SecurityContextHolder.clearContext();
    }

    @Test
    void requestWithoutTokenContinuesChain() throws Exception {
        SecurityContextHolder.clearContext();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        verifyNoInteractions(currentUserService);
        SecurityContextHolder.clearContext();
    }

    @Test
    void synchronizationFailureFailsClosed() throws Exception {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:8180/realms/delivflow")
                .subject("kc-user")
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(jwt, "token", List.of()));
        when(currentUserService.requireLocalUser(jwt)).thenThrow(new IllegalStateException("missing identity"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getContentAsString()).contains("Unable to synchronize authenticated user");
        assertThat(chain.getRequest()).isNull();
        SecurityContextHolder.clearContext();
    }
}