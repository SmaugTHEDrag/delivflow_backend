package com.example.delivflowbackend.common.security;

import com.example.delivflowbackend.common.exception.UserDisabledException;
import com.example.delivflowbackend.user.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.MockHttpServletResponse;
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

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private KeycloakUserSyncFilter filter;

    @Test
    void activeUserLetsTheChainProceed() throws Exception {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:8180/realms/delivflow")
                .subject("kc-active")
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(jwt, "token", List.of()));
        when(currentUserService.loadOrCreate(jwt)).thenReturn(new User());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.wasCalled).isTrue();
        verify(currentUserService).loadOrCreate(jwt);
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
        when(currentUserService.loadOrCreate(jwt))
                .thenThrow(new UserDisabledException("Account is disabled"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(chain.wasCalled).isFalse();
        SecurityContextHolder.clearContext();
    }

    @Test
    void requestWithoutTokenContinuesChain() throws Exception {
        SecurityContextHolder.clearContext();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.wasCalled).isTrue();
        verifyNoInteractions(currentUserService);
        SecurityContextHolder.clearContext();
    }
}