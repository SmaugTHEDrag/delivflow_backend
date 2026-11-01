package com.example.delivflowbackend.common.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.http.HttpStatus;
import java.io.IOException;

/**
 * Logout success handler for the OIDC login session.
 *
 * Local logout always invalidates the HTTP session and clears the session cookie
 * (configured in {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#logout}).
 * When the user authenticated through the OIDC Authorization Code Flow, the
 * browser is additionally redirected to Keycloak's end-session endpoint
 * (discovered from the OIDC provider metadata - the URL is not hardcoded here)
 * with an {@code id_token_hint}, so that the Keycloak SSO session can be
 * terminated as well.
 *
 * Local logout and provider logout are independent: logging out locally always
 * works, even if Keycloak is unreachable or the post-logout redirect URI is not
 * (yet) registered in the Keycloak client. Conversely, logging out of Keycloak
 * does not invalidate the local session - the local session must be logged out
 * separately through {@code POST /logout}.
 */
public class    OidcLogoutSuccessHandler implements LogoutSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OidcLogoutSuccessHandler.class);

    private final OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler;
    private final LogoutSuccessHandler localLogoutSuccessHandler = new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK);

    public OidcLogoutSuccessHandler(OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler) {
        this.oidcLogoutSuccessHandler = oidcLogoutSuccessHandler;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            if (hasOidcIdToken(authentication)) {
                // The SecurityContextLogoutHandler already ran, but LogoutFilter still
                // passes the original Authentication to the success handler, so the
                // ID token is still available for the id_token_hint.
                oidcLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
            } else {
                // No OIDC session (e.g. unauthenticated caller): local logout only.
                localLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
            }
        } catch (Exception e) {
            log.error("Error during logout success handler", e);
        }
    }

    private boolean hasOidcIdToken(Authentication authentication) {
        return authentication != null
                && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof OidcUser;
    }
}