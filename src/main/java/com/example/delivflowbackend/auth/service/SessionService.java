package com.example.delivflowbackend.auth.service;

import com.example.delivflowbackend.auth.dto.UserResponse;
import com.example.delivflowbackend.common.exception.UserNotFoundException;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.repository.IUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import java.util.UUID;

/**
 * Server-side session management for backend-managed authentication.
 * <p>
 * Uses Spring HTTP session with a cookie (HttpOnly, Secure, SameSite-configured).
 * Tokens are never exposed to the frontend.
 * </p>
 */
@Service
public class SessionService {

    private final IUserRepository userRepository;

    public SessionService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Create a server-side session for the authenticated user.
     * The session ID is stored in an HttpOnly cookie.
     *
     * @param user the authenticated user
     * @return the session ID
     */
    public String createSession(User user) {
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                .getRequest().getSession(true);

        // Store user identity in the session
        session.setAttribute("userId", user.getId().toString());
        session.setAttribute("keycloakId", user.getKeycloakId());
        session.setAttribute("email", user.getEmail());
        session.setAttribute("emailVerified", user.getEmailVerified());
        session.setAttribute("status", user.getStatus());
        session.setMaxInactiveInterval(30 * 60); // 30 minutes

        return session.getId();
    }

    /**
     * Get the current authenticated user from the session.
     *
     * @return the user, or null if no authenticated session
     */
    public User getCurrentUser() {
        HttpSession session = getHttpSession();
        if (session == null) {
            return null;
        }

        String userId = (String) session.getAttribute("userId");
        if (userId == null) {
            return null;
        }

        try {
            return userRepository.findById(UUID.fromString(userId)).orElse(null);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    /**
     * Invalidate the current server-side session and clear the cookie.
     */
    public void invalidateSession() {
        HttpSession session = getHttpSession();
        if (session != null) {
            session.invalidate();
        }
    }

    /**
     * Get the current HTTP session, or null if no session exists.
     *
     * @return the HttpSession, or null
     */
    private HttpSession getHttpSession() {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        if (attr == null) {
            return null;
        }
        HttpServletRequest request = attr.getRequest();
        return request.getSession(false); // false = don't create a new session
    }
}