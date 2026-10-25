package com.example.delivflowbackend.user.repository;

import com.example.delivflowbackend.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;
import java.util.UUID;

public interface IUserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User> {

    // find user by the Keycloak OIDC identity pair (issuer, subject)
    Optional<User> findByKeycloakIssuerAndKeycloakSubject(String keycloakIssuer, String keycloakSubject);

    // find user by normalized email
    Optional<User> findByEmail(String email);

    boolean existsByKeycloakIssuerAndKeycloakSubject(String keycloakIssuer, String keycloakSubject);
}