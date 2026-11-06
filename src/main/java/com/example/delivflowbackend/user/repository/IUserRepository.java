package com.example.delivflowbackend.user.repository;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface IUserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User> {

    // find user by normalized email
    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameIgnoreCase(String username);

    // find user by keycloakId
    Optional<User> findByKeycloakId(String keycloakId);

    List<User> findAllByStatusAndEmailVerifiedFalse(UserStatus status);
}