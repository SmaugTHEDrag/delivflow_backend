package com.example.delivflowbackend.user.repository;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface IUserRepository extends JpaRepository<User, UUID> {

    // find user by normalized email
    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameIgnoreCase(String username);

    // find user by keycloakId
    Optional<User> findByKeycloakId(String keycloakId);

    @Query("SELECT u FROM User u WHERE u.status = :pendingStatus "
            + "OR (u.status = :activeStatus AND u.emailVerified = false)")
    List<User> findAllEligibleForEmailVerificationReconciliation(
            @Param("pendingStatus") UserStatus pendingStatus,
            @Param("activeStatus") UserStatus activeStatus);
}