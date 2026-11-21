package com.example.delivflowbackend.auth.controller;

import com.example.delivflowbackend.auth.dto.UserInfoDto;
import com.example.delivflowbackend.common.security.CurrentUserService;
import com.example.delivflowbackend.user.dto.UpdateMyProfileRequest;
import com.example.delivflowbackend.user.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me")
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
public class CurrentUserController {

    private final CurrentUserService currentUserService;

    @GetMapping
    public UserInfoDto currentUser() {
        return toProfile(currentUserService.getCurrentUser());
    }

    @Operation(summary = "Update the authenticated user's editable profile fields")
    @PatchMapping
    public UserInfoDto updateCurrentUser(@Valid @RequestBody UpdateMyProfileRequest request) {
        User user = currentUserService.updateCurrentUserProfile(
                request.firstName(), request.lastName(), request.avatarUrl());
        return toProfile(user);
    }

    private UserInfoDto toProfile(User user) {
        return new UserInfoDto(
                user.getKeycloakId(),
                user.getUsername(),
                user.getEmail(),
                user.getEmailVerified(),
                java.util.stream.Stream.of(user.getFirstName(), user.getLastName())
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining(" ")).trim(),
                user.getFirstName(),
                user.getLastName(),
                user.getAvatarUrl());
    }
}
