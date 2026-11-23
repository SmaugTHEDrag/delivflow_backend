package com.example.delivflowbackend.auth.controller;

import com.example.delivflowbackend.auth.dto.UserInfoDto;
import com.example.delivflowbackend.common.security.CurrentUserService;
import com.example.delivflowbackend.user.dto.UpdateMyProfileRequest;
import com.example.delivflowbackend.user.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;

import java.util.Objects;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    private static final Set<String> EDITABLE_PROFILE_FIELDS = Set.of("firstName", "lastName", "avatarUrl");

    private final CurrentUserService currentUserService;
    private final Validator validator;

    @Operation(summary = "Read the authenticated user's profile")
    @GetMapping
    public UserInfoDto currentUser() {
        return toProfile(currentUserService.getCurrentUser());
    }

    @Operation(summary = "Update the authenticated user's editable profile fields")
    @PatchMapping
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Only firstName, lastName, and avatarUrl may be updated",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = UpdateMyProfileRequest.class)))
    public ResponseEntity<?> updateCurrentUser(@RequestBody Map<String, Object> fields) {
        if (fields == null || !EDITABLE_PROFILE_FIELDS.containsAll(fields.keySet())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Unsupported profile field"));
        }
        if (hasNonStringValue(fields, "firstName")
                || hasNonStringValue(fields, "lastName")
                || hasNonStringValue(fields, "avatarUrl")) {
            return ResponseEntity.badRequest().body(Map.of("message", "Profile fields must be strings or null"));
        }

        UpdateMyProfileRequest request = new UpdateMyProfileRequest(
                stringValue(fields, "firstName"),
                stringValue(fields, "lastName"),
                stringValue(fields, "avatarUrl"));
        Map<String, String> errors = validator.validate(request).stream()
                .collect(Collectors.toMap(
                        violation -> violation.getPropertyPath().toString(),
                        ConstraintViolation::getMessage,
                        (first, ignored) -> first,
                        LinkedHashMap::new));
        if (!errors.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Validation failed", "errors", errors));
        }

        User user = currentUserService.updateCurrentUserProfile(
                request.firstName(), request.lastName(), request.avatarUrl());
        return ResponseEntity.ok(toProfile(user));
    }

    private boolean hasNonStringValue(Map<String, Object> fields, String name) {
        Object value = fields.get(name);
        return value != null && !(value instanceof String);
    }

    private String stringValue(Map<String, Object> fields, String name) {
        return (String) fields.get(name);
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
