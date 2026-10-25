package com.example.delivflowbackend.user.controller;
import java.util.UUID;
import com.example.delivflowbackend.user.dto.UserDTO;
import com.example.delivflowbackend.user.dto.UserPageResponse;
import com.example.delivflowbackend.user.dto.UserRequestDTO;
import com.example.delivflowbackend.user.form.UserFilterForm;
import com.example.delivflowbackend.user.service.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Application user administration. Accounts are created by Keycloak on
 * registration; the row here is created on the user's first authenticated request.
 * Users are never hard-deleted: disabling sets status = DISABLED (+ deactivated_at).
 */
@RestController
@RequestMapping("api/users")
@Tag(name = "User API", description = "APIs for application users")
@RequiredArgsConstructor
public class UserController {

    private final IUserService userService;

    @Operation(summary = "Get all users", description = "Admin can get paginated list of users")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<UserPageResponse> getAllUsers(UserFilterForm form, @PageableDefault(page = 0, size = 10, sort = "id", direction = Sort.Direction.ASC) Pageable pageable){
        return ResponseEntity.ok(userService.getAllUsers(form, pageable));
    }

    @Operation(summary = "Get user by ID", description = "Only admin can get user by ID")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable UUID id){
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @Operation(summary = "Update user profile", description = "Only admin can update a user profile")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable UUID id, @RequestBody @Valid UserRequestDTO userRequestDTO){
        UserDTO updateUserDTO = userService.updateUser(id, userRequestDTO);
        return ResponseEntity.ok(updateUserDTO);
    }

    @Operation(summary = "Disable user", description = "Only admin can disable a user (sets DISABLED + deactivated_at)")
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("{id}")
    public ResponseEntity<Object> disableUser(@PathVariable UUID id){
        userService.disableUser(id);
        return new ResponseEntity<>("Id: " + id + " is disabled", HttpStatus.OK);
    }
}