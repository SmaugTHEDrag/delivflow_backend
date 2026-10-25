package com.example.delivflowbackend.user.service;

import com.example.delivflowbackend.user.dto.UserDTO;
import com.example.delivflowbackend.user.dto.UserPageResponse;
import com.example.delivflowbackend.user.dto.UserRequestDTO;
import com.example.delivflowbackend.user.form.UserFilterForm;
import org.springframework.data.domain.Pageable;
import java.util.UUID;

public interface IUserService  {

    // Get paginated user with filters
    UserPageResponse getAllUsers(UserFilterForm form, Pageable pageable);

    // Get a user by ID
    UserDTO getUserById(UUID id);

    // Update the application profile of an existing user
    UserDTO updateUser(UUID id, UserRequestDTO userRequestDTO);

    // Disable a user (set status DISABLED + deactivated_at). Never hard-delete.
    void disableUser(UUID id);
}