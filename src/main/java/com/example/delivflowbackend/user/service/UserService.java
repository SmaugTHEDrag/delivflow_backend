package com.example.delivflowbackend.user.service;

import com.example.delivflowbackend.user.dto.UserDTO;
import com.example.delivflowbackend.user.dto.UserPageResponse;
import com.example.delivflowbackend.user.dto.UserRequestDTO;
import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;

import java.time.Instant;
import java.util.UUID;
import com.example.delivflowbackend.common.exception.ResourceNotFoundException;
import com.example.delivflowbackend.user.form.UserFilterForm;
import com.example.delivflowbackend.user.mapper.UserMapper;
import com.example.delivflowbackend.user.repository.IUserRepository;
import com.example.delivflowbackend.user.specification.UserSpecification;
import com.example.delivflowbackend.common.util.EmailUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

/**
 * Admin side of the application users.
 * Roles are membership-based (workspace_members.role / project_members.role) and
 * are intentionally not managed here.
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserService implements IUserService {

    private final IUserRepository userRepository;

    private final UserMapper userMapper;

    // Get users with pagination and filter
    @Override
    public UserPageResponse getAllUsers(UserFilterForm form, Pageable pageable) {
        Specification<User> where = UserSpecification.buildWhere(form);
        Page<User> users = userRepository.findAll(where, pageable);
        Page<UserDTO> userDTOS = users.map(userMapper::toDTO);

        return new UserPageResponse(
                userDTOS.getContent(),
                userDTOS.getNumber(),
                userDTOS.getTotalElements(),
                userDTOS.getTotalPages(),
                userDTOS.getSize(),
                userDTOS.isLast(),
                userDTOS.isFirst()
        );
    }

    // Get a user by ID
    @Override
    public UserDTO getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return userMapper.toDTO(user);
    }

    // Update the application profile of an existing user
    @Override
    public UserDTO updateUser(UUID id, UserRequestDTO userRequestDTO) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));

        // email is normalized before every save
        if (userRequestDTO.getEmail() != null) {
            existingUser.setEmail(EmailUtils.normalizeEmail(userRequestDTO.getEmail()));
        }
        if (userRequestDTO.getDisplayName() != null) {
            existingUser.setDisplayName(userRequestDTO.getDisplayName());
        }
        if (userRequestDTO.getAvatarUrl() != null) {
            existingUser.setAvatarUrl(userRequestDTO.getAvatarUrl());
        }
        if (userRequestDTO.getStatus() != null) {
            UserStatus newStatus = UserStatus.valueOf(userRequestDTO.getStatus());
            existingUser.setStatus(newStatus);
            if (newStatus == UserStatus.DISABLED) {
                existingUser.setDeactivatedAt(Instant.now());
            } else {
                existingUser.setDeactivatedAt(null);
            }
        }

        User updatedUser = userRepository.save(existingUser);

        return userMapper.toDTO(updatedUser);
    }

    // Disable a user by ID (status = DISABLED + deactivated_at). Never hard-delete.
    @Override
    public void disableUser(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));

        user.setStatus(UserStatus.DISABLED);
        user.setDeactivatedAt(Instant.now());
        userRepository.save(user);
    }
}