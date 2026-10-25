package com.example.delivflowbackend.user.mapper;

import com.example.delivflowbackend.user.dto.UserDTO;
import com.example.delivflowbackend.user.dto.UserRequestDTO;
import com.example.delivflowbackend.user.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDTO toDTO(User user);

    // json null means "leave unchanged", not "set to null"
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "keycloakIssuer", ignore = true)
    @Mapping(target = "keycloakSubject", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "emailVerified", ignore = true)
    @Mapping(target = "deactivatedAt", ignore = true)
    @Mapping(target = "lastLoginAt", ignore = true)
    void updateEntityFromDTO(UserRequestDTO userRequestDTO, @MappingTarget User existingUser);
}