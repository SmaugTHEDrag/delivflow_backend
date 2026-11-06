package com.example.delivflowbackend.user.mapper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserMapperConfig {

    @Bean
    public UserMapper userMapper() {
        return new UserMapperImpl();
    }
}
