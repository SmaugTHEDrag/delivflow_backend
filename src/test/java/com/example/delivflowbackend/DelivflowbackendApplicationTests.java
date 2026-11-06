package com.example.delivflowbackend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(
    properties = {
        "spring.datasource.password=dummy",
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=none"
    }
)
@ActiveProfiles("test")
class DelivflowbackendApplicationTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void contextLoads() {
    }

}
