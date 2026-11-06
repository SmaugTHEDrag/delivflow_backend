package com.example.delivflowbackend.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakPropertiesBindingTest {

    @Test
    void applicationYamlDefaultsDirectAccessGrantToEnabled() throws IOException {
        List<PropertySource<?>> yamlSources = loadApplicationYaml();
        new ApplicationContextRunner()
                .withInitializer(context -> yamlSources.forEach(
                        context.getEnvironment().getPropertySources()::addLast))
                .withUserConfiguration(KeycloakProperties.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    KeycloakProperties properties = context.getBean(KeycloakProperties.class);
                    assertThat(properties.isDirectAccessGrantEnabled()).isTrue();
                    assertThat(properties.getEmailVerificationClientId()).isEqualTo("delivflow-frontend");
                    assertThat(properties.getEmailVerificationRedirectUri())
                            .isEqualTo("http://localhost:3000/login");
                    assertThat(properties.getEmailVerificationLifespanSeconds()).isEqualTo(86400);
                });
    }

    @Test
    void environmentVariableOverridesYamlDirectAccessGrantValue() throws IOException {
        List<PropertySource<?>> yamlSources = loadApplicationYaml();
        new ApplicationContextRunner()
                .withInitializer(context -> {
                    yamlSources.forEach(context.getEnvironment().getPropertySources()::addLast);
                    context.getEnvironment().getPropertySources().addFirst(
                            new MapPropertySource("testEnvironment",
                                    Map.of("KEYCLOAK_DIRECT_ACCESS_GRANT_ENABLED", "false")));
                })
                .withUserConfiguration(KeycloakProperties.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    KeycloakProperties properties = context.getBean(KeycloakProperties.class);
                    assertThat(properties.isDirectAccessGrantEnabled()).isFalse();
                });
    }

    @Test
    void environmentVariablesOverrideEmailActionSettings() throws IOException {
        List<PropertySource<?>> yamlSources = loadApplicationYaml();
        new ApplicationContextRunner()
                .withInitializer(context -> {
                    yamlSources.forEach(context.getEnvironment().getPropertySources()::addLast);
                    context.getEnvironment().getPropertySources().addFirst(
                            new MapPropertySource("testEnvironment", Map.of(
                                    "KEYCLOAK_EMAIL_VERIFICATION_CLIENT_ID", "test-frontend",
                                    "KEYCLOAK_EMAIL_VERIFICATION_REDIRECT_URI", "https://app.example.test/login",
                                    "KEYCLOAK_EMAIL_VERIFICATION_LIFESPAN_SECONDS", "3600")));
                })
                .withUserConfiguration(KeycloakProperties.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    KeycloakProperties properties = context.getBean(KeycloakProperties.class);
                    assertThat(properties.getEmailVerificationClientId()).isEqualTo("test-frontend");
                    assertThat(properties.getEmailVerificationRedirectUri())
                            .isEqualTo("https://app.example.test/login");
                    assertThat(properties.getEmailVerificationLifespanSeconds()).isEqualTo(3600);
                });
    }

    private List<PropertySource<?>> loadApplicationYaml() throws IOException {
        return new YamlPropertySourceLoader()
                .load("application", new ClassPathResource("application.yaml"));
    }
}
