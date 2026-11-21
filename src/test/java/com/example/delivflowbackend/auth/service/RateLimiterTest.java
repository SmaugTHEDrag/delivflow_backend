package com.example.delivflowbackend.auth.service;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-21T00:00:00Z"));
    private final RateLimiter rateLimiter = new RateLimiter(clock);

    @Test
    void loginThrottleIsBoundToSourceAndCannotLockTheSameEmailFromAnotherAddress() {
        for (int attempt = 0; attempt < 5; attempt++) {
            assertThat(rateLimiter.checkLoginRate("victim@example.com", "192.0.2.10")).isTrue();
        }
        assertThat(rateLimiter.checkLoginRate("victim@example.com", "192.0.2.10")).isFalse();
        assertThat(rateLimiter.checkLoginRate("victim@example.com", "192.0.2.11")).isTrue();
    }

    @Test
    void loginThrottleAlsoLimitsManyAccountsFromOneAddress() {
        for (int attempt = 0; attempt < 30; attempt++) {
            assertThat(rateLimiter.checkLoginRate("user" + attempt + "@example.com", "192.0.2.20"))
                    .isTrue();
        }

        assertThat(rateLimiter.checkLoginRate("another@example.com", "192.0.2.20")).isFalse();
    }

    @Test
    void expiredLoginBucketsAllowRequestsAgainAndAreCleaned() {
        for (int attempt = 0; attempt < 5; attempt++) {
            rateLimiter.checkLoginRate("victim@example.com", "192.0.2.30");
        }
        assertThat(rateLimiter.checkLoginRate("victim@example.com", "192.0.2.30")).isFalse();

        clock.advance(Duration.ofMinutes(30));

        assertThat(rateLimiter.checkLoginRate("victim@example.com", "192.0.2.30")).isTrue();
        assertThat(rateLimiter.trackedKeyCount()).isEqualTo(2);
    }

    @Test
    void trackedBucketsRemainBoundedForHighCardinalityInputs() {
        for (int index = 0; index < RateLimiter.MAX_TRACKED_KEYS + 100; index++) {
            rateLimiter.checkLoginRate("user" + index + "@example.com", "192.0.2." + index);
        }

        assertThat(rateLimiter.trackedKeyCount()).isLessThanOrEqualTo(RateLimiter.MAX_TRACKED_KEYS);
        assertThat(rateLimiter.checkLoginRate("user0@example.com", "192.0.2.0")).isTrue();
        assertThat(rateLimiter.checkLoginRate("new@example.com", "192.0.2.10001")).isFalse();
    }

    @Test
    void resendThrottleLimitsBothRecipientsAndSourceAddresses() {
        assertThat(rateLimiter.checkVerificationResendRate("victim@example.com", "192.0.2.40")).isTrue();
        assertThat(rateLimiter.checkVerificationResendRate("victim@example.com", "192.0.2.41")).isTrue();
        assertThat(rateLimiter.checkVerificationResendRate("victim@example.com", "192.0.2.42")).isTrue();
        assertThat(rateLimiter.checkVerificationResendRate("victim@example.com", "192.0.2.43")).isFalse();

        for (int attempt = 0; attempt < 10; attempt++) {
            assertThat(rateLimiter.checkVerificationResendRate(
                    "user" + attempt + "@example.com", "192.0.2.50")).isTrue();
        }
        assertThat(rateLimiter.checkVerificationResendRate("other@example.com", "192.0.2.50")).isFalse();
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant);
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
    }
}
