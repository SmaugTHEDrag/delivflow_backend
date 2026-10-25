package com.example.delivflowbackend.common.util;

/**
 * Single shared helper for email normalization.
 *
 * DelivFlow stores emails lowercase and trimmed (see {@code ck_users_email_lower}
 * and {@code uq_users_email} in the schema). This helper MUST be used before every
 * save and every search - normalizing only in the frontend is not acceptable.
 */
public final class EmailUtils {

    private EmailUtils() {
    }

    /**
     * Normalize an email address: trim whitespace and convert to lowercase.
     * Returns {@code null} for a {@code null} input.
     */
    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}