-- Preserve the existing profile name by splitting it across first_name and last_name.
ALTER TABLE users
    ADD COLUMN username VARCHAR(320),
    ADD COLUMN first_name VARCHAR(160),
    ADD COLUMN last_name VARCHAR(160);

UPDATE users
SET first_name = CASE
        WHEN display_name IS NULL THEN NULL
        WHEN strpos(display_name, ' ') = 0 THEN display_name
        ELSE substring(display_name FROM 1 FOR strpos(display_name, ' ') - 1)
    END,
    last_name = CASE
        WHEN display_name IS NULL THEN NULL
        WHEN strpos(display_name, ' ') = 0 THEN ''
        ELSE substring(display_name FROM strpos(display_name, ' ') + 1)
    END;

-- Older backend registrations used the email itself as the Keycloak username.
UPDATE users
SET username = lower(btrim(email))
WHERE email IS NOT NULL;

UPDATE users
SET username = 'legacy_' || replace(id::text, '-', '')
WHERE email IS NULL;

UPDATE users
SET keycloak_id = keycloak_subject
WHERE keycloak_id IS NULL;

ALTER TABLE users
    ALTER COLUMN keycloak_id TYPE VARCHAR(255),
    ALTER COLUMN keycloak_id SET NOT NULL,
    ALTER COLUMN username SET NOT NULL,
    ALTER COLUMN email SET NOT NULL;

DROP INDEX IF EXISTS uq_users_keycloak_id;
DROP INDEX IF EXISTS uq_users_email;
ALTER TABLE users
    ADD CONSTRAINT uq_users_keycloak_id UNIQUE (keycloak_id),
    ADD CONSTRAINT uq_users_email UNIQUE (email);

CREATE UNIQUE INDEX uq_users_username ON users (lower(username));

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS uq_users_oidc_identity,
    DROP COLUMN keycloak_issuer,
    DROP COLUMN keycloak_subject,
    DROP COLUMN display_name;
