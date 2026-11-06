-- DelivFlow PostgreSQL schema update V2
-- Add the Admin API user ID and PENDING_VERIFICATION status support
-- ---------------------------------------------------------------------------

-- Existing rows have only the OIDC issuer/subject pair; do not infer an Admin API
-- user ID from the OIDC subject.
ALTER TABLE users ADD COLUMN keycloak_id VARCHAR(36);

CREATE UNIQUE INDEX uq_users_keycloak_id ON users(keycloak_id);

-- A newly created Keycloak Admin API user has an ID before it has issued a JWT.
-- Store its OIDC subject only after an authenticated token supplies iss/sub.
ALTER TABLE users ALTER COLUMN keycloak_subject DROP NOT NULL;

-- Add PENDING_VERIFICATION to the user_status enum
ALTER TYPE user_status ADD VALUE 'PENDING_VERIFICATION';