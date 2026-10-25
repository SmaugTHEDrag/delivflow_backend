-- DelivFlow PostgreSQL schema
-- Target: PostgreSQL 16+
-- Authentication: Keycloak via OpenID Connect (Authorization Code + PKCE recommended).
--
-- Keycloak owns credentials, OAuth/OIDC identity federation, email verification,
-- password reset, MFA, and login sessions.
-- This database stores an application-side user profile keyed by the OIDC "sub"
-- claim. Never store passwords, access tokens, refresh tokens, or Keycloak secrets here.
--
-- Apply using Flyway as V1__init_delivflow.sql, or run directly against an empty database.
-- Flyway wraps each migration in a transaction, so there is no explicit BEGIN/COMMIT here.
-- If Keycloak uses a different issuer/realm, the issuer column allows future multi-realm support.

-- ---------------------------------------------------------------------------
-- ENUM TYPES
-- ---------------------------------------------------------------------------

CREATE TYPE user_status AS ENUM ('ACTIVE', 'DISABLED');
CREATE TYPE membership_status AS ENUM ('ACTIVE', 'INVITED', 'REVOKED');
CREATE TYPE workspace_role AS ENUM ('OWNER', 'ADMIN', 'MEMBER');
CREATE TYPE project_role AS ENUM ('AGENCY_OWNER', 'AGENCY_MEMBER', 'CLIENT');
CREATE TYPE project_status AS ENUM ('ACTIVE', 'ON_HOLD', 'COMPLETED', 'ARCHIVED');
CREATE TYPE deliverable_status AS ENUM (
    'DRAFT', 'IN_REVIEW', 'CHANGES_REQUESTED', 'APPROVED', 'ARCHIVED'
);
CREATE TYPE deliverable_version_status AS ENUM (
    'DRAFT', 'IN_REVIEW', 'CHANGES_REQUESTED', 'APPROVED', 'WITHDRAWN'
);
CREATE TYPE approval_decision AS ENUM ('APPROVE', 'REQUEST_CHANGES');
CREATE TYPE bug_status AS ENUM (
    'OPEN', 'TRIAGED', 'IN_PROGRESS', 'FIXED', 'RESOLVED', 'REOPENED', 'REJECTED'
);
CREATE TYPE bug_severity AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE notification_channel AS ENUM ('IN_APP', 'EMAIL');
CREATE TYPE notification_status AS ENUM ('PENDING', 'SENT', 'FAILED', 'READ', 'DISMISSED');

-- ---------------------------------------------------------------------------
-- UPDATED_AT TRIGGER FUNCTION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- IDENTITY / WORKSPACE / PROJECT
-- ---------------------------------------------------------------------------

-- Application profile only. Keycloak remains the source of truth for authentication.
-- keycloak_subject stores the OIDC "sub" claim; treat it as opaque text, not necessarily a UUID.
-- email_verified is a synchronized snapshot for display/business logic, not proof on its own.
-- email is always stored lowercase and trimmed. The backend must normalize it
-- (trim + toLowerCase) before saving or searching; the CHECK below enforces it at DB level.
-- status/deactivated_at: do not delete a user when the Keycloak account is disabled;
-- mark the user DISABLED instead so audit references stay intact.
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_issuer     VARCHAR(512) NOT NULL,
    keycloak_subject    VARCHAR(255) NOT NULL,
    email               VARCHAR(320),
    display_name        VARCHAR(160),
    avatar_url          TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    status              user_status NOT NULL DEFAULT 'ACTIVE',
    deactivated_at      TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_oidc_identity UNIQUE (keycloak_issuer, keycloak_subject),
    CONSTRAINT ck_users_email_lower
        CHECK (email IS NULL OR email = lower(email)),
    CONSTRAINT ck_users_deactivated_at
        CHECK (status <> 'DISABLED' OR deactivated_at IS NOT NULL)
);

CREATE UNIQUE INDEX uq_users_email
    ON users (email)
    WHERE email IS NOT NULL;

CREATE INDEX idx_users_status ON users (status);

CREATE TABLE workspaces (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(160) NOT NULL,
    slug                VARCHAR(100) NOT NULL,
    owner_user_id       UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_workspaces_slug UNIQUE (slug),
    CONSTRAINT ck_workspaces_name_nonempty CHECK (length(trim(name)) > 0),
    CONSTRAINT ck_workspaces_slug_format CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

CREATE TABLE workspace_members (
    workspace_id        UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role                workspace_role NOT NULL DEFAULT 'MEMBER',
    status              membership_status NOT NULL DEFAULT 'ACTIVE',
    invited_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    invited_at          TIMESTAMPTZ,
    joined_at           TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT ck_workspace_member_dates CHECK (
        (status <> 'REVOKED' OR revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_workspace_members_user_status
    ON workspace_members (user_id, status);

CREATE TABLE projects (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    name                VARCHAR(200) NOT NULL,
    description         TEXT,
    status              project_status NOT NULL DEFAULT 'ACTIVE',
    start_date          DATE,
    due_date            DATE,
    created_by_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_projects_name_nonempty CHECK (length(trim(name)) > 0),
    CONSTRAINT ck_projects_dates CHECK (due_date IS NULL OR start_date IS NULL OR due_date >= start_date),
    CONSTRAINT uq_projects_id_workspace UNIQUE (id, workspace_id)
);

CREATE INDEX idx_projects_workspace_status ON projects (workspace_id, status);
CREATE INDEX idx_projects_due_date ON projects (due_date) WHERE due_date IS NOT NULL;

CREATE TABLE project_members (
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role                project_role NOT NULL,
    status              membership_status NOT NULL DEFAULT 'ACTIVE',
    invited_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    invited_at          TIMESTAMPTZ,
    joined_at           TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id),
    CONSTRAINT ck_project_member_dates CHECK (
        (status <> 'REVOKED' OR revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_project_members_user_status ON project_members (user_id, status);
CREATE INDEX idx_project_members_project_role ON project_members (project_id, role, status);

-- ---------------------------------------------------------------------------
-- DELIVERABLES / IMMUTABLE VERSIONS
-- ---------------------------------------------------------------------------

CREATE TABLE deliverables (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    title               VARCHAR(200) NOT NULL,
    description         TEXT,
    status              deliverable_status NOT NULL DEFAULT 'DRAFT',
    created_by_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at         TIMESTAMPTZ,
    CONSTRAINT ck_deliverables_title_nonempty CHECK (length(trim(title)) > 0),
    CONSTRAINT uq_deliverables_id_project UNIQUE (id, project_id)
);

CREATE INDEX idx_deliverables_project_status
    ON deliverables (project_id, status, updated_at DESC);

CREATE TABLE deliverable_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deliverable_id      UUID NOT NULL REFERENCES deliverables(id) ON DELETE RESTRICT,
    version_no          INTEGER NOT NULL,
    description         TEXT NOT NULL,
    resource_url        TEXT,
    status              deliverable_version_status NOT NULL DEFAULT 'DRAFT',
    submitted_by_user_id UUID REFERENCES users(id) ON DELETE RESTRICT,
    submitted_at        TIMESTAMPTZ,
    created_by_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_deliverable_version_no UNIQUE (deliverable_id, version_no),
    CONSTRAINT uq_deliverable_version_id_deliverable UNIQUE (id, deliverable_id),
    CONSTRAINT ck_deliverable_version_no CHECK (version_no > 0),
    CONSTRAINT ck_deliverable_version_description CHECK (length(trim(description)) > 0),
    CONSTRAINT ck_deliverable_version_submission CHECK (
        (status = 'DRAFT' AND submitted_at IS NULL)
        OR
        (status <> 'DRAFT' AND submitted_at IS NOT NULL AND submitted_by_user_id IS NOT NULL)
    )
);

CREATE INDEX idx_deliverable_versions_review
    ON deliverable_versions (status, submitted_at DESC);

-- ---------------------------------------------------------------------------
-- COMMENTS / REPLIES
-- A single comments table supports threads. Replies must point to a comment
-- in the same version through the composite FK.
-- ---------------------------------------------------------------------------

CREATE TABLE comments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id          UUID NOT NULL REFERENCES deliverable_versions(id) ON DELETE RESTRICT,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    parent_comment_id   UUID,
    content             TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    edited_at           TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT ck_comments_content_nonempty CHECK (length(trim(content)) > 0),
    CONSTRAINT uq_comments_id_version UNIQUE (id, version_id),
    CONSTRAINT fk_comments_parent_same_version
        FOREIGN KEY (parent_comment_id, version_id)
        REFERENCES comments (id, version_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_comments_not_self_parent CHECK (parent_comment_id IS NULL OR parent_comment_id <> id)
);

CREATE INDEX idx_comments_version_created ON comments (version_id, created_at);
CREATE INDEX idx_comments_parent ON comments (parent_comment_id) WHERE parent_comment_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- APPROVALS
-- One final decision per version in MVP. Store decision as an immutable record.
-- ---------------------------------------------------------------------------

CREATE TABLE approvals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id          UUID NOT NULL UNIQUE REFERENCES deliverable_versions(id) ON DELETE RESTRICT,
    decided_by_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decision            approval_decision NOT NULL,
    reason              TEXT,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_approval_reason_for_changes CHECK (
        decision <> 'REQUEST_CHANGES'
        OR (reason IS NOT NULL AND length(trim(reason)) > 0)
    )
);

CREATE INDEX idx_approvals_decided_by ON approvals (decided_by_user_id, decided_at DESC);

-- ---------------------------------------------------------------------------
-- BUG REPORTING / RESOLUTION
-- ---------------------------------------------------------------------------

CREATE TABLE bugs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id              UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    deliverable_version_id  UUID REFERENCES deliverable_versions(id) ON DELETE RESTRICT,
    reported_by_user_id     UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_to_user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    title                   VARCHAR(200) NOT NULL,
    description             TEXT NOT NULL,
    steps_to_reproduce      TEXT,
    expected_result         TEXT,
    actual_result           TEXT,
    severity                bug_severity NOT NULL DEFAULT 'MEDIUM',
    status                  bug_status NOT NULL DEFAULT 'OPEN',
    rejection_reason        TEXT,
    resolution              TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    fixed_at                TIMESTAMPTZ,
    resolved_at             TIMESTAMPTZ,
    CONSTRAINT ck_bugs_title_nonempty CHECK (length(trim(title)) > 0),
    CONSTRAINT ck_bugs_description_nonempty CHECK (length(trim(description)) > 0),
    CONSTRAINT ck_bugs_rejection_reason CHECK (
        status <> 'REJECTED'
        OR (rejection_reason IS NOT NULL AND length(trim(rejection_reason)) > 0)
    ),
    CONSTRAINT ck_bugs_fixed_timestamp CHECK (
        status NOT IN ('FIXED', 'RESOLVED') OR fixed_at IS NOT NULL
    ),
    CONSTRAINT ck_bugs_resolved_timestamp CHECK (
        status <> 'RESOLVED' OR resolved_at IS NOT NULL
    )
);

CREATE INDEX idx_bugs_project_status ON bugs (project_id, status, created_at DESC);
CREATE INDEX idx_bugs_assignee_status ON bugs (assigned_to_user_id, status)
    WHERE assigned_to_user_id IS NOT NULL;
CREATE INDEX idx_bugs_reporter ON bugs (reported_by_user_id, created_at DESC);
CREATE INDEX idx_bugs_version ON bugs (deliverable_version_id)
    WHERE deliverable_version_id IS NOT NULL;

CREATE TABLE bug_comments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bug_id              UUID NOT NULL REFERENCES bugs(id) ON DELETE RESTRICT,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    content             TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    edited_at           TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT ck_bug_comments_content_nonempty CHECK (length(trim(content)) > 0)
);

CREATE INDEX idx_bug_comments_bug_created ON bug_comments (bug_id, created_at);

-- ---------------------------------------------------------------------------
-- NOTIFICATIONS / AUDIT LOGS
-- ---------------------------------------------------------------------------

CREATE TABLE notifications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel             notification_channel NOT NULL DEFAULT 'IN_APP',
    status              notification_status NOT NULL DEFAULT 'PENDING',
    type                VARCHAR(100) NOT NULL,
    title               VARCHAR(200) NOT NULL,
    body                TEXT,
    reference_type      VARCHAR(80),
    reference_id        UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at             TIMESTAMPTZ,
    sent_at             TIMESTAMPTZ,
    last_error          TEXT,
    CONSTRAINT ck_notifications_title_nonempty CHECK (length(trim(title)) > 0)
);

CREATE TABLE activity_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    workspace_id        UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    project_id          UUID REFERENCES projects(id) ON DELETE SET NULL,
    action              VARCHAR(100) NOT NULL,
    entity_type         VARCHAR(80) NOT NULL,
    entity_id           UUID,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_id          VARCHAR(100),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_activity_action_nonempty CHECK (length(trim(action)) > 0),
    CONSTRAINT ck_activity_entity_type_nonempty CHECK (length(trim(entity_type)) > 0)
);

CREATE INDEX idx_activity_project_created ON activity_logs (project_id, created_at DESC);
CREATE INDEX idx_activity_workspace_created ON activity_logs (workspace_id, created_at DESC);
CREATE INDEX idx_activity_entity ON activity_logs (entity_type, entity_id, created_at DESC);
CREATE INDEX idx_activity_metadata_gin ON activity_logs USING GIN (metadata);

-- ---------------------------------------------------------------------------
-- CORRECT CROSS-TABLE INTEGRITY FOR BUG VERSION
-- A bug's optional version must belong to a deliverable in the same project.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_bug_version_project()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_project_id UUID;
BEGIN
    IF NEW.deliverable_version_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT d.project_id
      INTO v_project_id
      FROM deliverable_versions dv
      JOIN deliverables d ON d.id = dv.deliverable_id
     WHERE dv.id = NEW.deliverable_version_id;

    IF v_project_id IS NULL THEN
        RAISE EXCEPTION 'Deliverable version % does not exist', NEW.deliverable_version_id
            USING ERRCODE = '23503';
    END IF;

    IF v_project_id <> NEW.project_id THEN
        RAISE EXCEPTION 'Bug project_id must match the project of the linked deliverable version'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_bugs_validate_version_project
BEFORE INSERT OR UPDATE OF deliverable_version_id, project_id
ON bugs
FOR EACH ROW EXECUTE FUNCTION validate_bug_version_project();

-- Ensure project belongs to workspace of its members only in service logic:
-- membership and role checks involve authorization policy and should be enforced in
-- the Spring Boot service layer (and optionally PostgreSQL row-level security later).

-- ---------------------------------------------------------------------------
-- UPDATED_AT TRIGGERS
-- ---------------------------------------------------------------------------

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_workspaces_updated_at BEFORE UPDATE ON workspaces
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_workspace_members_updated_at BEFORE UPDATE ON workspace_members
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_projects_updated_at BEFORE UPDATE ON projects
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_project_members_updated_at BEFORE UPDATE ON project_members
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_deliverables_updated_at BEFORE UPDATE ON deliverables
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_deliverable_versions_updated_at BEFORE UPDATE ON deliverable_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_comments_updated_at BEFORE UPDATE ON comments
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_bugs_updated_at BEFORE UPDATE ON bugs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_bug_comments_updated_at BEFORE UPDATE ON bug_comments
FOR EACH ROW EXECUTE FUNCTION set_updated_at();