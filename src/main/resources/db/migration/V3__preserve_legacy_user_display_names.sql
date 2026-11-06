-- Keep profile names intact while moving legacy user rows to the current
-- authentication model. The current schema already uses display_name; this
-- conditional backfill supports installations that still have the older
-- full_name column. Existing display_name values always take precedence.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'users'
          AND column_name = 'full_name'
    ) THEN
        EXECUTE 'UPDATE users
                 SET display_name = full_name
                 WHERE display_name IS NULL
                   AND full_name IS NOT NULL';
    END IF;
END;
$$;

COMMENT ON COLUMN users.display_name IS
    'Application profile display name; retained across authentication-provider migrations.';
