-- Multi-env entries (0.2.0). Strict, no backfill: an entry of the 0.1.0 shape has no env set,
-- so the migration refuses to run while any entry or pin row exists.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM entries) OR EXISTS (SELECT 1 FROM pins) THEN
    RAISE EXCEPTION 'migration 0002 needs empty entries and pins tables (no backfill)';
  END IF;
END
$$;

ALTER TABLE entries DROP CONSTRAINT entries_name_check;
ALTER TABLE entries ADD CONSTRAINT entries_name_check
  CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 120);
DROP INDEX entries_live_name;
CREATE UNIQUE INDEX entries_live_name ON entries (lower(name)) WHERE deleted_at IS NULL;

-- A readable env keeps its value here; a protected env never has a value, hash or length in
-- Postgres (its value lives only in the version's Kubernetes Secret).
CREATE TABLE entry_envs (
  entry_id uuid NOT NULL REFERENCES entries (id),
  env text NOT NULL CHECK (env ~ '^[A-Z_][A-Z0-9_]{0,127}$'),
  position int NOT NULL,
  protected boolean NOT NULL,
  value text CHECK ((protected AND value IS NULL)
                 OR (NOT protected AND value IS NOT NULL AND octet_length(value) <= 4096)),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entry_id, env),
  UNIQUE (entry_id, position)
);

ALTER TABLE pins ADD COLUMN entry_env text NOT NULL;

-- Events follow the entry by id: a free-text name can be renamed.
ALTER TABLE events ADD COLUMN entry_id uuid;
DROP INDEX events_entry;
CREATE INDEX events_entry ON events (entry_id, id DESC);
