CREATE TABLE entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (name ~ '^[A-Z_][A-Z0-9_]{0,127}$'),
  description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 500),
  labels text[] NOT NULL DEFAULT '{}',
  current_version int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX entries_live_name ON entries (name) WHERE deleted_at IS NULL;

CREATE TABLE versions (
  entry_id uuid NOT NULL REFERENCES entries (id),
  version int NOT NULL,
  state text NOT NULL CHECK (state IN ('writing', 'live', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  deleted_at timestamptz,
  PRIMARY KEY (entry_id, version)
);
CREATE INDEX versions_retired ON versions (entry_id, version)
  WHERE state = 'retired' AND deleted_at IS NULL;

CREATE TABLE pins (
  session_id uuid NOT NULL,
  env text NOT NULL,
  entry_id uuid NOT NULL REFERENCES entries (id),
  version int NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  PRIMARY KEY (session_id, env)
);
CREATE INDEX pins_live ON pins (entry_id, version) WHERE released_at IS NULL;

CREATE TABLE events (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL,
  actor text NOT NULL CHECK (actor IN ('user', 'orchestrator', 'sweeper')),
  entry_name text,
  data jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX events_entry ON events (entry_name, id DESC);
