-- An audit event may name the SSO user: actor `user:<identity>` next to the plain `user`.
ALTER TABLE events DROP CONSTRAINT events_actor_check;
ALTER TABLE events ADD CONSTRAINT events_actor_check
  CHECK (
    actor IN ('user', 'orchestrator', 'sweeper')
    OR (actor LIKE 'user:_%' AND char_length(actor) <= 205)
  );
