-- Backfill the persisted Codex device seed pool without changing the existing
-- first seed. The migration is idempotent and only touches enabled OpenAI
-- OAuth-like accounts that do not yet have a valid seed array.
WITH candidates AS (
    SELECT
        id,
        CASE
            WHEN extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
            THEN extra->>'codex_fingerprint_seed'
            ELSE gen_random_uuid()::text
        END AS seed,
        COALESCE(extra->>'codex_fingerprint_mode', '') = 'device' AS device_mode
    FROM accounts
    WHERE deleted_at IS NULL
      AND platform = 'openai'
      AND type IN ('oauth', 'setup-token')
      AND COALESCE(extra->>'codex_fingerprint_mode', '') IN ('device', 'session', 'full')
      AND jsonb_typeof(COALESCE(extra->'codex_fingerprint_seeds', 'null'::jsonb)) <> 'array'
)
UPDATE accounts AS a
SET extra = jsonb_set(
    jsonb_set(
        COALESCE(a.extra, '{}'::jsonb),
        '{codex_fingerprint_seed}',
        to_jsonb(c.seed),
        true
    ),
    '{codex_fingerprint_seeds}',
    CASE
        WHEN c.device_mode THEN jsonb_build_array(c.seed, gen_random_uuid()::text, gen_random_uuid()::text)
        ELSE jsonb_build_array(c.seed)
    END,
    true
)
FROM candidates AS c
WHERE a.id = c.id;

UPDATE accounts
SET extra = jsonb_set(
    COALESCE(extra, '{}'::jsonb),
    '{codex_fingerprint_seed_count}',
    '3'::jsonb,
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type IN ('oauth', 'setup-token')
  AND COALESCE(extra->>'codex_fingerprint_mode', '') = 'device'
  AND (
      extra->>'codex_fingerprint_seed_count' IS NULL
      OR extra->>'codex_fingerprint_seed_count' !~ '^[1-9][0-9]*$'
  );
