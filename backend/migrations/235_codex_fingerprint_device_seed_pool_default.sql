-- Upgrade accounts created by the original single-device implementation to
-- the three-seed device pool. This migration runs once: later administrator
-- choices (including setting the count back to 1) are not overwritten.
WITH candidates AS (
    SELECT
        id,
        CASE
            WHEN jsonb_typeof(extra->'codex_fingerprint_seeds') = 'array'
             AND jsonb_array_length(extra->'codex_fingerprint_seeds') > 0
            THEN extra->'codex_fingerprint_seeds'
            ELSE jsonb_build_array(
                CASE
                    WHEN extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                     AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
                    THEN extra->>'codex_fingerprint_seed'
                    ELSE gen_random_uuid()::text
                END
            )
        END AS base_seeds,
        CASE
            WHEN extra->>'codex_fingerprint_seed_count' ~ '^[1-9][0-9]*$'
             AND (extra->>'codex_fingerprint_seed_count')::int BETWEEN 1 AND 16
            THEN GREATEST(3, (extra->>'codex_fingerprint_seed_count')::int)
            ELSE 3
        END AS desired_count
    FROM accounts
    WHERE deleted_at IS NULL
      AND platform = 'openai'
      AND type IN ('oauth', 'setup-token')
      AND COALESCE(extra->>'codex_fingerprint_mode', '') = 'device'
), expanded AS (
    SELECT
        id,
        desired_count,
        base_seeds || COALESCE(
            (
                SELECT jsonb_agg(gen_random_uuid()::text)
                FROM generate_series(1, GREATEST(0, desired_count - jsonb_array_length(base_seeds)))
            ),
            '[]'::jsonb
        ) AS seeds
    FROM candidates
)
UPDATE accounts AS a
SET extra = jsonb_set(
    jsonb_set(
        jsonb_set(
            COALESCE(a.extra, '{}'::jsonb),
            '{codex_fingerprint_seed}',
            to_jsonb(e.seeds->>0),
            true
        ),
        '{codex_fingerprint_seeds}',
        e.seeds,
        true
    ),
    '{codex_fingerprint_seed_count}',
    to_jsonb(e.desired_count),
    true
)
FROM expanded AS e
WHERE a.id = e.id;
