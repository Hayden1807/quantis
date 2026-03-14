ALTER TABLE consumptions
  ADD COLUMN IF NOT EXISTS day date;

UPDATE consumptions
SET day = recorded_at::date
WHERE day IS NULL;

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY place_id, energy, day
      ORDER BY recorded_at DESC, created_at DESC, id DESC
    ) AS rn
  FROM consumptions
)
DELETE FROM consumptions c
USING ranked r
WHERE c.id = r.id
  AND r.rn > 1;

ALTER TABLE consumptions
  ALTER COLUMN day SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS consumptions_place_energy_day_uq
ON consumptions(place_id, energy, day);
