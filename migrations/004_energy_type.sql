DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'energy_type') THEN
    CREATE TYPE energy_type AS ENUM ('electricity', 'gas');
  END IF;
END $$;

ALTER TABLE consumptions
  ADD COLUMN IF NOT EXISTS energy energy_type NOT NULL DEFAULT 'electricity';

CREATE INDEX IF NOT EXISTS consumptions_energy_idx ON consumptions(energy);

