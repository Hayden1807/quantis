-- migrations/003_consumptions.sql
DO $$
BEGIN
   IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'energy_type') THEN 
	CREATE TYPE energy_type AS ENUM ('electricity', 'gas');
   END IF;
END $$;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS consumptions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  place_id uuid NOT NULL REFERENCES places(id) ON DELETE CASCADE,

  recorded_at timestamptz NOT NULL DEFAULT now(),
  day date NOT NULL,

  value double precision NOT NULL,
  unit text NOT NULL DEFAULT 'kwh',

  energy energy_type NOT NULL DEFAULT 'electricity',

  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS consumptions_place_energy_day_uq ON consumptions(place_id, energy, day);

CREATE INDEX IF NOT EXISTS consumptions_place_time_idx ON consumptions(place_id, recorded_at DESC);

