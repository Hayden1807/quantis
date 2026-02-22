-- migrations/003_consumptions.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS consumptions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  place_id uuid NOT NULL REFERENCES places(id) ON DELETE CASCADE,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  value double precision NOT NULL,
  unit text NOT NULL DEFAULT 'kwh',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS consumptions_place_time_idx ON consumptions(place_id, recorded_at DESC);

