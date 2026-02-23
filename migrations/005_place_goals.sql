CREATE TABLE IF NOT EXISTS place_goals (
  place_id uuid NOT NULL REFERENCES places(id) ON DELETE CASCADE,
  energy energy_type NOT NULL,
  weekly_target_kwh double precision NOT NULL DEFAULT 0,
  monthly_target_kwh double precision NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (place_id, energy)
);

CREATE INDEX IF NOT EXISTS place_goals_place_idx ON place_goals(place_id);

