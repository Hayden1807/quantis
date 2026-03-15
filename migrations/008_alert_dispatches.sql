CREATE TABLE IF NOT EXISTS alert_dispatches (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  place_id uuid NOT NULL REFERENCES places(id) ON DELETE CASCADE,
  energy energy_type NOT NULL,
  period text NOT NULL CHECK (period IN ('week', 'month')),
  period_key text NOT NULL,
  sent_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, place_id, energy, period, period_key)
);

CREATE INDEX IF NOT EXISTS alert_dispatches_user_idx
  ON alert_dispatches(user_id, sent_at DESC);
