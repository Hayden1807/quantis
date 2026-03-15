ALTER TABLE users
  ADD COLUMN IF NOT EXISTS username text;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS avatar_url text;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS alert_email_enabled boolean NOT NULL DEFAULT true;

UPDATE users
SET username = split_part(email, '@', 1)
WHERE username IS NULL OR btrim(username) = '';
