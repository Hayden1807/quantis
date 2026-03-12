DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'energy_type') THEN
    CREATE TYPE energy_type AS ENUM ('electricity', 'gas');
  END IF;
END $$;
