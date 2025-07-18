-- Drop indexes
DROP INDEX IF EXISTS idx_users_role;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;

-- Drop tables
DROP TABLE IF EXISTS users;

-- Drop extensions (only if no other tables are using it)
-- DROP EXTENSION IF EXISTS "uuid-ossp";
