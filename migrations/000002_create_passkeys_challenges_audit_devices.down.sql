-- 000002_create_passkeys_challenges_audit_devices.down.sql

DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS challenges CASCADE;
DROP TABLE IF EXISTS passkey_credentials CASCADE;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_id;
DROP TABLE IF EXISTS devices CASCADE;
