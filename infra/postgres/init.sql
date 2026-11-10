-- SentinelGraph PostgreSQL bootstrap
-- Creates a dedicated non-superuser application role without BYPASSRLS
-- so PostgreSQL Row-Level Security (RLS) is strictly enforced at the DB layer.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinelgraph_app') THEN
        CREATE ROLE sentinelgraph_app LOGIN PASSWORD 'sentinelgraph_dev_pw'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE sentinelgraph TO sentinelgraph_app;
GRANT USAGE ON SCHEMA public TO sentinelgraph_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinelgraph_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinelgraph_app;
