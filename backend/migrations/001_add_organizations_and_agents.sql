-- SaaS multi-tenancy foundation: organizations and registered agents.
-- Applied automatically via init_db() / SQLAlchemy create_all in development.
-- Run manually against PostgreSQL when not using create_all.

CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    enrollment_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE INDEX IF NOT EXISTS ix_organizations_enrollment_token
    ON organizations (enrollment_token);

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    hostname TEXT,
    os TEXT,
    last_seen TIMESTAMP,
    api_key TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS ix_agents_organization_id
    ON agents (organization_id);

CREATE INDEX IF NOT EXISTS ix_agents_api_key
    ON agents (api_key);
