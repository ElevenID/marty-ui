CREATE SCHEMA IF NOT EXISTS issuance_service;
DROP TABLE IF EXISTS issuance_service.issuance_events;
DROP TABLE IF EXISTS issuance_service.issued_credentials;
DROP TABLE IF EXISTS issuance_service.authorization_sessions;
DROP TABLE IF EXISTS issuance_service.issuance_transactions;
CREATE TABLE issuance_service.issuance_transactions (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    application_id text,
    pre_auth_code text,
    oid4vci_client_id text,
    access_token text,
    claims jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE issuance_service.authorization_sessions (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    organization_id text,
    issuer_state text,
    access_token text,
    dpop_jkt text
);
CREATE TABLE issuance_service.issued_credentials (
    id text PRIMARY KEY,
    transaction_id text NOT NULL,
    organization_id text NOT NULL
);
CREATE TABLE issuance_service.issuance_events (
    id text PRIMARY KEY,
    transaction_id text,
    application_id text,
    event_type text NOT NULL,
    metadata json NOT NULL,
    created_at timestamptz NOT NULL
);
INSERT INTO issuance_service.issuance_transactions
    (id, organization_id, application_id, access_token, claims)
    VALUES ('tx-legacy', 'org-a', 'application-a', 'digest-a', '{}'::jsonb);
INSERT INTO issuance_service.authorization_sessions
    VALUES ('session-legacy', 'wallet-a', 'org-a', NULL, 'digest-b', NULL);
INSERT INTO issuance_service.issued_credentials
    VALUES ('credential-a', 'tx-legacy', 'org-a');
INSERT INTO issuance_service.issuance_events
    VALUES (
        'binding-a',
        'tx-legacy',
        NULL,
        'oid4vci_notification_binding',
        '{"notification_id":"notification-a","credential_id":"credential-a"}'::json,
        clock_timestamp()
    );
