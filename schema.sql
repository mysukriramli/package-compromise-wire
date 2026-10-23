CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR PRIMARY KEY,
    ecosystem VARCHAR,
    package_name VARCHAR,
    summary VARCHAR,
    published_date VARCHAR,
    modified_date VARCHAR,
    content_hash VARCHAR,
    raw_json VARCHAR
);

CREATE TABLE IF NOT EXISTS ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    event_id VARCHAR,
    ecosystem VARCHAR,
    package_name VARCHAR
);
