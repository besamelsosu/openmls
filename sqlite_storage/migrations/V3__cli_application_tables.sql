-- CLI application-level tables for storing user contacts, groups, configuration, and messages.

CREATE TABLE IF NOT EXISTS contacts (
    id BLOB PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS groups (
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS user_config (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    group_name TEXT,
    seq INTEGER,
    author TEXT,
    message TEXT,
    PRIMARY KEY (group_name, seq)
);
