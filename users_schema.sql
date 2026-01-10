-- Panda Cloud SQLite Database Schema
-- Run this to create the users database

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    aws_access_key TEXT NOT NULL,
    aws_secret_key TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    endpoint TEXT DEFAULT 's3.tebi.io',
    region TEXT DEFAULT 'us-east-1',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1
);

-- Insert existing users
INSERT OR IGNORE INTO users (username, password, aws_access_key, aws_secret_key, bucket_name, endpoint, region) VALUES
('momo', 'momo', 'CgH4qWDdOWPEAjcT', '0JM7qtRdD4qBO7QF8kNwKqbvDxTX9s6hGlJC9Kru', 'mgr', 's3.tebi.io', 'us-east-1'),
('panda', 'panda', 'XpLEzFrNsGIibeK8', 'swVubPu29njKi7WVFbQI8eqMvFSwOvBP0iX8KeK3', 'panda-cloud', 's3.tebi.io', 'us-east-1');

-- Create index for faster username lookups
CREATE INDEX IF NOT EXISTS idx_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_active ON users(is_active);

-- Example queries:
-- SELECT * FROM users WHERE username = 'momo' AND is_active = 1;
-- UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = 'momo';
-- INSERT INTO users (username, password, aws_access_key, aws_secret_key, bucket_name) VALUES (?, ?, ?, ?, ?);