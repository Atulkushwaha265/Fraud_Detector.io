CREATE DATABASE fraud_detector_db;

CREATE TABLE scan_history (
    id SERIAL PRIMARY KEY,
    input_type VARCHAR(20) NOT NULL,
    input_value TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,
    details TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);