-- Complete Database Schema for Secure File Sharing System (Phases 1-4)

CREATE DATABASE IF NOT EXISTS secure_file_sharing;
USE secure_file_sharing;

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    wallet_address VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Files Table (Phases 2-4)
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) DEFAULT 'application/octet-stream',
    encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
    nonce VARCHAR(255) NOT NULL,
    encrypted_key TEXT NOT NULL,
    storage_path VARCHAR(255) NOT NULL,
    sha256_hash CHAR(64) DEFAULT NULL,
    ipfs_cid VARCHAR(100) DEFAULT NULL,
    blockchain_recorded BOOLEAN DEFAULT FALSE,
    blockchain_tx_hash VARCHAR(100) DEFAULT NULL,
    status VARCHAR(50) DEFAULT 'encrypted',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
