-- Phase 2 Database Schema Migration for Secure File Sharing System

USE secure_file_sharing;

-- Create Files Table for Encrypted Metadata Storage
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
    status VARCHAR(50) DEFAULT 'encrypted',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
