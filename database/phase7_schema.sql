-- Phase 7 Database Schema Migration for ECC-Based Secure AES Key Sharing

USE secure_file_sharing;

-- Add persistent user ECC keypair columns to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS ecc_public_key TEXT NULL,
ADD COLUMN IF NOT EXISTS ecc_private_key_encrypted TEXT NULL;

-- Create file_key_shares table for ECC-wrapped file key management
CREATE TABLE IF NOT EXISTS file_key_shares (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_id INT NOT NULL,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    sender_ephemeral_public_key TEXT NOT NULL,
    encrypted_aes_key TEXT NOT NULL,
    key_wrap_nonce VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_shares_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    CONSTRAINT fk_shares_sender FOREIGN KEY (sender_id) REFERENCES users(id),
    CONSTRAINT fk_shares_receiver FOREIGN KEY (receiver_id) REFERENCES users(id),
    UNIQUE KEY unique_file_receiver (file_id, receiver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
