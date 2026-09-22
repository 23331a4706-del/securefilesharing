-- Phase 5 Database Schema Preparation for Secure File Sharing System

USE secure_file_sharing;

-- Add blockchain reference schema preparation columns to files table
ALTER TABLE files 
ADD COLUMN blockchain_recorded BOOLEAN DEFAULT FALSE AFTER ipfs_cid,
ADD COLUMN blockchain_tx_hash VARCHAR(100) NULL AFTER blockchain_recorded;
