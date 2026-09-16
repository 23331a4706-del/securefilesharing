-- Phase 4 Database Schema Migration for Secure File Sharing System

USE secure_file_sharing;

-- Add ipfs_cid column to files table without destroying existing records
ALTER TABLE files 
ADD COLUMN ipfs_cid VARCHAR(100) NULL AFTER sha256_hash;
