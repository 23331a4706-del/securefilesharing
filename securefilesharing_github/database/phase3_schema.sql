-- Phase 3 Database Schema Migration for Secure File Sharing System

USE secure_file_sharing;

-- Add sha256_hash column to files table without destroying existing records
ALTER TABLE files 
ADD COLUMN sha256_hash CHAR(64) NULL AFTER storage_path;
