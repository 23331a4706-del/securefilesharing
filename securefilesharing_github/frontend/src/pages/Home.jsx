import React from 'react';
import { Link } from 'react-router-dom';

export default function Home() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto 0', textAlign: 'center' }}>
      <div className="badge badge-success" style={{ marginBottom: '1.5rem', padding: '0.4rem 1rem' }}>
        Phase 1 — Foundation & Authentication Active
      </div>
      
      <h1 style={{ fontFamily: 'var(--font-heading)', fontSize: '2.8rem', fontWeight: '700', lineHeight: '1.2', color: '#fff', marginBottom: '1rem' }}>
        Secure File Sharing Using AES Encryption & Blockchain
      </h1>
      
      <p style={{ color: 'var(--text-muted)', fontSize: '1.15rem', marginBottom: '2.5rem', maxWidth: '640px', marginInline: 'auto' }}>
        Securely share files using encryption, integrity verification and blockchain-based access control.
      </p>

      <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginBottom: '3.5rem' }}>
        <Link to="/login" className="btn btn-primary" style={{ padding: '0.85rem 2rem', fontSize: '1rem' }}>
          Login
        </Link>
        <Link to="/register" className="btn btn-secondary" style={{ padding: '0.85rem 2rem', fontSize: '1rem' }}>
          Register
        </Link>
      </div>

      <div className="cyber-card" style={{ textAlign: 'left', background: 'rgba(28, 37, 65, 0.6)' }}>
        <h3 className="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Architecture & Implementation Roadmap
        </h3>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
          This system is built across multiple phases to deliver end-to-end zero-trust data confidentiality and decentralized verification.
        </p>

        <ul className="roadmap-list">
          <li className="roadmap-item completed">
            <span><strong>Phase 1:</strong> User Registration, Login & MySQL Database</span>
            <span className="badge badge-success">Implemented</span>
          </li>
          <li className="roadmap-item upcoming">
            <span><strong>Phase 2:</strong> Client-Side AES-256-GCM File Encryption</span>
            <span className="badge badge-pending">Phase 2</span>
          </li>
          <li className="roadmap-item upcoming">
            <span><strong>Phase 3:</strong> SHA-256 Hash Integrity Verification</span>
            <span className="badge badge-pending">Phase 3</span>
          </li>
          <li className="roadmap-item upcoming">
            <span><strong>Phase 4:</strong> IPFS Encrypted Storage</span>
            <span className="badge badge-pending">Phase 4</span>
          </li>
          <li className="roadmap-item upcoming">
            <span><strong>Phase 5:</strong> Smart Contract & Blockchain Access Control</span>
            <span className="badge badge-pending">Phase 5</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
