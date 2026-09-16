import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  uploadFile,
  getUserFiles,
  downloadFile,
  deleteFile,
  verifyFileIntegrity,
  retryBlockchainRegistration,
  shareFile,
  getFileShares,
  revokeShare,
  getSharedWithMe,
  getShareableUsers,
  downloadSharedFile
} from '../services/api';

export default function Dashboard() {
  const { user, token } = useAuth();
  const [activeTab, setActiveTab] = useState('myFiles'); // 'myFiles' | 'sharedWithMe'
  const [files, setFiles] = useState([]);
  const [sharedFiles, setSharedFiles] = useState([]);
  const [shareableUsers, setShareableUsers] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(true);
  const [loadingShared, setLoadingShared] = useState(false);

  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Modal State for Blockchain Verification
  const [verificationModalData, setVerificationModalData] = useState(null);
  const [verifyingFileId, setVerifyingFileId] = useState(null);
  const [retryingFileId, setRetryingFileId] = useState(null);

  // Modal State for Sharing
  const [shareModalFile, setShareModalFile] = useState(null);
  const [selectedReceiverId, setSelectedReceiverId] = useState('');
  const [isSharing, setIsSharing] = useState(false);

  // Modal State for Share Management
  const [manageSharesFile, setManageSharesFile] = useState(null);
  const [fileSharesList, setFileSharesList] = useState([]);
  const [loadingShares, setLoadingShares] = useState(false);
  const [revokingReceiverId, setRevokingReceiverId] = useState(null);

  const fileInputRef = useRef(null);

  // Load user files
  const fetchFiles = async () => {
    setLoadingFiles(true);
    try {
      const res = await getUserFiles(token);
      if (res.success) {
        setFiles(res.files || []);
      }
    } catch (err) {
      console.error("Failed to load user files:", err);
    } finally {
      setLoadingFiles(false);
    }
  };

  // Load shared files
  const fetchSharedFiles = async () => {
    setLoadingShared(true);
    try {
      const res = await getSharedWithMe(token);
      if (res.success) {
        setSharedFiles(res.files || []);
      }
    } catch (err) {
      console.error("Failed to load shared files:", err);
    } finally {
      setLoadingShared(false);
    }
  };

  // Load candidate users for sharing
  const fetchShareableUsers = async () => {
    try {
      const res = await getShareableUsers(token);
      if (res.success) {
        setShareableUsers(res.users || []);
      }
    } catch (err) {
      console.error("Failed to load shareable users:", err);
    }
  };

  useEffect(() => {
    if (token) {
      fetchFiles();
      fetchSharedFiles();
      fetchShareableUsers();
    }
  }, [token]);

  const handleFileChange = (e) => {
    setErrorMsg('');
    setSuccessMsg('');
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    if (!selectedFile) {
      setErrorMsg('Please select a file to upload.');
      return;
    }

    const maxMB = 16;
    if (selectedFile.size > maxMB * 1024 * 1024) {
      setErrorMsg(`File size exceeds the maximum limit of ${maxMB} MB.`);
      return;
    }

    setIsUploading(true);

    try {
      const res = await uploadFile(selectedFile, token);
      if (res.success) {
        setSuccessMsg(res.message || `✓ Encrypted with AES-256-GCM. ✓ Stored on IPFS. ✓ Registered on Blockchain.`);
        setSelectedFile(null);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        await fetchFiles();
      } else {
        setErrorMsg(res.message || 'File upload failed.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'An error occurred during file upload.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownload = async (fileId, filename) => {
    setErrorMsg('');
    try {
      await downloadFile(fileId, token, filename);
    } catch (err) {
      setErrorMsg(`Download failed: ${err.message}`);
    }
  };

  const handleDownloadShared = async (fileId, filename) => {
    setErrorMsg('');
    try {
      await downloadSharedFile(fileId, token, filename);
    } catch (err) {
      setErrorMsg(`Shared file download failed: ${err.message}`);
    }
  };

  const handleDelete = async (fileId, filename) => {
    if (!window.confirm(`Are you sure you want to delete "${filename}"?`)) {
      return;
    }
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await deleteFile(fileId, token);
      if (res.success) {
        setSuccessMsg(`File "${filename}" removed from your account successfully.`);
        await fetchFiles();
      }
    } catch (err) {
      setErrorMsg(`Delete failed: ${err.message}`);
    }
  };

  const handleVerifyBlockchain = async (fileId) => {
    setErrorMsg('');
    setVerifyingFileId(fileId);
    try {
      const res = await verifyFileIntegrity(fileId, token);
      if (res.success) {
        setVerificationModalData(res);
      } else {
        setErrorMsg(res.message || 'Blockchain verification failed.');
      }
    } catch (err) {
      setErrorMsg(`Verification error: ${err.message}`);
    } finally {
      setVerifyingFileId(null);
    }
  };

  const handleRetryBlockchain = async (fileId) => {
    setErrorMsg('');
    setRetryingFileId(fileId);
    try {
      const res = await retryBlockchainRegistration(fileId, token);
      if (res.success) {
        setSuccessMsg(`✓ File metadata successfully recorded on blockchain.`);
        await fetchFiles();
      } else {
        setErrorMsg(res.message || 'Blockchain registration failed.');
      }
    } catch (err) {
      setErrorMsg(`Retry failed: ${err.message}`);
    } finally {
      setRetryingFileId(null);
    }
  };

  // Open Share Modal
  const openShareModal = (file) => {
    setShareModalFile(file);
    setSelectedReceiverId('');
    setErrorMsg('');
    setSuccessMsg('');
  };

  // Execute File Share
  const handleExecuteShare = async (e) => {
    e.preventDefault();
    if (!selectedReceiverId) {
      setErrorMsg('Please select a receiver user.');
      return;
    }
    setIsSharing(true);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await shareFile(shareModalFile.id, selectedReceiverId, token);
      if (res.success) {
        setSuccessMsg(res.message || `File shared successfully via ECC P-256 key wrapping.`);
        setShareModalFile(null);
      } else {
        setErrorMsg(res.message || 'Sharing failed.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Failed to share file.');
    } finally {
      setIsSharing(false);
    }
  };

  // Open Manage Shares Modal
  const openManageSharesModal = async (file) => {
    setManageSharesFile(file);
    setLoadingShares(true);
    setErrorMsg('');
    try {
      const res = await getFileShares(file.id, token);
      if (res.success) {
        setFileSharesList(res.shares || []);
      }
    } catch (err) {
      setErrorMsg(`Failed to load shares: ${err.message}`);
    } finally {
      setLoadingShares(false);
    }
  };

  // Revoke Share Action
  const handleRevokeShare = async (receiverId) => {
    setRevokingReceiverId(receiverId);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await revokeShare(manageSharesFile.id, receiverId, token);
      if (res.success) {
        setSuccessMsg(`Share revoked successfully.`);
        setFileSharesList(prev => prev.map(s => s.receiver_id === receiverId ? { ...s, active: false } : s));
      }
    } catch (err) {
      setErrorMsg(`Revoke failed: ${err.message}`);
    } finally {
      setRevokingReceiverId(null);
    }
  };

  const formatSize = (bytes) => {
    if (!bytes && bytes !== 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontFamily: 'var(--font-heading)', fontSize: '2rem', color: '#fff', marginBottom: '0.25rem' }}>
          Secure File Sharing
        </h1>
        <p style={{ color: 'var(--accent-cyan)', fontSize: '1.1rem', fontWeight: '500' }}>
          Welcome, {user?.username || 'User'}
        </p>
      </div>

      {errorMsg && <div className="alert alert-danger">{errorMsg}</div>}
      {successMsg && <div className="alert alert-success">{successMsg}</div>}

      <div className="dashboard-grid">
        {/* Left Column: Upload Box & Tabbed File Lists */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {/* Upload Secure File Card */}
          <div className="cyber-card">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              Upload Secure File (IPFS + Blockchain)
            </h2>

            <form onSubmit={handleUploadSubmit}>
              <div style={{ background: 'var(--bg-primary)', padding: '1.5rem', borderRadius: 'var(--radius-sm)', border: '1px dashed var(--border-color)', marginBottom: '1.25rem', textAlign: 'center' }}>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  style={{ display: 'none' }}
                  id="file-upload-input"
                  disabled={isUploading}
                />
                <label htmlFor="file-upload-input" className="btn btn-secondary" style={{ cursor: isUploading ? 'not-allowed' : 'pointer', marginBottom: '0.75rem' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                  </svg>
                  Choose File
                </label>

                {selectedFile ? (
                  <div style={{ marginTop: '0.75rem', textAlign: 'left', background: 'var(--bg-card)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.9rem', color: '#fff', fontWeight: '600', marginBottom: '0.25rem' }}>
                      Selected File: <span style={{ color: 'var(--accent-cyan)' }}>{selectedFile.name}</span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
                      <span>Size: {formatSize(selectedFile.size)}</span>
                      <span>Cipher: AES-256-GCM</span>
                      <span>Hash: SHA-256</span>
                      <span>Storage: IPFS</span>
                      <span>Ledger: Hardhat Blockchain</span>
                    </div>
                  </div>
                ) : (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                    No file selected
                  </p>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Maximum file size: <strong>16 MB</strong> &bull; Storage: <strong>IPFS + Hardhat Blockchain</strong>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!selectedFile || isUploading}
                >
                  {isUploading ? 'Encrypting & Registering...' : 'Encrypt & Store File'}
                </button>
              </div>
            </form>
          </div>

          {/* Account Information Card */}
          <div className="cyber-card">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                <circle cx="12" cy="7" r="4"/>
              </svg>
              Account & Security Status
            </h2>
            <div className="info-grid">
              <div className="info-item">
                <div className="info-label">Username</div>
                <div className="info-value">{user?.username}</div>
              </div>
              <div className="info-item">
                <div className="info-label">Email</div>
                <div className="info-value">{user?.email}</div>
              </div>
              <div className="info-item">
                <div className="info-label">ECC Key Pair (P-256)</div>
                <div className="info-value" style={{ color: 'var(--success)', fontSize: '0.8rem' }}>
                  ✓ Active (Master Key Protected)
                </div>
              </div>
            </div>
          </div>

          {/* Tabbed File Section: My Files vs Shared With Me */}
          <div className="cyber-card">
            <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.25rem' }}>
              <button
                onClick={() => setActiveTab('myFiles')}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: activeTab === 'myFiles' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  color: activeTab === 'myFiles' ? '#fff' : 'var(--text-muted)',
                  fontSize: '1rem',
                  fontWeight: '600',
                  padding: '0.5rem 1rem',
                  cursor: 'pointer'
                }}
              >
                My Files ({files.length})
              </button>

              <button
                onClick={() => { setActiveTab('sharedWithMe'); fetchSharedFiles(); }}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: activeTab === 'sharedWithMe' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  color: activeTab === 'sharedWithMe' ? '#fff' : 'var(--text-muted)',
                  fontSize: '1rem',
                  fontWeight: '600',
                  padding: '0.5rem 1rem',
                  cursor: 'pointer'
                }}
              >
                Shared With Me ({sharedFiles.length})
              </button>
            </div>

            {/* TAB 1: My Files */}
            {activeTab === 'myFiles' && (
              <div>
                {loadingFiles ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    Loading files...
                  </div>
                ) : files.length === 0 ? (
                  <div style={{ background: 'var(--bg-primary)', padding: '2.5rem 1.5rem', borderRadius: 'var(--radius-sm)', textAlign: 'center', border: '1px dashed var(--border-color)' }}>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
                      No files uploaded yet.
                    </p>
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File Name</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Size</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Encryption</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Blockchain</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {files.map((file) => (
                          <tr key={file.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <td style={{ padding: '0.85rem 0.5rem', fontWeight: '500', color: '#fff' }}>
                              <div>{file.original_filename}</div>
                              {file.ipfs_cid && (
                                <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', marginTop: '0.2rem' }}>
                                  CID: {file.ipfs_cid.slice(0, 14)}...{file.ipfs_cid.slice(-6)}
                                </div>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--text-muted)' }}>
                              {formatSize(file.file_size)}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
                                AES-256-GCM
                              </span>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {file.blockchain_recorded ? (
                                <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
                                  Recorded
                                </span>
                              ) : (
                                <span className="badge badge-pending" style={{ fontSize: '0.7rem' }}>
                                  Pending
                                </span>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '0.4rem', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                <button
                                  onClick={() => openShareModal(file)}
                                  className="btn btn-primary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                >
                                  Share
                                </button>
                                <button
                                  onClick={() => openManageSharesModal(file)}
                                  className="btn btn-secondary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                >
                                  Manage Shares
                                </button>
                                <button
                                  onClick={() => handleDownload(file.id, file.original_filename)}
                                  className="btn btn-secondary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                >
                                  Download
                                </button>
                                <button
                                  onClick={() => handleDelete(file.id, file.original_filename)}
                                  className="btn btn-danger"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                >
                                  Delete
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: Shared With Me */}
            {activeTab === 'sharedWithMe' && (
              <div>
                {loadingShared ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    Loading shared files...
                  </div>
                ) : sharedFiles.length === 0 ? (
                  <div style={{ background: 'var(--bg-primary)', padding: '2.5rem 1.5rem', borderRadius: 'var(--radius-sm)', textAlign: 'center', border: '1px dashed var(--border-color)' }}>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
                      No files shared with you yet.
                    </p>
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File Name</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Owner</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Size</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Key Sharing</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sharedFiles.map((file) => (
                          <tr key={file.file_id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <td style={{ padding: '0.85rem 0.5rem', fontWeight: '500', color: '#fff' }}>
                              <div>{file.original_filename}</div>
                              {file.ipfs_cid && (
                                <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', marginTop: '0.2rem' }}>
                                  IPFS: {file.ipfs_cid.slice(0, 14)}...
                                </div>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--accent-cyan)' }}>
                              {file.owner_name} ({file.owner_email})
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--text-muted)' }}>
                              {formatSize(file.file_size)}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
                                P-256 ECDH + HKDF
                              </span>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', textAlign: 'right' }}>
                              <button
                                onClick={() => handleDownloadShared(file.file_id, file.original_filename)}
                                className="btn btn-primary"
                                style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                              >
                                Decrypt & Download
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Sidebar: Security Roadmap */}
        <div>
          <div className="cyber-card">
            <h2 className="section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              Security Features Status
            </h2>
            <ul className="roadmap-list">
              <li className="roadmap-item completed">
                <span>✓ Secure user authentication</span>
                <span className="badge badge-success">Phase 1</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ AES-256-GCM encryption</span>
                <span className="badge badge-success">Phase 2</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ SHA-256 integrity verification</span>
                <span className="badge badge-success">Phase 3</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ IPFS decentralized storage</span>
                <span className="badge badge-success">Phase 4</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ Blockchain metadata registry</span>
                <span className="badge badge-success">Phase 5</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ Flask-Web3 integration</span>
                <span className="badge badge-success">Phase 6</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ File sharing permissions</span>
                <span className="badge badge-success">Phase 7</span>
              </li>
              <li className="roadmap-item completed">
                <span>✓ ECC P-256 + ECDH key sharing</span>
                <span className="badge badge-success">Phase 7</span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Share File Modal */}
      {shareModalFile && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '500px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.2rem', color: '#fff', margin: 0 }}>
                Share File: <span style={{ color: 'var(--accent-cyan)' }}>{shareModalFile.original_filename}</span>
              </h2>
              <button onClick={() => setShareModalFile(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            <form onSubmit={handleExecuteShare}>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Select Receiver User:
                </label>
                <select
                  value={selectedReceiverId}
                  onChange={(e) => setSelectedReceiverId(e.target.value)}
                  style={{ width: '100%', padding: '0.75rem', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: '#fff', borderRadius: 'var(--radius-sm)' }}
                  required
                >
                  <option value="">-- Choose User --</option>
                  {shareableUsers.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.username} ({u.email})
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', marginBottom: '1.25rem' }}>
                🔑 <strong>Cryptographic Specification:</strong> P-256 ECDH agreement derives 32-byte HKDF key to wrap existing AES file key using AES-256-GCM.
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" onClick={() => setShareModalFile(null)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isSharing}>
                  {isSharing ? 'Wrapping & Sharing...' : 'Share File'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Manage Shares Modal */}
      {manageSharesFile && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '600px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.2rem', color: '#fff', margin: 0 }}>
                Manage Shares: <span style={{ color: 'var(--accent-cyan)' }}>{manageSharesFile.original_filename}</span>
              </h2>
              <button onClick={() => setManageSharesFile(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            {loadingShares ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading shares...</div>
            ) : fileSharesList.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No active or revoked shares for this file.</div>
            ) : (
              <div style={{ overflowX: 'auto', marginBottom: '1.25rem' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textAlign: 'left' }}>
                      <th style={{ padding: '0.5rem' }}>Recipient</th>
                      <th style={{ padding: '0.5rem' }}>Status</th>
                      <th style={{ padding: '0.5rem', textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fileSharesList.map(s => (
                      <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <td style={{ padding: '0.65rem 0.5rem', color: '#fff' }}>
                          {s.receiver_username} ({s.receiver_email})
                        </td>
                        <td style={{ padding: '0.65rem 0.5rem' }}>
                          {s.active ? (
                            <span className="badge badge-success">Active</span>
                          ) : (
                            <span className="badge badge-pending" style={{ color: '#ff4d4d', background: 'rgba(255,77,77,0.1)' }}>Revoked</span>
                          )}
                        </td>
                        <td style={{ padding: '0.65rem 0.5rem', textAlign: 'right' }}>
                          {s.active && (
                            <button
                              onClick={() => handleRevokeShare(s.receiver_id)}
                              disabled={revokingReceiverId === s.receiver_id}
                              className="btn btn-danger"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            >
                              {revokingReceiverId === s.receiver_id ? 'Revoking...' : 'Revoke Access'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div style={{ textAlign: 'right' }}>
              <button onClick={() => setManageSharesFile(null)} className="btn btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Blockchain Verification Modal */}
      {verificationModalData && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '600px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.25rem', color: '#fff', margin: 0 }}>
                Blockchain Verification Status
              </h2>
              <button onClick={() => setVerificationModalData(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <span className="badge badge-success">OVERALL VERIFIED ✓</span>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  File ID #{verificationModalData.file_id}
                </span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: 0 }}>
                {verificationModalData.message}
              </p>
            </div>

            <div style={{ textAlign: 'right' }}>
              <button onClick={() => setVerificationModalData(null)} className="btn btn-secondary">
                Close Verification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
