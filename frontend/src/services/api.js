const API_BASE = (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL.trim() !== '')
  ? `${import.meta.env.VITE_API_URL.replace(/\/$/, '')}/api`
  : (import.meta.env.MODE === 'production' ? 'https://securefilesharing-1.onrender.com/api' : '/api');

/**
 * Helper to execute API requests with proper headers and error handling.
 */
async function request(endpoint, options = {}) {
  const headers = {
    ...options.headers,
  };

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = data.message || `Request failed with status ${response.status}`;
    throw new Error(errorMsg);
  }

  return data;
}

/**
 * Health check endpoint.
 */
export async function healthCheck() {
  return request('/health', { method: 'GET' });
}

/**
 * Register a new user.
 */
export async function registerUser(username, email, password) {
  return request('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, email, password }),
  });
}

/**
 * Login user.
 */
export async function loginUser(email, password) {
  return request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

/**
 * Get current authenticated user profile.
 */
export async function getCurrentUser(token) {
  return request('/auth/me', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Connect/link Web3 wallet address.
 */
export async function connectWalletAddress(walletAddress, token) {
  return request('/auth/wallet', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ wallet_address: walletAddress }),
  });
}

/**
 * Phase 2 — Upload file with AES-256-GCM encryption.
 */
export async function uploadFile(fileObj, token) {
  const formData = new FormData();
  formData.append('file', fileObj);

  return request('/files/upload', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: formData,
  });
}

/**
 * Phase 2 — Get list of files owned by authenticated user.
 */
export async function getUserFiles(token) {
  return request('/files', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 2 — Download and decrypt original file.
 */
export async function downloadFile(fileId, token, originalFilename) {
  const response = await fetch(`${API_BASE}/files/${fileId}/download`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || 'Failed to download file.');
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = originalFilename || `decrypted_file_${fileId}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

/**
 * Phase 2 — Delete file.
 */
export async function deleteFile(fileId, token) {
  return request(`/files/${fileId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 6 — Get on-chain blockchain metadata record for a file.
 */
export async function getBlockchainRecord(fileId, token) {
  return request(`/files/${fileId}/blockchain`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 6 — Perform 4-way cross-system integrity verification.
 */
export async function verifyFileIntegrity(fileId, token) {
  return request(`/files/${fileId}/verify`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 6 — Retry pending/failed blockchain registration.
 */
export async function retryBlockchainRegistration(fileId, token) {
  return request(`/files/${fileId}/blockchain/register`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 7 — Share file with a receiver user.
 */
export async function shareFile(fileId, receiverId, token) {
  return request(`/files/${fileId}/share`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ receiver_id: receiverId }),
  });
}

/**
 * Phase 7 — Get list of shares for an owned file.
 */
export async function getFileShares(fileId, token) {
  return request(`/files/${fileId}/shares`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 7 — Revoke a share for a file.
 */
export async function revokeShare(fileId, receiverId, token) {
  return request(`/files/${fileId}/shares/${receiverId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 7 — Get files shared with current authenticated user.
 */
export async function getSharedWithMe(token) {
  return request('/shared-files', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Get files shared BY the current authenticated user to others.
 */
export async function getSharedByMe(token) {
  return request('/shared-by-me', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 7 — Get candidate shareable users.
 */
export async function getShareableUsers(token) {
  return request('/users/shareable', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

/**
 * Phase 7 — Download and decrypt shared file.
 */
export async function downloadSharedFile(fileId, token, originalFilename) {
  const response = await fetch(`${API_BASE}/shared-files/${fileId}/download`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || 'Failed to download shared file.');
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = originalFilename || `shared_decrypted_${fileId}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

/**
 * Real-Time Manual Inspection & Payload Hash Calculation.
 */
export async function inspectFilePayload(fileId, token) {
  return request(`/files/${fileId}/inspect`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

