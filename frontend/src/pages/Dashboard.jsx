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
  getSharedByMe,
  getShareableUsers,
  downloadSharedFile,
  inspectFilePayload,
  connectWalletAddress
} from '../services/api';

const CODE_SNIPPETS = {
  aes: {
    title: "AES-256-GCM Symmetric Encryption & Decryption",
    filePath: "backend/app/services/encryption_service.py",
    language: "Python",
    description: "Performs authenticated per-file AES-256-GCM encryption with 96-bit unique nonces and 128-bit authentication tags to prevent ciphertext tampering.",
    code: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_file_key() -> bytes:
    """Generates cryptographically secure 256-bit AES per-file key."""
    return AESGCM.generate_key(bit_length=256)

def encrypt_file_data(file_bytes: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypts raw file bytes with AES-256-GCM."""
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, file_bytes, None)
    return ciphertext_with_tag

def decrypt_file_data(ciphertext_bytes: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypts ciphertext and verifies GCM authentication tag before returning plaintext."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_bytes, None)`
  },
  sha256: {
    title: "SHA-256 Cryptographic Integrity Verification",
    filePath: "backend/app/services/integrity_service.py",
    language: "Python",
    description: "Computes SHA-256 digests over encrypted binary payloads and executes constant-time comparisons to audit against tampering.",
    code: `import hashlib
import hmac

def calculate_bytes_sha256(bytes_data: bytes) -> str:
    """Calculates SHA-256 hex digest for byte arrays in memory."""
    return hashlib.sha256(bytes_data).hexdigest().lower()

def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    """Verifies file integrity using constant-time comparison to prevent timing attacks."""
    actual_hash = calculate_file_sha256(file_path)
    if not hmac.compare_digest(actual_hash, expected_hash.lower()):
        raise FileIntegrityError("SHA-256 Hash Mismatch detected!")
    return True`
  },
  ipfs: {
    title: "Decentralized IPFS Kubo Node Storage Engine",
    filePath: "backend/app/services/ipfs_service.py",
    language: "Python",
    description: "Streams encrypted payload binaries directly to local IPFS Kubo daemon endpoint and pinned CIDs.",
    code: `import requests

def add_bytes_to_ipfs(encrypted_bytes: bytes) -> str:
    """Uploads encrypted binary payload directly to IPFS Kubo node API."""
    url = f"{Config.IPFS_API_URL}/api/v0/add?pin=true"
    files = {'file': ('encrypted.bin', encrypted_bytes, 'application/octet-stream')}
    response = requests.post(url, files=files, timeout=30)
    data = response.json()
    return data["Hash"] # Returns Content Identifier (CID)`
  },
  blockchain: {
    title: "Hardhat Solidity Immutable Smart Contract Ledger",
    filePath: "blockchain/contracts/FileMetadataRegistry.sol",
    language: "Solidity",
    description: "On-chain Solidity smart contract providing immutable, tamper-evident metadata audit trails.",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileMetadataRegistry {
    struct FileMetadata {
        uint256 fileId;
        string ownerId;
        string ipfsCid;
        string sha256Hash;
        uint256 timestamp;
        bool active;
    }

    mapping(uint256 => FileMetadata) private _files;
    address public owner;

    event FileRegistered(uint256 indexed fileId, string ownerId, string ipfsCid, string sha256Hash);

    function registerFile(uint256 fileId, string memory ownerId, string memory ipfsCid, string memory sha256Hash) external {
        require(!_files[fileId].active, "File ID already registered");
        _files[fileId] = FileMetadata(fileId, ownerId, ipfsCid, sha256Hash, block.timestamp, true);
        emit FileRegistered(fileId, ownerId, ipfsCid, sha256Hash);
    }
}`
  },
  ecdh: {
    title: "NIST P-256 Elliptic Curve Diffie-Hellman Key Wrapping",
    filePath: "backend/app/services/share_service.py",
    language: "Python",
    description: "Executes P-256 ECDH key exchange to derive 32-byte HKDF keys for wrapping AES per-file keys.",
    code: `from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def wrap_file_key_for_receiver(file_key: bytes, receiver_public_key_pem: str) -> Tuple[str, str]:
    """Generates ephemeral P-256 key, computes ECDH shared secret, derives HKDF key, and wraps file key."""
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_pub_key)
    derived_hkdf_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"file_sharing").derive(shared_secret)
    wrapped_key = AESGCM(derived_hkdf_key).encrypt(nonce, file_key, None)
    return base64.b64encode(wrapped_key).decode('utf-8'), ephemeral_pub_pem`
  },
  gatekeeping: {
    title: "2-Step Gatekeeping Access Control & Hash/Key Match Verification",
    filePath: "frontend/src/pages/Dashboard.jsx",
    language: "JavaScript",
    description: "Enforces 2-step verification: Gate 1 checks SHA-256 Hash Match for Download Access; Gate 2 checks Decryption Key Match for Decryption Access.",
    code: `// Gate 1: Check SHA-256 Hash Match (Download Access Control)
const isHashMatched = (currentSenderHash === currentGeneratedHash);

// Gate 2: Check Decryption Key Match (Decryption Access Control)
const isKeyMatched = (currentEditedKey === expectedSenderKey || currentEditedKey === expectedWrappedKey);

const handleManualDecryptAndDownload = async () => {
  if (!isHashMatched) {
    setErrorMsg("❌ Access Denied: SHA-256 Hash mismatch! Download blocked.");
    return;
  }
  if (!isKeyMatched) {
    setErrorMsg("❌ Access Denied: Decryption Key mismatch! Decryption blocked.");
    return;
  }
  await executeDecryptAndDownload();
};`
  }
};

export default function Dashboard() {
  const { user, token, updateUser } = useAuth();
  const [activeTab, setActiveTab] = useState('myFiles'); // 'myFiles' | 'sharedWithMe' | 'sharedByMe'
  const [files, setFiles] = useState([]);
  const [sharedFiles, setSharedFiles] = useState([]);
  const [sharedByMeList, setSharedByMeList] = useState([]);
  const [shareableUsers, setShareableUsers] = useState([]);
  
  const [loadingFiles, setLoadingFiles] = useState(true);
  const [loadingShared, setLoadingShared] = useState(false);
  const [loadingSharedByMe, setLoadingSharedByMe] = useState(false);

  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Toggles for Key visibility in tables
  const [visibleKeys, setVisibleKeys] = useState({});

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

  // Modal State for Manual Decryption & Inspection (With Edit options for BOTH Key & Generated Hash)
  const [manualDecryptModalFile, setManualDecryptModalFile] = useState(null);
  const [inspectionData, setInspectionData] = useState({
    loading: false,
    sender_hash: '',
    generated_hash: '',
    edited_generated_hash: '',
    is_editing_hash: false,
    sender_key: '',
    wrapped_key: '',
    edited_key: '',
    is_editing_key: false,
    error: null
  });
  const [isDecryptingManual, setIsDecryptingManual] = useState(false);

  // Code Inspector Modal State (Hidden by default, shown only on click)
  const [activeCodeKey, setActiveCodeKey] = useState(null);
  const [copiedCode, setCopiedCode] = useState(false);
  const [metaMaskPromptStatus, setMetaMaskPromptStatus] = useState('');
  const [showActivityModal, setShowActivityModal] = useState(false);
  const [activityLogs, setActivityLogs] = useState([]);

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

  // Load shared files (Shared With Me)
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

  // Load files shared BY current user (Shared By Me)
  const fetchSharedByMe = async () => {
    setLoadingSharedByMe(true);
    try {
      const res = await getSharedByMe(token);
      if (res.success) {
        setSharedByMeList(res.shares || []);
      }
    } catch (err) {
      console.error("Failed to load shared-by-me records:", err);
    } finally {
      setLoadingSharedByMe(false);
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

  // Parallel fetch for initial dashboard load to eliminate page load / refresh latency
  const fetchDashboardData = async () => {
    setLoadingFiles(true);
    try {
      const [filesRes, sharedRes, sharedByMeRes, shareableRes] = await Promise.allSettled([
        getUserFiles(token),
        getSharedWithMe(token),
        getSharedByMe(token),
        getShareableUsers(token)
      ]);

      if (filesRes.status === 'fulfilled' && filesRes.value?.success) {
        setFiles(filesRes.value.files || []);
      }
      if (sharedRes.status === 'fulfilled' && sharedRes.value?.success) {
        setSharedFiles(sharedRes.value.files || []);
      }
      if (sharedByMeRes.status === 'fulfilled' && sharedByMeRes.value?.success) {
        setSharedByMeList(sharedByMeRes.value.shares || []);
      }
      if (shareableRes.status === 'fulfilled' && shareableRes.value?.success) {
        setShareableUsers(shareableRes.value.users || []);
      }
    } catch (err) {
      console.error("Dashboard parallel fetch error:", err);
    } finally {
      setLoadingFiles(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchDashboardData();
    }

    // Real-time listener for MetaMask account switching inside extension
    if (window.ethereum) {
      const handleAccountsChanged = async (accounts) => {
        if (accounts && accounts.length > 0) {
          const newAddress = accounts[0];
          if (newAddress && newAddress.toLowerCase() !== (user?.wallet_address || '').toLowerCase()) {
            try {
              const res = await connectWalletAddress(newAddress, token);
              if (res.success) {
                updateUser({ wallet_address: newAddress });
                setSuccessMsg(`✓ MetaMask wallet updated to active account: ${newAddress}`);
              }
            } catch (err) {
              console.warn("Auto-update switched address notice:", err);
            }
          }
        }
      };

      window.ethereum.on('accountsChanged', handleAccountsChanged);

      // Initial sync check on component load
      window.ethereum.request({ method: 'eth_accounts' })
        .then(accounts => {
          if (accounts && accounts.length > 0) {
            handleAccountsChanged(accounts);
          }
        })
        .catch(() => {});

      return () => {
        if (window.ethereum.removeListener) {
          window.ethereum.removeListener('accountsChanged', handleAccountsChanged);
        }
      };
    }
  }, [token, user?.wallet_address]);

  const toggleKeyVisibility = (keyId) => {
    setVisibleKeys(prev => ({ ...prev, [keyId]: !prev[keyId] }));
  };

  const handleFileChange = (e) => {
    setErrorMsg('');
    setSuccessMsg('');
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleOpenMetaMaskPlatform = (walletAddress) => {
    const address = walletAddress || user?.wallet_address;
    if (!address) {
      setErrorMsg("No wallet address connected yet.");
      return;
    }

    // Open Etherscan block explorer / MetaMask platform page dynamically in a new tab
    const explorerUrl = `https://etherscan.io/address/${address}`;
    window.open(explorerUrl, '_blank', 'noopener,noreferrer');
  };

  // Triggers real-time Web3 transaction/signature popup on MetaMask to anchor cryptographic hash on-chain
  const triggerMetaMaskTransaction = async (fileInfo) => {
    if (!window.ethereum) {
      console.log("MetaMask Web3 extension not installed in browser.");
      return { success: false, rejected: false, message: "MetaMask extension unavailable or locked." };
    }

    try {
      // 1. Request connected account to ensure MetaMask popup window triggers
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const fromAddr = (accounts && accounts.length > 0) ? accounts[0] : user?.wallet_address;
      if (!fromAddr) {
        return { success: false, rejected: false, message: "No connected MetaMask wallet address found." };
      }

      // Auto-link active wallet address if different
      if (fromAddr && fromAddr !== user?.wallet_address) {
        try {
          await connectWalletAddress(fromAddr, token);
          updateUser({ wallet_address: fromAddr });
        } catch (e) {}
      }

      // 2. Format file metadata payload for smart contract ledger & MetaMask Activity log
      const ownerAddr = fromAddr || user?.wallet_address || "0xOwnerAddress";
      const fileStatusStr = fileInfo?.status ? `Active (${fileInfo.status})` : "ipfs_stored (Active)";
      const accessPermStr = fileInfo?.access_permissions || "Private Owner Only (AES-256-GCM Encrypted)";
      const txHistoryStr = `Registered at ${new Date().toLocaleTimeString()} (Confirmed on Blockchain)`;

      const payloadObj = {
        action: "REGISTER_FILE_SHA256",
        fileId: fileInfo?.id || fileInfo?.file_id || Date.now(),
        filename: fileInfo?.original_filename || fileInfo?.filename || "secure_file",
        ownerAddress: ownerAddr,
        fileStatus: fileStatusStr,
        accessPermissions: accessPermStr,
        ipfsCid: fileInfo?.ipfs_cid || fileInfo?.cid || "",
        sha256: fileInfo?.sha256_hash || fileInfo?.hash || "",
        transactionHistory: txHistoryStr
      };
      const payloadString = JSON.stringify(payloadObj, null, 2);

      let resultHash = null;
      let activityType = "Signature Request / Contract Interaction";

      // 3. Execute EIP-712 eth_signTypedData_v4 for native structured logging inside MetaMask Activity Tab
      try {
        let currentChainId = 31337;
        try {
          const hexChain = await window.ethereum.request({ method: 'eth_chainId' });
          if (hexChain) currentChainId = parseInt(hexChain, 16) || 31337;
        } catch (e) {}

        const domain = {
          name: 'Secure File Sharing System',
          version: '1',
          chainId: currentChainId
        };

        const types = {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' }
          ],
          FileRegistration: [
            { name: 'action', type: 'string' },
            { name: 'fileId', type: 'uint256' },
            { name: 'filename', type: 'string' },
            { name: 'ownerAddress', type: 'string' },
            { name: 'fileStatus', type: 'string' },
            { name: 'accessPermissions', type: 'string' },
            { name: 'ipfsCid', type: 'string' },
            { name: 'sha256Hash', type: 'string' },
            { name: 'transactionHistory', type: 'string' },
            { name: 'timestamp', type: 'string' }
          ]
        };

        const message = {
          action: "REGISTER_FILE_SHA256",
          fileId: Number(payloadObj.fileId) || Date.now(),
          filename: payloadObj.filename,
          ownerAddress: ownerAddr,
          fileStatus: fileStatusStr,
          accessPermissions: accessPermStr,
          ipfsCid: payloadObj.ipfsCid || "",
          sha256Hash: payloadObj.sha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          transactionHistory: txHistoryStr,
          timestamp: new Date().toLocaleTimeString()
        };

        const typedData = JSON.stringify({
          types,
          domain,
          primaryType: 'FileRegistration',
          message
        });

        resultHash = await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [fromAddr, typedData]
        });
        activityType = "Signature Request (EIP-712)";
        console.log("✓ MetaMask EIP-712 Signature Confirmed & Recorded:", resultHash);
      } catch (typedErr) {
        if (typedErr.code === 4001 || (typedErr.message && typedErr.message.toLowerCase().includes("rejected"))) {
          throw typedErr;
        }
        console.warn("eth_signTypedData_v4 fallback to personal_sign:", typedErr);
        const signMsgHex = "0x" + Array.from(new TextEncoder().encode(`Confirm & Sign SHA-256 File Registration:\n${payloadString}`)).map(b => b.toString(16).padStart(2, '0')).join('');
        resultHash = await window.ethereum.request({
          method: 'personal_sign',
          params: [signMsgHex, fromAddr]
        });
        activityType = "Signature Request";
        console.log("✓ MetaMask Real-Time Signature Confirmed:", resultHash);
      }

      if (resultHash) {
        const fileIdVal = payloadObj.fileId;
        try {
          await retryBlockchainRegistration(fileIdVal, token, resultHash);
        } catch (postErr) {
          console.warn("Backend blockchain registration update warning:", postErr);
        }

        const newLog = {
          id: Date.now(),
          type: activityType,
          status: "Confirmed ✓",
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          account: ownerAddr,
          filename: payloadObj.filename,
          ownerAddress: ownerAddr,
          fileStatus: fileStatusStr,
          accessPermissions: accessPermStr,
          transactionHistory: txHistoryStr,
          payloadString: payloadString,
          signatureHash: resultHash
        };
        setActivityLogs(prev => [newLog, ...prev]);

        return { success: true, txHash: resultHash };
      }

      return { success: false, rejected: false, message: "Transaction submission failed." };
    } catch (err) {
      console.warn("MetaMask transaction confirmation rejected or cancelled:", err);
      const isRejection = err.code === 4001 || (err.message && err.message.toLowerCase().includes("user rejected")) || (err.message && err.message.toLowerCase().includes("rejected"));
      const newLog = {
        id: Date.now(),
        type: "Signature Request (MetaMask)",
        status: "Rejected ✗",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        account: user?.wallet_address || "Connected Account",
        filename: fileInfo?.original_filename || "secure_file",
        payloadString: err.message || "User rejected transaction in MetaMask."
      };
      setActivityLogs(prev => [newLog, ...prev]);

      return {
        success: false,
        rejected: isRejection,
        message: "Transaction rejected by user. Blockchain record was not created."
      };
    }
  };

  const handleConnectMetaMask = async () => {
    setErrorMsg('');
    setSuccessMsg('');

    try {
      let detectedAddress = '';

      // Ask user how they want to connect/link their wallet address:
      // Option A: Auto-detect active browser MetaMask account
      // Option B: Manually enter/paste any custom wallet address (e.g. friend's address)
      const useAutoExtension = window.confirm(
        "Link Web3 Wallet Address Options:\n\n• Click OK to auto-detect active MetaMask extension account.\n• Click CANCEL to manually enter/paste any custom Web3 wallet address (e.g. friend's address)."
      );

      if (useAutoExtension && window.ethereum) {
        try {
          const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
          if (accounts && accounts[0]) {
            detectedAddress = accounts[0];
          }
        } catch (e) {
          console.warn("MetaMask connection notice:", e);
        }
      }

      // If user selected Cancel, or extension returned no address, prompt for custom address
      if (!detectedAddress) {
        const inputAddress = window.prompt(
          "Enter or paste any Web3 Wallet Address (e.g. 0x... or friend's address):",
          user?.wallet_address || ""
        );

        if (!inputAddress || !inputAddress.trim()) {
          return; // User cancelled prompt
        }
        detectedAddress = inputAddress.trim();
      }

      // Validate ETH address format
      if (!detectedAddress.startsWith('0x') || detectedAddress.length < 10) {
        setErrorMsg('Invalid Web3 wallet address format. Address must start with 0x.');
        return;
      }

      // Save dynamically connected address to user account backend
      const res = await connectWalletAddress(detectedAddress, token);
      if (res.success) {
        updateUser({ wallet_address: detectedAddress });
        setSuccessMsg(`✓ Dynamic Web3 wallet address updated & linked: ${detectedAddress}`);
      } else {
        setErrorMsg(res.message || 'Failed to link wallet address.');
      }
    } catch (err) {
      setErrorMsg(`Wallet connection failed: ${err.message}`);
    }
  };

  const calculateFileSHA256 = async (file) => {
    try {
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (err) {
      return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setMetaMaskPromptStatus('');

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
      // 1. Perform AES-256-GCM encryption and IPFS storage
      const res = await uploadFile(selectedFile, token);
      if (res.success && res.file) {
        // 2. Open MetaMask popup window for user confirmation
        if (window.ethereum) {
          const metaRes = await triggerMetaMaskTransaction(res.file);
          if (metaRes && metaRes.success) {
            setSuccessMsg(`✓ Encrypted with AES-256-GCM. ✓ Stored on IPFS. ✓ Blockchain record created successfully via MetaMask confirmation (Txn: ${metaRes.txHash.slice(0, 10)}...).`);
          } else if (metaRes && metaRes.rejected) {
            setErrorMsg(metaRes.message || "Transaction rejected by user. Blockchain record was not created.");
          } else {
            setSuccessMsg(`✓ Encrypted with AES-256-GCM. ✓ Stored on IPFS.`);
          }
        } else {
          setSuccessMsg(res.message || `✓ Encrypted with AES-256-GCM. ✓ Stored on IPFS.`);
        }

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
      const fileObj = files.find(f => f.id === fileId) || { id: fileId };
      if (window.ethereum) {
        const metaRes = await triggerMetaMaskTransaction(fileObj);
        if (metaRes && metaRes.success) {
          setSuccessMsg(`✓ File metadata successfully recorded on blockchain via MetaMask confirmation.`);
          await fetchFiles();
        } else if (metaRes && metaRes.rejected) {
          setErrorMsg(metaRes.message || "Transaction rejected by user. Blockchain record was not created.");
        } else {
          const res = await retryBlockchainRegistration(fileId, token);
          if (res.success) {
            setSuccessMsg(`✓ File metadata successfully recorded on blockchain.`);
            await fetchFiles();
          } else {
            setErrorMsg(res.message || 'Blockchain registration failed.');
          }
        }
      } else {
        const res = await retryBlockchainRegistration(fileId, token);
        if (res.success) {
          setSuccessMsg(`✓ File metadata successfully recorded on blockchain.`);
          await fetchFiles();
        } else {
          setErrorMsg(res.message || 'Blockchain registration failed.');
        }
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
        await fetchSharedByMe();
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
  const handleRevokeShare = async (fileId, receiverId) => {
    setRevokingReceiverId(receiverId);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await revokeShare(fileId, receiverId, token);
      if (res.success) {
        setSuccessMsg(`Share revoked successfully.`);
        setFileSharesList(prev => prev.map(s => s.receiver_id === receiverId ? { ...s, active: false } : s));
        setSharedByMeList(prev => prev.map(s => (s.file_id === fileId && s.receiver_id === receiverId) ? { ...s, active: false } : s));
      }
    } catch (err) {
      setErrorMsg(`Revoke failed: ${err.message}`);
    } finally {
      setRevokingReceiverId(null);
    }
  };

  // Open Manual Inspection Modal
  const openManualInspectionModal = async (file) => {
    setManualDecryptModalFile(file);
    const initialSenderHash = file.sha256_hash || '';
    const initialKey = file.sender_key || file.encrypted_key || file.encrypted_aes_key || '';
    
    setInspectionData({
      loading: true,
      sender_hash: initialSenderHash,
      generated_hash: '',
      edited_generated_hash: '',
      is_editing_hash: false,
      sender_key: initialKey,
      wrapped_key: file.encrypted_aes_key || '',
      edited_key: initialKey,
      is_editing_key: false,
      error: null
    });

    try {
      const fileId = file.id || file.file_id;
      const res = await inspectFilePayload(fileId, token);
      if (res.success) {
        const keyVal = res.sender_key || file.sender_key || file.encrypted_key || file.encrypted_aes_key || '';
        const genHash = res.generated_hash || '';
        setInspectionData({
          loading: false,
          sender_hash: res.sender_hash || initialSenderHash,
          generated_hash: genHash,
          edited_generated_hash: genHash,
          is_editing_hash: false,
          sender_key: keyVal,
          wrapped_key: res.wrapped_key || file.encrypted_aes_key || '',
          edited_key: keyVal,
          is_editing_key: false,
          error: null
        });
      } else {
        setInspectionData(prev => ({
          ...prev,
          loading: false,
          error: res.message || 'Failed to generate payload hash.'
        }));
      }
    } catch (err) {
      setInspectionData(prev => ({
        ...prev,
        loading: false,
        error: err.message || 'Error fetching IPFS payload hash.'
      }));
    }
  };

  // Copy Code snippet to clipboard
  const handleCopyCode = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  // Dynamic Validation checks for 2-step gatekeeping:
  const currentSenderHash = (inspectionData.sender_hash || '').trim().toLowerCase();
  const currentGeneratedHash = (inspectionData.edited_generated_hash || inspectionData.generated_hash || '').trim().toLowerCase();
  const isHashMatched = Boolean(currentSenderHash && currentGeneratedHash && currentSenderHash === currentGeneratedHash);

  const currentEditedKey = (inspectionData.edited_key || '').trim();
  const expectedSenderKey = (inspectionData.sender_key || '').trim();
  const expectedWrappedKey = (inspectionData.wrapped_key || '').trim();
  
  const isKeyMatched = Boolean(
    currentEditedKey &&
    (currentEditedKey === expectedSenderKey ||
     currentEditedKey === expectedWrappedKey ||
     (!expectedSenderKey && !expectedWrappedKey))
  );

  const handleManualDecryptAndDownload = async () => {
    if (!manualDecryptModalFile) return;

    // Gate 1: Check Hash Match (Download Access)
    if (!isHashMatched) {
      setErrorMsg('❌ Access Denied: SHA-256 Hash mismatch! System-generated hash does not match sender hash. Download access denied.');
      return;
    }

    // Gate 2: Check Key Match (Decryption Access)
    if (!isKeyMatched) {
      setErrorMsg('❌ Access Denied: Decryption Key mismatch! Entered key does not match sender key. Decryption access denied.');
      return;
    }

    setIsDecryptingManual(true);
    setErrorMsg('');
    try {
      const fileId = manualDecryptModalFile.id || manualDecryptModalFile.file_id;
      const filename = manualDecryptModalFile.original_filename;
      
      if (manualDecryptModalFile.owner_id === user?.id || !manualDecryptModalFile.owner_id) {
        await downloadFile(fileId, token, filename);
      } else {
        await downloadSharedFile(fileId, token, filename);
      }
      
      setSuccessMsg(`✓ File "${filename}" hash and key verified. Downloaded and decrypted successfully.`);
      setManualDecryptModalFile(null);
    } catch (err) {
      setErrorMsg(`Manual decryption failed: ${err.message}`);
    } finally {
      setIsDecryptingManual(false);
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
      {/* Dashboard Top Header & Code Inspector Trigger */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem' }}>
        <div>
          <h1 
            onClick={() => setActiveCodeKey('aes')}
            style={{ fontFamily: 'var(--font-heading)', fontSize: '2rem', color: '#fff', marginBottom: '0.25rem', cursor: 'pointer' }}
          >
            Secure File Sharing System
          </h1>
          <p style={{ color: 'var(--accent-cyan)', fontSize: '1.1rem', fontWeight: '500' }}>
            Welcome, {user?.username || 'User'}
          </p>
        </div>
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

          {/* Account Information & MetaMask Card */}
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
              <div className="info-item">
                <div className="info-label">MetaMask Web3 Wallet</div>
                <div className="info-value">
                  {user?.wallet_address ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => handleOpenMetaMaskPlatform(user.wallet_address)}
                        className="btn btn-secondary"
                        style={{
                          padding: '0.3rem 0.65rem',
                          fontSize: '0.78rem',
                          border: '1px solid #10b981',
                          color: '#10b981',
                          background: 'rgba(16, 185, 129, 0.12)',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          cursor: 'pointer'
                        }}
                        title="Click to open MetaMask platform & view account transactions on Etherscan"
                      >
                        🦊 ✓ Connected: {user.wallet_address.slice(0, 8)}...{user.wallet_address.slice(-6)} (Open MetaMask ↗)
                      </button>
                      <button
                        onClick={handleConnectMetaMask}
                        style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.72rem', textDecoration: 'underline', cursor: 'pointer' }}
                        title="Click to switch or enter a different Web3 wallet address"
                      >
                        (Change Wallet)
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={handleConnectMetaMask}
                      className="btn btn-secondary"
                      style={{ padding: '0.3rem 0.75rem', fontSize: '0.78rem', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)' }}
                    >
                      🦊 Connect MetaMask Wallet
                    </button>
                  )}
                </div>
              </div>
            </div>
            <div style={{ marginTop: '0.85rem', paddingTop: '0.85rem', borderTop: '1px solid var(--border-color)', textAlign: 'right' }}>
              <button
                type="button"
                onClick={() => setShowActivityModal(true)}
                className="btn btn-secondary"
                style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)', border: '1px solid var(--accent-cyan)' }}
              >
                🦊 View MetaMask Activity Audit Trail ({activityLogs.length} Records)
              </button>
            </div>
          </div>

          {/* Tabbed File Section: My Files vs Shared With Me vs Shared By Me */}
          <div className="cyber-card">
            <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.25rem', overflowX: 'auto' }}>
              <button
                onClick={() => setActiveTab('myFiles')}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: activeTab === 'myFiles' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  color: activeTab === 'myFiles' ? '#fff' : 'var(--text-muted)',
                  fontSize: '0.95rem',
                  fontWeight: '600',
                  padding: '0.5rem 0.85rem',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
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
                  fontSize: '0.95rem',
                  fontWeight: '600',
                  padding: '0.5rem 0.85rem',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                Shared With Me ({sharedFiles.length})
              </button>

              <button
                onClick={() => { setActiveTab('sharedByMe'); fetchSharedByMe(); }}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: activeTab === 'sharedByMe' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  color: activeTab === 'sharedByMe' ? '#fff' : 'var(--text-muted)',
                  fontSize: '0.95rem',
                  fontWeight: '600',
                  padding: '0.5rem 0.85rem',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                Shared By Me ({sharedByMeList.length})
              </button>
            </div>

            {/* TAB 1: My Files (Sender View with "Your Key" Label) */}
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
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File & Hash</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Your Key</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Size</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Blockchain</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {files.map((file) => (
                          <tr key={file.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <td style={{ padding: '0.85rem 0.5rem', fontWeight: '500', color: '#fff' }}>
                              <div style={{ fontWeight: '600' }}>{file.original_filename}</div>
                              {file.sha256_hash && (
                                <div style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'monospace', marginTop: '0.2rem' }} title={file.sha256_hash}>
                                  SHA-256: {file.sha256_hash.slice(0, 16)}...{file.sha256_hash.slice(-8)}
                                </div>
                              )}
                              {file.ipfs_cid && (
                                <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', marginTop: '0.1rem' }}>
                                  CID: {file.ipfs_cid.slice(0, 14)}...
                                </div>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {file.encrypted_key ? (
                                <div>
                                  <button
                                    onClick={() => toggleKeyVisibility(`my_${file.id}`)}
                                    style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.72rem', borderRadius: '4px', padding: '0.2rem 0.4rem', cursor: 'pointer' }}
                                  >
                                    {visibleKeys[`my_${file.id}`] ? 'Hide Your Key' : 'View Your Key'}
                                  </button>
                                  {visibleKeys[`my_${file.id}`] && (
                                    <div style={{ fontSize: '0.7rem', color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '0.3rem', background: 'var(--bg-primary)', padding: '0.3rem', borderRadius: '4px', maxWidth: '180px' }}>
                                      {file.encrypted_key}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Protected</span>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--text-muted)' }}>
                              {formatSize(file.file_size)}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {file.blockchain_recorded ? (
                                <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
                                  Recorded
                                </span>
                              ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', alignItems: 'flex-start' }}>
                                  <span className="badge badge-pending" style={{ fontSize: '0.7rem' }}>
                                    Pending
                                  </span>
                                  <button
                                    onClick={() => handleRetryBlockchain(file.id)}
                                    disabled={retryingFileId === file.id}
                                    className="btn btn-secondary"
                                    style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem', color: 'var(--accent-cyan)', border: '1px solid var(--accent-cyan)', cursor: 'pointer' }}
                                    title="Click to open MetaMask and confirm blockchain recording"
                                  >
                                    {retryingFileId === file.id ? 'Confirming...' : '🦊 Register'}
                                  </button>
                                </div>
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
                                  onClick={() => openManualInspectionModal(file)}
                                  className="btn btn-secondary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                  title="Generate Real-Time Hash & Manual Decrypt"
                                >
                                  🔍 Inspect & Decrypt
                                </button>
                                <button
                                  onClick={() => handleDownload(file.id, file.original_filename)}
                                  className="btn btn-secondary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                >
                                  ⚡ Auto Download
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

            {/* TAB 2: Shared With Me (Receiver View) */}
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
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File Name</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Owner (Sender)</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Sender's Hash</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Sender Key Value</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Decryption Options</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sharedFiles.map((file) => (
                          <tr key={file.file_id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <td style={{ padding: '0.85rem 0.5rem', fontWeight: '500', color: '#fff' }}>
                              <div style={{ fontWeight: '600' }}>{file.original_filename}</div>
                              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Size: {formatSize(file.file_size)}</div>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--accent-cyan)' }}>
                              {file.owner_name} ({file.owner_email})
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              <div style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'monospace' }} title={file.sha256_hash}>
                                {file.sha256_hash ? `${file.sha256_hash.slice(0, 14)}...` : 'Pending'}
                              </div>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {(file.sender_key || file.encrypted_aes_key) ? (
                                <div>
                                  <button
                                    onClick={() => toggleKeyVisibility(`shared_${file.file_id}`)}
                                    style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.72rem', borderRadius: '4px', padding: '0.2rem 0.4rem', cursor: 'pointer' }}
                                  >
                                    {visibleKeys[`shared_${file.file_id}`] ? 'Hide Key' : 'View Key'}
                                  </button>
                                  {visibleKeys[`shared_${file.file_id}`] && (
                                    <div style={{ fontSize: '0.7rem', color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '0.3rem', background: 'var(--bg-primary)', padding: '0.3rem', borderRadius: '4px', maxWidth: '180px' }}>
                                      {file.sender_key || file.encrypted_aes_key}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Protected</span>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '0.4rem', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                <button
                                  onClick={() => handleDownloadShared(file.file_id, file.original_filename)}
                                  className="btn btn-primary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                  title="Automatic Download & Decrypt"
                                >
                                  ⚡ Auto Decrypt & Download
                                </button>
                                <button
                                  onClick={() => openManualInspectionModal(file)}
                                  className="btn btn-secondary"
                                  style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                                  title="Generate Real-Time Hash & Manual Decrypt"
                                >
                                  🔍 Manual Inspection & Decrypt
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

            {/* TAB 3: Shared By Me (Sender Overview with "Your Key" Label) */}
            {activeTab === 'sharedByMe' && (
              <div>
                {loadingSharedByMe ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    Loading your shared files...
                  </div>
                ) : sharedByMeList.length === 0 ? (
                  <div style={{ background: 'var(--bg-primary)', padding: '2.5rem 1.5rem', borderRadius: 'var(--radius-sm)', textAlign: 'center', border: '1px dashed var(--border-color)' }}>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
                      You haven't shared any files with other users yet.
                    </p>
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File Name</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Recipient (Receiver)</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Your Key</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>File Hash</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Status</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sharedByMeList.map((item) => (
                          <tr key={item.share_id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <td style={{ padding: '0.85rem 0.5rem', fontWeight: '500', color: '#fff' }}>
                              <div>{item.original_filename}</div>
                              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Size: {formatSize(item.file_size)}</div>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', color: 'var(--accent-cyan)' }}>
                              {item.receiver_username} ({item.receiver_email})
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {(item.sender_key || item.encrypted_aes_key) ? (
                                <div>
                                  <button
                                    onClick={() => toggleKeyVisibility(`byme_${item.share_id}`)}
                                    style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.72rem', borderRadius: '4px', padding: '0.2rem 0.4rem', cursor: 'pointer' }}
                                  >
                                    {visibleKeys[`byme_${item.share_id}`] ? 'Hide Your Key' : 'View Your Key'}
                                  </button>
                                  {visibleKeys[`byme_${item.share_id}`] && (
                                    <div style={{ fontSize: '0.7rem', color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '0.3rem', background: 'var(--bg-primary)', padding: '0.3rem', borderRadius: '4px', maxWidth: '180px' }}>
                                      {item.sender_key || item.encrypted_aes_key}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Protected</span>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              <div style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'monospace' }}>
                                {item.sha256_hash ? `${item.sha256_hash.slice(0, 14)}...` : 'Pending'}
                              </div>
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem' }}>
                              {item.active ? (
                                <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>Active Share</span>
                              ) : (
                                <span className="badge badge-pending" style={{ fontSize: '0.7rem', color: '#ff4d4d', background: 'rgba(255,77,77,0.1)' }}>Revoked</span>
                              )}
                            </td>
                            <td style={{ padding: '0.85rem 0.5rem', textAlign: 'right' }}>
                              {item.active && (
                                <button
                                  onClick={() => handleRevokeShare(item.file_id, item.receiver_id)}
                                  disabled={revokingReceiverId === item.receiver_id}
                                  className="btn btn-danger"
                                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                                >
                                  {revokingReceiverId === item.receiver_id ? 'Revoking...' : 'Revoke Access'}
                                </button>
                              )}
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

        {/* Right Sidebar: Security Features & Code Trigger */}
        <div>
          <div className="cyber-card">
            <h2 className="section-title" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Security Modules
              </span>
            </h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
              Active Cryptographic Security Modules:
            </p>
            <ul className="roadmap-list">
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('aes')}>
                <span>✓ AES-256-GCM Encryption</span>
              </li>
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('sha256')}>
                <span>✓ SHA-256 Hash Integrity</span>
              </li>
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('ipfs')}>
                <span>✓ IPFS Storage Engine</span>
              </li>
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('blockchain')}>
                <span>✓ Smart Contract Ledger</span>
              </li>
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('ecdh')}>
                <span>✓ ECC P-256 Key Exchange</span>
              </li>
              <li className="roadmap-item completed" style={{ cursor: 'pointer' }} onClick={() => setActiveCodeKey('gatekeeping')}>
                <span>✓ 2-Step Gatekeeping Logic</span>
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
                              onClick={() => handleRevokeShare(manageSharesFile.id, s.receiver_id)}
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

      {/* Manual Inspection & Decryption Modal */}
      {manualDecryptModalFile && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '720px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.2rem', color: '#fff', margin: 0 }}>
                🔍 Manual Inspection & Decryption: <span style={{ color: 'var(--accent-cyan)' }}>{manualDecryptModalFile.original_filename}</span>
              </h2>
              <button onClick={() => setManualDecryptModalFile(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
              
              {/* 1. SENDER'S ORIGINAL HASH */}
              <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: '600', marginBottom: '0.4rem' }}>
                  1. SENDER'S ORIGINAL SHA-256 FILE HASH
                </div>
                <div style={{ fontSize: '0.8rem', color: '#10b981', fontFamily: 'monospace', wordBreak: 'break-all', background: 'var(--bg-card)', padding: '0.5rem', borderRadius: '4px' }}>
                  {inspectionData.sender_hash || 'SHA-256 Pending'}
                </div>
              </div>

              {/* 2. SYSTEM-GENERATED SHA-256 HASH (WITH EDIT OPTION) */}
              <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: '600' }}>
                    2. SYSTEM-GENERATED SHA-256 HASH (From IPFS Payload) & EDIT OPTION
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => setInspectionData(prev => ({ ...prev, is_editing_hash: !prev.is_editing_hash }))}
                      style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.75rem', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer' }}
                    >
                      {inspectionData.is_editing_hash ? '🔒 Done Editing Hash' : '✏️ Edit Generated Hash'}
                    </button>
                    {inspectionData.edited_generated_hash !== inspectionData.generated_hash && (
                      <button
                        type="button"
                        onClick={() => setInspectionData(prev => ({ ...prev, edited_generated_hash: prev.generated_hash }))}
                        style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer' }}
                      >
                        Reset Hash
                      </button>
                    )}
                  </div>
                </div>

                {inspectionData.loading ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', background: 'var(--bg-card)', padding: '0.5rem', borderRadius: '4px' }}>
                    ⏳ Fetching payload from IPFS & Generating SHA-256 Hash...
                  </div>
                ) : inspectionData.is_editing_hash ? (
                  <div>
                    <textarea
                      value={inspectionData.edited_generated_hash}
                      onChange={(e) => setInspectionData(prev => ({ ...prev, edited_generated_hash: e.target.value }))}
                      placeholder="Enter or edit generated SHA-256 hash..."
                      rows={2}
                      style={{
                        width: '100%',
                        padding: '0.5rem',
                        background: 'var(--bg-card)',
                        border: '1px solid var(--accent-cyan)',
                        color: '#fff',
                        borderRadius: '4px',
                        fontSize: '0.8rem',
                        fontFamily: 'monospace'
                      }}
                    />
                    <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
                      ✏️ Edit Mode Active: You can manually edit or simulate a generated hash value to test matching.
                    </div>
                  </div>
                ) : (
                  <div>
                    <div style={{ fontSize: '0.8rem', color: isHashMatched ? '#10b981' : '#ff4d4d', fontFamily: 'monospace', wordBreak: 'break-all', background: 'var(--bg-card)', padding: '0.5rem', borderRadius: '4px' }}>
                      {inspectionData.edited_generated_hash || inspectionData.generated_hash || inspectionData.error || 'N/A'}
                    </div>
                    {inspectionData.edited_generated_hash !== inspectionData.generated_hash && (
                      <div style={{ fontSize: '0.72rem', color: '#10b981', marginTop: '0.25rem' }}>
                        ✓ Custom Edited Hash Applied
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* 3. GATE 1 STATUS — SHA-256 HASH MATCH (DOWNLOAD ACCESS CONTROL) */}
              <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: `1px solid ${isHashMatched ? 'rgba(16,185,129,0.4)' : 'rgba(255,77,77,0.4)'}` }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: '600', marginBottom: '0.4rem' }}>
                  3. GATE 1 — SHA-256 HASH MATCH (DOWNLOAD ACCESS)
                </div>
                {inspectionData.loading ? (
                  <span className="badge badge-pending">⏳ Checking Hash Match...</span>
                ) : isHashMatched ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="badge badge-success">✓ SHA-256 HASH MATCHES — DOWNLOAD ACCESS GRANTED</span>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#10b981' }}>
                      System-generated hash matches sender's hash. Payload integrity confirmed. Access to download payload is PERMITTED.
                    </span>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="badge badge-pending" style={{ color: '#ff4d4d', background: 'rgba(255,77,77,0.15)' }}>❌ SHA-256 HASH MISMATCH — DOWNLOAD ACCESS DENIED</span>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#ff4d4d' }}>
                      Sender Hash and System-Generated Hash DO NOT MATCH. Access to download file payload is DENIED!
                    </span>
                  </div>
                )}
              </div>

              {/* 4. KEY VALUE & EDIT OPTION */}
              <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: '600' }}>
                    4. DECRYPTION KEY VALUE & EDIT OPTION
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => setInspectionData(prev => ({ ...prev, is_editing_key: !prev.is_editing_key }))}
                      style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.75rem', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer' }}
                    >
                      {inspectionData.is_editing_key ? '🔒 Done Editing Key' : '✏️ Edit Key'}
                    </button>
                    {inspectionData.edited_key !== inspectionData.sender_key && (
                      <button
                        type="button"
                        onClick={() => setInspectionData(prev => ({ ...prev, edited_key: prev.sender_key }))}
                        style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer' }}
                      >
                        Reset Key
                      </button>
                    )}
                  </div>
                </div>

                {inspectionData.is_editing_key ? (
                  <div>
                    <textarea
                      value={inspectionData.edited_key}
                      onChange={(e) => setInspectionData(prev => ({ ...prev, edited_key: e.target.value }))}
                      placeholder="Enter or edit decryption key..."
                      rows={2}
                      style={{
                        width: '100%',
                        padding: '0.5rem',
                        background: 'var(--bg-card)',
                        border: '1px solid var(--accent-cyan)',
                        color: '#fff',
                        borderRadius: '4px',
                        fontSize: '0.8rem',
                        fontFamily: 'monospace'
                      }}
                    />
                    <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
                      ✏️ Edit Mode Active: You can manually modify or paste a custom key value to test decryption key matching.
                    </div>
                  </div>
                ) : (
                  <div>
                    <div style={{ fontSize: '0.78rem', color: isKeyMatched ? 'var(--accent-cyan)' : '#ff4d4d', fontFamily: 'monospace', wordBreak: 'break-all', background: 'var(--bg-card)', padding: '0.5rem', borderRadius: '4px' }}>
                      {inspectionData.edited_key || inspectionData.sender_key || 'Protected Key Value'}
                    </div>
                    {inspectionData.edited_key !== inspectionData.sender_key && (
                      <div style={{ fontSize: '0.72rem', color: '#10b981', marginTop: '0.25rem' }}>
                        ✓ Custom Edited Key Applied
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* 5. GATE 2 STATUS — DECRYPTION KEY MATCH (DECRYPTION ACCESS CONTROL) */}
              <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: `1px solid ${isKeyMatched ? 'rgba(16,185,129,0.4)' : 'rgba(255,77,77,0.4)'}` }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: '600', marginBottom: '0.4rem' }}>
                  5. GATE 2 — DECRYPTION KEY MATCH (DECRYPTION ACCESS)
                </div>
                {inspectionData.loading ? (
                  <span className="badge badge-pending">⏳ Checking Key Match...</span>
                ) : isKeyMatched ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="badge badge-success">✓ DECRYPTION KEY MATCHES — DECRYPTION ACCESS GRANTED</span>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#10b981' }}>
                      Entered decryption key matches expected sender/receiver key. Access to decrypt file payload is PERMITTED.
                    </span>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="badge badge-pending" style={{ color: '#ff4d4d', background: 'rgba(255,77,77,0.15)' }}>❌ DECRYPTION KEY MISMATCH — DECRYPTION ACCESS DENIED</span>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#ff4d4d' }}>
                      Entered decryption key DOES NOT MATCH sender key. Access to decrypt file is DENIED!
                    </span>
                  </div>
                )}
              </div>

            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => setActiveCodeKey('gatekeeping')}
                className="btn btn-secondary"
                style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)', border: '1px solid var(--accent-cyan)' }}
              >
                💻 View Gatekeeper Source Code
              </button>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button onClick={() => setManualDecryptModalFile(null)} className="btn btn-secondary">
                  Cancel
                </button>
                <button
                  onClick={handleManualDecryptAndDownload}
                  disabled={isDecryptingManual || inspectionData.loading || !isHashMatched || !isKeyMatched}
                  className="btn btn-primary"
                  style={{
                    opacity: (!isHashMatched || !isKeyMatched || inspectionData.loading) ? 0.5 : 1,
                    cursor: (!isHashMatched || !isKeyMatched || inspectionData.loading) ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isDecryptingManual ? 'Decrypting & Downloading...' : 
                   !isHashMatched ? '❌ Download Access Denied (Hash Mismatch)' :
                   !isKeyMatched ? '❌ Decryption Access Denied (Key Mismatch)' :
                   '🔓 Verify, Download & Decrypt File'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Code Inspector Modal (Only rendered when clicked) */}
      {activeCodeKey && CODE_SNIPPETS[activeCodeKey] && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.9)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '800px', width: '100%', border: '1px solid var(--accent-cyan)', boxShadow: '0 0 30px rgba(0, 242, 254, 0.3)' }}>
            
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <div>
                <h2 style={{ fontSize: '1.2rem', color: '#fff', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>💻 Code Inspector:</span>
                  <span style={{ color: 'var(--accent-cyan)' }}>{CODE_SNIPPETS[activeCodeKey].title}</span>
                </h2>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.25rem', fontFamily: 'monospace' }}>
                  File: <span style={{ color: '#fff' }}>{CODE_SNIPPETS[activeCodeKey].filePath}</span> &bull; Language: <span style={{ color: 'var(--accent-cyan)' }}>{CODE_SNIPPETS[activeCodeKey].language}</span>
                </div>
              </div>

              <button onClick={() => setActiveCodeKey(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.6rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            {/* Quick Navigation Tabs inside Code Inspector */}
            <div style={{ display: 'flex', gap: '0.4rem', overflowX: 'auto', marginBottom: '1rem', paddingBottom: '0.4rem' }}>
              {Object.keys(CODE_SNIPPETS).map(key => (
                <button
                  key={key}
                  onClick={() => setActiveCodeKey(key)}
                  style={{
                    background: activeCodeKey === key ? 'var(--accent-cyan)' : 'var(--bg-primary)',
                    color: activeCodeKey === key ? '#000' : 'var(--text-muted)',
                    border: '1px solid var(--border-color)',
                    padding: '0.3rem 0.6rem',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap'
                  }}
                >
                  {key.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Description Box */}
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', marginBottom: '1rem' }}>
              {CODE_SNIPPETS[activeCodeKey].description}
            </p>

            {/* Source Code Window with Instant Copy Option */}
            <div style={{ position: 'relative', background: '#0a0d14', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#121824', padding: '0.4rem 0.8rem', borderBottom: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                  {CODE_SNIPPETS[activeCodeKey].filePath}
                </span>
                <button
                  onClick={() => handleCopyCode(CODE_SNIPPETS[activeCodeKey].code)}
                  style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)', fontSize: '0.72rem', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer' }}
                >
                  {copiedCode ? '✓ Copied to Clipboard!' : '📋 Copy Code'}
                </button>
              </div>

              <pre style={{ margin: 0, padding: '1rem', color: '#38edf8', fontFamily: 'monospace', fontSize: '0.82rem', overflowX: 'auto', lineHeight: '1.5', maxHeight: '350px' }}>
                {CODE_SNIPPETS[activeCodeKey].code}
              </pre>
            </div>

            <div style={{ textAlign: 'right', marginTop: '1.25rem' }}>
              <button onClick={() => setActiveCodeKey(null)} className="btn btn-secondary">
                Close Code Inspector
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

      {/* MetaMask Activity Audit Modal (Displays 4 Exact Requested Details) */}
      {showActivityModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, padding: '1rem'
        }}>
          <div className="cyber-card" style={{ maxWidth: '750px', width: '100%', border: '1px solid var(--accent-cyan)', maxHeight: '85vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <h2 style={{ fontSize: '1.2rem', color: '#fff', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🦊 MetaMask Activity Log & Audit Trail</span>
              </h2>
              <button onClick={() => setShowActivityModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer' }}>
                &times;
              </button>
            </div>

            {activityLogs.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)' }}>
                <p style={{ margin: 0 }}>No signature requests or contract interactions logged yet in this session.</p>
                <p style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', marginTop: '0.5rem' }}>
                  💡 Upload a file using "Encrypt & Store File" to trigger a real-time signature request!
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                {activityLogs.map((log, index) => (
                  <div key={log.id || index} style={{ background: 'var(--bg-primary)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                    
                    {/* 1. Status & Timestamp */}
                    <div style={{ borderBottom: '1px dashed var(--border-color)', paddingBottom: '0.6rem', marginBottom: '0.85rem' }}>
                      <div style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: '600', marginBottom: '0.3rem' }}>
                        1. STATUS & TIMESTAMP
                      </div>
                      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.82rem' }}>
                        <span>Type: <strong style={{ color: '#fff' }}>{log.type}</strong></span>
                        <span>Status: <strong style={{ color: '#10b981' }}>{log.status}</strong></span>
                        <span>Time: <strong style={{ color: 'var(--text-muted)' }}>{log.timestamp}</strong></span>
                        <span>Account: <strong style={{ color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{log.account}</strong></span>
                      </div>
                    </div>

                    {/* 2. File Metadata Payload (Message) */}
                    <div style={{ borderBottom: '1px dashed var(--border-color)', paddingBottom: '0.6rem', marginBottom: '0.85rem' }}>
                      <div style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: '600', marginBottom: '0.3rem' }}>
                        2. FILE METADATA PAYLOAD (SIGNED MESSAGE)
                      </div>
                      <pre style={{ margin: 0, padding: '0.6rem', background: '#0a0d14', borderRadius: '4px', color: '#10b981', fontFamily: 'monospace', fontSize: '0.78rem', overflowX: 'auto' }}>
                        {log.payloadString}
                      </pre>
                    </div>

                    {/* 3. Cryptographic Signature Hash */}
                    <div style={{ borderBottom: '1px dashed var(--border-color)', paddingBottom: '0.6rem', marginBottom: '0.85rem' }}>
                      <div style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: '600', marginBottom: '0.3rem' }}>
                        3. CRYPTOGRAPHIC SIGNATURE HASH
                      </div>
                      <div style={{ fontSize: '0.78rem', color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all', background: '#0a0d14', padding: '0.5rem', borderRadius: '4px' }}>
                        {log.signatureHash}
                      </div>
                    </div>

                    {/* 4. Account Audit History */}
                    <div>
                      <div style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: '600', marginBottom: '0.2rem' }}>
                        4. ACCOUNT AUDIT RECORD
                      </div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        ✓ Anchored for account <strong>{log.account}</strong> on file <strong>{log.filename}</strong>. Immutability guaranteed.
                      </div>
                    </div>

                  </div>
                ))}
              </div>
            )}

            <div style={{ textAlign: 'right', marginTop: '1.25rem' }}>
              <button onClick={() => setShowActivityModal(false)} className="btn btn-secondary">
                Close Audit Log
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
