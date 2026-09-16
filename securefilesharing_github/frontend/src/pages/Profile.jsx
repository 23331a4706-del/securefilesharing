import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { connectWalletAddress } from '../services/api';

export default function Profile() {
  const { user, token, updateUser } = useAuth();
  const [connecting, setConnecting] = useState(false);
  const [manualAddress, setManualAddress] = useState('');
  const [showManualInput, setShowManualInput] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleConnectMetaMask = async () => {
    setConnecting(true);
    setErrorMsg(null);
    setStatusMsg(null);

    if (window.ethereum) {
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (accounts && accounts.length > 0) {
          const selectedAddress = accounts[0];
          await saveWalletToBackend(selectedAddress);
        } else {
          setErrorMsg('No Ethereum accounts found in MetaMask.');
        }
      } catch (err) {
        console.error('MetaMask connection error:', err);
        setErrorMsg(err.message || 'MetaMask connection request rejected.');
      } finally {
        setConnecting(false);
      }
    } else {
      setShowManualInput(true);
      setErrorMsg('MetaMask browser extension not detected. Enter Web3 wallet address manually below.');
      setConnecting(false);
    }
  };

  const handleSaveManualWallet = async (e) => {
    e.preventDefault();
    if (!manualAddress.trim()) {
      setErrorMsg('Please enter a valid Web3 wallet address.');
      return;
    }
    setConnecting(true);
    setErrorMsg(null);
    try {
      await saveWalletToBackend(manualAddress.trim());
    } catch (err) {
      setErrorMsg(err.message || 'Failed to save wallet address.');
    } finally {
      setConnecting(false);
    }
  };

  const saveWalletToBackend = async (address) => {
    const res = await connectWalletAddress(address, token);
    if (res.success && res.user) {
      updateUser({ wallet_address: res.user.wallet_address });
      setStatusMsg(`Successfully connected Web3 Wallet: ${address}`);
      setShowManualInput(false);
    } else {
      setErrorMsg(res.message || 'Failed to connect wallet address.');
    }
  };

  return (
    <div style={{ maxWidth: '650px', margin: '1.5rem auto 0' }}>
      <div className="cyber-card">
        <h2 className="section-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
          User Profile
        </h2>

        {statusMsg && (
          <div style={{ padding: '0.75rem 1rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', borderRadius: '6px', color: '#10b981', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            ✓ {statusMsg}
          </div>
        )}

        {errorMsg && (
          <div style={{ padding: '0.75rem 1rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '6px', color: '#ef4444', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            {errorMsg}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '1.5rem' }}>
          <div className="info-item">
            <div className="info-label">Username</div>
            <div className="info-value">{user?.username}</div>
          </div>

          <div className="info-item">
            <div className="info-label">Email Address</div>
            <div className="info-value">{user?.email}</div>
          </div>

          <div className="info-item">
            <div className="info-label">Wallet Address</div>
            {user?.wallet_address ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span style={{ display: 'inline-block', width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
                  <span style={{ color: '#10b981', fontWeight: '600', fontSize: '0.85rem' }}>Connected</span>
                </div>
                <div className="info-value" style={{ fontFamily: 'monospace', wordBreak: 'break-all', color: 'var(--accent-cyan)' }}>
                  {user.wallet_address}
                </div>
              </div>
            ) : (
              <div>
                <div className="info-value" style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                  Not Connected
                </div>
                
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  <button 
                    onClick={handleConnectMetaMask} 
                    disabled={connecting}
                    className="cyber-btn"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}
                  >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="5" width="20" height="14" rx="2"/>
                      <line x1="2" y1="10" x2="22" y2="10"/>
                    </svg>
                    {connecting ? 'Connecting...' : 'Connect MetaMask Wallet'}
                  </button>

                  {!showManualInput && (
                    <button 
                      onClick={() => setShowManualInput(true)} 
                      style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: '0.85rem', textDecoration: 'underline' }}
                    >
                      Enter Address Manually
                    </button>
                  )}
                </div>

                {showManualInput && (
                  <form onSubmit={handleSaveManualWallet} style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
                    <input 
                      type="text" 
                      placeholder="e.g. 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" 
                      value={manualAddress}
                      onChange={(e) => setManualAddress(e.target.value)}
                      className="cyber-input"
                      style={{ flex: 1, fontSize: '0.85rem', fontFamily: 'monospace' }}
                    />
                    <button type="submit" disabled={connecting} className="cyber-btn" style={{ fontSize: '0.85rem' }}>
                      Save Wallet
                    </button>
                  </form>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
