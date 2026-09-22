import React from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="nav-container">
        <Link to="/" className="brand-logo">
          <div className="brand-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span>SecureShare</span>
        </Link>

        <ul className="nav-links">
          {!user ? (
            <>
              <li>
                <NavLink to="/" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                  Home
                </NavLink>
              </li>
              <li>
                <NavLink to="/login" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                  Login
                </NavLink>
              </li>
              <li>
                <NavLink to="/register" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                  Register
                </NavLink>
              </li>
            </>
          ) : (
            <>
              <li>
                <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                  Dashboard
                </NavLink>
              </li>
              <li>
                <NavLink to="/profile" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                  Profile
                </NavLink>
              </li>
              <li>
                <button onClick={handleLogout} className="btn btn-secondary" style={{ padding: '0.35rem 0.85rem', fontSize: '0.85rem' }}>
                  Logout
                </button>
              </li>
            </>
          )}
        </ul>
      </div>
    </nav>
  );
}
