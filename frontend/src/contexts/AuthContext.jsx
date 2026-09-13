import React, { createContext, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

function safeGetItem(key) {
  try {
    return localStorage.getItem(key);
  } catch (e) {
    console.error("localStorage access error:", e);
    return null;
  }
}

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => safeGetItem('token'));
  const [emailAccountId, setEmailAccountId] = useState(() => safeGetItem('email_account_id'));
  const [emailAddress, setEmailAddress] = useState(() => safeGetItem('email_address'));
  const navigate = useNavigate();

  const login = (newToken, newEmailAccountId, newEmailAddress) => {
    try {
      localStorage.setItem('token', newToken);
      if (newEmailAccountId) localStorage.setItem('email_account_id', newEmailAccountId);
      if (newEmailAddress) localStorage.setItem('email_address', newEmailAddress);
    } catch(e) {
      console.error("localStorage set error:", e);
    }
    setToken(newToken);
    if (newEmailAccountId) setEmailAccountId(newEmailAccountId);
    if (newEmailAddress) setEmailAddress(newEmailAddress);
    navigate('/');
  };

  const updateEmailAccountId = (id) => {
    try {
      localStorage.setItem('email_account_id', id);
    } catch(e) {}
    setEmailAccountId(id);
  };

  const disconnectAccount = () => {
    try {
      localStorage.removeItem('email_account_id');
    } catch(e) {}
    setEmailAccountId(null);
  };

  const logout = () => {
    try {
      localStorage.removeItem('token');
      localStorage.removeItem('email_account_id');
      localStorage.removeItem('email_address');
    } catch(e) {}
    setToken(null);
    setEmailAccountId(null);
    setEmailAddress(null);
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: !!token, emailAccountId, emailAddress, login, logout, updateEmailAccountId, disconnectAccount }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
