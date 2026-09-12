import React, { createContext, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [emailAccountId, setEmailAccountId] = useState(localStorage.getItem('email_account_id'));
  const [emailAddress, setEmailAddress] = useState(localStorage.getItem('email_address'));
  const navigate = useNavigate();

  const login = (newToken, newEmailAccountId, newEmailAddress) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
    if (newEmailAccountId) {
      localStorage.setItem('email_account_id', newEmailAccountId);
      setEmailAccountId(newEmailAccountId);
    }
    if (newEmailAddress) {
      localStorage.setItem('email_address', newEmailAddress);
      setEmailAddress(newEmailAddress);
    }
    navigate('/');
  };

  const updateEmailAccountId = (id) => {
    localStorage.setItem('email_account_id', id);
    setEmailAccountId(id);
  };


  const disconnectAccount = () => {
    localStorage.removeItem('email_account_id');
    setEmailAccountId(null);
  };

  const logout = () => {

    localStorage.removeItem('token');
    localStorage.removeItem('email_account_id');
    localStorage.removeItem('email_address');
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
