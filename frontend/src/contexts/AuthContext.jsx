import React, { createContext, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [emailAccountId, setEmailAccountId] = useState(localStorage.getItem('email_account_id'));
  const navigate = useNavigate();

  const login = (newToken, newEmailAccountId) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
    if (newEmailAccountId) {
      localStorage.setItem('email_account_id', newEmailAccountId);
      setEmailAccountId(newEmailAccountId);
    }
    navigate('/');
  };

  const updateEmailAccountId = (id) => {
    localStorage.setItem('email_account_id', id);
    setEmailAccountId(id);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('email_account_id');
    setToken(null);
    setEmailAccountId(null);
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: !!token, emailAccountId, login, logout, updateEmailAccountId }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
