import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Login from '../pages/Login';
import { AuthProvider } from '../contexts/AuthContext';
import { MemoryRouter } from 'react-router-dom';

describe('Login Page', () => {
  const renderLogin = () => {
    return render(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>
    );
  };

  it('renders branding and identity', () => {
    renderLogin();
    expect(screen.getByText('MailForensics AI')).toBeInTheDocument();
    expect(screen.getByText(/Every email tells a story/i)).toBeInTheDocument();
    expect(screen.getByText(/Smarter Emails/i)).toBeInTheDocument();
  });

  it('renders login card and Welcome back', () => {
    renderLogin();
    expect(screen.getByText('Welcome back')).toBeInTheDocument();
    expect(screen.getByText(/Connect your Gmail account/i)).toBeInTheDocument();
  });

  it('renders the connect button and triggers OAuth', () => {
    const mockOpen = vi.fn(() => ({
      closed: true,
      location: { href: '' },
      document: { body: { innerText: '' } },
      close: vi.fn()
    }));
    window.open = mockOpen;

    renderLogin();
    const connectButton = screen.getByText('Connect Gmail');
    expect(connectButton).toBeInTheDocument();
    
    fireEvent.click(connectButton);
    
    expect(mockOpen).toHaveBeenCalled();
  });
  
  it('renders secure connection reassurance', () => {
    renderLogin();
    expect(screen.getByText('Secure connection')).toBeInTheDocument();
    expect(screen.getByText(/We use Google's secure OAuth/i)).toBeInTheDocument();
  });
});
