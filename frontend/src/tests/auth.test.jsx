import React from 'react';
import { render, screen, act, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import Dashboard from '../pages/Dashboard';
import Login from '../pages/Login';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Mock the API
vi.mock('../lib/api', () => ({
  api: {
    getDashboardSummary: vi.fn().mockResolvedValue({
      total_emails: 0,
      threats_detected: 0,
      high_risk: 0,
      critical: 0,
      threat_distribution: {},
      ioc_summary: {},
      recent_investigations: []
    }),
    getSyncStatus: vi.fn().mockResolvedValue({
      status: 'idle',
      total_discovered: 0,
      processed: 0,
      newly_added: 0,
      skipped_duplicate: 0,
      failed_count: 0,
      errors: []
    }),
    syncGmail: vi.fn().mockResolvedValue({ message: 'Sync started' })
  }
}));

// Mock window.open for GmailConnectButton
const mockPopup = {
  closed: false,
  location: { href: '' },
  document: { body: { innerText: '' } },
  close: vi.fn()
};
window.open = vi.fn(() => mockPopup);

describe('Gmail Connection State Synchronization', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  const renderApp = (initialRoute = '/') => {
    return render(
      <MemoryRouter initialEntries={[initialRoute]}>
        <AuthProvider>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/login" element={<Login />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
  };

  it('successful Gmail connection persists account ID via AuthContext', async () => {
    // Render an empty component just to access context
    let contextValues;
    const TestComponent = () => {
      contextValues = useAuth();
      return null;
    };
    
    render(
      <MemoryRouter>
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      </MemoryRouter>
    );
    
    act(() => {
      contextValues.login('fake-token', 42);
    });
    
    expect(localStorage.getItem('token')).toBe('fake-token');
    expect(localStorage.getItem('email_account_id')).toBe('42');
    expect(contextValues.emailAccountId).toBe(42);
    expect(contextValues.isAuthenticated).toBe(true);
  });

  it('existing logout clears application state correctly', async () => {
    localStorage.setItem('token', 'fake-token');
    localStorage.setItem('email_account_id', '42');
    
    let contextValues;
    const TestComponent = () => {
      contextValues = useAuth();
      return null;
    };
    
    render(
      <MemoryRouter>
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      </MemoryRouter>
    );
    
    act(() => {
      contextValues.logout();
    });
    
    expect(localStorage.getItem('token')).toBeNull();
    expect(localStorage.getItem('email_account_id')).toBeNull();
    expect(contextValues.token).toBeNull();
    expect(contextValues.emailAccountId).toBeNull();
  });

  it('Dashboard renders connected state after remount with valid localStorage', async () => {
    localStorage.setItem('token', 'fake-token');
    localStorage.setItem('email_account_id', '42');
    
    renderApp('/');
    
    // Header should show connected
    await waitFor(() => {
      const connectedButtons = screen.getAllByText('Connected');
      expect(connectedButtons.length).toBeGreaterThan(0);
    });
    
    // Since total_emails is 0, empty state should show "syncing emails"
    expect(screen.getByText('Gmail connected — syncing emails...')).toBeInTheDocument();
    
    // The "Connect Gmail" button should NOT be present
    expect(screen.queryByText('Connect Gmail')).not.toBeInTheDocument();
  });

  it('connected account with zero emails shows syncing/connected state', async () => {
    // Same as above essentially, but explicitly focusing on empty state text
    localStorage.setItem('token', 'fake-token');
    localStorage.setItem('email_account_id', '99');
    
    renderApp('/');
    
    await waitFor(() => {
      expect(screen.getByText('Gmail connected — syncing emails...')).toBeInTheDocument();
    });
  });

});
