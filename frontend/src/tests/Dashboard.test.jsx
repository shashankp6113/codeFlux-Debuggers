import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';

vi.mock('../contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../lib/api', () => ({
  api: {
    getDashboardSummary: vi.fn(),
    syncGmail: vi.fn(),
    getSyncStatus: vi.fn(),
  }
}));

describe('Dashboard Sync Gmail Button', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    // Default mock data
    api.getDashboardSummary.mockResolvedValue({
      total_emails: 10,
      threats_detected: 2,
      high_risk: 1,
      critical: 0,
      threat_distribution: {},
      ioc_summary: {},
      recent_investigations: []
    });
    
    api.getSyncStatus.mockResolvedValue({
      status: 'idle',
      total_discovered: 0,
      processed: 0,
      newly_added: 0,
      skipped_duplicate: 0,
      failed_count: 0,
      errors: []
    });
  });

  const renderDashboard = (emailAccountId) => {
    useAuth.mockReturnValue({
      emailAccountId,
      updateEmailAccountId: vi.fn(),
    });
    return render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );
  };

  it('does not show Sync Gmail button when disconnected', async () => {
    renderDashboard(null);
    await waitFor(() => {
      expect(screen.queryByText('Sync Gmail')).not.toBeInTheDocument();
      expect(screen.getAllByRole('button', { name: /Connect Gmail/i }).length).toBeGreaterThan(0);
    });
  });

  it('shows Sync Gmail button when connected', async () => {
    renderDashboard(123);
    await waitFor(() => {
      expect(screen.getByText('Sync Gmail')).toBeInTheDocument();
      expect(screen.getByText('Connected')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Connect Gmail/i })).not.toBeInTheDocument();
    });
  });

  it('clicking Sync Gmail starts sync and disables button', async () => {
    api.syncGmail.mockResolvedValue({});
    
    renderDashboard(123);
    
    let syncBtn;
    await waitFor(() => {
      syncBtn = screen.getByText('Sync Gmail');
      expect(syncBtn).toBeInTheDocument();
    });

    api.getSyncStatus.mockResolvedValue({ status: 'syncing', processed: 0, total_discovered: 15 });
    fireEvent.click(syncBtn);
    
    expect(api.syncGmail).toHaveBeenCalledWith(123, 15);
    
    await waitFor(() => {
      expect(screen.getByText('Syncing...')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Syncing\.\.\./i })).toBeDisabled();
    });
  });

  it('handles 409 concurrent sync gracefully by switching to syncing state', async () => {
    api.syncGmail.mockRejectedValue({ status: 409 });
    
    renderDashboard(123);
    
    let syncBtn;
    await waitFor(() => {
      syncBtn = screen.getByText('Sync Gmail');
    });

    api.getSyncStatus.mockResolvedValue({ status: 'syncing', processed: 0, total_discovered: 15 });
    fireEvent.click(syncBtn);
    
    await waitFor(() => {
      expect(screen.getByText('Syncing...')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Syncing\.\.\./i })).toBeDisabled();
    });
  });


  it('a completed response resets isSyncing and shows completion state', async () => {
    renderDashboard(123);
    
    // Initial fetch
    expect(api.getSyncStatus).toHaveBeenCalledWith(123);
    
    let syncBtn;
    await waitFor(() => {
      syncBtn = screen.getByText('Sync Gmail');
    });

    // Mock completion on next poll (triggered by click)
    api.syncGmail.mockResolvedValueOnce({});
    api.getSyncStatus.mockResolvedValueOnce({ status: 'completed', processed: 15, total_discovered: 15 });
    
    fireEvent.click(syncBtn);
    
    await waitFor(() => {
      expect(screen.getByText('Sync Completed')).toBeInTheDocument();
      expect(screen.queryByText('Syncing...')).not.toBeInTheDocument();
      expect(screen.getByText('Sync Gmail')).toBeInTheDocument();
    });
    
    // fetchDashboard is called on mount, and then on completion
    expect(api.getDashboardSummary).toHaveBeenCalledTimes(3);
  });

  it('a failed response resets isSyncing and shows failed state', async () => {
    api.getSyncStatus.mockResolvedValue({ status: 'failed', processed: 10, total_discovered: 15, errors: ['Rate limit exceeded'] });
    
    renderDashboard(123);
    
    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
      expect(screen.getByText('Rate limit exceeded')).toBeInTheDocument();
      expect(screen.getByText('Sync Gmail')).toBeInTheDocument();
    });
  });
});
