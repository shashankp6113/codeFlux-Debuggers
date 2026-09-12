import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Settings from '../pages/Settings';
import { AuthProvider } from '../contexts/AuthContext';
import { BrowserRouter } from 'react-router-dom';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    getSettingsInfo: vi.fn(),
    disconnectGmail: vi.fn(),
    deleteAccount: vi.fn(),
  }
}));

const renderSettings = (emailAccountId = '123') => {
  if (emailAccountId) {
    localStorage.setItem('token', 'fake-token');
    localStorage.setItem('email_account_id', emailAccountId);
    localStorage.setItem('email_address', 'test@example.com');
  } else {
    localStorage.removeItem('token');
    localStorage.removeItem('email_account_id');
    localStorage.removeItem('email_address');
  }

  return render(
    <BrowserRouter>
      <AuthProvider>
        <Settings />
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Settings Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getSettingsInfo.mockResolvedValue({ ai_provider: 'gemini', ai_model: 'gemini-1.5-flash' });
    window.confirm = vi.fn();
    window.prompt = vi.fn();
    window.alert = vi.fn();
  });

  it('renders correctly', async () => {
    renderSettings();
    expect(await screen.findByText('Account Information')).toBeInTheDocument();
  });

  it('handles disconnect cancel', async () => {
    renderSettings();
    window.confirm.mockReturnValue(false);
    
    const btn = await screen.findByText('Disconnect Gmail & Delete Data');
    fireEvent.click(btn);
    
    expect(api.disconnectGmail).not.toHaveBeenCalled();
  });

  it('handles disconnect confirm', async () => {
    renderSettings();
    window.confirm.mockReturnValue(true);
    api.disconnectGmail.mockResolvedValue({});
    
    const btn = await screen.findByText('Disconnect Gmail & Delete Data');
    fireEvent.click(btn);
    
    await waitFor(() => {
      expect(api.disconnectGmail).toHaveBeenCalledWith('123');
    });
    // Context is updated so the button should disappear
    expect(screen.queryByText('Disconnect Gmail & Delete Data')).not.toBeInTheDocument();
  });

  it('handles delete account cancel', async () => {
    renderSettings();
    window.confirm.mockReturnValue(true);
    window.prompt.mockReturnValue('CANCEL');
    
    const btn = await screen.findByText('Delete Account & Data');
    fireEvent.click(btn);
    
    expect(api.deleteAccount).not.toHaveBeenCalled();
  });

  it('handles delete account confirm', async () => {
    renderSettings();
    window.confirm.mockReturnValue(true);
    window.prompt.mockReturnValue('DELETE');
    api.deleteAccount.mockResolvedValue({});
    
    const btn = await screen.findByText('Delete Account & Data');
    fireEvent.click(btn);
    
    await waitFor(() => {
      expect(api.deleteAccount).toHaveBeenCalled();
    });
  });
});
