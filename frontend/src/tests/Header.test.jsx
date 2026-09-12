import { api } from '../lib/api';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Header from '../components/Header';
import { AuthProvider } from '../contexts/AuthContext';
import { describe, it, expect, vi } from 'vitest';

const renderWithProviders = (ui) => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        {ui}
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Header', () => {
  it('renders search input', () => {
    renderWithProviders(<Header />);
    expect(screen.getByPlaceholderText('Search emails, senders, domains, IPs, URLs, or IOCs...')).toBeInTheDocument();
  });




  it('opens and closes notification dropdown', () => {
    renderWithProviders(<Header />);
    const notifBtn = screen.getByLabelText('Notifications');
    fireEvent.click(notifBtn);
    expect(screen.getByText('Alerts')).toBeInTheDocument();
    
    // Click outside should close, but testing just the toggle
    fireEvent.click(notifBtn);
    expect(screen.queryByText('Alerts')).not.toBeInTheDocument();
  });



  it('typing triggers debounced search and shows results', async () => {
    api.globalSearch = vi.fn().mockResolvedValue({
      emails: [{id: 1, subject: 'Phishing Attempt', sender: 'bad@bad.com'}],
      iocs: [],
      threats: []
    });

    renderWithProviders(<Header />);
    const input = screen.getByPlaceholderText('Search emails, senders, domains, IPs, URLs, or IOCs...');
    
    fireEvent.change(input, { target: { value: 'bad' } });
    
    // Fast forward debounce timer (300ms)
    
    await waitFor(() => {
      expect(api.globalSearch).toHaveBeenCalledWith('bad');
      expect(screen.getByText('Phishing Attempt')).toBeInTheDocument();
      expect(screen.getByText('bad@bad.com')).toBeInTheDocument();
    });
  });

  it('clicking a search result closes the dropdown', async () => {
    api.globalSearch = vi.fn().mockResolvedValue({
      emails: [{id: 1, subject: 'Phishing Attempt', sender: 'bad@bad.com'}],
      iocs: [],
      threats: []
    });

    renderWithProviders(<Header />);
    const input = screen.getByPlaceholderText('Search emails, senders, domains, IPs, URLs, or IOCs...');
    
    fireEvent.change(input, { target: { value: 'bad' } });
    
    await waitFor(() => {
      expect(screen.getByText('Phishing Attempt')).toBeInTheDocument();
    });
    
    const result = screen.getByText('Phishing Attempt');
    fireEvent.click(result);
    
    // Check that it's closed
    expect(screen.queryByText('Search results')).not.toBeInTheDocument();
  });
});
