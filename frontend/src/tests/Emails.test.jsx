import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { BrowserRouter, MemoryRouter, Routes, Route } from 'react-router-dom';
import Emails from '../pages/Emails';
import { AuthProvider } from '../contexts/AuthContext';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    getEmails: vi.fn()
  }
}));

describe('Emails Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders emails correctly in row layout', async () => {
    api.getEmails.mockResolvedValue([
      { 
        id: 1, 
        subject: 'Important Invoice', 
        sender: 'billing@acme.com', 
        received_at: '2023-10-10T12:00:00Z',
        body_text: 'Please find your invoice attached below for the services rendered.',
        forensics: {
          threat_score: { risk_level: 'safe' }
        }
      }
    ]);

    render(
      <MemoryRouter initialEntries={['/emails']}>
        <AuthProvider>
          <Routes>
            <Route path="/emails" element={<Emails />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    await waitFor(() => {
      // Sender
      expect(screen.getByText('billing@acme.com')).toBeInTheDocument();
      // Subject
      expect(screen.getByText('Important Invoice')).toBeInTheDocument();
      // Snippet
      expect(screen.getByText(/- Please find your invoice attached below/)).toBeInTheDocument();
      // Badge
      expect(screen.getByText('Safe')).toBeInTheDocument();
    });
  });

  it('navigates to EmailDetail on row click', async () => {
    api.getEmails.mockResolvedValue([
      { id: 2, subject: 'Click me', sender: 'test@example.com' }
    ]);

    render(
      <MemoryRouter initialEntries={['/emails']}>
        <AuthProvider>
          <Routes>
            <Route path="/emails" element={<Emails />} />
            <Route path="/emails/:id" element={<div data-testid="detail-page" />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    await waitFor(() => {
      expect(screen.getByText('Click me')).toBeInTheDocument();
    });

    const row = screen.getByText('Click me').closest('a');
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByTestId('detail-page')).toBeInTheDocument();
    });
  });

  it('calls api.getEmails with search param from url', async () => {
    api.getEmails.mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={['/emails?q=Invoice']}>
        <AuthProvider>
          <Routes>
            <Route path="/emails" element={<Emails />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    await waitFor(() => {
      expect(api.getEmails).toHaveBeenCalledWith(50, 'Invoice');
    });
    
    // Check search input reflects URL
      });

  it('shows generic empty state when there are absolutely no emails', async () => {
    api.getEmails.mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={['/emails']}>
        <AuthProvider>
          <Routes>
            <Route path="/emails" element={<Emails />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    await waitFor(() => {
      expect(screen.getByText('Your inbox is empty')).toBeInTheDocument();
    });
  });

  it('shows search-specific empty state when query yields no results', async () => {
    api.getEmails.mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={['/emails?q=MissingEmail']}>
        <AuthProvider>
          <Routes>
            <Route path="/emails" element={<Emails />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    await waitFor(() => {
      expect(screen.getByText('No results found')).toBeInTheDocument();
      expect(screen.getByText(/No emails match your search query/)).toBeInTheDocument();
    });
  });
});
