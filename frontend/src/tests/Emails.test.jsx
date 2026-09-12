import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { BrowserRouter, MemoryRouter, Routes, Route } from 'react-router-dom';
import Emails from '../pages/Emails';
import { AuthProvider } from '../contexts/AuthContext';
import { describe, it, expect, vi } from 'vitest';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    getEmails: vi.fn().mockResolvedValue([
      { id: 1, subject: 'Invoice', sender: 'test@acme.com', received_at: new Date().toISOString() }
    ])
  }
}));

describe('Emails', () => {
  it('calls api.getEmails with search param from url', async () => {
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
    expect(screen.getByDisplayValue('Invoice')).toBeInTheDocument();
  });
});
