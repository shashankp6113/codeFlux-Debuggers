import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EmailDetail from '../pages/EmailDetail';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    getEmail: vi.fn(),
  }
}));

describe('EmailDetail Rendering', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderEmailDetail = (id = '1') => {
    return render(
      <MemoryRouter initialEntries={[`/emails/${id}`]}>
        <Routes>
          <Route path="/emails/:id" element={<EmailDetail />} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('renders successfully without crashing even if AI data has errors (ReferenceError check)', async () => {
    api.getEmail.mockResolvedValue({
      id: 1,
      subject: 'Test Suspicious Email',
      sender: 'test@example.com',
      recipient: 'user@example.com',
      created_at: '2023-10-10T12:00:00Z',
      forensics: {
        ai_analysis: {
          error: 'Some AI Error',
          error_category: 'quota_exceeded'
        }
      }
    });

    renderEmailDetail();

    await waitFor(() => {
      expect(screen.getByText('Test Suspicious Email')).toBeInTheDocument();
    });

    // Check if the retry button renders and doesn't crash the page
    expect(screen.getByText('Retry AI Analysis')).toBeInTheDocument();
  });

  it('renders successfully with missing optional forensics data', async () => {
    api.getEmail.mockResolvedValue({
      id: 2,
      subject: 'Safe Email',
      sender: 'safe@example.com',
      recipient: 'user@example.com',
      created_at: '2023-10-11T12:00:00Z',
      // forensics missing entirely
    });

    renderEmailDetail('2');

    await waitFor(() => {
      expect(screen.getByText('Safe Email')).toBeInTheDocument();
    });
    
    // Default score of 0 should render
    expect(screen.getByText('-- / 100 (low)')).toBeInTheDocument();
  });

  it('renders error state on API failure', async () => {
    api.getEmail.mockRejectedValue(new Error('404 Not Found'));

    renderEmailDetail('99');

    await waitFor(() => {
      expect(screen.getByText('Email not found.')).toBeInTheDocument();
    });
  });
});
