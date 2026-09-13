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
      body_text: 'Hello world, this is the body text.',
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

    // Subject, Sender, Recipient should be present
    expect(screen.getByText('test@example.com')).toBeInTheDocument();
    expect(screen.getByText(/user@example.com/)).toBeInTheDocument();
    
    // Body text renders
    expect(screen.getByText('Hello world, this is the body text.')).toBeInTheDocument();

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
      body_html: '<p>HTML body content</p>',
      // forensics missing entirely
    });

    const { container } = renderEmailDetail('2');

    await waitFor(() => {
      expect(screen.getByText('Safe Email')).toBeInTheDocument();
    });
    
    // Default banner should render safely
    expect(screen.getByText('No Threats Detected')).toBeInTheDocument();
    
    // Check that the iframe renders with srcDoc containing the body_html
    const iframe = container.querySelector('iframe');
    expect(iframe).toBeInTheDocument();
    expect(iframe.getAttribute('srcDoc')).toBe('<p>HTML body content</p>');
    expect(iframe.getAttribute('sandbox')).toBe(''); // Strict security isolation
  });

  it('renders empty body fallback when neither body_html nor body_text exist', async () => {
    api.getEmail.mockResolvedValue({
      id: 3,
      subject: 'Empty Email',
      sender: 'safe@example.com',
      recipient: 'user@example.com',
      created_at: '2023-10-11T12:00:00Z',
      // No body
    });

    renderEmailDetail('3');

    await waitFor(() => {
      expect(screen.getByText('No message body available.')).toBeInTheDocument();
    });
  });

  it('renders security banner with appropriate threat level', async () => {
    api.getEmail.mockResolvedValue({
      id: 4,
      subject: 'Phishing Alert',
      sender: 'hacker@example.com',
      recipient: 'user@example.com',
      created_at: '2023-10-11T12:00:00Z',
      body_text: 'Click here',
      forensics: {
        threat_score: { score: 98, risk_level: 'critical' },
        ai_analysis: { classification: 'phishing' }
      }
    });

    renderEmailDetail('4');

    await waitFor(() => {
      expect(screen.getByText('Phishing Detected')).toBeInTheDocument();
      expect(screen.getByText(/Threat Score: 98 \/ 100 \(critical\)/)).toBeInTheDocument();
    });
  });

  it('renders error state on API failure', async () => {
    api.getEmail.mockRejectedValue(new Error('404 Not Found'));

    renderEmailDetail('99');

    await waitFor(() => {
      expect(screen.getByText('Email not found.')).toBeInTheDocument();
    });
  });
});
