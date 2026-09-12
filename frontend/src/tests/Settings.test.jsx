import { render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Settings from '../pages/Settings';
import { AuthProvider } from '../contexts/AuthContext';
import { describe, it, expect, vi } from 'vitest';

vi.mock('../lib/api', () => ({
  api: {
    getSettingsInfo: vi.fn().mockResolvedValue({
      ai_provider: 'gemini',
      ai_model: 'gemini-3.6-flash'
    })
  }
}));

const renderWithProviders = (ui) => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        {ui}
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Settings', () => {
  it('renders settings layout and fetches AI info', async () => {
    renderWithProviders(<Settings />);
    expect(screen.getByText('Account Information')).toBeInTheDocument();
    
    await waitFor(() => {
      expect(screen.getByText('gemini-3.6-flash')).toBeInTheDocument();
    });
  });
});
