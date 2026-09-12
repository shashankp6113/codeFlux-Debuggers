import { render, screen, fireEvent } from '@testing-library/react';
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
    expect(screen.getByPlaceholderText('Search emails...')).toBeInTheDocument();
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
});
