import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import PrivacyPolicy from '../pages/PrivacyPolicy';
import TermsOfService from '../pages/TermsOfService';

describe('Legal Pages', () => {
  it('renders Privacy Policy page correctly', () => {
    render(
      <BrowserRouter>
        <PrivacyPolicy />
      </BrowserRouter>
    );
    expect(screen.getByText('Privacy Policy')).toBeInTheDocument();
    expect(screen.getByText(/gmail\.readonly/i)).toBeInTheDocument();
    expect(screen.getByText(/Google Gemini AI:/i)).toBeInTheDocument();
    expect(screen.getByText(/VirusTotal:/i)).toBeInTheDocument();
  });

  it('renders Terms of Service page correctly', () => {
    render(
      <BrowserRouter>
        <TermsOfService />
      </BrowserRouter>
    );
    expect(screen.getByText('Terms of Service')).toBeInTheDocument();
    expect(screen.getByText(/officially approved, endorsed, or verified by Google/i)).toBeInTheDocument();
    expect(screen.getByText(/IP Geolocation data is inherently approximate/i)).toBeInTheDocument();
  });
});
