import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from '../components/Layout';
import { AuthProvider } from '../contexts/AuthContext';
import { describe, it, expect } from 'vitest';

const renderWithProviders = (ui) => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={ui}>
            <Route index element={<div>Dashboard Content</div>} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Layout & Sidebar Collapsibility', () => {
  it('initially renders expanded sidebar with labels', () => {
    renderWithProviders(<Layout />);
    // Brand label should be visible
    expect(screen.getByText('MailForensics AI')).toBeInTheDocument();
    // Nav labels should be visible
    expect(screen.getByText('Threat Analysis')).toBeInTheDocument();
  });

  it('collapses sidebar when hamburger menu is clicked', () => {
    renderWithProviders(<Layout />);
    
    // Find the hamburger button (it has aria-label="Collapse sidebar" when expanded)
    const toggleBtn = screen.getByLabelText('Collapse sidebar');
    fireEvent.click(toggleBtn);
    
    // Brand label should be removed/hidden
    expect(screen.queryByText('MailForensics AI')).not.toBeInTheDocument();
    // Nav labels should be removed/hidden
    expect(screen.queryByText('Threat Analysis')).not.toBeInTheDocument();
    
    // Button should now have aria-label="Expand sidebar"
    expect(screen.getByLabelText('Expand sidebar')).toBeInTheDocument();
  });

  it('expands sidebar when hamburger menu is clicked again', () => {
    renderWithProviders(<Layout />);
    const collapseBtn = screen.getByLabelText('Collapse sidebar');
    fireEvent.click(collapseBtn);
    
    // It is now collapsed. Click to expand.
    const expandBtn = screen.getByLabelText('Expand sidebar');
    fireEvent.click(expandBtn);
    
    // Labels should be back
    expect(screen.getByText('MailForensics AI')).toBeInTheDocument();
    expect(screen.getByText('Threat Analysis')).toBeInTheDocument();
  });
});
