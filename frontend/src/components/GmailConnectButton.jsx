import { useState } from 'react';
import { Loader, Check, AlertTriangle } from 'lucide-react';

const GoogleLogo = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" xmlns="http://www.w3.org/2000/svg" style={{ marginRight: '8px' }}>
    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
  </svg>
);

export default function GmailConnectButton({ onConnect }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const handleConnect = () => {
    setLoading(true);
    setError(null);
    setSuccess(false);

    const width = 600;
    const height = 700;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;
    
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
    const popup = window.open(
      `${API_BASE_URL}/api/auth/gmail`,
      'Gmail OAuth',
      `width=${width},height=${height},left=${left},top=${top}`
    );

    if (!popup) {
      setError('Popup blocked. Please allow popups for this site.');
      setLoading(false);
      return;
    }

    let intervalId;
    
    intervalId = setInterval(() => {
      if (popup.closed) {
        clearInterval(intervalId);
        setLoading((prevLoading) => {
            if (prevLoading) setError("Authentication cancelled.");
            return false;
        });
        return;
      }

      try {
        const popupUrl = popup.location.href;
        if (popupUrl.includes('/api/auth/gmail/callback')) {
          const jsonText = popup.document.body.innerText;
          if (jsonText) {
            clearInterval(intervalId);
            try {
              const data = JSON.parse(jsonText);
              if (data.email_account_id) {
                setSuccess(true);
                if (onConnect) onConnect(data);
              } else if (data.detail) {
                setError(data.detail);
              } else {
                setError("Invalid response from server.");
              }
            } catch {
              setError("Authentication failed: invalid server response.");
            }
            popup.close();
            setLoading(false);
          }
        }
      } catch {
        // Cross-origin, still authenticating
      }
    }, 500);
  };

  if (success) {
    return (
      <button className="btn-primary" style={{ backgroundColor: 'var(--status-safe-text)', borderColor: 'var(--status-safe-text)' }} disabled>
        <Check size={16} strokeWidth={1.5} />
        Connected
      </button>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'center', width: '100%' }}>
      <button 
        className="btn-primary" 
        style={{ width: '100%', justifyContent: 'center', padding: '0.85rem', fontSize: '1rem', backgroundColor: '#3b82f6', borderColor: '#3b82f6', color: 'white', display: 'flex', alignItems: 'center', gap: '4px' }}
        onClick={handleConnect} 
        disabled={loading}
      >
        {loading ? <Loader size={18} strokeWidth={2} className="animate-spin" /> : <GoogleLogo />}
        {loading ? 'Connecting...' : 'Continue with Google'}
      </button>
      {error && (
        <div style={{ color: 'var(--status-critical-text)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '4px' }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}
    </div>
  );
}
