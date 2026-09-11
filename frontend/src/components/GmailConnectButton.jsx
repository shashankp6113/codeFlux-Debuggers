import { useState } from 'react';
import { Mail, Loader, Check, AlertTriangle } from 'lucide-react';

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
    
    const popup = window.open(
      '/api/auth/gmail',
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
      <button className="btn-primary" style={{ backgroundColor: '#22c55e', borderColor: '#22c55e' }} disabled>
        <Check size={18} />
        Connected
      </button>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'flex-start' }}>
      <button 
        className="btn-primary" 
        onClick={handleConnect} 
        disabled={loading}
      >
        {loading ? <Loader size={18} className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} /> : <Mail size={18} />}
        {loading ? 'Connecting...' : 'Connect Gmail'}
      </button>
      {error && (
        <div style={{ color: '#ef4444', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}
    </div>
  );
}
