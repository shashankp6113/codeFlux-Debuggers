import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, User, Database, Cpu } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';

export default function Settings() {
  const { emailAddress, logout } = useAuth();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadSettings() {
      try {
        const data = await api.getSettingsInfo();
        setConfig(data);
      } catch (err) {
        console.error("Failed to load settings info", err);
      } finally {
        setLoading(false);
      }
    }
    loadSettings();
  }, []);

  return (
    <div>
      <h1 className="page-title"><SettingsIcon size={24} style={{ marginRight: '8px', verticalAlign: 'text-bottom' }} /> Settings</h1>
      
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h2 className="card-title"><User size={18} /> Account Information</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
          <p style={{ marginBottom: '0.5rem' }}><strong>Signed In As:</strong> {emailAddress || 'User'}</p>
          <p style={{ marginBottom: '1.5rem' }}><strong>Authentication:</strong> Active Session</p>
          <button className="btn-secondary" onClick={logout}>Sign Out</button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h2 className="card-title"><Database size={18} /> Data Source</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
          <p style={{ marginBottom: '0.5rem' }}><strong>Connected Gmail:</strong> {emailAddress || 'None'}</p>
          <p style={{ marginBottom: '0.5rem' }}><strong>Storage:</strong> PostgreSQL (Local)</p>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title"><Cpu size={18} /> AI Configuration</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
          {loading ? (
            <p>Loading AI status...</p>
          ) : config ? (
            <>
              <p style={{ marginBottom: '0.5rem' }}><strong>Provider:</strong> <span style={{ textTransform: 'capitalize' }}>{config.ai_provider}</span></p>
              <p style={{ marginBottom: '0.5rem' }}><strong>Model:</strong> {config.ai_model}</p>
              <p style={{ fontSize: '0.85rem', marginTop: '1rem' }}><em>Note: AI credentials are securely configured via environment variables.</em></p>
            </>
          ) : (
            <p>Unable to retrieve AI configuration.</p>
          )}
        </div>
      </div>
    </div>
  );
}
