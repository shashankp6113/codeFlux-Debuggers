import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, User, Database, Cpu, AlertTriangle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';


export default function Settings() {
  const { emailAddress, emailAccountId, logout, disconnectAccount } = useAuth();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [disconnecting, setDisconnecting] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDisconnect = async () => {
    if (!window.confirm("Are you sure you want to disconnect your Gmail account? All synced emails and forensic data will be permanently deleted from our servers.")) {
      return;
    }
    try {
      setDisconnecting(true);
      if (emailAccountId) {
        await api.disconnectGmail(emailAccountId);
      }
      disconnectAccount();
      alert("Gmail account disconnected and data deleted successfully.");
    } catch (err) {
      console.error(err);
      alert("Failed to disconnect Gmail account.");
    } finally {
      setDisconnecting(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!window.confirm("CRITICAL WARNING: This will permanently delete your entire MailForensics account, including all disconnected or connected Gmail accounts, tokens, and scanned forensic data. This action cannot be undone.")) return;
    if (window.prompt("Type DELETE to confirm") !== "DELETE") return;
    try {
      setDeleting(true);
      await api.deleteAccount();
      logout();
    } catch (err) {
      console.error(err);
      alert("Failed to delete account.");
      setDeleting(false);
    }
  };


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
          <div style={{ display: 'flex', gap: '1rem' }}>
            <button className="btn-secondary" onClick={logout}>Sign Out</button>
            <button className="btn-secondary" style={{ color: '#ef4444', borderColor: '#ef4444' }} onClick={handleDeleteAccount} disabled={deleting}>
              {deleting ? "Deleting..." : "Delete Account & Data"}
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h2 className="card-title"><Database size={18} /> Data Source</h2>
        <div style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
          <p style={{ marginBottom: '0.5rem' }}><strong>Connected Gmail:</strong> {emailAccountId ? emailAddress : 'None'}</p>
          <p style={{ marginBottom: '1.5rem' }}><strong>Storage:</strong> PostgreSQL (Local)</p>
          {emailAccountId && (
            <button className="btn-secondary" style={{ color: '#ef4444', borderColor: '#ef4444' }} onClick={handleDisconnect} disabled={disconnecting}>
              {disconnecting ? "Disconnecting..." : "Disconnect Gmail & Delete Data"}
            </button>
          )}
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
