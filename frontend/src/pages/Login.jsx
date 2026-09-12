import { useAuth } from '../contexts/AuthContext';
import GmailConnectButton from '../components/GmailConnectButton';
import { ShieldAlert } from 'lucide-react';

export default function Login() {
  const { login } = useAuth();

  const handleConnect = (data) => {
    if (data.token) {
      login(data.token, data.email_account_id, data.email_address);
    }
  };

  return (
    <div className="login-container">
      <div className="login-glow"></div>
      <div className="login-card">
        <ShieldAlert size={32} strokeWidth={1.5} color="var(--accent-primary)" style={{ marginBottom: '24px' }} />
        <h1 className="text-h1" style={{ marginBottom: '8px' }}>MailForensics AI</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginBottom: '32px' }}>
          Sign in via Google to access your secure forensic workspace.
        </p>
        <GmailConnectButton onConnect={handleConnect} />
      </div>
    </div>
  );
}
