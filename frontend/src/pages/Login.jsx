import { useAuth } from '../contexts/AuthContext';
import GmailConnectButton from '../components/GmailConnectButton';
import { ShieldAlert } from 'lucide-react';

export default function Login() {
  const { login } = useAuth();

  const handleConnect = (data) => {
    if (data.token) {
      login(data.token, data.email_account_id);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', backgroundColor: 'var(--bg-dark)' }}>
      <div className="card" style={{ padding: '3rem', display: 'flex', flexDirection: 'column', alignItems: 'center', maxWidth: '400px', width: '100%' }}>
        <ShieldAlert size={48} color="#3b82f6" style={{ marginBottom: '1rem' }} />
        <h1 style={{ marginBottom: '0.5rem', textAlign: 'center' }}>MailForensics AI</h1>
        <p style={{ color: 'var(--text-secondary)', textAlign: 'center', marginBottom: '2rem' }}>
          Sign in via Google to access your secure forensic workspace.
        </p>
        <GmailConnectButton onConnect={handleConnect} />
      </div>
    </div>
  );
}
