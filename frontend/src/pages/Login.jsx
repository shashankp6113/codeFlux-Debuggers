import { useAuth } from '../contexts/AuthContext';
import GmailConnectButton from '../components/GmailConnectButton';
import { ShieldCheck, Mail, Lock, CheckCircle2 } from 'lucide-react';

export default function Login() {
  const { login } = useAuth();

  const handleConnect = (data) => {
    if (data.token) {
      login(data.token, data.email_account_id, data.email_address);
    }
  };

  return (
    <div className="login-page-container">
      
      {/* LEFT PANEL: Branding & Identity */}
      <div className="login-left-panel">
        
        {/* Decorative Background Artwork */}
        <div className="login-bg-graphics" aria-hidden="true">
          <Mail size={400} strokeWidth={0.5} style={{ position: 'absolute', top: '-10%', left: '-10%', transform: 'rotate(-15deg)' }} />
          <ShieldCheck size={300} strokeWidth={0.5} style={{ position: 'absolute', bottom: '-5%', right: '-10%', transform: 'rotate(10deg)' }} />
        </div>

        <div className="login-brand-header">
          <ShieldCheck size={28} color="var(--accent-primary)" />
          MailForensics AI
        </div>

        <div className="login-quote-container">
          <h1 className="login-quote">
            "Every email tells a story.<br/>We help you see the real one."
          </h1>
          <div className="login-tagline">
            Smarter Emails. Safer Tomorrows.
          </div>
          <p className="login-support-text">
            Investigate suspicious emails, uncover hidden indicators, and understand threats before they become incidents.
          </p>
        </div>
      </div>

      {/* RIGHT PANEL: Authentication */}
      <div className="login-right-panel">
        <div className="login-card-modern">
          
          <h2 style={{ fontSize: '1.75rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '12px' }}>
            Welcome back
          </h2>
          
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', marginBottom: '32px', lineHeight: 1.5 }}>
            Connect your Gmail account to begin analyzing your emails.
          </p>
          
          <GmailConnectButton onConnect={handleConnect} />

          <div className="login-secure-message">
            <Lock size={18} className="login-secure-icon" style={{ color: 'var(--text-muted)' }} />
            <div className="login-secure-text">
              <strong style={{ color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>Secure connection</strong>
              We use Google's secure OAuth authorization. Your Gmail password is never shared with MailForensics AI.
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
