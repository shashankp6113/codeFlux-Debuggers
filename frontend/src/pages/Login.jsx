import { useAuth } from '../contexts/AuthContext';
import GmailConnectButton from '../components/GmailConnectButton';
import { Shield, Lock, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import FloatingBackground from '../components/FloatingBackground';

export default function Login() {
  const { login } = useAuth();

  function handleConnect(data) {
    if (data.token) {
      login(data.token, data.email_account_id, data.email_address);
    }
  };

  return (
    <div className="login-page-container" style={{ position: 'relative' }}>
      <FloatingBackground />
      
      {/* LEFT PANEL: Branding & Identity */}
      <div className="login-left-panel" style={{ zIndex: 10 }}>
        
        <div className="login-brand-header" style={{ position: 'relative', top: 0, left: 0, marginBottom: '1.5rem' }}>
          <span style={{ fontSize: '2.5rem', fontWeight: '800', color: '#111827', letterSpacing: '-0.02em' }}>MailForensics AI</span>
        </div>

        <div className="login-quote-container" style={{ marginLeft: 0 }}>
          <h1 className="login-quote" style={{ fontSize: '3.5rem', lineHeight: 1.1, fontWeight: 700, color: '#111827', marginBottom: '0.5rem', letterSpacing: '-0.02em' }}>
            Every email tells<br/>a story.
          </h1>
        </div>
      </div>

      {/* RIGHT PANEL: Authentication */}
      <div className="login-right-panel" style={{ zIndex: 10 }}>
        <div className="login-card-modern" style={{ padding: '3.5rem', borderRadius: '24px', maxWidth: '480px', width: '100%', textAlign: 'left', display: 'flex', flexDirection: 'column', alignItems: 'flex-start', border: '1px solid rgba(255,255,255,0.8)', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.1)', backgroundColor: 'rgba(255, 255, 255, 0.9)', backdropFilter: 'blur(10px)' }}>
          
          <div style={{ textTransform: 'uppercase', letterSpacing: '0.1em', fontSize: '0.75rem', fontWeight: 700, color: '#6b82a4', marginBottom: '1rem', width: '100%' }}>
            WELCOME BACK
          </div>
          
          <h2 style={{ fontSize: '2.2rem', fontWeight: 700, color: '#111827', marginBottom: '12px', letterSpacing: '-0.02em', width: '100%' }}>
            Connect your Gmail
          </h2>
          
          <p style={{ color: '#6b7280', fontSize: '1rem', marginBottom: '2.5rem', lineHeight: 1.5, width: '100%' }}>
            Sign in with Google to start analyzing your emails with MailForensics AI.
          </p>
          
          <div style={{ width: '100%' }}>
            <GmailConnectButton onConnect={handleConnect} />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', margin: '2.5rem 0', gap: '1rem', width: '100%' }}>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#e2e8f0' }}></div>
            <span style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 600 }}>OR</span>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#e2e8f0' }}></div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginBottom: '3rem', width: '100%' }}>
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
              <div style={{ backgroundColor: '#ecfdf5', color: '#10b981', borderRadius: '50%', flexShrink: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', width: '40px', height: '40px' }}>
                <Lock size={18} strokeWidth={2} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '0.95rem' }}>Secure & Private</div>
                <div style={{ fontSize: '0.85rem', color: '#64748b', lineHeight: 1.3 }}>We use Google's secure OAuth authorization.</div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
              <div style={{ backgroundColor: '#eff6ff', color: '#3b82f6', borderRadius: '50%', flexShrink: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', width: '40px', height: '40px' }}>
                <Shield size={18} strokeWidth={2} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '0.95rem' }}>Your data stays yours</div>
                <div style={{ fontSize: '0.85rem', color: '#64748b', lineHeight: 1.3 }}>Your Gmail password is never shared with us.</div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
              <div style={{ backgroundColor: '#f3e8ff', color: '#8b5cf6', borderRadius: '50%', flexShrink: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', width: '40px', height: '40px' }}>
                <Users size={18} strokeWidth={2} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '0.95rem' }}>Built for a safer internet</div>
                <div style={{ fontSize: '0.85rem', color: '#64748b', lineHeight: 1.3 }}>Detect threats. Prevent incidents.</div>
              </div>
            </div>
          </div>

          <div style={{ fontSize: '0.8rem', color: '#64748b', lineHeight: 1.5, width: '100%' }}>
            By continuing, you agree to our <Link to="/terms" style={{ color: '#3b82f6', textDecoration: 'none' }}>Terms of Service</Link> and acknowledge our <Link to="/privacy" style={{ color: '#3b82f6', textDecoration: 'none' }}>Privacy Policy</Link>.
          </div>
        </div>
      </div>

    </div>
  );
}
