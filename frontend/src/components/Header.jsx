import { useState, useRef, useEffect } from 'react';
import { Bell, Search, Settings, LogOut, ChevronDown, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function Header() {
  const { logout, emailAddress } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);
  
  // Use first character for avatar, or 'U' if undefined
  const initial = emailAddress ? emailAddress.charAt(0).toUpperCase() : 'U';

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    }
    
    function handleEscape(event) {
      if (event.key === 'Escape') {
        setDropdownOpen(false);
      }
    }

    if (dropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape);
    }
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [dropdownOpen]);

  return (
    <header className="top-header">
      <div className="header-title text-h2">
      </div>
      <div className="header-actions">
        <button className="icon-btn" aria-label="Search">
          <Search size={20} strokeWidth={1.5} />
        </button>
        <button className="icon-btn" aria-label="Notifications">
          <Bell size={20} strokeWidth={1.5} />
        </button>
        <button className="icon-btn" aria-label="Settings">
          <Settings size={20} strokeWidth={1.5} />
        </button>
        
        {/* Profile Dropdown */}
        <div className="dropdown-container" ref={dropdownRef}>
          <button 
            className={`profile-btn ${dropdownOpen ? 'active' : ''}`}
            onClick={() => setDropdownOpen(!dropdownOpen)}
            aria-label="Profile menu"
          >
            <div className="avatar">{initial}</div>
            {emailAddress && (
              <span className="text-small truncate" style={{ maxWidth: '120px' }}>
                {emailAddress}
              </span>
            )}
            <ChevronDown size={16} strokeWidth={1.5} style={{ opacity: 0.5, marginLeft: '4px' }} />
          </button>
          
          {dropdownOpen && (
            <div className="dropdown-menu">
              <div className="dropdown-section">
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div className="avatar" style={{ width: '40px', height: '40px', fontSize: '18px' }}>
                    {initial}
                  </div>
                  <div className="truncate">
                    <div className="text-primary truncate" style={{ fontWeight: 500 }}>
                      {emailAddress || 'User'}
                    </div>
                    <div className="text-small text-muted" style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                      <CheckCircle2 size={12} strokeWidth={2} style={{ color: 'var(--status-safe-text)' }} />
                      Signed in
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="dropdown-divider"></div>
              
              <div className="dropdown-section" style={{ padding: '12px 16px' }}>
                <div className="text-small text-muted" style={{ textTransform: 'uppercase', marginBottom: '8px', fontSize: '11px', letterSpacing: '0.05em' }}>
                  Connected Account
                </div>
                <div className="text-small truncate" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--status-safe-bg)', border: '1px solid var(--status-safe-text)' }}></div>
                  {emailAddress || 'Not connected'}
                </div>
              </div>
              
              <div className="dropdown-divider"></div>
              
              <button className="dropdown-item" onClick={logout}>
                <LogOut size={16} strokeWidth={1.5} />
                Log out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
