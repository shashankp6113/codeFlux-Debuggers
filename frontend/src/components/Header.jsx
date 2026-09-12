import { useState, useRef, useEffect } from 'react';
import { Bell, Search, Settings, LogOut, ChevronDown, CheckCircle2, Menu } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';

export default function Header({ toggleSidebar, collapsed }) {
  const { logout, emailAddress } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState('');
  
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [loadingNotifs, setLoadingNotifs] = useState(false);

  const dropdownRef = useRef(null);
  const notifRef = useRef(null);
  
  const initial = emailAddress ? emailAddress.charAt(0).toUpperCase() : 'U';

  useEffect(() => {
    // If not on emails page, clicking search should take us there
    if (searchParams.get('q')) {
      setSearchQuery(searchParams.get('q'));
    } else {
      setSearchQuery('');
    }
  }, [searchParams]);

  useEffect(() => {
    async function loadNotifs() {
      if (notifOpen && notifications.length === 0) {
        setLoadingNotifs(true);
        try {
          const data = await api.getNotifications();
          setNotifications(data || []);
        } catch (err) {
          console.error("Failed to load notifications", err);
        } finally {
          setLoadingNotifs(false);
        }
      }
    }
    loadNotifs();
  }, [notifOpen, notifications.length]);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
        setNotifOpen(false);
      }
      if (notifRef.current && !notifRef.current.contains(event.target)) {
        setNotifOpen(false);
      }
    }

    
    function handleEscape(event) {
      if (event.key === 'Escape') {
        setDropdownOpen(false);
        setNotifOpen(false);
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
      <div className="header-title text-h2" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <button 
          className="icon-btn" 
          onClick={toggleSidebar} 
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
        >
          <Menu size={20} strokeWidth={1.5} />
        </button>
      </div>
      <div className="header-actions">
        <form 
          className="search-container" 
          style={{ width: '250px', background: 'var(--bg-base)', border: '1px solid var(--border-base)', display: 'flex', alignItems: 'center', padding: '0 0.75rem', borderRadius: '4px' }}
          onSubmit={(e) => {
            e.preventDefault();
            navigate(searchQuery ? `/emails?q=${encodeURIComponent(searchQuery)}` : '/emails');
          }}
        >
          <Search size={16} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
          <input 
            type="text" 
            placeholder="Search emails..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ border: 'none', background: 'transparent', outline: 'none', color: 'var(--text-primary)', padding: '0.5rem', width: '100%', fontSize: '0.875rem' }}
          />
        </form>
        
        <div className="dropdown-container" ref={notifRef}>
          <button 
            className={`icon-btn ${notifOpen ? 'active' : ''}`} 
            aria-label="Notifications"
            onClick={() => setNotifOpen(!notifOpen)}
          >
            <Bell size={20} strokeWidth={1.5} />
          </button>
          
          {notifOpen && (
            <div className="dropdown-menu" style={{ width: '320px', right: 0, padding: 0 }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-base)', fontWeight: 500 }}>
                Alerts
              </div>
              <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                {loadingNotifs ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>Loading...</div>
                ) : notifications.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No new alerts.</div>
                ) : (
                  notifications.map(n => (
                    <div 
                      key={n.id} 
                      onClick={() => { setNotifOpen(false); if (n.email_id) navigate(`/emails/${n.email_id}`); }}
                      style={{ padding: '1rem', borderBottom: '1px solid var(--border-base)', cursor: 'pointer' }}
                      className="dropdown-item-hover"
                    >
                      <div style={{ fontWeight: 500, fontSize: '0.9rem', marginBottom: '4px', color: n.type === 'threat' ? 'var(--status-critical-text)' : 'var(--text-primary)' }}>{n.title}</div>
                      <div className="text-small text-muted">{n.message}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '6px' }}>{new Date(n.created_at).toLocaleString()}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <button className="icon-btn" aria-label="Settings" onClick={() => navigate('/settings')}>
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
