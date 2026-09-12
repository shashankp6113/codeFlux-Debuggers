import { useState, useEffect, useRef } from 'react';
import { Bell, Search, Settings, LogOut, ChevronDown, CheckCircle2, Menu, Mail, Activity, ShieldAlert, Loader, ArrowRight } from 'lucide-react';
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

  // Global search state
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const searchTimerRef = useRef(null);
  const searchReqIdRef = useRef(0);

  const dropdownRef = useRef(null);
  const notifRef = useRef(null);
  const searchRef = useRef(null);
  
  const initial = emailAddress ? emailAddress.charAt(0).toUpperCase() : 'U';

  useEffect(() => {
    // If not on search or emails page with query, maybe don't override search?
    // Actually, if we navigate, we probably want to keep the query if we are on /search
    if (window.location.pathname === '/search' && searchParams.get('q')) {
      setSearchQuery(searchParams.get('q'));
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
      }
      if (notifRef.current && !notifRef.current.contains(event.target)) {
        setNotifOpen(false);
      }
      if (searchRef.current && !searchRef.current.contains(event.target)) {
        setSearchOpen(false);
      }
    }

    function handleEscape(event) {
      if (event.key === 'Escape') {
        setDropdownOpen(false);
        setNotifOpen(false);
        setSearchOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, []);

  const handleSearchChange = (e) => {
    const val = e.target.value;
    setSearchQuery(val);
    
    if (!val.trim()) {
      setSearchOpen(false);
      setSearchResults(null);
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
      return;
    }
    
    setSearchOpen(true);
    setSearchLoading(true);
    
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    
    searchTimerRef.current = setTimeout(async () => {
      try {
        const res = await api.globalSearch(val);
        setSearchResults(res);
      } catch (err) {
        console.error("Global search failed", err);
        setSearchResults({ error: true });
      } finally {
        setSearchLoading(false);
      }
    }, 300);
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      setSearchOpen(false);
      navigate(`/search?q=${encodeURIComponent(searchQuery)}`);
    }
  };

  return (
    <header className="top-header" style={{ backgroundColor: 'var(--bg-surface)', padding: '8px 16px', height: '64px' }}>
      {/* LEFT: Menu button */}
      <div className="header-left" style={{ display: 'flex', alignItems: 'center', minWidth: '120px' }}>
        <button 
          className="icon-btn" 
          onClick={toggleSidebar} 
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
        >
          <Menu size={24} strokeWidth={1.5} />
        </button>
      </div>
      
      {/* CENTER: Global Search */}
      <div className="header-center" style={{ flex: 1, display: 'flex', justifyContent: 'center', maxWidth: '720px', padding: '0 8px', position: 'relative' }} ref={searchRef}>
        <form 
          className="search-container header-search-form" 
          onSubmit={handleSearchSubmit}
          style={{ width: '100%', position: 'relative' }}
        >
          <button type="submit" style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 8px 0 0' }} aria-label="Search">
            <Search size={20} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
          </button>
          <input 
            type="text" 
            placeholder="Search emails, senders, domains, IPs, URLs, or IOCs..." 
            value={searchQuery}
            onChange={handleSearchChange}
            onFocus={() => { if (searchQuery.trim()) setSearchOpen(true); }}
            className="header-search-input"
            aria-label="Search across application"
          />
        </form>

        {searchOpen && (
          <div className="search-dropdown" style={{ 
            position: 'absolute', 
            top: 'calc(100% + 8px)', 
            left: '8px', 
            right: '8px', 
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-base)',
            borderRadius: '12px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.08)',
            zIndex: 100,
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            maxHeight: '60vh'
          }}>
            {searchLoading ? (
              <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                <Loader className="animate-spin" size={24} />
              </div>
            ) : searchResults?.error ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--status-critical-text)' }}>
                Search failed. Please try again.
              </div>
            ) : searchResults ? (
              <div style={{ overflowY: 'auto' }}>
                {searchResults.emails?.length === 0 && searchResults.iocs?.length === 0 && searchResults.threats?.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                    No results found for "{searchQuery}".
                  </div>
                ) : (
                  <>
                    <div style={{ padding: '12px 16px', fontSize: '0.85rem', color: 'var(--text-secondary)', background: 'var(--bg-body)' }}>
                      Search results
                    </div>
                    
                    {searchResults.emails?.length > 0 && (
                      <div className="search-group">
                        <div style={{ padding: '8px 16px', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Emails</div>
                        {searchResults.emails.map(email => (
                          <div 
                            key={email.id} 
                            onClick={() => { setSearchOpen(false); navigate(`/emails/${email.id}`); }}
                            className="dropdown-item-hover"
                            style={{ padding: '8px 16px', cursor: 'pointer', display: 'flex', gap: '12px', alignItems: 'center' }}
                          >
                            <Mail size={16} color="var(--icon-muted)" style={{ flexShrink: 0 }} />
                            <div style={{ overflow: 'hidden' }}>
                              <div className="truncate" style={{ fontWeight: 500, fontSize: '0.9rem', color: 'var(--text-primary)' }}>{email.subject || '(No Subject)'}</div>
                              <div className="truncate" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{email.sender}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {searchResults.iocs?.length > 0 && (
                      <div className="search-group" style={{ borderTop: '1px solid var(--border-subtle)' }}>
                        <div style={{ padding: '8px 16px', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>IOCs</div>
                        {searchResults.iocs.map((ioc, idx) => (
                          <div 
                            key={idx} 
                            onClick={() => { setSearchOpen(false); navigate('/iocs'); }}
                            className="dropdown-item-hover"
                            style={{ padding: '8px 16px', cursor: 'pointer', display: 'flex', gap: '12px', alignItems: 'center' }}
                          >
                            <Activity size={16} color="var(--icon-muted)" style={{ flexShrink: 0 }} />
                            <div style={{ overflow: 'hidden' }}>
                              <div className="truncate" style={{ fontWeight: 500, fontSize: '0.9rem', color: 'var(--text-primary)' }}>{ioc.value}</div>
                              <div className="truncate" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{ioc.type}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.threats?.length > 0 && (
                      <div className="search-group" style={{ borderTop: '1px solid var(--border-subtle)' }}>
                        <div style={{ padding: '8px 16px', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Threats</div>
                        {searchResults.threats.map((threat, idx) => {
                          const isCritical = threat.risk_level === 'critical';
                          const color = isCritical ? 'var(--status-critical-text)' : 'var(--status-high-text)';
                          return (
                            <div 
                              key={idx} 
                              onClick={() => { setSearchOpen(false); navigate(`/emails/${threat.email_id}`); }}
                              className="dropdown-item-hover"
                              style={{ padding: '8px 16px', cursor: 'pointer', display: 'flex', gap: '12px', alignItems: 'center' }}
                            >
                              <ShieldAlert size={16} color={color} style={{ flexShrink: 0 }} />
                              <div style={{ overflow: 'hidden' }}>
                                <div className="truncate" style={{ fontWeight: 500, fontSize: '0.9rem', color: 'var(--text-primary)', textTransform: 'capitalize' }}>{threat.classification}</div>
                                <div className="truncate" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{threat.risk_level.toUpperCase()} Risk</div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                    
                    <div style={{ borderTop: '1px solid var(--border-base)' }}>
                      <button 
                        onClick={handleSearchSubmit}
                        style={{ width: '100%', padding: '12px 16px', background: 'transparent', border: 'none', textAlign: 'left', cursor: 'pointer', color: 'var(--accent-primary)', fontSize: '0.9rem', fontWeight: 500, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
                        className="dropdown-item-hover"
                      >
                        View all results 
                        <ArrowRight size={14} />
                      </button>
                    </div>
                  </>
                )}
              </div>
            ) : null}
          </div>
        )}
      </div>

      {/* RIGHT: Actions */}
      <div className="header-actions" style={{ display: 'flex', alignItems: 'center', gap: '4px', minWidth: '120px', justifyContent: 'flex-end' }}>
        
        <div className="dropdown-container" ref={notifRef}>
          <button 
            className={`icon-btn ${notifOpen ? 'active' : ''}`} 
            aria-label="Notifications"
            onClick={() => setNotifOpen(!notifOpen)}
          >
            <Bell size={24} strokeWidth={1.5} />
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
          <Settings size={24} strokeWidth={1.5} />
        </button>
        
        {/* Profile Dropdown */}
        <div className="dropdown-container" ref={dropdownRef} style={{ marginLeft: '8px' }}>
          <button 
            className={`profile-btn ${dropdownOpen ? 'active' : ''}`}
            onClick={() => setDropdownOpen(!dropdownOpen)}
            aria-label="Profile menu"
            style={{ padding: '4px' }}
          >
            <div className="avatar" style={{ width: '32px', height: '32px' }}>{initial}</div>
          </button>
          
          {dropdownOpen && (
            <div className="dropdown-menu" style={{ width: '300px', right: '4px', top: 'calc(100% + 4px)' }}>
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
                      Signed in
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="dropdown-divider"></div>
              
              <button className="dropdown-item" onClick={logout} style={{ padding: '16px' }}>
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
