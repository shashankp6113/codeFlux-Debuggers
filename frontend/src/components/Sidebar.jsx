import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Mail, 
  Activity, 
  Fingerprint,
  FileText
} from 'lucide-react';

export default function Sidebar({ collapsed }) {
  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/emails', label: 'Emails', icon: Mail },
    { path: '/threats', label: 'Threat Analysis', icon: Activity },
    { path: '/iocs', label: 'IOCs', icon: Fingerprint },
    { path: '/reports', label: 'Reports', icon: FileText },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldAlert size={20} strokeWidth={1.5} color="var(--accent-primary)" />
        {!collapsed && <span style={{ fontSize: '14px', letterSpacing: '-0.01em' }}>MailForensics AI</span>}
      </div>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              aria-label={item.label}
              title={collapsed ? item.label : undefined}
              key={item.path}
              to={item.path}
              className={({ isActive }) => 
                `nav-item ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={16} strokeWidth={1.5} />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>
      {!collapsed && (
        <div style={{ marginTop: 'auto', padding: '1rem', fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', gap: '10px', flexWrap: 'wrap', borderTop: '1px solid var(--border-color)' }}>
          <NavLink to="/privacy" style={{ color: 'inherit', textDecoration: 'none' }}>Privacy Policy</NavLink>
          <NavLink to="/terms" style={{ color: 'inherit', textDecoration: 'none' }}>Terms of Service</NavLink>
        </div>
      )}
    </aside>
  );
}
