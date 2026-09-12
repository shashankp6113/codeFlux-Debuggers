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
    </aside>
  );
}
