import { Bell, Search, Settings, LogOut } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function Header() {
  const { logout } = useAuth();
  
  return (
    <header className="top-header">
      <div className="header-title">
        {/* We can inject dynamic title here later if needed */}
      </div>
      <div className="header-actions">
        <button className="icon-btn" aria-label="Search">
          <Search size={20} />
        </button>
        <button className="icon-btn" aria-label="Notifications">
          <Bell size={20} />
        </button>
        <button className="icon-btn" aria-label="Settings">
          <Settings size={20} />
        </button>
        <button className="icon-btn" aria-label="Logout" onClick={logout} title="Logout">
          <LogOut size={20} />
        </button>
      </div>
    </header>
  );
}
