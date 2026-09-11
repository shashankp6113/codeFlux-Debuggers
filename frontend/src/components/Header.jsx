import { Bell, Search, Settings, User } from 'lucide-react';

export default function Header() {
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
        <button className="icon-btn" aria-label="Profile">
          <User size={20} />
        </button>
      </div>
    </header>
  );
}
