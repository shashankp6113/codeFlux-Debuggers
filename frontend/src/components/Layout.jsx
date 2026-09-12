import { Outlet } from 'react-router-dom';
import { useState } from 'react';
import Sidebar from './Sidebar';
import Header from './Header';

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <div className={`app-layout ${collapsed ? 'collapsed' : ''}`}>
      <Sidebar collapsed={collapsed} />
      <div className="main-content">
        <Header toggleSidebar={() => setCollapsed(!collapsed)} collapsed={collapsed} />
        <main className="page-container">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
