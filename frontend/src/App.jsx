import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Emails from './pages/Emails';
import EmailDetail from './pages/EmailDetail';
import ThreatAnalysis from './pages/ThreatAnalysis';
import IOCs from './pages/IOCs';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Login from './pages/Login';
import SearchResults from './pages/SearchResults';

import ProtectedRoute from './components/ProtectedRoute';
import { AuthProvider } from './contexts/AuthContext';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
                            <Route path="search" element={<SearchResults />} />
              <Route path="emails" element={<Emails />} />
              <Route path="emails/:id" element={<EmailDetail />} />
              <Route path="threats" element={<ThreatAnalysis />} />
              <Route path="iocs" element={<IOCs />} />
              <Route path="reports" element={<Reports />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
