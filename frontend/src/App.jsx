import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Emails from './pages/Emails';
import EmailDetail from './pages/EmailDetail';
import ThreatAnalysis from './pages/ThreatAnalysis';
import IOCs from './pages/IOCs';
import Reports from './pages/Reports';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="emails" element={<Emails />} />
          <Route path="emails/:id" element={<EmailDetail />} />
          <Route path="threats" element={<ThreatAnalysis />} />
          <Route path="iocs" element={<IOCs />} />
          <Route path="reports" element={<Reports />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
