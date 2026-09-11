import { useEffect, useState } from 'react';
import { 
  Mail, ShieldAlert, AlertTriangle, Bug, 
  Search, Inbox, PieChart, Activity, Loader
} from 'lucide-react';
import { api } from '../lib/api';
import UploadButton from '../components/UploadButton';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);
        const summary = await api.getDashboardSummary();
        setData(summary);
      } catch (err) {
        setError(err.message || "Failed to load dashboard data.");
      } finally {
        setLoading(false);
      }
    }
    loadDashboard();
  }, []);

  if (loading) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <Loader size={48} className="empty-state-icon" />
        <h3>Loading Security Overview...</h3>
      </div>
    );
  }

  if (error) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <AlertTriangle size={48} color="#ef4444" className="empty-state-icon" />
        <h3>Error Loading Dashboard</h3>
        <p>{error}</p>
        <button className="btn-primary" onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  const { 
    total_emails = 0, 
    threats_detected = 0, 
    high_risk = 0, 
    critical = 0,
    recent_investigations = [],
    threat_distribution = {},
    ioc_summary = {}
  } = data || {};

  const hasInvestigations = recent_investigations.length > 0;
  const hasThreatDist = Object.keys(threat_distribution).length > 0;
  const hasIocSummary = Object.keys(ioc_summary).length > 0;

  return (
    <div>
      <div className="dashboard-header">
        <h1 className="page-title">Security Overview</h1>
        <UploadButton label="New Analysis" />
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-label">
            <span>Total Emails</span>
            <Mail size={16} />
          </div>
          <div className="metric-value">{total_emails}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">
            <span>Threats Detected</span>
            <Bug size={16} color="#ef4444" />
          </div>
          <div className="metric-value">{threats_detected}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">
            <span>High Risk</span>
            <AlertTriangle size={16} color="#f59e0b" />
          </div>
          <div className="metric-value">{high_risk}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">
            <span>Critical</span>
            <ShieldAlert size={16} color="#dc2626" />
          </div>
          <div className="metric-value">{critical}</div>
        </div>
      </div>

      <div className="content-grid">
        <div className="card" style={{ minHeight: '350px' }}>
          <div className="card-title">
            <Search size={18} />
            Recent Investigations
          </div>
          
          {hasInvestigations ? (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {recent_investigations.map(inv => {
                const aiClassification = inv.forensics?.ai_analysis?.classification || "unknown";
                const isThreat = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClassification.toLowerCase());
                return (
                  <div key={inv.id} style={{ 
                    padding: '1rem 0', 
                    borderBottom: '1px solid var(--border-color)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginRight: '1rem' }}>
                      <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>{inv.subject || "(No Subject)"}</div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{inv.sender}</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexShrink: 0 }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        backgroundColor: isThreat ? 'rgba(239, 68, 68, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                        color: isThreat ? '#ef4444' : 'var(--text-primary)'
                      }}>
                        {aiClassification.toUpperCase()}
                      </span>
                      <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                        {new Date(inv.received_at || inv.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <Inbox size={48} className="empty-state-icon" />
              <h3>No recent investigations</h3>
              <p>Connect an email account or upload an .eml file to start analyzing.</p>
              <UploadButton label="Import Email" icon={null} />
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="card" style={{ flex: 1 }}>
            <div className="card-title">
              <PieChart size={18} />
              Threat Distribution
            </div>
            {hasThreatDist ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
                {Object.entries(threat_distribution).map(([key, count]) => (
                  <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ textTransform: 'capitalize' }}>{key}</span>
                    <span style={{ fontWeight: 600, backgroundColor: 'var(--surface-color)', padding: '2px 8px', borderRadius: '12px' }}>{count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <p style={{ margin: 0, opacity: 0.5 }}>No data available</p>
              </div>
            )}
          </div>
          
          <div className="card" style={{ flex: 1 }}>
            <div className="card-title">
              <Activity size={18} />
              IOC Overview
            </div>
            {hasIocSummary ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
                {Object.entries(ioc_summary).map(([key, count]) => (
                  <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ textTransform: 'uppercase' }}>{key}</span>
                    <span style={{ fontWeight: 600, backgroundColor: 'var(--surface-color)', padding: '2px 8px', borderRadius: '12px' }}>{count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <p style={{ margin: 0, opacity: 0.5 }}>No data available</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
