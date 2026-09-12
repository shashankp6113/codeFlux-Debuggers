import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import { Mail, AlertTriangle, ShieldAlert, Bug, Search, Activity, PieChart, Loader, Inbox, CheckCircle, RefreshCw } from 'lucide-react';
import GmailConnectButton from '../components/GmailConnectButton';
import UploadButton from '../components/UploadButton';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Sync state
  const [syncStatus, setSyncStatus] = useState(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const { emailAccountId, updateEmailAccountId } = useAuth();
  const isConnected = !!emailAccountId;

  useEffect(() => {
    fetchDashboard();
    
    // Check if there's an ongoing sync for the current account
    const activeAccountId = emailAccountId;
    if (activeAccountId) {
      checkSyncStatus(activeAccountId);
    }
  }, []);

  const fetchDashboard = async () => {
    try {
      setLoading(true);
      const summary = await api.getDashboardSummary();
      setData(summary);
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  };

  const checkSyncStatus = async (accountId) => {
    try {
      const status = await api.getSyncStatus(accountId);
      setSyncStatus(status);
      
      if (status && status.status === 'syncing') {
        setIsSyncing(true);
        // Poll every 3 seconds
        setTimeout(() => checkSyncStatus(accountId), 3000);
      } else {
        setIsSyncing(false);
        fetchDashboard();
      }
    } catch (err) {
      console.error("Failed to fetch sync status", err);
    }
  };

  const handleGmailConnect = async (account) => {
    if (!account || !account.email_account_id) {
      setError("Invalid account data received");
      return;
    }
    try {
      updateEmailAccountId(account.email_account_id);
      // Start the background sync
      await api.syncGmail(account.email_account_id, 15);
      setIsSyncing(true);
      checkSyncStatus(account.email_account_id);
    } catch (err) {
      if (err.message && err.message.includes('409')) {
        // Already syncing, just start polling
        setIsSyncing(true);
        checkSyncStatus(account.email_account_id);
      } else {
        setError("Failed to start Gmail sync: " + (err.message || "Unknown error"));
      }
    }
  };

  if (loading && !data) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <Loader size={48} className="empty-state-icon animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
        <h3>Loading Security Overview...</h3>
      </div>
    );
  }

  if (error && !data) {
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
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          {isConnected ? (
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <button 
                className="btn-primary" 
                onClick={async () => {
                  try {
                    await api.syncGmail(emailAccountId, 15);
                    setIsSyncing(true);
                    checkSyncStatus(emailAccountId);
                  } catch (err) {
                    if (err.status === 409 || (err.response && err.response.status === 409)) {
                      setIsSyncing(true);
                      checkSyncStatus(emailAccountId);
                    } else {
                      console.error("Failed to start sync:", err);
                    }
                  }
                }}
                disabled={isSyncing}
                style={{ opacity: isSyncing ? 0.7 : 1 }}
              >
                <RefreshCw size={18} className={isSyncing ? "animate-spin" : ""} />
                {isSyncing ? 'Syncing...' : 'Sync Gmail'}
              </button>
              <button className="btn-primary" style={{ backgroundColor: '#22c55e', borderColor: '#22c55e', cursor: 'default' }} disabled>
                <CheckCircle size={18} />
                Connected
              </button>
            </div>
          ) : (
            <GmailConnectButton onConnect={handleGmailConnect} />
          )}
          <UploadButton label="New Analysis" />
        </div>
      </div>
      
      {syncStatus && syncStatus.status !== 'idle' && (
        <div style={{
          backgroundColor: syncStatus.status === 'failed' ? 'rgba(239, 68, 68, 0.1)' : 
                           syncStatus.status === 'completed' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(59, 130, 246, 0.1)',
          border: `1px solid ${syncStatus.status === 'failed' ? '#ef4444' : 
                               syncStatus.status === 'completed' ? '#22c55e' : '#3b82f6'}`,
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {syncStatus.status === 'syncing' && <Loader size={24} color="#3b82f6" className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} />}
            {syncStatus.status === 'completed' && <CheckCircle size={24} color="#22c55e" />}
            {syncStatus.status === 'failed' && <AlertTriangle size={24} color="#ef4444" />}
            <div>
              <h4 style={{ margin: 0, color: syncStatus.status === 'failed' ? '#ef4444' : 
                                             syncStatus.status === 'completed' ? '#22c55e' : '#3b82f6' }}>
                {syncStatus.status === 'syncing' ? 'Sync in Progress' : 
                 syncStatus.status === 'completed' ? 'Sync Completed' : 'Sync Failed'}
              </h4>
              <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                {syncStatus.processed} / {syncStatus.total_discovered} emails processed 
                ({syncStatus.newly_added} added, {syncStatus.skipped_duplicate} skipped, {syncStatus.failed_count} failed).
              </p>
            </div>
          </div>
          {syncStatus.status === 'failed' && syncStatus.errors && syncStatus.errors.length > 0 && (
             <div style={{ fontSize: '0.75rem', color: '#ef4444', maxWidth: '40%' }}>
                {syncStatus.errors[0]}
             </div>
          )}
        </div>
      )}

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
              {isConnected ? (
                <>
                  <h3>Gmail connected — syncing emails...</h3>
                  <p>We are analyzing your inbox in the background. Results will appear here shortly.</p>
                  <Loader size={32} color="#3b82f6" className="animate-spin" style={{ animation: 'spin 1s linear infinite', marginTop: '1rem' }} />
                </>
              ) : (
                <>
                  <h3>No recent investigations</h3>
                  <p>Connect an email account or upload an .eml file to start analyzing.</p>
                  <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', justifyContent: 'center' }}>
                    <GmailConnectButton onConnect={handleGmailConnect} />
                    <UploadButton label="Import Email" icon={null} />
                  </div>
                </>
              )}
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
