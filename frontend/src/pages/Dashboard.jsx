import { useEffect, useState, useRef } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import {Search,  Mail, AlertTriangle, ShieldAlert, Radar, Activity, PieChart, Loader, Inbox, CheckCircle, RefreshCw, ArrowRight, Shield, ShieldCheck, Link as LinkIcon, FileDigit, Globe, AtSign, Server } from 'lucide-react';
import { Link } from 'react-router-dom';
import GmailConnectButton from '../components/GmailConnectButton';
import UploadButton from '../components/UploadButton';


const iconMap = {
  ip: Server,
  domain: Globe,
  url: LinkIcon,
  email: AtSign,
  hash: FileDigit,
  default: Activity
};

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Sync state
    const syncTimerRef = useRef(null);
  const isMountedRef = useRef(true);

  const [syncStatus, setSyncStatus] = useState(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const { emailAccountId, updateEmailAccountId } = useAuth();
  const isConnected = !!emailAccountId;

  useEffect(() => {
    isMountedRef.current = true;
    fetchDashboard();
    
    const activeAccountId = emailAccountId;
    if (activeAccountId) {
      checkSyncStatus(activeAccountId);
    }
    
    return () => {
      isMountedRef.current = false;
      if (syncTimerRef.current) {
        clearTimeout(syncTimerRef.current);
      }
    };
  }, []);

  async function fetchDashboard() {
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
  }

  async function checkSyncStatus(accountId) {
    try {
      const status = await api.getSyncStatus(accountId);
      setSyncStatus(status);
      
      if (!isMountedRef.current) return;
      
      if (status && status.status === 'syncing') {
        setIsSyncing(true);
        // Poll every 3 seconds
        syncTimerRef.current = setTimeout(() => {
          if (isMountedRef.current) checkSyncStatus(accountId);
        }, 3000);
      } else {
        setIsSyncing(false);
        fetchDashboard();
      }
    } catch (err) {
      console.error("Failed to fetch sync status", err);
    }
  }

  async function handleGmailConnect(account) {
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
  }

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
        <AlertTriangle size={48}  strokeWidth={1.5} />
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


  const threatEntries = Object.entries(threat_distribution || {});
  
  const totalThreatsForChart = threatEntries.reduce((acc, [k, v]) => acc + v, 0);

  let currentPercentage = 0;
  const threatColors = {
    critical: 'var(--status-critical-text)',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    safe: '#22c55e'
  };
  
  const gradientStops = threatEntries.map(([key, count]) => {
      if (totalThreatsForChart === 0) return '';
      const percentage = (count / totalThreatsForChart) * 100;
      const color = threatColors[key.toLowerCase()] || 'var(--icon-muted)';
      const stop = `${color} ${currentPercentage}% ${currentPercentage + percentage}%`;
      currentPercentage += percentage;
      return stop;
  }).join(', ');
  
  const donutStyle = totalThreatsForChart > 0
      ? { background: `conic-gradient(${gradientStops})` }
      : { background: 'var(--border-base)' };

  

  return (
    <div className="page-container dashboard-page">
      <div className="dashboard-bg" aria-hidden="true">
        <div className="dashboard-blob blob-1"></div>
        <div className="dashboard-blob blob-2"></div>
        <div className="decorative-icon decorative-icon-1"><Mail size={400} strokeWidth={0.5} /></div>
        <div className="decorative-icon decorative-icon-2"><Inbox size={300} strokeWidth={0.5} /></div>
      </div>

      <div className="dashboard-hero">
        <div className="hero-text">
          <div className="hero-welcome">WELCOME BACK</div>
          <h1 className="hero-title">Security Overview</h1>
          <p className="hero-subtitle">Smarter Emails. Safer Tomorrows.</p>
        </div>
        <div className="hero-actions">
          {isConnected ? (
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button 
                className="btn-secondary" 
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
              >
                <RefreshCw size={16} strokeWidth={1.5} className={isSyncing ? "animate-spin" : ""} />
                {isSyncing ? 'Syncing...' : 'Sync Gmail'}
              </button>
              <button className="btn-success" style={{ cursor: 'default' }} disabled>
                <CheckCircle size={16} strokeWidth={1.5} />
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
        <div className={`sync-banner ${syncStatus.status === 'failed' ? 'sync-banner-error' : syncStatus.status === 'completed' ? 'sync-banner-success' : ''}`} style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {syncStatus.status === 'syncing' && <Loader size={24} className="animate-spin" />}
            {syncStatus.status === 'completed' && <CheckCircle size={24} />}
            {syncStatus.status === 'failed' && <AlertTriangle size={24} />}
            <div>
              <h4 className="text-h2">
                {syncStatus.status === 'syncing' ? 'Sync in Progress' : 
                 syncStatus.status === 'completed' ? 'Sync Completed' : 'Sync Failed'}
              </h4>
              <p style={{ margin: 0, fontSize: '14px', color: 'var(--text-muted)' }}>
                {syncStatus.processed} / {syncStatus.total_discovered} emails processed 
                ({syncStatus.newly_added} added, {syncStatus.skipped_duplicate} skipped, {syncStatus.failed_count} failed).
              </p>
            </div>
          </div>
          {syncStatus.status === 'failed' && syncStatus.errors && syncStatus.errors.length > 0 && (
             <div style={{ fontSize: '12px', color: 'var(--status-critical-text)', maxWidth: '40%' }}>
                {syncStatus.errors[0]}
             </div>
          )}
        </div>
      )}

      <div className="metrics-grid-modern">
        <div className="metric-card-modern">
          <div className="metric-icon-circle" style={{ backgroundColor: 'var(--bg-surface-hover)', color: 'var(--accent-primary)' }}>
            <Mail size={24} strokeWidth={1.5} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Total Emails</span>
            <span className="metric-value">{total_emails}</span>
          </div>
        </div>
        
        <div className="metric-card-modern">
          <div className="metric-icon-circle" style={{ backgroundColor: 'rgba(220, 38, 38, 0.1)', color: 'var(--status-critical-text)' }}>
            <Shield size={24} strokeWidth={1.5} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Threats Detected</span>
            <span className="metric-value">{threats_detected}</span>
          </div>
        </div>
        
        <div className="metric-card-modern">
          <div className="metric-icon-circle" style={{ backgroundColor: 'var(--status-high-bg)', color: 'var(--status-high-text)' }}>
            <AlertTriangle size={24} strokeWidth={1.5} />
          </div>
          <div className="metric-info">
            <span className="metric-label">High Risk</span>
            <span className="metric-value">{high_risk}</span>
          </div>
        </div>
        
        <div className="metric-card-modern">
          <div className="metric-icon-circle" style={{ backgroundColor: 'var(--status-safe-bg)', color: 'var(--status-safe-text)' }}>
            <ShieldCheck size={24} strokeWidth={1.5} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Safe</span>
            <span className="metric-value">{total_emails > 0 ? (total_emails - threats_detected) : 0}</span>
          </div>
        </div>
      </div>

      <div className="dashboard-content-modern">
        <div className="modern-card" style={{ minHeight: '350px' }}>
          <div className="modern-card-header">
            <div className="modern-card-title">
              <Search size={18} strokeWidth={1.5} />
              Recent Investigations
            </div>
            {hasInvestigations && (
              <Link to="/emails" className="view-all-link">
                View All <ArrowRight size={14} />
              </Link>
            )}
          </div>
          
          {hasInvestigations ? (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {recent_investigations.map(inv => {
                const aiClassification = inv.forensics?.ai_analysis?.classification || "unknown";
                const isThreat = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClassification.toLowerCase());
                const riskLevel = inv.forensics?.threat_score?.risk_level || "low";
                
                let badgeClass = 'badge-safe';
                if (riskLevel === 'critical' || isThreat) badgeClass = 'badge-critical';
                else if (riskLevel === 'high') badgeClass = 'badge-high';
                else if (riskLevel === 'medium') badgeClass = 'badge-medium';

                return (
                  <Link key={inv.id} to={`/emails/${inv.id}`} className="inv-row">
                    <div className="inv-left">
                      <div className="inv-icon">
                        <Mail size={16} />
                      </div>
                      <div className="inv-text">
                        <span className="inv-subject">{inv.subject || "(No Subject)"}</span>
                        <span className="inv-sender">{inv.sender}</span>
                      </div>
                    </div>
                    <div className="inv-right">
                      <span className={`compact-badge ${badgeClass}`}>
                        {riskLevel === 'critical' || isThreat ? 'CRITICAL' : riskLevel.toUpperCase()}
                      </span>
                      <span className="inv-date">
                        {new Date(inv.received_at || inv.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="empty-state" style={{ height: '200px' }}>
              <div className="empty-state-icon-wrap"><Inbox size={24} strokeWidth={1.5} /></div>
              {isConnected ? (
                <>
                  <h3>Gmail connected — syncing emails...</h3>
                  <p>We are analyzing your inbox in the background. Results will appear here shortly.</p>
                  <Loader size={32} className="animate-spin" style={{ animation: 'spin 1s linear infinite', marginTop: '1rem' }} />
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
          <div className="modern-card" style={{ flex: 1 }}>
            <div className="modern-card-header" style={{ marginBottom: '0.5rem' }}>
              <div className="modern-card-title">
                <PieChart size={18} strokeWidth={1.5} />
                Threat Distribution
              </div>
            </div>
            {hasThreatDist ? (
              <div className="donut-container">
                <div className="donut-chart" style={donutStyle}>
                  <div className="donut-hole">
                    <span className="donut-total">{totalThreatsForChart}</span>
                    <span className="donut-label">Threats</span>
                  </div>
                </div>
                <div className="donut-legend">
                  {threatEntries.map(([key, count]) => {
                    const color = threatColors[key.toLowerCase()] || 'var(--icon-muted)';
                    return (
                      <div key={key} className="legend-item">
                        <div className="legend-left">
                          <div className="legend-dot" style={{ backgroundColor: color }}></div>
                          <span style={{ textTransform: 'capitalize' }}>{key}</span>
                        </div>
                        <span className="legend-val">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="empty-state" style={{ height: '120px' }}>
                <p style={{ margin: 0, opacity: 0.5, color: 'var(--text-secondary)' }}>No threat data</p>
              </div>
            )}
          </div>
          
          <div className="modern-card" style={{ flex: 1 }}>
            <div className="modern-card-header" style={{ marginBottom: '1rem' }}>
              <div className="modern-card-title">
                <Activity size={18} strokeWidth={1.5} />
                IOC Overview
              </div>
              {hasIocSummary && (
                <Link to="/iocs" className="view-all-link">
                  View Details <ArrowRight size={14} />
                </Link>
              )}
            </div>
            {hasIocSummary ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {Object.entries(ioc_summary).map(([key, count]) => {
                  const CategoryIcon = iconMap[key.toLowerCase()] || iconMap.default;
                  return (
                    <div key={key} className="legend-item" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                      <div className="legend-left">
                        <CategoryIcon size={16} style={{ color: 'var(--icon-muted)' }} />
                        <span style={{ textTransform: 'capitalize' }}>{key}</span>
                      </div>
                      <span className="legend-val">{count}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="empty-state" style={{ height: '100px' }}>
                <p style={{ margin: 0, opacity: 0.5, color: 'var(--text-secondary)' }}>No IOC data</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
