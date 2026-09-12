import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { Loader, AlertTriangle, Search, Filter, ShieldAlert, Globe, Crosshair } from 'lucide-react';

export default function IOCs() {
  const [data, setData] = useState({ iocs: [], stats: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
    const [iocType, setIocType] = useState('');
  const [verdict, setVerdict] = useState('');
  
  const navigate = useNavigate();

  useEffect(() => {
    fetchIocs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [iocType, verdict]);

  const fetchIocs = async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await api.getIocs({ search: "", ioc_type: iocType, verdict });
      setData(result || { iocs: [], stats: {} });
    } catch (err) {
      setError(err.message || 'Failed to load IOCs');
    } finally {
      setLoading(false);
    }
  };

  const handleFilter = (e) => {
    e.preventDefault();
    fetchIocs();
  };

  const { iocs, stats } = data;

  const getVerdictColor = (v) => {
    switch (v?.toLowerCase()) {
      case 'malicious': return '#dc2626';
      case 'suspicious': return 'var(--status-high-text)';
      case 'benign': return '#10b981';
      default: return 'var(--text-secondary)';
    }
  };

  return (
    <div>
      <h1 className="page-title">Indicators of Compromise (IOCs)</h1>
      
      {!loading && !error && (
        <div className="metrics-grid" style={{ marginBottom: '1.5rem' }}>
          <div className="metric-card">
            <div className="metric-label">
              <span>Total Unique IOCs</span>
              <Crosshair size={16} strokeWidth={1.5} />
            </div>
            <div className="metric-value">{stats.total || 0}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">
              <span>IP Addresses</span>
              <Globe size={16} strokeWidth={1.5} />
            </div>
            <div className="metric-value">{stats.ip || 0}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">
              <span>Domains & URLs</span>
            </div>
            <div className="metric-value">{(stats.domain || 0) + (stats.url || 0)}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">
              <span>Email Addresses</span>
            </div>
            <div className="metric-value">{stats.email || 0}</div>
          </div>
        </div>
      )}

      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <form onSubmit={handleFilter} className="toolbar">
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <Filter size={16} strokeWidth={1.5} color="var(--text-secondary)" />
            <select 
              value={iocType} 
              onChange={(e) => setIocType(e.target.value)}
              className="select-input"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="email">Email</option>
            </select>
            
            <select 
              value={verdict} 
              onChange={(e) => setVerdict(e.target.value)}
              className="select-input"
            >
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="benign">Benign</option>
              <option value="unknown">Unknown</option>
            </select>
            
            <button type="submit" className="btn-secondary">Apply Filters</button>
          </div>
        </form>
      </div>

      {loading ? (
        <div className="empty-state">
          <Loader size={48} className="empty-state-icon animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
          <h3>Loading IOCs...</h3>
        </div>
      ) : error ? (
        <div className="empty-state">
          <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
          <h3>Error Loading IOCs</h3>
          <p>{error}</p>
        </div>
      ) : iocs.length === 0 ? (
        <div className="empty-state">
          <ShieldAlert size={48} color="#10b981" className="empty-state-icon" />
          <h3>No IOCs Found</h3>
          <p>No indicators match the current filters.</p>
        </div>
      ) : (
        <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Context</th>
                <th>Occurrences</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, idx) => (
                <tr 
                  key={`${ioc.value}-${idx}`} 
                  style={{ borderBottom: '1px solid var(--border-base)', cursor: 'pointer', transition: 'background-color 0.2s' }}
                  onClick={() => ioc.latest_email_id && navigate(`/emails/${ioc.latest_email_id}`)}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <td style={{ fontWeight: 500, wordBreak: "break-all" }} className="text-mono">{ioc.value}</td>
                  <td className="text-small" style={{ textTransform: 'uppercase' }}>{ioc.ioc_type}</td>
                  <td style={{ }}>
                    <span className="badge badge-neutral" style={{ color: getVerdictColor(ioc.verdict) }}>
                      {ioc.verdict}
                      {ioc.confidence > 0 && <span style={{ opacity: 0.7, marginLeft: '4px', fontSize: '0.8em' }}>{Math.round(ioc.confidence * 100)}%</span>}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {ioc.country && <span style={{ marginRight: '8px' }} title="Country">📍 {ioc.country}</span>}
                    {ioc.asn && <span title="ASN">🏢 {ioc.asn}</span>}
                  </td>
                  <td style={{ }}>
                    <div style={{ fontWeight: 600 }}>{ioc.occurrence_count} times</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>across {ioc.associated_email_count} emails</div>
                  </td>
                  <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : 'Unknown'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
