import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { Loader, AlertTriangle, Search, Filter, ShieldAlert, Globe, Crosshair } from 'lucide-react';

export default function IOCs() {
  const [data, setData] = useState({ iocs: [], stats: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [search, setSearch] = useState('');
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
      const result = await api.getIocs({ search, ioc_type: iocType, verdict });
      setData(result || { iocs: [], stats: {} });
    } catch (err) {
      setError(err.message || 'Failed to load IOCs');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    fetchIocs();
  };

  const { iocs, stats } = data;

  const getVerdictColor = (v) => {
    switch (v?.toLowerCase()) {
      case 'malicious': return '#dc2626';
      case 'suspicious': return '#f59e0b';
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
              <Crosshair size={16} />
            </div>
            <div className="metric-value">{stats.total || 0}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">
              <span>IP Addresses</span>
              <Globe size={16} />
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
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 250px', display: 'flex', gap: '0.5rem', alignItems: 'center', backgroundColor: 'var(--bg-dark)', padding: '0.5rem 1rem', borderRadius: '4px' }}>
            <Search size={18} color="var(--text-secondary)" />
            <input 
              type="text" 
              placeholder="Search IOC value..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', width: '100%', outline: 'none' }}
            />
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <Filter size={18} color="var(--text-secondary)" />
            <select 
              value={iocType} 
              onChange={(e) => setIocType(e.target.value)}
              style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'var(--bg-dark)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
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
              style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'var(--bg-dark)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
            >
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="benign">Benign</option>
              <option value="unknown">Unknown</option>
            </select>
            
            <button type="submit" className="btn-primary">Search</button>
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
          <AlertTriangle size={48} color="#ef4444" className="empty-state-icon" />
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
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'rgba(255,255,255,0.02)' }}>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Value</th>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Type</th>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Verdict</th>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Context</th>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Occurrences</th>
                <th style={{ padding: '1rem', fontWeight: 600 }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, idx) => (
                <tr 
                  key={`${ioc.value}-${idx}`} 
                  style={{ borderBottom: '1px solid var(--border-color)', cursor: 'pointer', transition: 'background-color 0.2s' }}
                  onClick={() => ioc.latest_email_id && navigate(`/emails/${ioc.latest_email_id}`)}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <td style={{ padding: '1rem', fontWeight: 500, wordBreak: 'break-all' }}>{ioc.value}</td>
                  <td style={{ padding: '1rem', textTransform: 'uppercase', fontSize: '0.85rem' }}>{ioc.ioc_type}</td>
                  <td style={{ padding: '1rem' }}>
                    <span style={{ 
                      color: getVerdictColor(ioc.verdict), 
                      fontWeight: 600, 
                      backgroundColor: 'var(--bg-dark)', 
                      padding: '4px 8px', 
                      borderRadius: '4px',
                      textTransform: 'capitalize' 
                    }}>
                      {ioc.verdict}
                      {ioc.confidence > 0 && <span style={{ opacity: 0.7, marginLeft: '4px', fontSize: '0.8em' }}>{Math.round(ioc.confidence * 100)}%</span>}
                    </span>
                  </td>
                  <td style={{ padding: '1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {ioc.country && <span style={{ marginRight: '8px' }} title="Country">📍 {ioc.country}</span>}
                    {ioc.asn && <span title="ASN">🏢 {ioc.asn}</span>}
                  </td>
                  <td style={{ padding: '1rem' }}>
                    <div style={{ fontWeight: 600 }}>{ioc.occurrence_count} times</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>across {ioc.associated_email_count} emails</div>
                  </td>
                  <td style={{ padding: '1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
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
