import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { Loader, AlertTriangle, ShieldAlert, Search, Filter } from 'lucide-react';

export default function ThreatAnalysis() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [search, setSearch] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [classification, setClassification] = useState('');
  
  const navigate = useNavigate();

  useEffect(() => {
    fetchThreats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [riskLevel, classification]);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getThreats({ search, risk_level: riskLevel, classification });
      setThreats(data || []);
    } catch (err) {
      setError(err.message || 'Failed to load threats');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    fetchThreats();
  };

  const getRiskColor = (risk) => {
    switch(risk?.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'high': return 'var(--status-high-text)';
      case 'medium': return '#fbbf24';
      default: return '#10b981';
    }
  };

  return (
    <div>
      <h1 className="page-title">Threat Analysis</h1>
      
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <form onSubmit={handleSearch} className="toolbar">
          <div className="search-container">
            <Search size={16} strokeWidth={1.5} color="var(--text-secondary)" />
            <input 
              type="text" 
              placeholder="Search sender or subject..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <Filter size={16} strokeWidth={1.5} color="var(--text-secondary)" />
            <select 
              value={riskLevel} 
              onChange={(e) => setRiskLevel(e.target.value)}
              className="select-input"
            >
              <option value="">All Risks</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            
            <select 
              value={classification} 
              onChange={(e) => setClassification(e.target.value)}
              className="select-input"
            >
              <option value="">All Classifications</option>
              <option value="phishing">Phishing</option>
              <option value="malware">Malware</option>
              <option value="suspicious">Suspicious</option>
              <option value="spam">Spam</option>
            </select>
            
            <button type="submit" className="btn-primary">Search</button>
          </div>
        </form>
      </div>

      {loading ? (
        <div className="empty-state">
          <Loader size={48} className="empty-state-icon animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
          <h3>Analyzing Threats...</h3>
        </div>
      ) : error ? (
        <div className="empty-state">
          <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
          <h3>Error Loading Threats</h3>
          <p>{error}</p>
        </div>
      ) : threats.length === 0 ? (
        <div className="empty-state">
          <ShieldAlert size={48} color="#10b981" className="empty-state-icon" />
          <h3>No Threats Found</h3>
          <p>Your inbox looks secure based on the current filters.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {threats.map(threat => (
            <div 
              key={threat.id} 
              className="card" 
              style={{ cursor: 'pointer', borderLeft: `4px solid ${getRiskColor(threat.risk_level)}` }}
              onClick={() => navigate(`/emails/${threat.id}`)}
              onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--primary-color)'}
              onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-base)'}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ flex: '1 1 300px' }}>
                  <h3 className="text-h2" style={{ marginBottom: '8px' }}>{threat.subject || '(No Subject)'}</h3>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
                    <strong>From:</strong> {threat.sender}
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                    {threat.received_at ? new Date(threat.received_at).toLocaleString() : 'Unknown Date'}
                  </div>
                </div>
                
                <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Risk Level</div>
                    <div style={{ fontWeight: 'bold', color: getRiskColor(threat.risk_level) }}>{threat.risk_level.toUpperCase()}</div>
                  </div>
                  
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Classification</div>
                    <div style={{ fontWeight: 'bold', backgroundColor: 'var(--bg-base)', padding: '2px 8px', borderRadius: '4px', textTransform: 'capitalize' }}>
                      {threat.classification}
                      {threat.confidence > 0 && <span style={{ opacity: 0.7, marginLeft: '4px', fontSize: '0.8em' }}>{Math.round(threat.confidence * 100)}%</span>}
                    </div>
                  </div>
                  
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Score</div>
                    <div style={{ fontWeight: 'bold', fontSize: '1.25rem' }}>{threat.threat_score}</div>
                  </div>
                </div>
              </div>
              
              {(threat.flag_count > 0 || threat.ioc_count > 0) && (
                <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-base)', display: 'flex', gap: '1rem', fontSize: '0.875rem' }}>
                  {threat.flag_count > 0 && <div><strong style={{ color: 'var(--status-critical-text)' }}>{threat.flag_count}</strong> Forensic Flags</div>}
                  {threat.ioc_count > 0 && <div><strong style={{ color: 'var(--status-high-text)' }}>{threat.ioc_count}</strong> IOCs Extracted</div>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
