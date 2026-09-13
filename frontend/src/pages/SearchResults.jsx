import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import {Search,  Mail, Activity, ShieldAlert, ArrowRight, Loader } from 'lucide-react';

export default function SearchResults() {
  const [searchParams] = useSearchParams();
  const q = searchParams.get('q') || '';
  const navigate = useNavigate();
  
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchResults() {
      if (!q.trim()) {
        setResults({ emails: [], iocs: [], threats: [] });
        setLoading(false);
        return;
      }
      
      setLoading(true);
      setError(null);
      try {
        const res = await api.globalSearch(q);
        setResults(res);
      } catch (err) {
        console.error("Failed to load search results", err);
        setError("An error occurred while fetching search results.");
      } finally {
        setLoading(false);
      }
    }
    fetchResults();
  }, [q]);

  if (loading) {
    return (
      <div className="page-container" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '50vh' }}>
        <Loader className="animate-spin" size={48} color="var(--accent-primary)" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-container">
        <div className="empty-state">
          <ShieldAlert size={48} color="var(--status-critical-text)" />
          <h3>Search Error</h3>
          <p>{error}</p>
        </div>
      </div>
    );
  }

  const hasResults = results && (results.emails?.length > 0 || results.iocs?.length > 0 || results.threats?.length > 0);

  return (
    <div className="page-container">
      <div className="dashboard-header" style={{ marginBottom: '2rem' }}>
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Search size={24} />
          Search Results for "{q}"
        </h1>
      </div>

      {!hasResults ? (
        <div className="empty-state">
          <Search size={48} color="var(--icon-muted)" />
          <h3>No results found</h3>
          <p>We couldn't find any emails, IOCs, or threats matching "{q}".</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {results.emails?.length > 0 && (
            <div className="modern-card">
              <div className="modern-card-header">
                <div className="modern-card-title">
                  <Mail size={18} />
                  Emails ({results.emails.length})
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {results.emails.map(email => (
                  <div 
                    key={email.id} 
                    className="inv-row" 
                    onClick={() => navigate(`/emails/${email.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="inv-left">
                      <div className="inv-icon"><Mail size={16} /></div>
                      <div className="inv-text">
                        <span className="inv-subject">{email.subject || '(No Subject)'}</span>
                        <span className="inv-sender">{email.sender}</span>
                      </div>
                    </div>
                    <div className="inv-right">
                      {email.is_threat && (
                        <span className="compact-badge badge-critical">THREAT</span>
                      )}
                      <span className="inv-date">{new Date(email.received_at).toLocaleDateString()}</span>
                      <ArrowRight size={16} color="var(--icon-muted)" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {results.iocs?.length > 0 && (
            <div className="modern-card">
              <div className="modern-card-header">
                <div className="modern-card-title">
                  <Activity size={18} />
                  Indicators of Compromise ({results.iocs.length})
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {results.iocs.map((ioc, idx) => (
                  <div 
                    key={idx} 
                    className="inv-row" 
                    onClick={() => navigate('/iocs')}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="inv-left">
                      <div className="inv-icon"><Activity size={16} /></div>
                      <div className="inv-text">
                        <span className="inv-subject">{ioc.value}</span>
                        <span className="inv-sender" style={{ textTransform: 'capitalize' }}>{ioc.type}</span>
                      </div>
                    </div>
                    <div className="inv-right">
                      <span className="inv-date" style={{ maxWidth: '200px' }} title={ioc.associated_subject}>
                        Found in: {ioc.associated_subject ? (ioc.associated_subject.substring(0, 30) + (ioc.associated_subject.length > 30 ? '...' : '')) : 'Unknown'}
                      </span>
                      <ArrowRight size={16} color="var(--icon-muted)" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {results.threats?.length > 0 && (
            <div className="modern-card">
              <div className="modern-card-header">
                <div className="modern-card-title">
                  <ShieldAlert size={18} />
                  Threats ({results.threats.length})
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {results.threats.map((threat, idx) => (
                  <div 
                    key={idx} 
                    className="inv-row" 
                    onClick={() => navigate(`/emails/${threat.email_id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="inv-left">
                      <div className="inv-icon"><ShieldAlert size={16} color={threat.risk_level === 'critical' ? 'var(--status-critical-text)' : 'var(--status-high-text)'} /></div>
                      <div className="inv-text">
                        <span className="inv-subject" style={{ textTransform: 'capitalize' }}>{threat.classification}</span>
                        <span className="inv-sender">{threat.sender}</span>
                      </div>
                    </div>
                    <div className="inv-right">
                      <span className={`compact-badge ${threat.risk_level === 'critical' ? 'badge-critical' : 'badge-high'}`}>
                        {threat.risk_level.toUpperCase()}
                      </span>
                      <ArrowRight size={16} color="var(--icon-muted)" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
