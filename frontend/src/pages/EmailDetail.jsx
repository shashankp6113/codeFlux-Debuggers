import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, Cpu, AlertTriangle, Globe, MapPin, 
  List, Flag, Network, Key, Activity
} from 'lucide-react';
import { api } from '../lib/api';

export default function EmailDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [email, setEmail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadEmail() {
      try {
        setLoading(true);
        const data = await api.getEmail(id);
        if (!data) {
          setError("Email not found.");
        } else {
          setEmail(data);
        }
      } catch (err) {
        if (err.message && err.message.includes('404')) {
           setError("Email not found.");
        } else if (err.message && err.message.includes('401')) {
           setError("Unauthorized to view this email.");
        } else {
           setError(err.message || "Failed to load email.");
        }
      } finally {
        setLoading(false);
      }
    }
    loadEmail();
  }, [id]);

  if (loading) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <h3>Loading Investigation...</h3>
      </div>
    );
  }

  if (error || !email) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <AlertTriangle size={48} color="#ef4444" className="empty-state-icon" />
        <h3>Error</h3>
        <p>{error || "Email not found"}</p>
        <button className="btn-secondary" onClick={() => navigate('/emails')}>
          Back to Emails
        </button>
      </div>
    );
  }

  const f = email.forensics || {};
  const ai = f.ai_analysis || {};
  const auth = f.authentication || {};
  const ti = f.threat_intelligence || {};
  const iocExt = f.ioc_extraction || {};
  const geo = f.geolocation || {};

  const riskLevel = (f.threat_score?.risk_level || "low").toLowerCase();
  let riskColor = 'var(--text-secondary)';
  if (riskLevel === 'critical') riskColor = '#dc2626';
  else if (riskLevel === 'high') riskColor = '#f59e0b';
  else if (riskLevel === 'medium') riskColor = '#eab308';
  else if (riskLevel === 'low') riskColor = '#22c55e';

  const aiClass = (ai.classification || "unknown").toLowerCase();
  const isThreatClass = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClass);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <button className="icon-btn" onClick={() => navigate('/emails')} title="Back to Emails">
          <ArrowLeft size={24} />
        </button>
        <div>
          <h1 className="page-title" style={{ marginBottom: '0.25rem' }}>{email.subject || "(No Subject)"}</h1>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', display: 'flex', gap: '1rem' }}>
            <span><strong>From:</strong> {email.sender}</span>
            <span><strong>To:</strong> {email.recipient}</span>
            <span>{new Date(email.received_at || email.created_at).toLocaleString()}</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Threat Score</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: riskColor, textTransform: 'capitalize' }}>
            {f.threat_score?.score ?? "--"} / 100 ({riskLevel})
          </div>
        </div>
        <div className="card" style={{ padding: '1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>AI Classification</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: isThreatClass ? '#ef4444' : 'var(--text-primary)', textTransform: 'capitalize' }}>
            {aiClass} {ai.confidence !== undefined && ai.confidence !== null ? <span style={{ fontSize: '1rem', color: 'var(--text-secondary)', fontWeight: 'normal' }}>({Math.round(ai.confidence * 100)}%)</span> : ''}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* AI Analysis */}
        {(ai.summary || ai.error) && (
          <div className="card">
            <h2 className="card-title"><Cpu size={18} /> AI Forensic Analysis</h2>
            
            {ai.error ? (
              <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', color: '#ef4444', padding: '1rem', borderRadius: '6px', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <AlertTriangle size={20} />
                <div>
                  <strong>AI Analysis Unavailable</strong>
                  <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>
                    {ai.error_category === "quota_exceeded"
                      ? "The daily AI analysis quota for this prototype has been reached. Please try again after the quota resets."
                      : "The AI provider failed to analyze this email. This may be due to rate limits or configuration issues."}
                  </div>
                </div>
              </div>
            ) : (
              <>
                <div style={{ backgroundColor: 'var(--bg-dark)', padding: '1rem', borderRadius: '6px', marginBottom: '1rem' }}>
                  <strong>Summary:</strong> {ai.summary}
                </div>
                {ai.explanation && (
                  <div style={{ marginBottom: '1rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                    {ai.explanation}
                  </div>
                )}
                {ai.recommended_actions?.length > 0 && (
                  <div>
                    <strong style={{ fontSize: '0.9rem' }}>Recommended Actions:</strong>
                    <ul style={{ marginLeft: '1.5rem', marginTop: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                      {ai.recommended_actions.map((act, i) => <li key={i}>{act}</li>)}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Authentication */}
        <div className="card">
          <h2 className="card-title"><Key size={18} /> Authentication Results</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
            {['spf', 'dkim', 'dmarc'].map(mech => {
              const verdict = (auth[`${mech}_verdict`] || "none").toLowerCase();
              let vColor = 'var(--text-secondary)';
              if (verdict === 'pass') vColor = '#22c55e';
              else if (['fail', 'softfail', 'neutral'].includes(verdict)) vColor = '#ef4444';
              
              return (
                <div key={mech} style={{ backgroundColor: 'var(--bg-dark)', padding: '1rem', borderRadius: '6px' }}>
                  <div style={{ textTransform: 'uppercase', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{mech}</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: vColor, textTransform: 'uppercase' }}>
                    {verdict}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Threat Intelligence */}
        {ti.enrichments?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Activity size={18} /> Threat Intelligence</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>IOC</th>
                  <th>Verdict</th>
                  <th>Provider</th>
                </tr>
              </thead>
              <tbody>
                {ti.enrichments.map((en, i) => (
                  <tr key={i}>
                    <td><strong>{en.ioc_value}</strong> <span style={{fontSize:'0.75rem', color:'var(--text-secondary)'}}>({en.ioc_type})</span></td>
                    <td>
                      <span style={{
                        color: ['malicious', 'suspicious'].includes((en.verdict || '').toLowerCase()) ? '#ef4444' : 'var(--text-primary)',
                        fontWeight: 'bold', textTransform: 'capitalize'
                      }}>{en.verdict}</span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{en.provider}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Extracted IOCs */}
        {iocExt.iocs?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><List size={18} /> Extracted IOCs</h2>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {iocExt.iocs.map((ioc, i) => (
                <div key={i} style={{ backgroundColor: 'var(--bg-dark)', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}>
                  <span style={{ color: 'var(--text-secondary)', marginRight: '0.5rem' }}>{ioc.ioc_type}:</span>
                  <span style={{ fontFamily: 'monospace' }}>{ioc.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Geolocation */}
        {geo.results?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Globe size={18} /> Geolocation & ASN</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              {geo.results.map((g, i) => (
                <div key={i} style={{ backgroundColor: 'var(--bg-dark)', padding: '1rem', borderRadius: '6px' }}>
                  <div style={{ fontWeight: 'bold', marginBottom: '0.25rem' }}>{g.ip}</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <MapPin size={12} /> {g.city ? `${g.city}, ` : ''}{g.country || "Unknown Location"}
                  </div>
                  {g.organization && (
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      Org: {g.organization} {g.asn ? `(AS${g.asn})` : ''}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Flags */}
        {f.flags?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Flag size={18} /> Forensic Flags</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {f.flags.map((flag, i) => (
                <div key={i} style={{ padding: '0.75rem', backgroundColor: 'var(--bg-dark)', borderLeft: `3px solid ${flag.severity === 'high' || flag.severity === 'critical' ? '#ef4444' : 'var(--accent-color)'}`}}>
                  <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>{flag.description}</div>
                  {flag.evidence && <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem', fontFamily: 'monospace' }}>{flag.evidence}</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Received Hops */}
        {f.received_hops?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Network size={18} /> Received Hops</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hop</th>
                  <th>Source</th>
                  <th>IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {f.received_hops.map(hop => (
                  <tr key={hop.hop_number}>
                    <td>{hop.hop_number}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{hop.source_host || "--"}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{hop.ipv4 || hop.ipv6 || "--"}</td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{hop.timestamp || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
