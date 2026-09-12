import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, Cpu, AlertTriangle, Globe, MapPin, 
  List, Flag, Network, Key, Activity
} from 'lucide-react';
import { api } from '../lib/api';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';

function MapBounds({ markers }) {
  const map = useMap();
  useEffect(() => {
    if (markers && markers.length > 0) {
      const bounds = L.latLngBounds(markers.map(m => [m.lat, m.lng]));
      map.fitBounds(bounds, { padding: [30, 30], maxZoom: 13 });
    }
  }, [markers, map]);
  return null;
}


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
        <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
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
  else if (riskLevel === 'high') riskColor = 'var(--status-high-text)';
  else if (riskLevel === 'medium') riskColor = '#eab308';
  else if (riskLevel === 'low') riskColor = 'var(--status-safe-text)';

  const aiClass = (ai.classification || "unknown").toLowerCase();
  const isThreatClass = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClass);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <button className="icon-btn" onClick={() => navigate('/emails')} title="Back to Emails">
          <ArrowLeft size={24} strokeWidth={1.5} />
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
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: isThreatClass ? 'var(--status-critical-text)' : 'var(--text-primary)', textTransform: 'capitalize' }}>
            {aiClass} {ai.confidence !== undefined && ai.confidence !== null ? <span style={{ fontSize: '1rem', color: 'var(--text-secondary)', fontWeight: 'normal' }}>({Math.round(ai.confidence * 100)}%)</span> : ''}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* AI Analysis */}
        {(ai.summary || ai.error) && (
          <div className="card">
            <h2 className="card-title"><Cpu size={16} strokeWidth={1.5} /> AI Forensic Analysis</h2>
            
            {ai.error ? (
              <div style={{ backgroundColor: 'var(--bg-base)', border: '1px solid var(--border-base)', color: 'var(--text-secondary)', padding: '1rem', borderRadius: '6px', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <Cpu size={20} strokeWidth={1.5} />
                <div>
                  <strong style={{ color: 'var(--text-primary)' }}>Forensic analysis completed, but AI explanation unavailable</strong>
                  <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>
                    {ai.error_category === "quota_exceeded"
                      ? "The daily AI analysis quota for this prototype has been reached. Please try again after the quota resets."
                      : ai.error_category === "configuration_error"
                      ? "The AI provider is not configured properly (missing or invalid API key)."
                      : ai.error_category === "timeout"
                      ? "The AI provider took too long to respond. This is a transient error; you can safely retry later."
                      : "The AI provider encountered an unexpected failure and could not provide an explanation."}
                  </div>
                </div>
              </div>
            ) : (
              <>
                <div style={{ backgroundColor: 'var(--bg-base)', padding: '1rem', borderRadius: '6px', marginBottom: '1rem' }}>
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
          <h2 className="card-title"><Key size={16} strokeWidth={1.5} /> Authentication Results</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
            {['spf', 'dkim', 'dmarc'].map(mech => {
              const verdict = (auth[`${mech}_verdict`] || "none").toLowerCase();
              let vColor = 'var(--text-secondary)';
              if (verdict === 'pass') vColor = 'var(--status-safe-text)';
              else if (['fail', 'softfail', 'neutral'].includes(verdict)) vColor = 'var(--status-critical-text)';
              
              return (
                <div key={mech} style={{ backgroundColor: 'var(--bg-base)', padding: '1rem', borderRadius: '6px' }}>
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
            <h2 className="card-title"><Activity size={16} strokeWidth={1.5} /> Threat Intelligence</h2>
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
                        color: ['malicious', 'suspicious'].includes((en.verdict || '').toLowerCase()) ? 'var(--status-critical-text)' : 'var(--text-primary)',
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
            <h2 className="card-title"><List size={16} strokeWidth={1.5} /> Extracted IOCs</h2>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {iocExt.iocs.map((ioc, i) => (
                <div key={i} style={{ backgroundColor: 'var(--bg-base)', border: '1px solid var(--border-base)', borderRadius: '4px', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}>
                  <span style={{ color: 'var(--text-secondary)', marginRight: '0.5rem' }}>{ioc.ioc_type}:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>{ioc.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Geolocation */}
        {geo.results?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Globe size={16} strokeWidth={1.5} /> Geolocation & ASN</h2>
            
            {(() => {
              const validMarkers = geo.results
                .filter(g => g.latitude != null && g.longitude != null)
                .map(g => ({
                  lat: g.latitude,
                  lng: g.longitude,
                  ip: g.ip,
                  city: g.city,
                  country: g.country,
                  org: g.organization,
                  asn: g.asn
                }));

              return validMarkers.length > 0 ? (
                <div style={{ height: '240px', width: '100%', marginBottom: '1.5rem', borderRadius: '8px', overflow: 'hidden' }}>
                  <MapContainer center={[validMarkers[0].lat, validMarkers[0].lng]} zoom={5} style={{ height: '100%', width: '100%' }} scrollWheelZoom={false}>
                    <TileLayer
                      attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                      url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    />
                    <MapBounds markers={validMarkers} />
                    {validMarkers.map((m, i) => (
                      <CircleMarker key={i} center={[m.lat, m.lng]} radius={8} pathOptions={{ color: 'var(--status-high-text)', fillColor: 'var(--status-high-text)', fillOpacity: 0.6 }}>
                        <Popup>
                          <div className="text-small">
                            <div style={{ fontWeight: 600, marginBottom: '4px' }}>{m.ip}</div>
                            <div>{m.city ? `${m.city}, ` : ''}{m.country || "Unknown Location"}</div>
                            {m.org && <div className="text-muted" style={{ marginTop: '4px' }}>{m.org} {m.asn ? `(AS${m.asn})` : ''}</div>}
                            <div className="text-muted" style={{ marginTop: '6px', fontStyle: 'italic', fontSize: '11px' }}>Approximate IP geolocation</div>
                          </div>
                        </Popup>
                      </CircleMarker>
                    ))}
                  </MapContainer>
                </div>
              ) : (
                <div className="map-unavailable">
                  <div className="text-muted" style={{ textAlign: 'center' }}>
                    <Globe size={24} strokeWidth={1.5} style={{ opacity: 0.5, marginBottom: '8px', margin: '0 auto' }} />
                    <div style={{ fontWeight: 500 }}>Map unavailable</div>
                    <div className="text-small" style={{ marginTop: '4px' }}>No valid coordinates were returned for these IPs.</div>
                  </div>
                </div>
              );
            })()}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              {geo.results.map((g, i) => (
                <div key={i} style={{ backgroundColor: 'var(--bg-base)', padding: '1rem', borderRadius: '6px' }}>
                  <div style={{ fontWeight: 'bold', marginBottom: '0.25rem' }}>{g.ip}</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <MapPin size={12} strokeWidth={1.5} /> {g.city ? `${g.city}, ` : ''}{g.country || "Unknown Location"}
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
            <h2 className="card-title"><Flag size={16} strokeWidth={1.5} /> Forensic Flags</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {f.flags.map((flag, i) => (
                <div key={i} style={{ padding: '0.75rem', backgroundColor: 'var(--bg-base)', borderLeft: `3px solid ${flag.severity === 'high' || flag.severity === 'critical' ? 'var(--status-critical-border)' : 'var(--border-base)'}`}}>
                  <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>{flag.description}</div>
                  {flag.evidence && <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>{flag.evidence}</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Received Hops */}
        {f.received_hops?.length > 0 && (
          <div className="card">
            <h2 className="card-title"><Network size={16} strokeWidth={1.5} /> Received Hops</h2>
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
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontSize: '0.85rem' }}>{hop.source_host || "--"}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontSize: '0.85rem' }}>{hop.ipv4 || hop.ipv6 || "--"}</td>
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
