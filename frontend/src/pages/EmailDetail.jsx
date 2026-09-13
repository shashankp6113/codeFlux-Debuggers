import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, Cpu, AlertTriangle, Globe, MapPin, 
  List, Flag, Network, Key, Activity, FileText
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
  const [isRetrying, setIsRetrying] = useState(false);
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

  async function handleRetryAI() {
    try {
      setIsRetrying(true);
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/emails/${id}/retry-ai`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        }
      });
      if (!response.ok) {
        throw new Error('Failed to retry AI analysis');
      }
      const data = await response.json();
      setEmail(data);
    } catch (err) {
      console.error("AI Retry Error:", err);
      alert("Failed to retry AI analysis. Please try again.");
    } finally {
      setIsRetrying(false);
    }
  }

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
  
  const aiClass = (ai.classification || "unknown").toLowerCase();
  const isThreatClass = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClass);

  let bannerClass = 'security-banner-neutral';
  let bannerIcon = <AlertTriangle size={18} strokeWidth={2} />;
  let bannerTitle = "Security Scan Complete";
  
  if (riskLevel === 'critical' || isThreatClass) {
    bannerClass = 'security-banner-critical';
    bannerTitle = aiClass !== 'unknown' ? `${aiClass.charAt(0).toUpperCase() + aiClass.slice(1)} Detected` : "Critical Threat Detected";
  } else if (riskLevel === 'high') {
    bannerClass = 'security-banner-high';
    bannerTitle = "High Risk Email";
  } else if (riskLevel === 'medium') {
    bannerClass = 'security-banner-medium';
    bannerTitle = "Suspicious Email";
  } else if (riskLevel === 'low') {
    bannerClass = 'security-banner-low';
    bannerTitle = "No Threats Detected";
  }

  const senderInitial = email.sender ? email.sender.charAt(0).toUpperCase() : '?';

  return (
    <div className="email-detail-layout">
      {/* HEADER AND BANNER */}
      <div className="email-detail-header">
        <button className="icon-btn" onClick={() => navigate('/emails')} title="Back to Emails" style={{ marginTop: '0.25rem' }}>
          <ArrowLeft size={24} strokeWidth={1.5} />
        </button>
        <div className="email-detail-meta">
          <h1 className="page-title" style={{ marginBottom: '0.5rem' }}>{email.subject || "(No Subject)"}</h1>
          
          <div className={`security-banner ${bannerClass}`}>
            {bannerIcon}
            <div style={{ flex: 1, textTransform: 'capitalize' }}>
              <strong>{bannerTitle}</strong>
              <span style={{ opacity: 0.8 }}> &mdash; Threat Score: {f.threat_score?.score ?? "--"} / 100 ({riskLevel})</span>
            </div>
            {email.report_id && (
                <button className="btn-secondary btn-small" onClick={() => navigate(`/reports/${email.report_id}`)}>
                  View Report
                </button>
            )}
          </div>

          <div className="email-sender-info">
             <div className="avatar" style={{ width: '40px', height: '40px', fontSize: '18px' }}>{senderInitial}</div>
             <div className="sender-details">
                <div className="sender-line">
                  <strong style={{ fontSize: '1.1rem' }}>{email.sender}</strong>
                  <span className="text-muted text-small">{new Date(email.received_at || email.created_at).toLocaleString()}</span>
                </div>
                <div className="to-line text-small text-muted">To: {email.recipient}</div>
             </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="email-detail-content">
         {/* LEFT PANE: EMAIL BODY */}
         <div className="email-body-pane">
            {email.body_html ? (
               <iframe 
                 title="Email Content"
                 srcDoc={email.body_html}
                 sandbox=""
                 className="email-iframe"
               />
            ) : email.body_text ? (
               <div className="email-text-body">
                 {email.body_text}
               </div>
            ) : (
               <div className="empty-state" style={{ height: '100%', justifyContent: 'center' }}>
                  <FileText size={32} className="empty-state-icon" />
                  <p>No message body available.</p>
               </div>
            )}
         </div>

         {/* RIGHT PANE: FORENSICS */}
         <div className="email-forensic-pane">
           
            {/* AI Analysis */}
            {(ai.summary || ai.error) && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Cpu size={16} strokeWidth={1.5} /> AI Forensic Analysis</h2>
                
                {ai.error ? (
                  <div style={{ backgroundColor: 'var(--bg-base)', border: '1px solid var(--border-base)', color: 'var(--text-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <Cpu size={16} strokeWidth={1.5} />
                      <strong style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>AI explanation unavailable</strong>
                    </div>
                    <div style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
                      {ai.error_category === "quota_exceeded"
                        ? "The daily AI analysis quota for this prototype has been reached."
                        : ai.error_category === "configuration_error"
                        ? "The AI provider is not configured properly."
                        : ai.error_category === "timeout"
                        ? "The AI provider took too long to respond."
                        : "The AI provider encountered an unexpected failure."}
                    </div>
                    <div style={{ marginTop: '0.75rem' }}>
                      <button 
                        className="btn-secondary btn-small" 
                        onClick={handleRetryAI} 
                        disabled={isRetrying}
                        style={{ width: '100%', justifyContent: 'center' }}
                      >
                        {isRetrying ? "Retrying..." : "Retry AI Analysis"}
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-primary)' }}>
                      {ai.summary}
                    </div>
                    {ai.key_findings?.length > 0 && (
                      <ul style={{ marginTop: '0.75rem', paddingLeft: '1.25rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {ai.key_findings.map((finding, i) => (
                          <li key={i} style={{ marginBottom: '0.25rem' }}>{finding}</li>
                        ))}
                      </ul>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Authentication */}
            {(auth.spf || auth.dkim || auth.dmarc) && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Key size={16} strokeWidth={1.5} /> Authentication</h2>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {['spf', 'dkim', 'dmarc'].map(mech => {
                    const result = auth[mech];
                    if (!result) return null;
                    const verdict = (result.verdict || "unknown").toLowerCase();
                    let vColor = 'var(--text-primary)';
                    if (verdict === 'pass') vColor = 'var(--status-safe-text)';
                    else if (verdict === 'fail' || verdict === 'softfail') vColor = 'var(--status-critical-text)';
                    
                    return (
                      <div key={mech} style={{ backgroundColor: 'var(--bg-base)', padding: '0.5rem', borderRadius: '4px', flex: 1, minWidth: '80px', textAlign: 'center' }}>
                        <div style={{ textTransform: 'uppercase', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{mech}</div>
                        <div style={{ fontSize: '0.9rem', fontWeight: 'bold', color: vColor, textTransform: 'uppercase' }}>
                          {verdict}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Threat Intelligence */}
            {ti.enrichments?.length > 0 && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Activity size={16} strokeWidth={1.5} /> Threat Intel</h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {ti.enrichments.map((en, i) => (
                    <div key={i} style={{ fontSize: '0.85rem', display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-base)', paddingBottom: '0.5rem' }}>
                      <div>
                        <strong>{en.ioc_value}</strong> <span style={{fontSize:'0.7rem', color:'var(--text-secondary)'}}>({en.ioc_type})</span>
                      </div>
                      <span style={{
                        color: ['malicious', 'suspicious'].includes((en.verdict || '').toLowerCase()) ? 'var(--status-critical-text)' : 'var(--text-primary)',
                        fontWeight: 'bold', textTransform: 'capitalize'
                      }}>{en.verdict}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Extracted IOCs */}
            {iocExt.iocs?.length > 0 && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><List size={16} strokeWidth={1.5} /> IOCs</h2>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                  {iocExt.iocs.map((ioc, i) => (
                    <div key={i} style={{ backgroundColor: 'var(--bg-base)', border: '1px solid var(--border-base)', borderRadius: '4px', padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                      <span style={{ color: 'var(--text-secondary)', marginRight: '0.25rem' }}>{ioc.ioc_type}:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{ioc.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Geolocation */}
            {geo.results?.length > 0 && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Globe size={16} strokeWidth={1.5} /> Geolocation</h2>
                
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
                    <div style={{ height: '150px', width: '100%', marginBottom: '1rem', borderRadius: '4px', overflow: 'hidden' }}>
                      <MapContainer center={[validMarkers[0].lat, validMarkers[0].lng]} zoom={3} style={{ height: '100%', width: '100%' }} scrollWheelZoom={false}>
                        <TileLayer
                          attribution='&copy; OpenStreetMap'
                          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        <MapBounds markers={validMarkers} />
                        {validMarkers.map((m, i) => (
                          <CircleMarker key={i} center={[m.lat, m.lng]} radius={6} pathOptions={{ color: 'var(--status-high-text)', fillColor: 'var(--status-high-text)', fillOpacity: 0.6 }}>
                            <Popup>
                              <div className="text-small">
                                <div style={{ fontWeight: 600 }}>{m.ip}</div>
                                <div>{m.city ? `${m.city}, ` : ''}{m.country}</div>
                              </div>
                            </Popup>
                          </CircleMarker>
                        ))}
                      </MapContainer>
                    </div>
                  ) : null;
                })()}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {geo.results.map((g, i) => (
                    <div key={i} style={{ backgroundColor: 'var(--bg-base)', padding: '0.5rem', borderRadius: '4px' }}>
                      <div style={{ fontWeight: 'bold', fontSize: '0.85rem' }}>{g.ip}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        <MapPin size={10} strokeWidth={1.5} style={{ display: 'inline' }} /> {g.city ? `${g.city}, ` : ''}{g.country || "Unknown"}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Flags */}
            {f.flags?.length > 0 && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Flag size={16} strokeWidth={1.5} /> Flags</h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {f.flags.map((flag, i) => (
                    <div key={i} style={{ padding: '0.5rem', backgroundColor: 'var(--bg-base)', borderLeft: `3px solid ${flag.severity === 'high' || flag.severity === 'critical' ? 'var(--status-critical-border)' : 'var(--border-base)'}`}}>
                      <div style={{ fontWeight: 'bold', fontSize: '0.8rem' }}>{flag.description}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Received Hops */}
            {f.received_hops?.length > 0 && (
              <div className="card forensic-card">
                <h2 className="card-title text-small"><Network size={16} strokeWidth={1.5} /> Hops</h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
                    {f.received_hops.slice(0, 3).map(hop => (
                      <div key={hop.hop_number} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-base)', paddingBottom: '0.25rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{hop.ipv4 || hop.ipv6 || hop.source_host}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>Hop {hop.hop_number}</span>
                      </div>
                    ))}
                    {f.received_hops.length > 3 && (
                      <div style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                        +{f.received_hops.length - 3} more hops
                      </div>
                    )}
                </div>
              </div>
            )}

         </div>
      </div>
    </div>
  );
}
