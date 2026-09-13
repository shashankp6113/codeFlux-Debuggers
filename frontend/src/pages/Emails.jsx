import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {Search,  Inbox, AlertTriangle, Loader, ShieldCheck, ShieldAlert } from 'lucide-react';
import { api } from '../lib/api';
import UploadButton from '../components/UploadButton';

function formatEmailDate(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  const now = new Date();
  
  const isToday = date.getDate() === now.getDate() && 
                  date.getMonth() === now.getMonth() && 
                  date.getFullYear() === now.getFullYear();
                  
  if (isToday) {
    return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  } else if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } else {
    return date.toLocaleDateString([], { month: 'numeric', day: 'numeric', year: '2-digit' });
  }
}

export default function Emails() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get('q') || '';
  
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState(q);

  useEffect(() => {
    async function loadEmails() {
      try {
        setLoading(true);
        const data = await api.getEmails(50, q);
        setEmails(data || []);
      } catch (err) {
        setError(err.message || "Failed to load emails.");
      } finally {
        setLoading(false);
      }
    }
    loadEmails();
  }, [q]);

  function handleSearchSubmit(e) {
    e.preventDefault();
    setSearchParams(searchQuery ? { q: searchQuery } : {});
  }

  const filteredEmails = emails;

  if (loading) {
    return (
      <div className="page-container">
        <h1 className="page-title" style={{ marginBottom: '1rem' }}>Inbox</h1>
        <div className="card" style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <Loader size={48} className="empty-state-icon" style={{ opacity: 0.5 }} />
            <h3 style={{ color: 'var(--text-primary)' }}>Loading emails...</h3>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-container">
        <h1 className="page-title" style={{ marginBottom: '1rem' }}>Inbox</h1>
        <div className="card" style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
            <h3 style={{ color: 'var(--text-primary)' }}>Error Loading Emails</h3>
            <p>{error}</p>
            <button className="btn-primary" onClick={() => window.location.reload()} style={{ marginTop: '1rem' }}>Retry</button>
          </div>
        </div>
      </div>
    );
  }

  // Determine if search is active but there are no actual emails at all vs just no search results
  const noEmailsAtAll = emails.length === 0 && !q;
  const noSearchResults = emails.length === 0 && !!q;

  return (
    <div className="page-container">
      <h1 className="page-title" style={{ marginBottom: '1rem' }}>Inbox</h1>
      
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                {filteredEmails.length === 0 ? (
          <div className="empty-state" style={{ padding: '4rem 1rem' }}>
            {noEmailsAtAll ? (
              <>
                <Inbox size={48} className="empty-state-icon" style={{ opacity: 0.3 }} />
                <h3 style={{ color: 'var(--text-primary)' }}>Your inbox is empty</h3>
                <p style={{ marginBottom: '1.5rem', color: 'var(--text-secondary)' }}>Upload or connect an inbox to start analyzing emails.</p>
                <UploadButton label="Upload .eml File" />
              </>
            ) : (
              <>
                <Search size={48} className="empty-state-icon" style={{ opacity: 0.3 }} />
                <h3 style={{ color: 'var(--text-primary)' }}>No results found</h3>
                <p style={{ color: 'var(--text-secondary)' }}>No emails match your search query "{q}".</p>
              </>
            )}
          </div>
        ) : (
          <div className="email-list-container">
            {filteredEmails.map(email => {
              const forensics = email.forensics || {};
              
              // AI Classification
              const aiClass = (forensics.ai_analysis?.classification || "unknown").toLowerCase();
              const isThreatClass = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClass);
              
              // Deterministic Threat Risk
              const riskLevel = (forensics.threat_score?.risk_level || "low").toLowerCase();
              
              let badgeClass = 'badge-safe';
              let badgeText = 'Safe';
              let Icon = ShieldCheck;
              
              if (riskLevel === 'critical' || isThreatClass) {
                badgeClass = 'badge-critical';
                badgeText = 'Critical';
                Icon = ShieldAlert;
              } else if (riskLevel === 'high') {
                badgeClass = 'badge-high';
                badgeText = 'High';
                Icon = ShieldAlert;
              } else if (riskLevel === 'medium') {
                badgeClass = 'badge-medium';
                badgeText = 'Suspicious';
                Icon = AlertTriangle;
              }

              // Extract snippet
              const bodySnippet = (email.body_text || '').substring(0, 150).replace(/\s+/g, ' ').trim();

              return (
                <a 
                  key={email.id} 
                  href={`/emails/${email.id}`}
                  className="email-row"
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(`/emails/${email.id}`);
                  }}
                >
                  <div className="email-row-sender truncate" title={email.sender}>
                    {email.sender || "(Unknown)"}
                  </div>
                  
                  <div className="email-row-content truncate">
                    <span className="email-row-subject">{email.subject || "(No Subject)"}</span>
                    <span className="email-row-snippet">
                      {bodySnippet ? ` - ${bodySnippet}` : ''}
                    </span>
                  </div>
                  
                  <div className="email-row-badges">
                    <span className={`compact-badge ${badgeClass}`} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Icon size={12} strokeWidth={2} />
                      {badgeText}
                    </span>
                  </div>
                  
                  <div className="email-row-date">
                    {formatEmailDate(email.received_at || email.created_at)}
                  </div>
                </a>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
