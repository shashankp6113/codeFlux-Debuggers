import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Inbox, AlertTriangle, Loader } from 'lucide-react';
import { api } from '../lib/api';
import UploadButton from '../components/UploadButton';

export default function Emails() {
  const navigate = useNavigate();
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    async function loadEmails() {
      try {
        setLoading(true);
        const data = await api.getEmails();
        setEmails(data || []);
      } catch (err) {
        setError(err.message || "Failed to load emails.");
      } finally {
        setLoading(false);
      }
    }
    loadEmails();
  }, []);

  const filteredEmails = emails.filter(email => {
    if (!searchQuery) return true;
    const lowerQuery = searchQuery.toLowerCase();
    const subjectMatch = (email.subject || '').toLowerCase().includes(lowerQuery);
    const senderMatch = (email.sender || '').toLowerCase().includes(lowerQuery);
    return subjectMatch || senderMatch;
  });

  if (loading) {
    return (
      <div>
        <h1 className="page-title">Investigations</h1>
        <div className="card" style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <Loader size={48} className="empty-state-icon" />
            <h3>Loading emails...</h3>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <h1 className="page-title">Investigations</h1>
        <div className="card" style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
            <h3>Error Loading Emails</h3>
            <p>{error}</p>
            <button className="btn-primary" onClick={() => window.location.reload()}>Retry</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="page-title">Investigations</h1>
      
      <div className="card">
        <div className="search-container">
          <Search size={16} strokeWidth={1.5} className="search-icon" />
          <input 
            type="text" 
            className="search-input" 
            placeholder="Search by subject or sender..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {filteredEmails.length === 0 ? (
          <div className="empty-state" style={{ padding: '4rem 1rem' }}>
            {emails.length === 0 ? (
              <>
                <Inbox size={48} className="empty-state-icon" />
                <h3>No emails processed</h3>
                <p style={{ marginBottom: '1rem' }}>Upload or connect an inbox to start analyzing emails.</p>
                <UploadButton label="Upload .eml File" />
              </>
            ) : (
              <>
                <Search size={48} className="empty-state-icon" />
                <h3>No results found</h3>
                <p>No emails match your search query "{searchQuery}".</p>
              </>
            )}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th>Date</th>
                  <th>AI Classification</th>
                  <th>Threat Risk</th>
                </tr>
              </thead>
              <tbody>
                {filteredEmails.map(email => {
                  const forensics = email.forensics || {};
                  
                  // AI Classification
                  const aiClass = (forensics.ai_analysis?.classification || "unknown").toLowerCase();
                  const isThreatClass = ["suspicious", "malicious", "phishing", "malware", "spam"].includes(aiClass);
                  
                  // Deterministic Threat Risk
                  const riskLevel = (forensics.threat_score?.risk_level || "low").toLowerCase();
                  
                  let riskColor = 'var(--text-secondary)';
                  if (riskLevel === 'critical') riskColor = '#dc2626';
                  else if (riskLevel === 'high') riskColor = 'var(--status-high-text)';
                  else if (riskLevel === 'medium') riskColor = '#eab308';
                  else if (riskLevel === 'low') riskColor = 'var(--status-safe-text)';

                  return (
                    <tr key={email.id} onClick={() => navigate(`/emails/${email.id}`)}>
                      <td className="truncate" style={{ fontWeight: 500, maxWidth: '300px' }}>
                        {email.subject || "(No Subject)"}
                      </td>
                      <td className="truncate text-muted" style={{ maxWidth: '200px' }}>
                        {email.sender}
                      </td>
                      <td style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        {new Date(email.received_at || email.created_at).toLocaleString()}
                      </td>
                      <td>
                        <span className={`badge ${isThreatClass ? 'badge-critical' : 'badge-neutral'}`}>
                          {aiClass}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${
                          riskLevel === 'critical' ? 'badge-critical' :
                          riskLevel === 'high' ? 'badge-high' :
                          riskLevel === 'low' ? 'badge-safe' : 'badge-neutral'
                        }`}>
                          {riskLevel}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
