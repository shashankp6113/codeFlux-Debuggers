import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { Loader, AlertTriangle, FileText, Printer, Download, ArrowLeft, ShieldAlert } from 'lucide-react';

export default function Reports() {
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [selectedReport, setSelectedReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  useEffect(() => {
    fetchEmails();
  }, []);

  async function fetchEmails() {
    try {
      setLoading(true);
      const data = await api.getEmails(100);
      setEmails(data || []);
    } catch (err) {
      setError(err.message || 'Failed to load emails');
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectReport(id) {
    try {
      setReportLoading(true);
      setError(null);
      const reportData = await api.getEmailReport(id);
      setSelectedReport(reportData);
    } catch (err) {
      setError(err.message || 'Failed to load report');
    } finally {
      setReportLoading(false);
    }
  }

  function handlePrint() {
    window.print();
  };

  function handleExportCsv() {
    if (!selectedReport || !selectedReport.forensics) return;
    
    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Type,Value,Category/Context,Severity/Confidence\n";
    
    const flags = selectedReport.forensics.flags || [];
    flags.forEach(f => {
      csvContent += `"Flag","${f.description}","${f.rule_id}","${f.severity}"\n`;
    });
    
    const iocs = selectedReport.forensics.ioc_extraction?.iocs || [];
    iocs.forEach(ioc => {
      csvContent += `"IOC","${ioc.value}","${ioc.ioc_type}","${ioc.context}"\n`;
    });
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `forensic_report_${selectedReport.id}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (loading && !selectedReport) {
    return (
      <div className="empty-state">
        <Loader size={48} className="empty-state-icon animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
        <h3>Loading Reports...</h3>
      </div>
    );
  }

  if (error && !selectedReport) {
    return (
      <div className="empty-state">
        <AlertTriangle size={48} color="var(--status-critical-text)" className="empty-state-icon" />
        <h3>Error Loading Data</h3>
        <p>{error}</p>
      </div>
    );
  }

  if (selectedReport) {
    const f = selectedReport.forensics;
    return (
      <div className="report-container">
        <div className="no-print" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem' }}>
          <button className="btn-secondary" onClick={() => setSelectedReport(null)}>
            <ArrowLeft size={16} strokeWidth={1.5} /> Back to Reports
          </button>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <button className="btn-secondary" onClick={handleExportCsv} disabled={!f}>
              <Download size={16} strokeWidth={1.5} /> Export CSV
            </button>
            <button className="btn-primary" onClick={handlePrint}>
              <Printer size={16} strokeWidth={1.5} /> Print / Save PDF
            </button>
          </div>
        </div>
        
        <div className="card report-print-area" style={{ padding: '3rem' }}>
          <div style={{ textAlign: 'center', marginBottom: '3rem', borderBottom: '1px solid var(--border-base)', paddingBottom: '1.5rem' }}>
            <h1 className="text-h1" style={{ margin: 0 }}>Forensic Email Analysis Report</h1>
            <p className="text-secondary" style={{ margin: '0.5rem 0' }}>MailForensics AI</p>
            <div className="text-small text-muted">Report ID: {selectedReport.id} | Generated: {new Date().toLocaleString()}</div>
          </div>
          
          <h2 className="text-h2" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>1. Executive Summary</h2>
          <table style={{ width: '100%', marginBottom: '2rem', borderCollapse: 'collapse' }}>
            <tbody>
              <tr>
                <td style={{ padding: '0.5rem 0', fontWeight: 'bold', width: '20%', borderBottom: '1px solid var(--border-subtle)' }}>Subject</td>
                <td style={{ padding: '0.5rem 0', borderBottom: '1px solid var(--border-subtle)' }}>{selectedReport.subject || '(No Subject)'}</td>
              </tr>
              <tr>
                <td style={{ padding: '0.5rem 0', fontWeight: 'bold', borderBottom: '1px solid var(--border-subtle)' }}>Sender</td>
                <td style={{ padding: '0.5rem 0', borderBottom: '1px solid var(--border-subtle)' }}>{selectedReport.sender}</td>
              </tr>
              <tr>
                <td style={{ padding: '0.5rem 0', fontWeight: 'bold', borderBottom: '1px solid var(--border-subtle)' }}>Recipient</td>
                <td style={{ padding: '0.5rem 0', borderBottom: '1px solid var(--border-subtle)' }}>{selectedReport.recipient}</td>
              </tr>
              <tr>
                <td style={{ padding: '0.5rem 0', fontWeight: 'bold', borderBottom: '1px solid var(--border-subtle)' }}>Received</td>
                <td style={{ padding: '0.5rem 0', borderBottom: '1px solid var(--border-subtle)' }}>{selectedReport.received_at ? new Date(selectedReport.received_at).toLocaleString() : 'N/A'}</td>
              </tr>
            </tbody>
          </table>
          
          {f ? (
            <>
              <h2 className="text-h2" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>2. Threat Assessment</h2>
              <div style={{ display: 'flex', gap: '2rem', marginBottom: '2rem' }}>
                <div style={{ flex: 1, backgroundColor: 'var(--bg-surface-hover)', padding: '1rem', borderRadius: '4px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Threat Score</div>
                  <div style={{ fontSize: '2rem', fontWeight: 'bold', color: 'var(--text-primary)' }}>{f.threat_score?.score || 0}/100</div>
                  <div style={{ fontWeight: 'bold', color: f.threat_score?.risk_level === 'critical' ? 'var(--status-critical-text)' : 'var(--text-primary)', textTransform: 'capitalize' }}>
                    {f.threat_score?.risk_level || 'Low'} Risk
                  </div>
                </div>
                <div style={{ flex: 1, backgroundColor: 'var(--bg-surface-hover)', padding: '1rem', borderRadius: '4px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>AI Classification</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                    {f.ai_analysis?.classification || 'Unknown'}
                  </div>
                  <div style={{ color: 'var(--text-secondary)' }}>
                    {f.ai_analysis?.confidence ? Math.round(f.ai_analysis.confidence * 100) + '% Confidence' : 'N/A'}
                  </div>
                </div>
              </div>
              
              {f.ai_analysis?.explanation && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 className="text-h2">AI Reasoning</h3>
                  <p style={{ lineHeight: '1.6' }}>{f.ai_analysis.explanation}</p>
                </div>
              )}
              
              <h2 className="text-h2" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>3. Authentication & Headers</h2>
              <table style={{ width: '100%', marginBottom: '2rem', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-surface-hover)' }}>
                    <th style={{ padding: '0.5rem', textAlign: 'left', borderBottom: '1px solid var(--border-base)' }}>Protocol</th>
                    <th style={{ padding: '0.5rem', textAlign: 'left', borderBottom: '1px solid var(--border-base)' }}>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>SPF</td>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)', fontWeight: 'bold' }}>{f.authentication?.spf_verdict?.toUpperCase() || 'NONE'}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>DKIM</td>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)', fontWeight: 'bold' }}>{f.authentication?.dkim_verdict?.toUpperCase() || 'NONE'}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>DMARC</td>
                    <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)', fontWeight: 'bold' }}>{f.authentication?.dmarc_verdict?.toUpperCase() || 'NONE'}</td>
                  </tr>
                </tbody>
              </table>

              <h2 className="text-h2" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>4. Anomalies & Flags</h2>
              {f.flags && f.flags.length > 0 ? (
                <ul style={{ paddingLeft: '1.5rem', marginBottom: '2rem', lineHeight: '1.6' }}>
                  {f.flags.map((flag, idx) => (
                    <li key={idx}>
                      <strong>{flag.rule_id}</strong> ({flag.severity}): {flag.description}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ marginBottom: '2rem' }}>No significant anomalies detected.</p>
              )}
              
              <h2 className="text-h2" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>5. Indicators of Compromise</h2>
              {f.ioc_extraction?.iocs && f.ioc_extraction.iocs.length > 0 ? (
                <table style={{ width: '100%', marginBottom: '2rem', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'var(--bg-surface-hover)' }}>
                      <th style={{ padding: '0.5rem', textAlign: 'left', borderBottom: '1px solid var(--border-base)' }}>Type</th>
                      <th style={{ padding: '0.5rem', textAlign: 'left', borderBottom: '1px solid var(--border-base)' }}>Value</th>
                      <th style={{ padding: '0.5rem', textAlign: 'left', borderBottom: '1px solid var(--border-base)' }}>Context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {f.ioc_extraction.iocs.map((ioc, idx) => (
                      <tr key={idx}>
                        <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)', textTransform: 'uppercase' }}>{ioc.ioc_type}</td>
                        <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)', wordBreak: 'break-all' }}>{ioc.value}</td>
                        <td style={{ padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>{ioc.context}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p style={{ marginBottom: '2rem' }}>No IOCs extracted.</p>
              )}
              
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: '3rem', backgroundColor: 'var(--bg-surface-hover)', color: 'var(--text-secondary)' }}>
              <ShieldAlert size={48} style={{ margin: '0 auto 1rem auto', opacity: 0.5 }} />
              <p>Forensic analysis has not been completed for this email yet.</p>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="page-title">Forensic Reports</h1>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
        Select an email to generate and export a comprehensive forensic report.
      </p>
      
      {emails.length === 0 ? (
        <div className="empty-state">
          <FileText size={48} className="empty-state-icon" />
          <h3>No Emails Available</h3>
          <p>Sync your Gmail or upload an email to generate reports.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {emails.map(email => (
            <div 
              key={email.id} 
              className="card" 
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', transition: 'background-color 0.2s' }}
              onClick={() => handleSelectReport(email.id)}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-base)'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'var(--surface-color)'}
            >
              <div style={{ flex: '1 1 auto', overflow: 'hidden' }}>
                <h3 style={{ margin: '0 0 0.5rem 0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {email.subject || '(No Subject)'}
                </h3>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
                  {email.sender} &bull; {email.received_at ? new Date(email.received_at).toLocaleDateString() : 'Unknown Date'}
                </div>
              </div>
              <div style={{ flexShrink: 0, marginLeft: '1rem' }}>
                <button 
                  className="btn-primary" 
                  onClick={(e) => { e.stopPropagation(); handleSelectReport(email.id); }}
                  disabled={reportLoading}
                >
                  {reportLoading && selectedReport?.id === email.id ? <Loader size={16} className="animate-spin" /> : <FileText size={16} strokeWidth={1.5} />} 
                  View Report
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
