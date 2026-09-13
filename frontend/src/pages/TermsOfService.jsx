import React from 'react';
import { Link } from 'react-router-dom';

export default function TermsOfService() {
  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '3rem 1.5rem', lineHeight: '1.6', color: '#333' }}>
      <div style={{ marginBottom: '2rem' }}>
        <Link to="/login" style={{ color: '#3b82f6', textDecoration: 'none' }}>&larr; Back to Home</Link>
      </div>
      
      <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem', color: '#111827' }}>Terms of Service</h1>
      <p style={{ color: '#6b7280', marginBottom: '2rem' }}>Effective Date: September 13, 2026</p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>1. Acceptance of Terms</h2>
          <p>
            By accessing or using MailForensics AI ("the Service"), operated by MailForensics AI ("we," "us," or "our"), you agree to be bound by these Terms of Service. If you do not agree to these terms, you may not use the Service.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>2. Description of Service</h2>
          <p>
            MailForensics AI provides tools for analyzing emails to detect security threats, phishing attempts, and indicators of compromise. The Service connects to your Gmail account via OAuth to read and analyze your emails.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>3. No Legal or Security Guarantees</h2>
          <p>
            The Service is provided for informational and analytical purposes only. We do not guarantee that the Service will detect all security threats, phishing attempts, or malicious content. You acknowledge that:
          </p>
          <ul style={{ paddingLeft: '1.5rem', marginTop: '0.5rem' }}>
            <li>The Service relies on third-party APIs (including Google Gemini and VirusTotal) which may produce false positives or false negatives.</li>
            <li>IP Geolocation data is inherently approximate and should not be relied upon for exact physical location tracking.</li>
            <li>We are not responsible for any security breaches, data loss, or damages resulting from your reliance on the Service.</li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>4. Third-Party Affiliations</h2>
          <p>
            MailForensics AI integrates with Google APIs, but it is <strong>not</strong> officially approved, endorsed, or verified by Google LLC. We do not claim any official certification, including Cloud Application Security Assessment (CASA) certification, unless explicitly stated otherwise upon completion of such audits.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>5. User Responsibilities</h2>
          <p>
            You agree not to misuse the Service or help anyone else do so. You must only connect email accounts that you own or have explicit legal authorization to analyze. You are responsible for safeguarding any passwords or tokens used to access the Service.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>6. Termination and Data Deletion</h2>
          <p>
            You may terminate your use of the Service at any time by disconnecting your Gmail account or deleting your MailForensics AI account via the Settings page. Upon deletion, your data will be permanently removed from our active servers in accordance with our Privacy Policy.
          </p>
          <p style={{ marginTop: '0.5rem' }}>
            We reserve the right to suspend or terminate your access to the Service at any time, with or without cause or notice.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>7. Changes to Terms</h2>
          <p>
            We may modify these Terms at any time. We will provide notice of significant changes by updating the "Effective Date" at the top of this page. Your continued use of the Service constitutes your acceptance of the revised Terms.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>8. Contact</h2>
          <p>
            For any questions regarding these Terms, please contact us at:
          </p>
          <p style={{ marginTop: '0.5rem', fontWeight: 'bold' }}>
            MailForensics AI<br/>
            [PRIVACY CONTACT EMAIL]
          </p>
        </section>
      </div>
    </div>
  );
}
