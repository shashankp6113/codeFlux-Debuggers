import React from 'react';
import { Link } from 'react-router-dom';

export default function PrivacyPolicy() {
  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '3rem 1.5rem', lineHeight: '1.6', color: '#333' }}>
      <div style={{ marginBottom: '2rem' }}>
        <Link to="/login" style={{ color: '#3b82f6', textDecoration: 'none' }}>&larr; Back to Home</Link>
      </div>
      
      <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem', color: '#111827' }}>Privacy Policy</h1>
      <p style={{ color: '#6b7280', marginBottom: '2rem' }}>Effective Date: September 13, 2026</p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>1. Introduction</h2>
          <p>
            Welcome to MailForensics AI ("we," "our," or "us"). We are committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our application.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>2. Data Collection and Gmail API Access</h2>
          <p>
            Our application connects to your Google account using the Google Gmail API. We explicitly request the <strong>gmail.readonly</strong> scope, which allows us to read your emails for the purpose of forensic analysis and threat detection.
          </p>
          <p>
            <strong>What we collect:</strong> When you connect your Gmail account, we retrieve and store specific email data locally on our servers. This includes the email subject, sender, recipient, CC, message body (text and HTML), and raw headers.
          </p>
          <p>
            <strong>Why we collect it:</strong> We collect this data exclusively to provide the core functionality of MailForensics AI—analyzing your emails for security threats, phishing attempts, and indicators of compromise (IOCs).
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>3. Third-Party Service Providers</h2>
          <p>
            To provide advanced security analysis, we share specific subsets of your data with trusted third-party services. By using our application, you consent to this processing:
          </p>
          <ul style={{ paddingLeft: '1.5rem', marginTop: '0.5rem' }}>
            <li style={{ marginBottom: '0.5rem' }}><strong>Google Gemini AI:</strong> We transmit email bodies, subjects, and headers to Google's Gemini API for semantic threat analysis. We proactively redact known sensitive tokens (e.g., access tokens, API keys) from headers before transmission.</li>
            <li style={{ marginBottom: '0.5rem' }}><strong>VirusTotal:</strong> We extract Indicators of Compromise (such as IP addresses, URLs, and file hashes) and query them against VirusTotal to determine their reputation. The raw email body is <em>never</em> sent to VirusTotal.</li>
            <li><strong>IP Geolocation:</strong> We extract IP addresses from email headers and query third-party geolocation APIs to map approximate sender origins. This location data is approximate and used solely for security context.</li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>4. Google API Services User Data Policy (Limited Use)</h2>
          <p>
            MailForensics AI's use and transfer to any other app of information received from Google APIs will adhere to the <a href="https://developers.google.com/terms/api-services-user-data-policy" target="_blank" rel="noreferrer" style={{ color: '#3b82f6' }}>Google API Services User Data Policy</a>, including the Limited Use requirements.
          </p>
          <p style={{ marginTop: '0.5rem' }}>
            Specifically:
          </p>
          <ul style={{ paddingLeft: '1.5rem', marginTop: '0.5rem' }}>
            <li>We do not sell your data to third parties or data brokers.</li>
            <li>We do not use your data for advertising purposes.</li>
            <li>Your data is used strictly to provide or improve the user-facing features of the application.</li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>5. Data Retention, Disconnect, and Deletion</h2>
          <p>
            <strong>Data Retention:</strong> We store your synced emails indefinitely within our secure PostgreSQL database to allow for historical threat analysis, unless you request deletion.
          </p>
          <p>
            <strong>Disconnecting Gmail:</strong> You can revoke MailForensics AI's access to your Gmail account at any time via the Settings page. Disconnecting your account will immediately revoke our OAuth tokens and permanently delete all your synced emails and forensic data from our servers.
          </p>
          <p>
            <strong>Account Deletion:</strong> You may permanently delete your entire MailForensics AI account from the Settings page. This action instantly revokes all connected accounts and permanently wipes all associated data, tokens, and records.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#1f2937' }}>6. Contact Us</h2>
          <p>
            If you have any questions, privacy concerns, or data deletion requests, please contact us at:
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
