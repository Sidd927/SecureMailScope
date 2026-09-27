import React from 'react';
import { CheckCircle2, AlertCircle, Shield } from 'lucide-react';
import type { DashboardViewModel } from '../../../api/types';

interface ObservabilityBoundaryProps {
  dashboard: DashboardViewModel;
}

export const ObservabilityBoundary: React.FC<ObservabilityBoundaryProps> = ({ dashboard }) => {
  const limitations = dashboard.limitations ?? [];
  const abstentions = dashboard.abstentions ?? [];

  return (
    <section className="sms-observability-boundary" aria-label="Forensic Observability Boundary">
      <div className="sms-observability-boundary__head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={16} style={{ color: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
          <h3 className="sms-observability-boundary__title">Passive Forensic Observability Boundary</h3>
        </div>
        <span className="sms-muted sms-mono sms-text-xs">
          RFC 8446 / RFC 3207 Epistemic Limits
        </span>
      </div>

      <div className="sms-observability-boundary__grid">
        {/* Lane 1: What the capture CAN establish */}
        <div className="sms-boundary-lane sms-boundary-lane--can">
          <div className="sms-boundary-lane__header">
            <CheckCircle2 size={14} className="sms-boundary-lane__icon--can" aria-hidden="true" />
            <span className="sms-boundary-lane__label">What This Capture Can Establish</span>
          </div>

          <ul className="sms-boundary-lane__list">
            <li>
              <strong>Observed Wire Protocol Events:</strong> Exact frame-accurate SMTP, IMAP, and POP3 commands, responses, and state sequences.
            </li>
            <li>
              <strong>Transport Encryption Transitions:</strong> Direct wire observation of whether TLS handshakes occur before or after authentication activity.
            </li>
            <li>
              <strong>Visible Cryptographic Parameters:</strong> Negotiated cipher suites, protocol versions, key exchanges, and visible X.509 certificate fields (e.g. RSA key length, signature algorithms in TLS 1.0–1.2).
            </li>
            <li>
              <strong>Cross-Session Behavioral Differentials:</strong> Statistically observable behavioral differences across distinct client/server endpoints under identical server contexts.
            </li>
          </ul>
        </div>

        {/* Lane 2: What the capture CANNOT establish */}
        <div className="sms-boundary-lane sms-boundary-lane--cannot">
          <div className="sms-boundary-lane__header">
            <AlertCircle size={14} className="sms-boundary-lane__icon--cannot" aria-hidden="true" />
            <span className="sms-boundary-lane__label">What This Capture Cannot Establish</span>
          </div>

          <ul className="sms-boundary-lane__list">
            {limitations.length > 0 ? (
              limitations.map((limit, idx) => (
                <li key={idx}>{limit}</li>
              ))
            ) : (
              <>
                <li>
                  <strong>Attacker Intent or Attribution:</strong> Passive PCAP analysis proves what traversed the network wire, not the identity or motivations of human actors.
                </li>
                <li>
                  <strong>Server Trust Store & Private Configuration:</strong> Passive inspection cannot observe internal server root store validation or local private key configurations.
                </li>
                <li>
                  <strong>Encrypted TLS 1.3 Certificate Content:</strong> Handshake certificates in TLS 1.3 (RFC 8446) are cryptographically encrypted on the wire; extraction is inherently <span className="sms-mono" style={{ color: 'var(--sms-brand-cyan)' }}>NOT_OBSERVABLE</span>.
                </li>
              </>
            )}

            {abstentions.length > 0 && (
              <li style={{ marginTop: '8px', borderTop: '1px solid var(--sms-border-subtle)', paddingTop: '8px' }}>
                <strong>Explicit Engine Abstentions ({abstentions.length}):</strong>
                <div className="sms-stack sms-stack--tight" style={{ marginTop: '4px' }}>
                  {abstentions.map((a, i) => (
                    <div key={i} className="sms-mono sms-text-xs" style={{ color: 'var(--sms-text-secondary)' }}>
                      • {a.what_could_not_be_concluded}: {a.why} ({a.resolved_by})
                    </div>
                  ))}
                </div>
              </li>
            )}
          </ul>
        </div>
      </div>
    </section>
  );
};
