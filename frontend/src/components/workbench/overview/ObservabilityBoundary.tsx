import React, { useState } from 'react';
import { CheckCircle2, MinusCircle, Shield, ChevronDown, ChevronUp } from 'lucide-react';
import type { DashboardViewModel } from '../../../api/types';

interface ObservabilityBoundaryProps {
  dashboard: DashboardViewModel;
}

export const ObservabilityBoundary: React.FC<ObservabilityBoundaryProps> = ({ dashboard }) => {
  const [expanded, setExpanded] = useState(false);
  const limitations = dashboard.limitations ?? [];
  const abstentions = dashboard.abstentions ?? [];

  return (
    <section className="sms-observability-boundary" aria-label="Forensic Observability Boundary">
      <div className="sms-observability-boundary__head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={16} style={{ color: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
          <h3 className="sms-observability-boundary__title">Observability Boundary</h3>
        </div>
        <span className="sms-muted sms-text-xs">
          What this capture can prove
        </span>
      </div>

      <div className="sms-observability-boundary__grid">
        {/* Lane 1: ESTABLISHED */}
        <div className="sms-boundary-lane sms-boundary-lane--can">
          <div className="sms-boundary-lane__header">
            <CheckCircle2 size={14} className="sms-boundary-lane__icon--can" aria-hidden="true" />
            <span className="sms-boundary-lane__label">ESTABLISHED</span>
          </div>

          <ul className="sms-boundary-lane__checklist">
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--yes">✓</span>
              <span>Wire-level protocol events</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--yes">✓</span>
              <span>TLS transitions</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--yes">✓</span>
              <span>Observable certificates</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--yes">✓</span>
              <span>Cross-session deviations</span>
            </li>
          </ul>
        </div>

        {/* Lane 2: NOT OBSERVABLE */}
        <div className="sms-boundary-lane sms-boundary-lane--cannot">
          <div className="sms-boundary-lane__header">
            <MinusCircle size={14} className="sms-boundary-lane__icon--cannot" aria-hidden="true" />
            <span className="sms-boundary-lane__label">NOT OBSERVABLE</span>
          </div>

          <ul className="sms-boundary-lane__checklist">
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--no">—</span>
              <span>Attacker identity</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--no">—</span>
              <span>Server-side configuration</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--no">—</span>
              <span>Trust store validation</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--no">—</span>
              <span>Revocation when unavailable</span>
            </li>
            <li>
              <span className="sms-boundary-mark sms-boundary-mark--no">—</span>
              <span>Encrypted TLS 1.3 certificate content</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Progressive Disclosure: Technical details & Engine abstentions */}
      {(limitations.length > 0 || abstentions.length > 0) && (
        <div className="sms-observability-boundary__expand-wrap">
          <button
            type="button"
            className="sms-link"
            style={{ fontSize: 'var(--ds-text-12)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
            onClick={() => setExpanded(!expanded)}
            aria-expanded={expanded}
          >
            <span>{expanded ? 'Hide limitations' : 'Limitations'}</span>
            {expanded ? <ChevronUp size={13} aria-hidden="true" /> : <ChevronDown size={13} aria-hidden="true" />}
          </button>

          {expanded && (
            <div className="sms-observability-boundary__details">
              {limitations.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <span className="sms-label" style={{ marginBottom: 4, display: 'block' }}>Normative Limitations</span>
                  <ul className="sms-list sms-list--bulleted">
                    {limitations.map((limit, idx) => (
                      <li key={idx} className="sms-text-xs sms-muted">{limit}</li>
                    ))}
                  </ul>
                </div>
              )}

              {abstentions.length > 0 && (
                <div>
                  <span className="sms-label" style={{ marginBottom: 4, display: 'block' }}>
                    Engine Abstentions ({abstentions.length})
                  </span>
                  <div className="sms-stack sms-stack--tight">
                    {abstentions.map((a, i) => (
                      <div key={i} className="sms-mono sms-text-xs" style={{ color: 'var(--sms-text-secondary)', padding: '4px 8px', background: 'var(--sms-surface-recessed)', borderRadius: 4 }}>
                        • <strong>{a.what_could_not_be_concluded}:</strong> {a.why} (Resolution: {a.resolved_by})
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
};
