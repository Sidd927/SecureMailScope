import React, { useEffect, useState } from 'react';
import { Shield, Cpu, Lock, GitCompare, FileCheck } from 'lucide-react';
import { api } from '../../api/client';
import type { HealthResponse } from '../../api/types';
import { OfflineBanner } from '../common/OfflineBanner';
import { BrandLogo } from '../common/BrandLogo';
import { CaptureUpload } from './CaptureUpload';
import { RecentAnalyses } from './RecentAnalyses';

export const HomeView: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);

  useEffect(() => {
    api.getHealth()
      .then(setHealth)
      .catch(() => setHealthFailed(true));
  }, []);

  return (
    <>
      <OfflineBanner />
      <main className="sms-case-desk" role="main" aria-label="Forensic Investigation Case Desk">
        <div className="sms-case-desk__inner">
          {/* A. PRODUCT & EDITORIAL HERO */}
          <header className="sms-case-desk__hero">
            <div className="sms-case-desk__badge-row">
              <span className="sms-label sms-case-desk__overline">
                Forensic Case Desk
              </span>
              <span className="sms-badge sms-badge--muted sms-case-desk__version-badge">
                Engine {health?.version ?? '0.8.0'}
              </span>
            </div>

            <div className="sms-case-desk__brand-heading">
              <BrandLogo variant="full" size="lg" showSubtitle={false} />
            </div>

            <h1 className="sms-case-desk__title">
              Cryptographic Security Posture Assessment
            </h1>

            <p className="sms-case-desk__tagline">
              Evidence-driven forensic dissection of email communication protocols (SMTP, IMAP, POP3) from passive packet captures.
            </p>

            {/* Technical Characteristics Line */}
            <div className="sms-case-desk__tech-pills" aria-label="System characteristics">
              <div className="sms-tech-pill" title="Passive offline packet capture only; zero active network probing">
                <Shield size={12} className="sms-tech-pill__icon" aria-hidden="true" />
                <span>100% Passive Ingestion</span>
              </div>
              <div className="sms-tech-pill" title="Full TLS handshake and cryptographic suite extraction via TShark">
                <Cpu size={12} className="sms-tech-pill__icon" aria-hidden="true" />
                <span>{health?.tshark ? `TShark ${health.tshark.slice(0, 12)}` : 'TShark Dissection'}</span>
              </div>
              <div className="sms-tech-pill" title="Evaluated against RFC 8314, RFC 8996, and NIST SP 800-52r2 standards">
                <Lock size={12} className="sms-tech-pill__icon" aria-hidden="true" />
                <span>NIST & RFC Normative Rules</span>
              </div>
              <div className="sms-tech-pill" title="Multi-session comparison for capability stripping and downgrade detection">
                <GitCompare size={12} className="sms-tech-pill__icon" aria-hidden="true" />
                <span>Cross-Session Reasoning</span>
              </div>
              <div className="sms-tech-pill" title="Full provenance from capture bytes to posture determination">
                <FileCheck size={12} className="sms-tech-pill__icon" aria-hidden="true" />
                <span>Byte-to-Posture Traceability</span>
              </div>
            </div>
          </header>

          {/* B. PRIMARY FORENSIC INGEST BAY */}
          <CaptureUpload
            maxUploadBytes={health?.limits.max_upload_bytes ?? null}
            maxAnalysisSeconds={health?.limits.max_analysis_seconds ?? null}
            disabled={healthFailed}
          />

          {healthFailed && (
            <div className="sms-case-desk__alert" role="alert">
              <span className="sms-dot" style={{ background: 'var(--ds-crimson-rail)' }} aria-hidden="true" />
              <span>
                Forensic analysis engine at <code>127.0.0.1:8001</code> is currently unavailable. Stored investigations can still be viewed, but new captures cannot be processed until the service is restored.
              </span>
            </div>
          )}

          {/* C. RECENT INVESTIGATIONS LEDGER & SECONDARY VALIDATED SCENARIOS */}
          <RecentAnalyses />
        </div>
      </main>
    </>
  );
};
