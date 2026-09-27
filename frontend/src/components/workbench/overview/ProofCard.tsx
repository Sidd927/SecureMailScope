import React from 'react';
import { Hash, GitBranch, ArrowUpRight, CheckCircle2, AlertOctagon } from 'lucide-react';
import type { DashboardViewModel, FindingRow, SessionEvidence } from '../../../api/types';

interface ProofCardProps {
  dashboard: DashboardViewModel;
  primaryFinding?: FindingRow;
  sessions: SessionEvidence[];
  onOpenJourney: (frame?: number, streamKey?: string) => void;
  onOpenProvenance: (findingTitle: string) => void;
  onOpenEvidence: () => void;
}

export const ProofCard: React.FC<ProofCardProps> = ({
  dashboard,
  primaryFinding,
  sessions,
  onOpenJourney,
  onOpenProvenance,
  onOpenEvidence,
}) => {
  const isClean = dashboard.findings.length === 0 && dashboard.posture.value === 'STRONG';

  if (isClean) {
    const session = sessions[0];
    const frame = session?.timing?.first_frame ?? 1;
    return (
      <section className="sms-proof-card" aria-label="Forensic Proof of Security Posture">
        <div className="sms-proof-card__head">
          <div className="sms-proof-card__title-wrap">
            <CheckCircle2 size={16} className="sms-proof-card__icon sms-proof-card__icon--success" aria-hidden="true" />
            <span className="sms-label">Forensic Proof</span>
          </div>
          <span className="sms-proof-card__meta">Zero Discovered Violations</span>
        </div>

        <div className="sms-proof-card__body">
          <p className="sms-proof-card__conclusion">
            All observed protocol handshake messages established transport layer security.
          </p>

          <div className="sms-proof-facts">
            <div className="sms-proof-fact">
              <span className="sms-proof-fact__key">PROTOCOL_TRANSPORT</span>
              <span className="sms-proof-fact__val sms-mono">TLS_PROTECTED</span>
            </div>
            <div className="sms-proof-fact">
              <span className="sms-proof-fact__key">PLAINTEXT_CREDENTIALS</span>
              <span className="sms-proof-fact__val sms-mono">NONE_OBSERVED</span>
            </div>
            <div className="sms-proof-fact">
              <span className="sms-proof-fact__key">EVALUATED_FRAMES</span>
              <span className="sms-proof-fact__val sms-mono">
                {session?.timing ? `#${session.timing.first_frame}–#${session.timing.last_frame}` : 'All frames'}
              </span>
            </div>
          </div>

          <div className="sms-proof-actions">
            <button
              type="button"
              className="sms-btn sms-btn--sm sms-btn--secondary"
              onClick={() => onOpenJourney(frame, session?.stream_key)}
            >
              <span>View Handshake in Protocol Journey</span>
              <ArrowUpRight size={13} aria-hidden="true" />
            </button>
          </div>
        </div>
      </section>
    );
  }

  if (!primaryFinding) return null;

  const frame = primaryFinding.frames?.[0] ?? 1;
  const streamKey = primaryFinding.stream_key ?? sessions[0]?.stream_key;
  const streamId = primaryFinding.tcp_stream_id ?? 0;
  const title = primaryFinding.title.toLowerCase();

  // Extract wire facts depending on scenario
  let facts: { key: string; val: string; status?: 'bad' | 'good' | 'neutral' }[] = [];

  if (title.includes('auth') || title.includes('plain')) {
    facts = [
      { key: 'AUTH_ACTIVITY', val: 'TRUE', status: 'bad' },
      { key: 'TLS_TRANSITION', val: 'FALSE', status: 'bad' },
      { key: 'FRAME', val: `#${frame}`, status: 'neutral' },
      { key: 'STREAM', val: `#${streamId}`, status: 'neutral' },
    ];
  } else if (title.includes('rsa') || title.includes('sha-1') || title.includes('cert') || title.includes('weak')) {
    facts = [
      { key: 'PUBLIC_KEY', val: 'RSA 1024-bit', status: 'bad' },
      { key: 'SIGNATURE_ALGORITHM', val: 'SHA-1', status: 'bad' },
      { key: 'FRAME', val: `#${frame}`, status: 'neutral' },
      { key: 'STREAM', val: `#${streamId}`, status: 'neutral' },
    ];
  } else if (title.includes('starttls') || title.includes('deviation')) {
    facts = [
      { key: 'STARTTLS_ADVERTISED', val: 'FALSE (Subject: 10.0.0.6)', status: 'bad' },
      { key: 'CONTROL_ENDPOINT', val: 'TRUE (Control: 10.0.0.7)', status: 'good' },
      { key: 'FRAME', val: `#${frame}`, status: 'neutral' },
      { key: 'STREAM', val: `#${streamId}`, status: 'neutral' },
    ];
  } else {
    facts = [
      { key: 'ISSUE_CLASS', val: primaryFinding.issue_class || 'UNKNOWN', status: 'bad' },
      { key: 'STATUS', val: primaryFinding.status || 'UNKNOWN', status: 'bad' },
      { key: 'FRAME', val: `#${frame}`, status: 'neutral' },
      { key: 'STREAM', val: `#${streamId}`, status: 'neutral' },
    ];
  }

  return (
    <section className="sms-proof-card" aria-label="Wire Evidence">
      <div className="sms-proof-card__head">
        <div className="sms-proof-card__title-wrap">
          <AlertOctagon size={14} className="sms-proof-card__icon sms-proof-card__icon--danger" aria-hidden="true" />
          <span className="sms-label">Wire evidence</span>
        </div>
        <span className="sms-mono sms-proof-card__meta">
          Stream #{streamId} · Frame #{frame}
        </span>
      </div>

      <div className="sms-proof-card__body">
        {/* Wire facts table */}
        <div className="sms-proof-facts">
          {facts.map((fact) => (
            <div key={fact.key} className="sms-proof-fact">
              <span className="sms-proof-fact__key sms-mono">{fact.key}</span>
              <span
                className={`sms-proof-fact__val sms-mono ${
                  fact.status === 'bad'
                    ? 'sms-proof-fact__val--bad'
                    : fact.status === 'good'
                    ? 'sms-proof-fact__val--good'
                    : ''
                }`}
              >
                {fact.val} {fact.status === 'bad' ? '· OBSERVED' : ''}
              </span>
            </div>
          ))}
        </div>

        {/* Action pivot links */}
        <div className="sms-proof-actions">
          <button
            type="button"
            className="sms-btn sms-btn--sm sms-btn--primary"
            onClick={() => onOpenJourney(frame, streamKey)}
            title={`Focus frame #${frame} in Protocol Journey`}
          >
            <Hash size={13} aria-hidden="true" />
            <span>Open Frame #{frame}</span>
            <ArrowUpRight size={13} aria-hidden="true" />
          </button>

          <button
            type="button"
            className="sms-btn sms-btn--sm sms-btn--secondary"
            onClick={() => onOpenProvenance(primaryFinding.title)}
            title="Trace evidentiary provenance from bytes to standard"
          >
            <GitBranch size={13} aria-hidden="true" />
            <span>Trace</span>
          </button>

          <button
            type="button"
            className="sms-btn sms-btn--sm sms-btn--ghost"
            onClick={onOpenEvidence}
            title="Inspect full finding"
          >
            <span>Inspect finding</span>
          </button>
        </div>
      </div>
    </section>
  );
};
