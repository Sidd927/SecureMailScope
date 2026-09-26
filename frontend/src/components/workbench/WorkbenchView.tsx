import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationOverview } from './overview/InvestigationOverview';
import { ProvenanceGraph } from './provenance/ProvenanceGraph';
import { ProtocolJourney } from './timeline/ProtocolJourney';
import { EvidenceLedger } from './evidence/EvidenceLedger';
import { CertificateForensics } from './evidence/CertificateForensics';
import { CrossSessionWorkspace } from './crosssession/CrossSessionWorkspace';
import { ReportExperience } from './report/ReportExperience';
import { InspectorDossier } from './inspector/InspectorDossier';
import type { ForensicTab } from '../../context/InvestigationContext';
import {
  Compass,
  GitBranch,
  Network,
  Table,
  KeyRound,
  Layers,
  FileText,
  AlertTriangle,
} from 'lucide-react';

export const WorkbenchView: React.FC = () => {
  const {
    activeRunId,
    activeRun,
    dashboard,
    activeTab,
    setActiveTab,
    setActiveView,
    isLoading,
    error,
    selectRun,
  } = useInvestigation();

  const handleOpenScoreModal = () => {
    const params = new URLSearchParams(window.location.search);
    params.set('modal', 'score');
    window.history.replaceState(null, '', window.location.pathname + '?' + params.toString());
    window.dispatchEvent(new PopStateEvent('popstate'));
  };

  if (isLoading) {
    return (
      <div style={{ maxWidth: '1240px', width: '100%', margin: '0 auto', padding: '32px 24px' }}>
        {/* Restrained Forensic Skeletons */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }} className="animate-pulse">
          {/* Case Identity Skeleton */}
          <div style={{ borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
              <div style={{ height: '14px', width: '90px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px' }} />
              <div style={{ height: '14px', width: '180px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px' }} />
            </div>
            <div style={{ height: '28px', width: '320px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px', marginBottom: '12px' }} />
            <div style={{ height: '16px', width: '560px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px' }} />
          </div>

          {/* Verdict Skeleton */}
          <div
            style={{
              padding: '24px',
              backgroundColor: 'var(--ds-bg-subtle)',
              border: '1px solid var(--ds-border-light)',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ height: '12px', width: '120px', backgroundColor: 'var(--ds-border-medium)', borderRadius: '3px' }} />
              <div style={{ height: '24px', width: '280px', backgroundColor: 'var(--ds-border-medium)', borderRadius: '4px' }} />
            </div>
            <div style={{ height: '48px', width: '140px', backgroundColor: 'var(--ds-border-medium)', borderRadius: '6px' }} />
          </div>

          {/* Findings Skeleton */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ height: '14px', width: '160px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '3px' }} />
            <div style={{ height: '72px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-light)', borderRadius: '6px' }} />
            <div style={{ height: '72px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-light)', borderRadius: '6px' }} />
          </div>
        </div>
      </div>
    );
  }

  if (error || !dashboard || !activeRun) {
    const isNetworkOr502 = typeof error === 'string' && (error.includes('502') || error.includes('fetch') || error.includes('network') || error.includes('Failed to fetch'));
    const displayReason = isNetworkOr502 ? 'Backend unavailable or network service unreachable.' : (error || 'Investigation session could not be resolved from storage.');
    const technicalDetail = error || 'HTTP 502 Bad Gateway / Connection Refused';

    return (
      <div style={{ maxWidth: '580px', margin: '80px auto', padding: '36px 32px', textAlign: 'center', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-light)', borderRadius: '8px', boxShadow: '0 4px 16px rgba(0,0,0,0.03)' }}>
        <div style={{ display: 'inline-flex', padding: '10px', borderRadius: '50%', backgroundColor: 'var(--ds-crimson-soft)', color: 'var(--ds-crimson)', marginBottom: '16px' }}>
          <AlertTriangle size={24} />
        </div>
        <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-crimson)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '6px' }}>
          ANALYSIS UNAVAILABLE
        </div>
        <h2 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--ds-ink-primary)', marginBottom: '8px' }}>
          We couldn't retrieve this investigation.
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginBottom: '16px', lineHeight: 1.5 }}>
          <strong>Reason:</strong> {displayReason}
        </p>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginBottom: '24px' }}>
          <button
            type="button"
            onClick={() => activeRunId && selectRun(activeRunId)}
            style={{
              padding: '8px 18px',
              backgroundColor: 'var(--ds-carbon)',
              color: '#ffffff',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-sans)',
              fontWeight: 600,
              cursor: 'pointer',
              border: 'none',
            }}
          >
            Retry Analysis
          </button>
          <button
            type="button"
            onClick={() => setActiveView('home')}
            style={{
              padding: '8px 18px',
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '1px solid var(--ds-border-medium)',
              color: 'var(--ds-ink-primary)',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-sans)',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Return to Case Desk
          </button>
        </div>

        {/* Collapsible Progressive Technical Detail */}
        <details style={{ textAlign: 'left', borderTop: '1px solid var(--ds-border-light)', paddingTop: '14px', fontSize: '12px', color: 'var(--ds-ink-muted)' }}>
          <summary style={{ cursor: 'pointer', fontFamily: 'var(--ds-font-mono)', fontSize: '11px' }}>
            Technical detail
          </summary>
          <pre style={{ margin: '10px 0 0', padding: '10px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-secondary)', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
            {technicalDetail}
          </pre>
        </details>
      </div>
    );
  }

  // Navigation Items
  const navTabs: Array<{ id: ForensicTab; label: string; icon: React.ReactNode; shortcut: string }> = [
    { id: 'overview', label: 'Overview & Verdict', icon: <Compass size={13} />, shortcut: '1' },
    { id: 'provenance', label: 'Provenance Trace', icon: <GitBranch size={13} />, shortcut: '2' },
    { id: 'journey', label: 'Protocol Journey', icon: <Network size={13} />, shortcut: '3' },
    { id: 'evidence', label: 'Evidence Ledger', icon: <Table size={13} />, shortcut: '4' },
    { id: 'certs', label: 'Certificate Forensics', icon: <KeyRound size={13} />, shortcut: '5' },
    { id: 'cross_session', label: 'Cross-Session Baseline', icon: <Layers size={13} />, shortcut: '6' },
    { id: 'report', label: 'Forensic Report', icon: <FileText size={13} />, shortcut: '7' },
  ];

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', width: '100%', backgroundColor: 'var(--bg-app)' }}>
      {/* Primary Investigation Navigation Bar */}
      <nav
        aria-label="Investigation Navigation"
        style={{
          backgroundColor: 'var(--ds-bg-canvas)',
          borderBottom: '1px solid var(--ds-border-light)',
          padding: '0 28px',
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
          overflowX: 'auto',
          position: 'sticky',
          top: '56px',
          zIndex: 90,
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
        }}
      >
        {navTabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '7px',
                padding: '11px 16px',
                fontSize: '12px',
                fontFamily: 'var(--ds-font-sans)',
                fontWeight: isActive ? 700 : 500,
                color: isActive ? 'var(--ds-ink-primary)' : 'var(--ds-ink-muted)',
                backgroundColor: 'transparent',
                borderBottom: isActive ? '2px solid var(--ds-carbon)' : '2px solid transparent',
                marginBottom: '-1px',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ color: isActive ? 'var(--ds-carbon)' : 'inherit' }}>{tab.icon}</span>
              <span>{tab.label}</span>
              <span
                style={{
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '10px',
                  color: isActive ? 'var(--ds-carbon)' : 'var(--ds-ink-faint)',
                  opacity: 0.8,
                  marginLeft: '2px',
                }}
              >
                [{tab.shortcut}]
              </span>
            </button>
          );
        })}
      </nav>

      {/* Primary View Content Area */}
      <main style={{ flex: 1, padding: '0 32px' }}>
        {activeTab === 'overview' && (
          <InvestigationOverview onOpenScoreModal={handleOpenScoreModal} />
        )}
        {activeTab === 'provenance' && <ProvenanceGraph />}
        {activeTab === 'journey' && <ProtocolJourney />}
        {activeTab === 'evidence' && <EvidenceLedger />}
        {activeTab === 'certs' && <CertificateForensics />}
        {activeTab === 'cross_session' && <CrossSessionWorkspace />}
        {activeTab === 'report' && <ReportExperience />}
      </main>

      {/* Contextual Sliding Investigation Dossier */}
      <InspectorDossier />
    </div>
  );
};
