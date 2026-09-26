import React, { useRef } from 'react';
import { Compass, FileText, GitBranch, KeyRound, Layers, Network, Table } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import type { ForensicTab } from '../../context/InvestigationContext';
import { OfflineBanner } from '../common/OfflineBanner';
import { ErrorState, SkeletonRows } from '../common/StateViews';
import { InvestigationOverview } from './overview/InvestigationOverview';
import { EvidenceLedger } from './evidence/EvidenceLedger';
import { ProtocolJourney } from './timeline/ProtocolJourney';
import { CertificateForensics } from './evidence/CertificateForensics';
import { CrossSessionWorkspace } from './crosssession/CrossSessionWorkspace';
import { ProvenanceGraph } from './provenance/ProvenanceGraph';
import { ReportExperience } from './report/ReportExperience';

interface TabDef { id: ForensicTab; label: string; icon: React.ElementType; key: string }

const GROUPS: Array<{ label: string; tabs: TabDef[] }> = [
  { label: 'Analysis', tabs: [
    { id: 'overview', label: 'Summary', icon: Compass, key: '1' },
    { id: 'evidence', label: 'Evidence & Findings', icon: Table, key: '2' },
  ] },
  { label: 'Technical', tabs: [
    { id: 'journey', label: 'Protocol Journey', icon: Network, key: '3' },
    { id: 'certs', label: 'Certificates', icon: KeyRound, key: '4' },
    { id: 'cross_session', label: 'Cross-Session', icon: Layers, key: '5' },
    { id: 'provenance', label: 'Provenance', icon: GitBranch, key: '6' },
  ] },
  { label: 'Deliverable', tabs: [
    { id: 'report', label: 'Report', icon: FileText, key: '7' },
  ] },
];
const ALL_TABS = GROUPS.flatMap((g) => g.tabs);

const PANELS: Record<ForensicTab, React.ComponentType> = {
  overview: InvestigationOverview,
  evidence: EvidenceLedger,
  journey: ProtocolJourney,
  certs: CertificateForensics,
  cross_session: CrossSessionWorkspace,
  provenance: ProvenanceGraph,
  report: ReportExperience,
};

export const WorkbenchView: React.FC = () => {
  const { activeRunId, activeRun, dashboard, activeTab, setActiveTab, setActiveView, isLoading, error, selectRun } = useInvestigation();
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const onTabKey = (e: React.KeyboardEvent, id: ForensicTab) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const i = ALL_TABS.findIndex((t) => t.id === id);
    const next = ALL_TABS[(i + (e.key === 'ArrowRight' ? 1 : ALL_TABS.length - 1)) % ALL_TABS.length];
    setActiveTab(next.id);
    tabRefs.current[next.id]?.focus();
  };

  let content: React.ReactNode;
  if (isLoading && !dashboard) {
    content = (
      <div className="sms-page">
        <SkeletonRows rows={1} height={72} />
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr 240px', gap: 'var(--ds-space-16)' }}>
          <SkeletonRows rows={5} height={40} />
          <SkeletonRows rows={4} height={96} gap="var(--ds-space-12)" />
          <SkeletonRows rows={5} height={40} />
        </div>
      </div>
    );
  } else if (error || !dashboard || !activeRun) {
    content = (
      <div className="sms-page">
        <ErrorState
          title="This investigation could not be loaded"
          detail={error || 'The analysis engine returned no data for this run.'}
          onRetry={activeRunId ? () => selectRun(activeRunId) : undefined}
        />
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <button type="button" className="sms-btn" onClick={() => setActiveView('home')}>Back to home</button>
        </div>
      </div>
    );
  } else {
    const Panel = PANELS[activeTab];
    content = <div id={`panel-${activeTab}`} role="tabpanel" aria-labelledby={`tab-${activeTab}`}><Panel /></div>;
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      <nav className="sms-tabs" aria-label="Investigation sections">
        {GROUPS.map((group) => (
          <div key={group.label} className="sms-tabs__group">
            <span className="sms-label">{group.label}</span>
            <div className="sms-tabs__list" role="tablist" aria-label={group.label}>
              {group.tabs.map((tab) => {
                const Icon = tab.icon;
                const selected = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    ref={(el) => { tabRefs.current[tab.id] = el; }}
                    id={`tab-${tab.id}`}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    aria-controls={`panel-${tab.id}`}
                    tabIndex={selected ? 0 : -1}
                    className="sms-tab"
                    onClick={() => setActiveTab(tab.id)}
                    onKeyDown={(e) => onTabKey(e, tab.id)}
                  >
                    <Icon size={14} aria-hidden="true" />
                    {tab.label}
                    <span className="sms-tab__key" aria-hidden="true">{tab.key}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <OfflineBanner />
      <main style={{ flex: 1, minWidth: 0 }}>{content}</main>
    </div>
  );
};
