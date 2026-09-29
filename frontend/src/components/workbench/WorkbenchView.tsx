import React, { useRef } from 'react';
import { Compass, FileText, GitBranch, KeyRound, Layers, Network, Table } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import type { ForensicTab } from '../../context/InvestigationContext';
import { ErrorState, SkeletonRows } from '../common/StateViews';
import { InvestigationOverview } from './overview/InvestigationOverview';
import { EvidenceLedger } from './evidence/EvidenceLedger';
import { ProtocolJourney } from './timeline/ProtocolJourney';
import { CertificateForensics } from './evidence/CertificateForensics';
import { CrossSessionWorkspace } from './crosssession/CrossSessionWorkspace';
import { ProvenanceGraph } from './provenance/ProvenanceGraph';
import { ReportExperience } from './report/ReportExperience';

interface TabDef {
  id: ForensicTab;
  label: string;
  icon: React.ElementType;
  key: string;
}

interface TabGroup {
  label: string;
  tabs: TabDef[];
}

const GROUPS: TabGroup[] = [
  {
    label: 'Understand',
    tabs: [
      { id: 'overview', label: 'Overview', icon: Compass, key: '1' },
      { id: 'evidence', label: 'Findings', icon: Table, key: '2' },
    ],
  },
  {
    label: 'Investigate',
    tabs: [
      { id: 'journey', label: 'Protocol', icon: Network, key: '3' },
      { id: 'certs', label: 'Certificates', icon: KeyRound, key: '4' },
      { id: 'cross_session', label: 'Cross-Session', icon: Layers, key: '5' },
    ],
  },
  {
    label: 'Trace',
    tabs: [
      { id: 'provenance', label: 'Provenance', icon: GitBranch, key: '6' },
    ],
  },
  {
    label: 'Deliver',
    tabs: [
      { id: 'report', label: 'Report', icon: FileText, key: '7' },
    ],
  },
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

interface WorkbenchViewProps {
  onOpenRunPicker?: () => void;
}

export const WorkbenchView: React.FC<WorkbenchViewProps> = () => {
  const {
    activeRunId,
    activeRun,
    dashboard,
    sessions,
    activeTab,
    setActiveTab,
    setActiveView,
    isLoading,
    error,
    selectRun,
    isUsingFixtures,
    setShowCommandPalette,
    setShowShortcuts,
  } = useInvestigation();
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const onTabKey = (e: React.KeyboardEvent, id: ForensicTab) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const i = ALL_TABS.findIndex((t) => t.id === id);
    const next = ALL_TABS[(i + (e.key === 'ArrowRight' ? 1 : ALL_TABS.length - 1)) % ALL_TABS.length];
    setActiveTab(next.id);
    tabRefs.current[next.id]?.focus();
  };

  const findingsCount = dashboard?.findings?.length || 0;
  const sessionsCount = sessions?.length || dashboard?.coverage?.sessions_total || 0;

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
          <button type="button" className="sms-btn" onClick={() => setActiveView('home')}>
            Back to Case Desk
          </button>
        </div>
      </div>
    );
  } else {
    const Panel = PANELS[activeTab];
    content = (
      <div id={`panel-${activeTab}`} role="tabpanel" aria-labelledby={`tab-${activeTab}`}>
        <Panel />
      </div>
    );
  }

  return (
    <div className="sms-workstation-layout">
      {/* 1. Desktop Vertical Investigation Rail (Visible on >= 1024px) */}
      <aside className="sms-investigation-rail" aria-label="Forensic Investigation Rail">
        {/* 4-Tier Forensic Navigation */}
        <nav className="sms-rail-nav" aria-label="Workstation Navigation">
          {GROUPS.map((group) => (
            <div key={group.label} className="sms-rail-group">
              <div className="sms-rail-group__title">{group.label}</div>
              <div className="sms-rail-group__list">
                {group.tabs.map((tab) => {
                  const Icon = tab.icon;
                  const selected = activeTab === tab.id;

                  let countBadge: number | null = null;
                  if (tab.id === 'evidence' && findingsCount > 0) countBadge = findingsCount;
                  if (tab.id === 'journey' && sessionsCount > 0) countBadge = sessionsCount;

                  return (
                    <button
                      key={tab.id}
                      ref={(el) => {
                        tabRefs.current[tab.id] = el;
                      }}
                      id={`rail-tab-${tab.id}`}
                      type="button"
                      role="tab"
                      aria-selected={selected}
                      className={`sms-rail-item ${selected ? 'is-active' : ''}`}
                      onClick={() => setActiveTab(tab.id)}
                      onKeyDown={(e) => onTabKey(e, tab.id)}
                    >
                      <Icon size={14} className="sms-rail-item__icon" aria-hidden="true" />
                      <span className="sms-rail-item__label">{tab.label}</span>
                      {countBadge !== null && (
                        <span className={`sms-rail-item__badge ${selected ? 'is-active' : ''}`}>
                          {countBadge}
                        </span>
                      )}
                      <kbd className="sms-rail-item__key" aria-hidden="true">
                        {tab.key}
                      </kbd>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Bottom Status & Key Hints */}
        <div className="sms-rail-footer">
          <div className="sms-rail-engine">
            <span
              className={`sms-status-dot ${isUsingFixtures ? 'sms-status-dot--fixture' : 'sms-status-dot--live'}`}
              aria-hidden="true"
            />
            <span className="sms-rail-engine__text">
              {isUsingFixtures ? 'Demo Fixture' : 'Engine Live · 0.8.0'}
            </span>
          </div>
          <div className="sms-rail-shortcuts">
            <button
              type="button"
              className="sms-rail-kbd-btn"
              onClick={() => setShowCommandPalette(true)}
              title="Forensic command palette (⌘K)"
              aria-label="Open command palette"
            >
              <kbd>⌘K</kbd>
            </button>
            <button
              type="button"
              className="sms-rail-kbd-btn"
              onClick={() => setShowShortcuts(true)}
              title="Keyboard shortcuts reference (?)"
              aria-label="Keyboard shortcuts reference"
            >
              <kbd>?</kbd>
            </button>
          </div>
        </div>
      </aside>

      {/* 2. Main Workstation Body */}
      <div className="sms-workstation-main">
        {/* Docked Forensic Toolstrip for Screen < 1024px */}
        <nav className="sms-tabs sms-tabs--mobile" aria-label="Forensic investigation tabs (mobile)">
          <div className="sms-tabs__container">
            {GROUPS.map((group) => (
              <div key={group.label} className="sms-tabs__group">
                <span className="sms-tabs__group-label">{group.label}</span>
                <div className="sms-tabs__list" role="tablist" aria-label={group.label}>
                  {group.tabs.map((tab) => {
                    const Icon = tab.icon;
                    const selected = activeTab === tab.id;

                    let countBadge: number | null = null;
                    if (tab.id === 'evidence' && findingsCount > 0) countBadge = findingsCount;
                    if (tab.id === 'journey' && sessionsCount > 0) countBadge = sessionsCount;

                    return (
                      <button
                        key={tab.id}
                        id={`tab-${tab.id}`}
                        type="button"
                        role="tab"
                        aria-selected={selected}
                        aria-controls={`panel-${tab.id}`}
                        className={`sms-tab ${selected ? 'is-active' : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                      >
                        <Icon size={13} className="sms-tab__icon" aria-hidden="true" />
                        <span className="sms-tab__label">{tab.label}</span>
                        {countBadge !== null && (
                          <span className={`sms-tab__badge ${selected ? 'sms-tab__badge--active' : ''}`}>
                            {countBadge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </nav>

        <main className="sms-workstation-content" style={{ flex: 1, minWidth: 0 }}>
          {content}
        </main>
      </div>
    </div>
  );
};
