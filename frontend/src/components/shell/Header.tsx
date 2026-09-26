import React, { useState } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { ScoreDecomposition } from '../common/ScoreDecomposition';
import {
  Network,
  ChevronDown,
  Upload,
  Search,
  HelpCircle,
  FolderOpen,
  SlidersHorizontal,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import '../../design-lab/direction-s/DirectionS.css';

interface HeaderProps {
  onOpenUpload?: () => void;
  onOpenRunPicker: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenUpload, onOpenRunPicker }) => {
  const {
    activeRun,
    dashboard,
    activeView,
    setActiveView,
    activeTab,
    setActiveTab,
    selectedEventFrame,
    setShowCommandPalette,
    setShowShortcuts,
  } = useInvestigation();

  const [showScoreModal, setShowScoreModal] = useState(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('modal') === 'score';
    }
    return false;
  });

  React.useEffect(() => {
    const handlePopState = () => {
      const modal = new URLSearchParams(window.location.search).get('modal');
      setShowScoreModal(modal === 'score');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleOpenScoreModal = () => {
    setShowScoreModal(true);
    const params = new URLSearchParams(window.location.search);
    params.set('modal', 'score');
    window.history.replaceState(null, '', window.location.pathname + '?' + params.toString());
  };

  const handleCloseScoreModal = () => {
    setShowScoreModal(false);
    const params = new URLSearchParams(window.location.search);
    if (params.get('modal') === 'score') {
      params.delete('modal');
      const search = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (search ? '?' + search : ''));
    }
  };

  const posture = dashboard?.posture;
  const isCritical = posture?.value === 'CRITICAL' || posture?.value === 'WEAK';

  return (
    <>
      <header className="ds-header">
        {/* Left: Brand & Case Identity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div
            onClick={() => setActiveView('home')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              cursor: 'pointer',
              userSelect: 'none',
            }}
          >
            <div
              style={{
                width: '28px',
                height: '28px',
                backgroundColor: 'var(--ds-carbon)',
                border: '1px solid var(--ds-carbon-border)',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Network size={16} color="#ffffff" />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
              <span
                style={{
                  fontSize: '14px',
                  fontWeight: 800,
                  letterSpacing: '-0.01em',
                  color: 'var(--ds-ink-primary)',
                }}
              >
                SECUREMAILSCOPE
              </span>
              <span
                style={{
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '10px',
                  fontWeight: 700,
                  color: 'var(--ds-ink-muted)',
                  letterSpacing: '0.04em',
                }}
              >
                FORENSIC CRYPTOGRAPHIC ANALYSIS
              </span>
            </div>
          </div>

          <div style={{ width: '1px', height: '18px', backgroundColor: 'var(--ds-border-light)' }} />

          {/* Breadcrumb Context Navigation when inside Workbench */}
          {activeView === 'workbench' && activeRun && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '11px',
                fontFamily: 'var(--ds-font-mono)',
                color: 'var(--ds-ink-muted)',
              }}
            >
              <button
                type="button"
                onClick={() => setActiveView('home')}
                style={{
                  color: 'var(--ds-ink-secondary)',
                  fontWeight: 600,
                  cursor: 'pointer',
                  padding: '2px 4px',
                  borderRadius: '3px',
                }}
                title="Return to Case Desk"
              >
                CASE DESK
              </button>
              <span style={{ color: 'var(--ds-border-medium)' }}>/</span>
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                style={{
                  color: 'var(--ds-ink-primary)',
                  fontWeight: 700,
                  cursor: 'pointer',
                  maxWidth: '220px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  padding: '2px 4px',
                  borderRadius: '3px',
                }}
                title="Jump to Investigation Overview"
              >
                {activeRun.source_filename}
              </button>
              <span style={{ color: 'var(--ds-border-medium)' }}>/</span>
              <span style={{ color: 'var(--ds-ink-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>
                {activeTab === 'overview' ? 'Overview' : activeTab === 'provenance' ? 'Provenance' : activeTab === 'journey' ? 'Protocol' : activeTab === 'evidence' ? 'Evidence' : activeTab === 'certs' ? 'Certificate' : activeTab === 'cross_session' ? 'Cross-Session' : 'Report'}
              </span>
              {selectedEventFrame !== null && (
                <>
                  <span style={{ color: 'var(--ds-border-medium)' }}>/</span>
                  <span style={{ color: 'var(--ds-crimson-ink)', fontWeight: 700 }}>
                    Frame #{selectedEventFrame}
                  </span>
                </>
              )}
            </div>
          )}

          {/* Active Case Selector Pill (when on home or for switching) */}
          {activeView === 'home' && (
            <button
              type="button"
              onClick={onOpenRunPicker}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '5px 12px',
                backgroundColor: 'var(--ds-bg-subtle)',
                border: '1px solid var(--ds-border-light)',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'var(--ds-font-mono)',
                color: 'var(--ds-ink-primary)',
                cursor: 'pointer',
                transition: 'border-color 0.15s ease',
              }}
              title="Switch Active Forensic Case"
            >
              <FolderOpen size={13} color="var(--ds-carbon)" />
              <span style={{ fontWeight: 600, maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {activeRun ? activeRun.source_filename : 'Select PCAP Case'}
              </span>
              {activeRun?.duration_ms && (
                <span style={{ color: 'var(--ds-ink-muted)', fontSize: '10px' }}>
                  {activeRun.duration_ms}ms
                </span>
              )}
              <ChevronDown size={11} color="var(--ds-ink-muted)" />
            </button>
          )}
        </div>

        {/* Center: Mode Switcher (Desk vs Workspace) */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: 'var(--ds-bg-subtle)',
            padding: '3px',
            borderRadius: '8px',
            border: '1px solid var(--ds-border-light)',
          }}
        >
          <button
            type="button"
            onClick={() => setActiveView('home')}
            style={{
              padding: '5px 14px',
              fontSize: '12px',
              fontWeight: activeView === 'home' ? 700 : 500,
              color: activeView === 'home' ? 'var(--ds-ink-primary)' : 'var(--ds-ink-muted)',
              backgroundColor: activeView === 'home' ? 'var(--ds-bg-canvas)' : 'transparent',
              borderRadius: '6px',
              boxShadow: activeView === 'home' ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
              transition: 'all 0.15s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer',
            }}
          >
            <SlidersHorizontal size={12} color={activeView === 'home' ? 'var(--ds-indigo)' : 'currentColor'} />
            <span>Case Desk</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveView('workbench')}
            style={{
              padding: '5px 14px',
              fontSize: '12px',
              fontWeight: activeView === 'workbench' ? 700 : 500,
              color: activeView === 'workbench' ? 'var(--ds-ink-primary)' : 'var(--ds-ink-muted)',
              backgroundColor: activeView === 'workbench' ? 'var(--ds-bg-canvas)' : 'transparent',
              borderRadius: '6px',
              boxShadow: activeView === 'workbench' ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
              transition: 'all 0.15s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer',
            }}
          >
            <Shield size={12} color={activeView === 'workbench' ? 'var(--ds-indigo)' : 'currentColor'} />
            <span>Investigation</span>
          </button>
        </div>

        {/* Right: Verdict Badge & Quick Utilities */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Posture Verdict Pill */}
          {posture && (
            <button
              type="button"
              onClick={handleOpenScoreModal}
              className={isCritical ? 'ds-badge-critical' : 'ds-badge-strong'}
              style={{
                cursor: 'pointer',
                padding: '4px 10px',
                fontSize: '11px',
              }}
              title="Click to view posture scoring calculus"
            >
              {isCritical ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
              <span>{posture.label}</span>
              <span style={{ opacity: 0.6 }}>//</span>
              <span>{posture.score_text}</span>
            </button>
          )}

          {/* Quick Search trigger (⌘K) */}
          <button
            type="button"
            onClick={() => setShowCommandPalette(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '5px 10px',
              color: 'var(--ds-ink-secondary)',
              backgroundColor: 'var(--ds-bg-subtle)',
              border: '1px solid var(--ds-border-light)',
              borderRadius: '6px',
              fontSize: '11px',
              fontFamily: 'var(--ds-font-mono)',
              cursor: 'pointer',
            }}
            title="Search findings, streams, and standards (⌘K)"
          >
            <Search size={12} color="var(--ds-ink-muted)" />
            <span style={{ color: 'var(--ds-ink-muted)', fontWeight: 600 }}>⌘K</span>
          </button>

          {/* Keyboard Shortcuts (?) */}
          <button
            type="button"
            onClick={() => setShowShortcuts(true)}
            style={{
              padding: '6px',
              color: 'var(--ds-ink-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '6px',
              cursor: 'pointer',
            }}
            aria-label="Keyboard shortcuts"
            title="Keyboard shortcuts (?)"
          >
            <HelpCircle size={16} />
          </button>

          {/* Ingest PCAP Action */}
          <button
            type="button"
            onClick={() => {
              setActiveView('home');
              if (onOpenUpload) onOpenUpload();
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: 'var(--ds-carbon)',
              color: '#ffffff',
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 700,
              fontFamily: 'var(--ds-font-mono)',
              border: 'none',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
          >
            <Upload size={12} strokeWidth={2.4} />
            <span>INGEST PCAP</span>
          </button>
        </div>
      </header>

      {/* Posture Score Breakdown Modal */}
      {showScoreModal && posture && (
        <ScoreDecomposition
          posture={posture}
          onClose={handleCloseScoreModal}
        />
      )}
    </>
  );
};
