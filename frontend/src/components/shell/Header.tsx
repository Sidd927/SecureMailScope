import React, { useState } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { PosturePill } from '../common/PosturePill';
import { ScoreDecomposition } from '../common/ScoreDecomposition';
import {
  Shield,
  ChevronDown,
  Upload,
  Search,
  HelpCircle,
  Compass,
  Network,
  Layers,
  FileCode,
  LayoutGrid,
} from 'lucide-react';

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

  return (
    <>
      <header
        style={{
          height: '48px',
          backgroundColor: 'var(--color-surface)',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 18px',
          zIndex: 100,
          position: 'sticky',
          top: 0,
        }}
      >
        {/* Left: Brand Identity & Active Case Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            onClick={() => setActiveView('home')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: 'pointer',
              userSelect: 'none',
            }}
          >
            <div
              style={{
                width: '26px',
                height: '26px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--color-accent)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield size={15} strokeWidth={2.4} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
              <span
                style={{
                  fontSize: '13px',
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-ink)',
                }}
              >
                SECUREMAILSCOPE
              </span>
              <span
                style={{
                  fontSize: '9px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--color-ink-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                FORENSIC
              </span>
            </div>
          </div>

          <div style={{ width: '1px', height: '18px', backgroundColor: 'var(--color-border)' }} />

          {/* Active Case Indicator */}
          {activeRun ? (
            <div
              onClick={onOpenRunPicker}
              role="button"
              tabIndex={0}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '3px 8px',
                backgroundColor: 'var(--color-panel)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
                transition: 'border-color var(--transition-fast)',
              }}
              title="Click to switch active investigation case file"
            >
              <span
                style={{
                  fontSize: 'var(--text-xs)',
                  fontWeight: 600,
                  color: 'var(--color-ink)',
                  maxWidth: '180px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {activeRun.source_filename}
              </span>
              {activeRun.duration_ms && (
                <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)' }}>
                  {activeRun.duration_ms}ms
                </span>
              )}
              <ChevronDown size={12} style={{ color: 'var(--color-ink-muted)' }} />
            </div>
          ) : (
            <button
              type="button"
              onClick={onOpenRunPicker}
              style={{ fontSize: 'var(--text-xs)', color: 'var(--color-accent)', fontWeight: 600 }}
            >
              Select Case File
            </button>
          )}
        </div>

        {/* Center: Primary Investigation Navigation Tabs */}
        {activeView === 'workbench' && (
          <nav
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '2px',
              backgroundColor: 'var(--color-panel)',
              padding: '3px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border)',
            }}
          >
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '3px 10px',
                fontSize: '12px',
                fontWeight: activeTab === 'overview' ? 700 : 500,
                color: activeTab === 'overview' ? 'var(--color-ink)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'overview' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'overview' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Compass size={13} />
              <span>1. Overview</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('timeline')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '3px 10px',
                fontSize: '12px',
                fontWeight: activeTab === 'timeline' ? 700 : 500,
                color: activeTab === 'timeline' ? 'var(--color-ink)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'timeline' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'timeline' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Network size={13} />
              <span>2. Protocol Journey</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('evidence')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '3px 10px',
                fontSize: '12px',
                fontWeight: activeTab === 'evidence' ? 700 : 500,
                color: activeTab === 'evidence' ? 'var(--color-ink)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'evidence' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'evidence' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Layers size={13} />
              <span>3. Evidence Ledger</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('certs')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '3px 10px',
                fontSize: '12px',
                fontWeight: activeTab === 'certs' ? 700 : 500,
                color: activeTab === 'certs' ? 'var(--color-ink)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'certs' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'certs' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <FileCode size={13} />
              <span>4. Certificates</span>
            </button>

            <div style={{ width: '1px', height: '14px', backgroundColor: 'var(--color-border)', margin: '0 4px' }} />

            <button
              type="button"
              onClick={() => setActiveView('home')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                padding: '3px 8px',
                fontSize: '11px',
                color: 'var(--color-ink-faint)',
                borderRadius: 'var(--radius-xs)',
              }}
              title="Return to Intake Launchpad"
            >
              <LayoutGrid size={12} />
              <span>Launchpad</span>
            </button>
          </nav>
        )}

        {/* Right: Posture Verdict, Search (⌘K), Shortcuts (?), Ingest */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Posture Verdict Pill */}
          {posture && (
            <PosturePill
              band={posture.value}
              score={posture.score_value}
              withheld={posture.withheld}
              size="sm"
              onClick={handleOpenScoreModal}
            />
          )}

          {/* Command Palette Trigger */}
          <button
            type="button"
            onClick={() => setShowCommandPalette(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 8px',
              backgroundColor: 'var(--color-panel)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-xs)',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: 'var(--color-ink-muted)',
              cursor: 'pointer',
            }}
            title="Global Forensic Command Menu (⌘K or /)"
          >
            <Search size={12} />
            <span>Search</span>
            <kbd
              style={{
                fontSize: '9px',
                backgroundColor: '#ffffff',
                border: '1px solid var(--color-border)',
                padding: '1px 3px',
                borderRadius: '2px',
                color: 'var(--color-ink)',
              }}
            >
              ⌘K
            </kbd>
          </button>

          {/* Shortcuts Modal Trigger */}
          <button
            type="button"
            onClick={() => setShowShortcuts(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '26px',
              height: '26px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--color-border)',
              backgroundColor: 'var(--color-panel)',
              color: 'var(--color-ink-muted)',
              cursor: 'pointer',
            }}
            title="Keyboard shortcuts (?)"
            aria-label="Keyboard shortcuts"
          >
            <HelpCircle size={13} />
          </button>

          {/* Ingest PCAP Button */}
          <button
            type="button"
            onClick={() => {
              if (onOpenUpload) onOpenUpload();
              setActiveView('home');
            }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              backgroundColor: 'var(--color-accent)',
              color: '#ffffff',
              fontSize: '12px',
              fontWeight: 600,
              borderRadius: 'var(--radius-xs)',
              boxShadow: 'var(--shadow-subtle)',
              cursor: 'pointer',
              transition: 'background-color var(--transition-fast)',
            }}
          >
            <Upload size={13} />
            <span>Ingest PCAP</span>
          </button>
        </div>
      </header>

      {/* Score Decomposition Calculus Modal */}
      {showScoreModal && posture && (
        <ScoreDecomposition posture={posture} onClose={handleCloseScoreModal} />
      )}
    </>
  );
};
