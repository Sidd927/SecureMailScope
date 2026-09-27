import React, { useEffect, useState } from 'react';
import { ChevronDown, Plus, FileSpreadsheet } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { PosturePill } from '../common/PosturePill';
import { BrandLogo } from '../common/BrandLogo';
import { ScoreDecomposition } from './ScoreDecomposition';

interface HeaderProps {
  onOpenRunPicker: () => void;
}

function setModalParam(value: string | null) {
  const params = new URLSearchParams(window.location.search);
  if (value) params.set('modal', value);
  else params.delete('modal');
  const search = params.toString();
  window.history.replaceState(null, '', window.location.pathname + (search ? `?${search}` : ''));
}

export const Header: React.FC<HeaderProps> = ({ onOpenRunPicker }) => {
  const {
    activeRun,
    dashboard,
    sessions,
    activeView,
    setActiveView,
    isUsingFixtures,
    setShowCommandPalette,
    setShowShortcuts,
  } = useInvestigation();

  const [showScore, setShowScore] = useState(
    () => new URLSearchParams(window.location.search).get('modal') === 'score'
  );

  useEffect(() => {
    const onPop = () => setShowScore(new URLSearchParams(window.location.search).get('modal') === 'score');
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const posture = dashboard?.posture;
  const inWorkbench = activeView === 'workbench';
  const openScore = () => {
    setShowScore(true);
    setModalParam('score');
  };
  const closeScore = () => {
    setShowScore(false);
    setModalParam(null);
  };

  const totalSessions = sessions?.length || dashboard?.coverage?.sessions_total || 0;
  const totalFindings = dashboard?.findings?.length || 0;

  return (
    <>
      <header className="sms-header" role="banner" aria-label="Forensic Investigation Shell">
        <div className="sms-header__top-row">
          {/* Left: Brand Identity & Active Case Selector */}
          <div className="sms-header__left">
            <button
              type="button"
              className="sms-brand-btn"
              onClick={() => setActiveView('home')}
              aria-label="Return to Case Desk"
              title="SecureMailScope Case Desk"
            >
              <BrandLogo variant="compact" size="md" />
            </button>

            {inWorkbench && activeRun && (
              <div className="sms-header__case-crumb sms-hide-tablet">
                <span className="sms-header__sep" aria-hidden="true">/</span>
                <button
                  type="button"
                  className="sms-header__case-pill"
                  onClick={onOpenRunPicker}
                  title={`Active capture: ${activeRun.source_filename} (${totalSessions} sessions, ${totalFindings} findings). Click to switch.`}
                  aria-haspopup="dialog"
                >
                  <FileSpreadsheet size={13} className="sms-header__case-icon" aria-hidden="true" />
                  <span className="sms-header__case-name">{activeRun.source_filename}</span>
                  <ChevronDown size={13} className="sms-header__chevron" aria-hidden="true" />
                </button>
              </div>
            )}
          </div>

          {/* Center: Persistent Posture & Determination Summary */}
          <div className="sms-header__center">
            {inWorkbench && posture ? (
              <div className="sms-header__posture-cluster">
                <PosturePill
                  band={posture.known ? posture.value : null}
                  withheld={posture.withheld}
                  onClick={openScore}
                />
                <button
                  type="button"
                  className="sms-header__score-link"
                  onClick={openScore}
                  title="View score deduction breakdown"
                  aria-label="View score deduction breakdown"
                >
                  <span className="sms-mono sms-header__score-val">
                    {posture.withheld
                      ? '—'
                      : posture.score_text || (posture.score_value != null ? `${posture.score_value.toFixed(1)} / 100` : '—')}
                  </span>
                </button>
              </div>
            ) : (
              <div className="sms-header__mode-tag">
                <span className="sms-mono" style={{ fontSize: 'var(--ds-text-11)', letterSpacing: '0.08em', color: 'var(--sms-text-muted)' }}>
                  PASSIVE CRYPTOGRAPHIC FORENSICS
                </span>
              </div>
            )}
          </div>

          {/* Right: Engine Status & Global Controls */}
          <div className="sms-header__right">
            {/* Real Backend Engine Liveness */}
            <div
              className={`sms-status-pill ${isUsingFixtures ? 'sms-status-pill--fixture' : 'sms-status-pill--live'}`}
              role="status"
              title={isUsingFixtures ? 'Running against demo fixture data' : 'Connected to live forensic backend (127.0.0.1:8001) · TShark Available · Passive / Offline'}
            >
              <span className="sms-status-dot" aria-hidden="true" />
              <span className="sms-status-label">{isUsingFixtures ? 'Demo Fixture' : 'ENGINE LIVE'}</span>
            </div>

            {/* Global Keyboard Shortcut Triggers */}
            <button
              type="button"
              className="sms-kbd-trigger"
              onClick={() => setShowCommandPalette(true)}
              aria-label="Open command palette"
              title="Forensic command palette (⌘K / Ctrl+K)"
            >
              <kbd>⌘K</kbd>
            </button>

            <button
              type="button"
              className="sms-kbd-trigger"
              onClick={() => setShowShortcuts(true)}
              aria-label="Keyboard shortcuts reference"
              title="Keyboard shortcuts reference (?)"
            >
              <kbd>?</kbd>
            </button>

            {/* New Investigation Action */}
            {inWorkbench && (
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-btn--sm sms-header__new-btn"
                onClick={() => setActiveView('home')}
                title="Return to intake bay to analyze a new capture"
              >
                <Plus size={13} aria-hidden="true" />
                <span>Intake</span>
              </button>
            )}
          </div>
        </div>

        {/* Mobile/Tablet Case Selector Row (shown only on <= 820px when in workbench) */}
        {inWorkbench && activeRun && (
          <div className="sms-header__case-row sms-show-tablet">
            <button
              type="button"
              className="sms-header__case-pill sms-header__case-pill--full"
              onClick={onOpenRunPicker}
              title={`Active capture: ${activeRun.source_filename}. Click to switch case.`}
              aria-haspopup="dialog"
            >
              <FileSpreadsheet size={13} className="sms-header__case-icon" aria-hidden="true" />
              <span className="sms-header__case-name">{activeRun.source_filename}</span>
              <span className="sms-mono sms-header__case-meta">{totalSessions} sessions · {totalFindings} findings</span>
              <ChevronDown size={13} className="sms-header__chevron" aria-hidden="true" />
            </button>
          </div>
        )}
      </header>

      {/* Score Deduction Breakdown Modal */}
      {showScore && posture && <ScoreDecomposition posture={posture} onClose={closeScore} />}
    </>
  );
};
