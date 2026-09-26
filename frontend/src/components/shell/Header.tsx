import React, { useEffect, useState } from 'react';
import { ChevronDown, Plus, ShieldHalf } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { PosturePill } from '../common/PosturePill';
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
  const { activeRun, dashboard, activeView, setActiveView, isUsingFixtures, setShowCommandPalette, setShowShortcuts } = useInvestigation();
  const [showScore, setShowScore] = useState(() => new URLSearchParams(window.location.search).get('modal') === 'score');

  useEffect(() => {
    const onPop = () => setShowScore(new URLSearchParams(window.location.search).get('modal') === 'score');
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const posture = dashboard?.posture;
  const inWorkbench = activeView === 'workbench';
  const openScore = () => { setShowScore(true); setModalParam('score'); };
  const closeScore = () => { setShowScore(false); setModalParam(null); };

  return (
    <>
      <header className="sms-header">
        <div className="sms-header__left">
          <button type="button" className="sms-brand" onClick={() => setActiveView('home')} aria-label="SecureMailScope home">
            <span className="sms-brand__mark" aria-hidden="true"><ShieldHalf size={14} /></span>
            SecureMailScope
          </button>
          {inWorkbench && activeRun && (
            <>
              <span className="sms-header__sep" aria-hidden="true">/</span>
              <button type="button" className="sms-header__run" onClick={onOpenRunPicker} title={`Switch analysis (current: ${activeRun.source_filename})`}>
                <span>{activeRun.source_filename}</span>
                <ChevronDown size={14} aria-hidden="true" />
              </button>
            </>
          )}
        </div>

        <div className="sms-header__center">
          {inWorkbench && posture && (
            <>
              <PosturePill band={posture.known ? posture.value : null} withheld={posture.withheld} onClick={openScore} />
              <span className="sms-mono" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>
                {posture.withheld ? '—' : posture.score_text || (posture.score_value != null ? `${posture.score_value} / 100` : '—')}
              </span>
            </>
          )}
        </div>

        <div className="sms-header__right">
          <span className={`sms-status ${isUsingFixtures ? 'sms-status--fixture' : 'sms-status--live'}`} role="status">
            <span className="sms-dot" aria-hidden="true" />
            {isUsingFixtures ? 'Demo data' : 'Engine live'}
          </span>
          <button type="button" className="sms-kbd" onClick={() => setShowCommandPalette(true)} aria-label="Open command palette" title="Command palette (⌘K)">⌘K</button>
          <button type="button" className="sms-kbd" onClick={() => setShowShortcuts(true)} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)">?</button>
          {inWorkbench && (
            <button type="button" className="sms-btn sms-btn--sm" onClick={() => setActiveView('home')}>
              <Plus size={13} aria-hidden="true" />
              New analysis
            </button>
          )}
        </div>
      </header>

      {showScore && posture && <ScoreDecomposition posture={posture} onClose={closeScore} />}
    </>
  );
};
