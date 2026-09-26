import React, { useState, useEffect } from 'react';
import type { FixtureKey } from './fixtures';
import { DirectionA_CaseDesk } from './direction-a/DirectionA_CaseDesk';
import { DirectionA_Overview } from './direction-a/DirectionA_Overview';
import { DirectionB_CaseDesk } from './direction-b/DirectionB_CaseDesk';
import { DirectionB_Overview } from './direction-b/DirectionB_Overview';
import { DirectionC_CaseDesk } from './direction-c/DirectionC_CaseDesk';
import { DirectionC_Overview } from './direction-c/DirectionC_Overview';
import { DirectionS_CaseDesk } from './direction-s/DirectionS_CaseDesk';
import { DirectionS_Overview } from './direction-s/DirectionS_Overview';

export type DirectionId = 'S' | 'A' | 'B' | 'C';
export type ScreenId = 'desk' | 'overview';

export const DesignLab: React.FC = () => {
  // Read initial state from URL query parameters if present
  const getInitialParam = <T extends string>(param: string, fallback: T): T => {
    if (typeof window !== 'undefined') {
      const val = new URLSearchParams(window.location.search).get(param);
      if (val) return val as T;
    }
    return fallback;
  };

  const [direction, setDirection] = useState<DirectionId>(() => getInitialParam('dir', 'S'));
  const [screen, setScreen] = useState<ScreenId>(() => getInitialParam('screen', 'desk'));
  const [fixtureKey, setFixtureKey] = useState<FixtureKey>(() =>
    getInitialParam('case', 'backup_weak_certificate')
  );

  // Sync state to URL without reloading
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    params.set('dir', direction);
    params.set('screen', screen);
    params.set('case', fixtureKey);
    const newUrl = `${window.location.pathname}?${params.toString()}`;
    window.history.replaceState(null, '', newUrl);
  }, [direction, screen, fixtureKey]);

  // Global Keyboard Navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't intercept if user is typing in an input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      if (e.key === '1') setDirection('A');
      if (e.key === '2') setDirection('B');
      if (e.key === '3') setDirection('C');
      if (e.key === '4' || e.key.toLowerCase() === 's') setDirection('S');
      if (e.key.toLowerCase() === 'd') setScreen('desk');
      if (e.key.toLowerCase() === 'o') setScreen('overview');
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleOpenCase = (key: FixtureKey) => {
    setFixtureKey(key);
    setScreen('overview');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      {/* Design Lab Floating Control Deck */}
      <div
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 9999,
          backgroundColor: '#05070a',
          color: '#f8fafc',
          borderBottom: '1px solid #1e293b',
          padding: '8px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '11px',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
        }}
      >
        {/* Lab Branding */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              padding: '2px 6px',
              borderRadius: '3px',
              backgroundColor: '#38bdf8',
              color: '#041019',
              fontWeight: 800,
              fontSize: '10px',
            }}
          >
            LAB
          </span>
          <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>SECUREMAILSCOPE DESIGN LAB</span>
        </div>

        {/* Direction Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ color: '#64748b', marginRight: '4px' }}>DIRECTION:</span>

          <button
            onClick={() => setDirection('S')}
            style={{
              padding: '4px 12px',
              borderRadius: '4px',
              backgroundColor: direction === 'S' ? '#4f46e5' : '#1e1b4b',
              color: direction === 'S' ? '#ffffff' : '#c7d2fe',
              border: `1px solid ${direction === 'S' ? '#818cf8' : '#4338ca'}`,
              fontWeight: 800,
              boxShadow: direction === 'S' ? '0 0 12px rgba(99, 102, 241, 0.5)' : 'none',
            }}
          >
            [S] SYNTHESIS (LIGHT WORKSTATION)
          </button>

          <button
            onClick={() => setDirection('A')}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: direction === 'A' ? '#1e293b' : 'transparent',
              color: direction === 'A' ? '#38bdf8' : '#94a3b8',
              border: `1px solid ${direction === 'A' ? '#38bdf8' : '#334155'}`,
              fontWeight: 700,
            }}
          >
            [1] A: COMMAND
          </button>

          <button
            onClick={() => setDirection('B')}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: direction === 'B' ? '#1e293b' : 'transparent',
              color: direction === 'B' ? '#fbbf24' : '#94a3b8',
              border: `1px solid ${direction === 'B' ? '#fbbf24' : '#334155'}`,
              fontWeight: 700,
            }}
          >
            [2] B: EDITORIAL
          </button>

          <button
            onClick={() => setDirection('C')}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: direction === 'C' ? '#1e293b' : 'transparent',
              color: direction === 'C' ? '#a78bfa' : '#94a3b8',
              border: `1px solid ${direction === 'C' ? '#a78bfa' : '#334155'}`,
              fontWeight: 700,
            }}
          >
            [3] C: THREAT INTEL
          </button>
        </div>

        {/* Screen Switcher (Desk vs Overview) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ color: '#64748b', marginRight: '4px' }}>SCREEN:</span>

          <button
            onClick={() => setScreen('desk')}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: screen === 'desk' ? '#1e293b' : 'transparent',
              color: screen === 'desk' ? '#10b981' : '#94a3b8',
              border: `1px solid ${screen === 'desk' ? '#10b981' : '#334155'}`,
              fontWeight: 700,
            }}
          >
            [D] CASE DESK
          </button>

          <button
            onClick={() => setScreen('overview')}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: screen === 'overview' ? '#1e293b' : 'transparent',
              color: screen === 'overview' ? '#10b981' : '#94a3b8',
              border: `1px solid ${screen === 'overview' ? '#10b981' : '#334155'}`,
              fontWeight: 700,
            }}
          >
            [O] INVESTIGATION OVERVIEW
          </button>
        </div>

        {/* Real Data Case Fixture Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ color: '#64748b' }}>FIXTURE:</span>
          <select
            value={fixtureKey}
            onChange={(e) => setFixtureKey(e.target.value as FixtureKey)}
            style={{
              backgroundColor: '#0f172a',
              color: '#f8fafc',
              border: '1px solid #334155',
              padding: '4px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              fontFamily: 'inherit',
              cursor: 'pointer',
            }}
          >
            <option value="backup_weak_certificate">backup_weak_certificate (CRITICAL 44.0)</option>
            <option value="scene_b_certificate_honesty">scene_b_certificate_honesty (STRONG 100.0)</option>
            <option value="deepdive_cross_session_control_endpoint">deepdive_cross_session (CRITICAL 22.15)</option>
          </select>
        </div>
      </div>

      {/* Render Selected Product Direction & Screen */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {direction === 'S' && screen === 'desk' && (
          <DirectionS_CaseDesk onOpenCase={handleOpenCase} />
        )}
        {direction === 'S' && screen === 'overview' && (
          <DirectionS_Overview fixtureKey={fixtureKey} onBackToDesk={() => setScreen('desk')} />
        )}

        {direction === 'A' && screen === 'desk' && (
          <DirectionA_CaseDesk onOpenCase={handleOpenCase} />
        )}
        {direction === 'A' && screen === 'overview' && (
          <DirectionA_Overview fixtureKey={fixtureKey} onBackToDesk={() => setScreen('desk')} />
        )}

        {direction === 'B' && screen === 'desk' && (
          <DirectionB_CaseDesk onOpenCase={handleOpenCase} />
        )}
        {direction === 'B' && screen === 'overview' && (
          <DirectionB_Overview fixtureKey={fixtureKey} onBackToDesk={() => setScreen('desk')} />
        )}

        {direction === 'C' && screen === 'desk' && (
          <DirectionC_CaseDesk onOpenCase={handleOpenCase} />
        )}
        {direction === 'C' && screen === 'overview' && (
          <DirectionC_Overview fixtureKey={fixtureKey} onBackToDesk={() => setScreen('desk')} />
        )}
      </div>
    </div>
  );
};

export default DesignLab;
