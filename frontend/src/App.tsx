import React, { useState } from 'react';
import { InvestigationProvider, useInvestigation } from './context/InvestigationContext';
import { Header } from './components/shell/Header';
import { RunSelectorModal } from './components/shell/RunSelectorModal';
import { CommandPalette } from './components/shell/CommandPalette';
import { KeyboardShortcutsModal } from './components/shell/KeyboardShortcutsModal';
import { HomeView } from './components/home/HomeView';
import { LandingHero } from './components/home/LandingHero';
import { WorkbenchView } from './components/workbench/WorkbenchView';

const MainLayout: React.FC = () => {
  // Errors are shown where they happen: the workbench's ErrorState and the upload zone.
  const { activeView } = useInvestigation();
  const [pass, setPass] = useState<'idle' | 'cover' | 'reveal'>('idle');
  const [showRunPicker, setShowRunPicker] = useState(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('modal') === 'run-picker';
    }
    return false;
  });

  React.useEffect(() => {
    const onPass = (event: Event) => {
      const phase = (event as CustomEvent<'cover' | 'reveal' | 'idle'>).detail;
      setPass(phase === 'cover' || phase === 'reveal' ? phase : 'idle');
    };
    window.addEventListener('sms-pass', onPass);
    return () => window.removeEventListener('sms-pass', onPass);
  }, []);

  React.useEffect(() => {
    const handlePopState = () => {
      const modal = new URLSearchParams(window.location.search).get('modal');
      setShowRunPicker(modal === 'run-picker');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleOpenRunPicker = () => {
    setShowRunPicker(true);
    const params = new URLSearchParams(window.location.search);
    params.set('modal', 'run-picker');
    window.history.replaceState(null, '', window.location.pathname + '?' + params.toString());
  };

  const handleCloseRunPicker = () => {
    setShowRunPicker(false);
    const params = new URLSearchParams(window.location.search);
    if (params.get('modal') === 'run-picker') {
      params.delete('modal');
      const search = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (search ? '?' + search : ''));
    }
  };

  return (
    <div className={activeView === 'landing' ? 'sms-app sms-app--landing' : 'sms-app'} style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', width: '100%' }}>
      {/* Keyboard Accessibility Skip Link */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {activeView !== 'landing' && <Header onOpenRunPicker={handleOpenRunPicker} />}

      {/* Main Content Area */}
      <div id="main-content" className={pass === 'reveal' ? 'is-revealing' : undefined} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {activeView === 'landing' ? (
          <LandingHero />
        ) : activeView === 'home' ? (
          <HomeView />
        ) : (
          <WorkbenchView onOpenRunPicker={handleOpenRunPicker} />
        )}
      </div>

      {/* Run Selector Modal */}
      <RunSelectorModal isOpen={showRunPicker} onClose={handleCloseRunPicker} />

      {/* Forensic Command Palette (Cmd+K) */}
      <CommandPalette />

      {/* Keyboard Shortcuts Reference Modal (?) */}
      <KeyboardShortcutsModal />

      <div className={pass === 'idle' ? 'sms-veil' : pass === 'cover' ? 'sms-veil is-on' : 'sms-veil is-on is-out'} aria-hidden="true" />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <InvestigationProvider>
      <MainLayout />
    </InvestigationProvider>
  );
};

export default App;
