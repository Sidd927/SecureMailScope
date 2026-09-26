import React, { useState } from 'react';
import { InvestigationProvider, useInvestigation } from './context/InvestigationContext';
import { Header } from './components/shell/Header';
import { RunSelectorModal } from './components/shell/RunSelectorModal';
import { CommandPalette } from './components/shell/CommandPalette';
import { KeyboardShortcutsModal } from './components/shell/KeyboardShortcutsModal';
import { HomeView } from './components/home/HomeView';
import { WorkbenchView } from './components/workbench/WorkbenchView';
import { DesignLab } from './design-lab/DesignLab';
import { AlertTriangle, X } from 'lucide-react';

const MainLayout: React.FC = () => {
  const isDesignLab = typeof window !== 'undefined' && (
    window.location.pathname.startsWith('/design-lab') ||
    new URLSearchParams(window.location.search).get('view') === 'design-lab' ||
    new URLSearchParams(window.location.search).has('design-lab') ||
    new URLSearchParams(window.location.search).has('lab')
  );

  if (isDesignLab) {
    return <DesignLab />;
  }

  const { activeView, error } = useInvestigation();
  const [showRunPicker, setShowRunPicker] = useState(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('modal') === 'run-picker';
    }
    return false;
  });
  const [dismissError, setDismissError] = useState(false);

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
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', width: '100%' }}>
      {/* Keyboard Accessibility Skip Link */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {/* Persistent Application Shell Header */}
      <Header
        onOpenRunPicker={handleOpenRunPicker}
        onOpenUpload={() => {
          // Switching to home brings up intake dropzone
          // Note: handled by navigation
        }}
      />

      {/* Global Error Banner */}
      {error && !dismissError && (
        <div
          role="alert"
          style={{
            backgroundColor: 'var(--color-sev-critical-bg)',
            borderBottom: '1px solid var(--color-sev-critical-border)',
            padding: '8px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 'var(--text-xs)',
            color: 'var(--color-sev-critical)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={14} />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => setDismissError(true)}
            style={{ color: 'var(--color-sev-critical)', padding: '2px' }}
            aria-label="Dismiss error"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <div id="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {activeView === 'home' ? <HomeView /> : <WorkbenchView />}
      </div>

      {/* Run Selector Modal */}
      <RunSelectorModal isOpen={showRunPicker} onClose={handleCloseRunPicker} />

      {/* Forensic Command Palette (Cmd+K) */}
      <CommandPalette />

      {/* Keyboard Shortcuts Reference Modal (?) */}
      <KeyboardShortcutsModal />

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
