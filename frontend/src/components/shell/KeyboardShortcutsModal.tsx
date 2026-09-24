import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { X, Keyboard } from 'lucide-react';

interface ShortcutGroup {
  category: string;
  items: Array<{ key: string; description: string }>;
}

export const KeyboardShortcutsModal: React.FC = () => {
  const { showShortcuts, setShowShortcuts } = useInvestigation();

  if (!showShortcuts) return null;

  const groups: ShortcutGroup[] = [
    {
      category: 'Primary Views & Workstation Tabs',
      items: [
        { key: '1', description: 'Investigation Overview & Verdict Summary' },
        { key: '2', description: 'Protocol Journey & Packet Dissection' },
        { key: '3', description: '13 Canonical Evidence Dimensions' },
        { key: '4', description: 'X.509 PKI & Certificate Chain' },
      ],
    },
    {
      category: 'Investigation & Command',
      items: [
        { key: '⌘ K / Ctrl K', description: 'Open Global Forensic Command Palette' },
        { key: 'Esc', description: 'Dismiss Contextual Drawer or Close Modal' },
        { key: '?', description: 'Toggle Keyboard Shortcuts Reference' },
      ],
    },
    {
      category: 'Command Palette Navigation',
      items: [
        { key: '↑ / ↓', description: 'Navigate Command Options & Findings' },
        { key: 'Enter', description: 'Execute Selected Command or Jump to Entity' },
      ],
    },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(21, 25, 30, 0.5)',
        backdropFilter: 'blur(4px)',
        WebkitBackdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 2100,
        padding: '20px',
      }}
      onClick={() => setShowShortcuts(false)}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '560px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border-strong)',
          boxShadow: 'var(--shadow-flyout)',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Keyboard size={18} style={{ color: 'var(--color-accent)' }} />
            <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Keyboard Navigation & Shortcuts
            </h3>
          </div>
          <button
            type="button"
            onClick={() => setShowShortcuts(false)}
            style={{ padding: '4px', color: 'var(--color-ink-muted)' }}
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {groups.map((grp) => (
            <div key={grp.category} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  color: 'var(--color-ink-muted)',
                  fontWeight: 600,
                }}
              >
                {grp.category}
              </div>
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  backgroundColor: 'var(--color-panel)',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {grp.items.map((item) => (
                  <div
                    key={item.key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: 'var(--text-xs)',
                    }}
                  >
                    <span style={{ color: 'var(--color-ink-secondary)' }}>{item.description}</span>
                    <kbd
                      style={{
                        padding: '2px 8px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        fontWeight: 700,
                        backgroundColor: '#ffffff',
                        border: '1px solid var(--color-border-strong)',
                        borderRadius: 'var(--radius-xs)',
                        boxShadow: '0 1px 0 rgba(0,0,0,0.06)',
                        color: 'var(--color-ink)',
                      }}
                    >
                      {item.key}
                    </kbd>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '10px 20px',
            borderTop: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
            fontSize: '11px',
            color: 'var(--color-ink-faint)',
            fontFamily: 'var(--font-mono)',
            textAlign: 'right',
          }}
        >
          Press <kbd style={{ padding: '1px 4px', border: '1px solid var(--color-border)' }}>Esc</kbd> to return to investigation
        </div>
      </div>
    </div>
  );
};
