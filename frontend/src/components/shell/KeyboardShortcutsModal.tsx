import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { Modal } from '../common/Modal';

// Mirrors the keyboard handler in InvestigationContext and the arrow-key tab list in WorkbenchView.
const GROUPS: Array<{ title: string; items: Array<[string, string]> }> = [
  {
    title: 'Views',
    items: [
      ['1', 'Summary'],
      ['2', 'Evidence & Findings'],
      ['3', 'Protocol Journey'],
      ['4', 'Certificates'],
      ['5', 'Cross-Session'],
      ['6', 'Provenance'],
      ['7', 'Report'],
      ['← →', 'Previous or next tab when the tab bar has focus'],
    ],
  },
  {
    title: 'Anywhere',
    items: [
      ['⌘K / Ctrl K', 'Command palette'],
      ['?', 'This list'],
      ['Esc', 'Close the open dialog'],
    ],
  },
  {
    title: 'Command palette',
    items: [
      ['↑ ↓', 'Move through results'],
      ['Enter', 'Open the selected result'],
    ],
  },
];

export const KeyboardShortcutsModal: React.FC = () => {
  const { showShortcuts, setShowShortcuts } = useInvestigation();
  if (!showShortcuts) return null;

  return (
    <Modal title="Keyboard shortcuts" onClose={() => setShowShortcuts(false)} width={520}>
      <div className="sms-stack">
        {GROUPS.map((g) => (
          <section key={g.title} className="sms-stack sms-stack--tight">
            <h3 className="sms-label">{g.title}</h3>
            <dl className="sms-kv" style={{ gridTemplateColumns: "112px minmax(0, 1fr)" }}>
              {g.items.map(([key, label]) => (
                <React.Fragment key={key}>
                  <dt><kbd className="sms-kbd">{key}</kbd></dt>
                  <dd className="sms-kv__key" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>{label}</dd>
                </React.Fragment>
              ))}
            </dl>
          </section>
        ))}
      </div>
    </Modal>
  );
};
