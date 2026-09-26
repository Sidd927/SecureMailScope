import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Award, FileText, GitBranch, Hash, HelpCircle, LayoutDashboard, Network, Rows3, Search, Upload, Waypoints } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import type { ForensicTab } from '../../context/InvestigationContext';
import { SeverityDot } from '../common/SeverityBadge';
import { sessionLabel } from '../../utils/session';

type Category = 'Views' | 'Findings' | 'Sessions' | 'Analyses' | 'Actions';

interface CommandItem {
  id: string;
  category: Category;
  title: string;
  subtitle?: string;
  hint?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

// Shortcut hints mirror the keyboard map in InvestigationContext.
const VIEWS: Array<{ tab: ForensicTab; title: string; subtitle: string; key: string; icon: React.ReactNode }> = [
  { tab: 'overview', title: 'Summary', subtitle: 'Posture, score and findings', key: '1', icon: <LayoutDashboard size={16} /> },
  { tab: 'evidence', title: 'Evidence & Findings', subtitle: 'Each finding with the evidence it cites', key: '2', icon: <Rows3 size={16} /> },
  { tab: 'journey', title: 'Protocol Journey', subtitle: 'Events, evidence and transitions per session', key: '3', icon: <Network size={16} /> },
  { tab: 'certs', title: 'Certificates', subtitle: 'Certificate evidence per TLS session', key: '4', icon: <Award size={16} /> },
  { tab: 'cross_session', title: 'Cross-Session', subtitle: 'Sessions compared, with engine deviations', key: '5', icon: <GitBranch size={16} /> },
  { tab: 'provenance', title: 'Provenance', subtitle: 'Trace a finding back to capture bytes', key: '6', icon: <Waypoints size={16} /> },
  { tab: 'report', title: 'Report', subtitle: 'Preview and download HTML, PDF, JSON', key: '7', icon: <FileText size={16} /> },
];

export const CommandPalette: React.FC = () => {
  const { showCommandPalette, setShowCommandPalette, dashboard, sessions, runs, selectRun, selectSession, selectFinding, setActiveView, setActiveTab, setShowShortcuts } = useInvestigation();
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  useEffect(() => {
    if (!showCommandPalette) return;
    setQuery('');
    setActive(0);
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [showCommandPalette]);

  const commands = useMemo<CommandItem[]>(() => {
    const go = (tab: ForensicTab) => { setActiveView('workbench'); setActiveTab(tab); };
    const list: CommandItem[] = VIEWS.map((v) => ({ id: `view-${v.tab}`, category: 'Views', title: v.title, subtitle: v.subtitle, hint: v.key, icon: v.icon, onSelect: () => go(v.tab) }));
    list.push({ id: 'view-home', category: 'Views', title: 'Home', subtitle: 'Upload a capture or open a recent analysis', icon: <Upload size={16} />, onSelect: () => setActiveView('home') });

    (dashboard?.findings ?? []).forEach((f, i) => list.push({
      id: `finding-${i}`,
      category: 'Findings',
      title: f.title,
      subtitle: [f.severity, f.source_rule_ids?.join(', ')].filter(Boolean).join(' · '),
      icon: <SeverityDot severity={f.severity} size={8} />,
      onSelect: () => { selectFinding(f); go('evidence'); },
    }));

    sessions.forEach((s) => list.push({
      id: `session-${s.stream_key}`,
      category: 'Sessions',
      title: sessionLabel(s),
      // Only implicit TLS is known from the session record itself; STARTTLS state lives in evidence fields.
      subtitle: [`${s.timing.packet_count} packets`, `frames ${s.timing.first_frame}–${s.timing.last_frame}`, s.implicit_tls ? 'implicit TLS' : null].filter(Boolean).join(' · '),
      icon: <Network size={16} />,
      onSelect: () => { selectSession(s.stream_key); go('journey'); },
    }));

    runs.filter((r) => r.state === 'COMPLETED').forEach((r) => list.push({
      id: `run-${r.run_id}`,
      category: 'Analyses',
      title: r.source_filename,
      subtitle: [r.overall_posture, r.score_value != null ? r.score_value.toFixed(2) : null, `SHA-256 ${r.capture_id.slice(0, 12)}…`].filter(Boolean).join(' · '),
      icon: <Hash size={16} />,
      onSelect: () => { go('overview'); selectRun(r.run_id); },
    }));

    list.push({ id: 'action-shortcuts', category: 'Actions', title: 'Keyboard shortcuts', hint: '?', icon: <HelpCircle size={16} />, onSelect: () => setShowShortcuts(true) });
    return list;
  }, [dashboard, sessions, runs, setActiveView, setActiveTab, selectFinding, selectSession, selectRun, setShowShortcuts]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => [c.title, c.subtitle, c.category].some((t) => t?.toLowerCase().includes(q)));
  }, [commands, query]);

  useEffect(() => { setActive(0); }, [filtered.length]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const run = (cmd: CommandItem | undefined) => {
    if (!cmd) return;
    setShowCommandPalette(false);
    cmd.onSelect();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => (i + 1) % Math.max(filtered.length, 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => (i - 1 + filtered.length) % Math.max(filtered.length, 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); run(filtered[active]); }
    else if (e.key === 'Escape') { e.preventDefault(); setShowCommandPalette(false); }
  };

  if (!showCommandPalette) return null;

  return (
    <div className="sms-overlay" onClick={() => setShowCommandPalette(false)}>
      <div className="sms-modal" role="dialog" aria-modal="true" aria-label="Command palette" onClick={(e) => e.stopPropagation()} onKeyDown={onKeyDown}>
        <div className="sms-palette__search">
          <Search size={16} aria-hidden="true" />
          <input
            ref={inputRef}
            className="sms-palette__input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to a view, finding, session or analysis"
            role="combobox"
            aria-expanded="true"
            aria-controls="sms-palette-list"
            aria-activedescendant={filtered[active] ? `sms-cmd-${filtered[active].id}` : undefined}
          />
          <span className="sms-kbd">Esc</span>
        </div>
        <ul ref={listRef} id="sms-palette-list" className="sms-palette__list" role="listbox" aria-label="Commands">
          {filtered.length === 0 && <li className="sms-palette__group" role="presentation">No matches for "{query}"</li>}
          {filtered.map((cmd, i) => (
            <React.Fragment key={cmd.id}>
              {(i === 0 || filtered[i - 1].category !== cmd.category) && <li className="sms-palette__group" role="presentation">{cmd.category}</li>}
              <li
                id={`sms-cmd-${cmd.id}`}
                data-index={i}
                role="option"
                aria-selected={i === active}
                className="sms-palette__item"
                onMouseMove={() => setActive(i)}
                onClick={() => run(cmd)}
              >
                <span style={{ display: 'grid', placeItems: 'center' }} aria-hidden="true">{cmd.icon}</span>
                <span style={{ minWidth: 0 }}>
                  <span className="sms-palette__title" style={{ display: 'block' }}>{cmd.title}</span>
                  {cmd.subtitle && <span className="sms-palette__sub" style={{ display: 'block' }}>{cmd.subtitle}</span>}
                </span>
                {cmd.hint && <span className="sms-kbd">{cmd.hint}</span>}
              </li>
            </React.Fragment>
          ))}
        </ul>
        <div className="sms-palette__foot" aria-hidden="true">
          <span>↑↓ move</span><span>Enter open</span><span>Esc close</span>
        </div>
      </div>
    </div>
  );
};
