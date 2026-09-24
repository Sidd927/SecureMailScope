import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import {
  Search,
  Compass,
  FileCode,
  ShieldAlert,
  Network,
  Upload,
  Layers,
  HelpCircle,
  Hash,
} from 'lucide-react';

interface CommandItem {
  id: string;
  category: 'Views' | 'Findings' | 'Streams' | 'Investigations' | 'Actions';
  title: string;
  subtitle?: string;
  badge?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

export const CommandPalette: React.FC = () => {
  const {
    showCommandPalette,
    setShowCommandPalette,
    dashboard,
    sessions,
    runs,
    selectRun,
    selectSession,
    selectFinding,
    setActiveView,
    setActiveTab,
    setShowShortcuts,
  } = useInvestigation();

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (showCommandPalette) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [showCommandPalette]);

  const commands = useMemo<CommandItem[]>(() => {
    const list: CommandItem[] = [];

    // 1. Navigation Views
    list.push(
      {
        id: 'nav-overview',
        category: 'Views',
        title: 'Investigation Overview',
        subtitle: 'Executive verdict, evidence coverage bar & provenance graph',
        badge: '1',
        icon: <Compass size={16} />,
        onSelect: () => {
          setActiveView('workbench');
          setActiveTab('overview');
        },
      },
      {
        id: 'nav-timeline',
        category: 'Views',
        title: 'Protocol Journey & Timeline',
        subtitle: 'Directional packet flows, state machine & frame inspection',
        badge: '2',
        icon: <Network size={16} />,
        onSelect: () => {
          setActiveView('workbench');
          setActiveTab('timeline');
        },
      },
      {
        id: 'nav-evidence',
        category: 'Views',
        title: 'Epistemic Evidence Ledger',
        subtitle: '13 canonical transport dimensions with state verifications',
        badge: '3',
        icon: <Layers size={16} />,
        onSelect: () => {
          setActiveView('workbench');
          setActiveTab('evidence');
        },
      },
      {
        id: 'nav-certs',
        category: 'Views',
        title: 'X.509 Certificates Forensics',
        subtitle: 'PKI leaf & chain inspection, key lengths, and validity',
        badge: '4',
        icon: <FileCode size={16} />,
        onSelect: () => {
          setActiveView('workbench');
          setActiveTab('certs');
        },
      },
      {
        id: 'nav-launchpad',
        category: 'Views',
        title: 'Case Intake Launchpad',
        subtitle: 'Ingest new capture or review triage matrix',
        badge: 'Home',
        icon: <Upload size={16} />,
        onSelect: () => {
          setActiveView('home');
        },
      }
    );

    // 2. Active Findings
    if (dashboard?.findings && dashboard.findings.length > 0) {
      dashboard.findings.forEach((f, idx) => {
        list.push({
          id: `finding-${idx}`,
          category: 'Findings',
          title: f.title,
          subtitle: f.conclusion || f.explanation,
          badge: f.severity || undefined,
          icon: <ShieldAlert size={16} style={{ color: 'var(--color-sev-critical)' }} />,
          onSelect: () => {
            setActiveView('workbench');
            selectFinding(f);
          },
        });
      });
    }

    // 3. Dissected Streams
    if (sessions && sessions.length > 0) {
      sessions.forEach((s) => {
        list.push({
          id: `stream-${s.stream_key}`,
          category: 'Streams',
          title: `Stream #${s.tcp_stream_id}: ${s.protocol} (${s.client.ip}:${s.client.port} → ${s.server.ip}:${s.server.port})`,
          subtitle: `${s.timing.packet_count} packets · Frames ${s.timing.first_frame}-${s.timing.last_frame}`,
          badge: s.implicit_tls ? 'DIRECT TLS' : 'STARTTLS',
          icon: <Network size={16} style={{ color: 'var(--color-accent)' }} />,
          onSelect: () => {
            setActiveView('workbench');
            selectSession(s.stream_key);
          },
        });
      });
    }

    // 4. Switch Investigation Cases
    if (runs && runs.length > 0) {
      runs
        .filter((r) => r.state === 'COMPLETED')
        .forEach((r) => {
          list.push({
            id: `run-${r.run_id}`,
            category: 'Investigations',
            title: r.source_filename,
            subtitle: `SHA-256: ${r.capture_id.slice(0, 16)}... · ${r.duration_ms ? `${r.duration_ms}ms` : ''}`,
            badge: r.overall_posture || undefined,
            icon: <Hash size={16} />,
            onSelect: async () => {
              await selectRun(r.run_id);
              setActiveView('workbench');
            },
          });
        });
    }

    // 5. Actions & Help
    list.push(
      {
        id: 'action-shortcuts',
        category: 'Actions',
        title: 'Keyboard Shortcuts Reference',
        subtitle: 'View all keyboard navigation and inspection bindings',
        badge: '?',
        icon: <HelpCircle size={16} />,
        onSelect: () => {
          setShowShortcuts(true);
        },
      },
      {
        id: 'action-upload',
        category: 'Actions',
        title: 'Ingest New PCAP Capture File',
        subtitle: 'Drag and drop or select packet capture from local drive',
        badge: 'Upload',
        icon: <Upload size={16} />,
        onSelect: () => {
          setActiveView('home');
        },
      }
    );

    return list;
  }, [
    dashboard,
    sessions,
    runs,
    setActiveView,
    setActiveTab,
    selectFinding,
    selectSession,
    selectRun,
    setShowShortcuts,
  ]);

  const filteredCommands = useMemo(() => {
    if (!query.trim()) return commands;
    const q = query.toLowerCase();
    return commands.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        (c.subtitle && c.subtitle.toLowerCase().includes(q)) ||
        c.category.toLowerCase().includes(q)
    );
  }, [commands, query]);

  // Keep selected index within bounds
  useEffect(() => {
    setSelectedIndex(0);
  }, [filteredCommands.length]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev < filteredCommands.length - 1 ? prev + 1 : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev > 0 ? prev - 1 : filteredCommands.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].onSelect();
        setShowCommandPalette(false);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setShowCommandPalette(false);
    }
  };

  if (!showCommandPalette) return null;

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
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '10vh',
        zIndex: 2000,
        paddingLeft: '20px',
        paddingRight: '20px',
      }}
      onClick={() => setShowCommandPalette(false)}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '680px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border-strong)',
          boxShadow: 'var(--shadow-flyout)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          maxHeight: '75vh',
        }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '14px 18px',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
          }}
        >
          <Search size={16} style={{ color: 'var(--color-ink-muted)' }} />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search case, sessions, findings, or jump to views... (↑↓ to move, Enter to run)"
            style={{
              flex: 1,
              border: 'none',
              outline: 'none',
              backgroundColor: 'transparent',
              fontSize: 'var(--text-base)',
              fontFamily: 'inherit',
              color: 'var(--color-ink)',
            }}
          />
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--color-border)',
              color: 'var(--color-ink-muted)',
            }}
          >
            ESC
          </span>
        </div>

        {/* Command List */}
        <div
          ref={listRef}
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '8px 0',
          }}
        >
          {filteredCommands.length === 0 ? (
            <div
              style={{
                padding: '32px 20px',
                textAlign: 'center',
                color: 'var(--color-ink-muted)',
                fontSize: 'var(--text-sm)',
              }}
            >
              No matching commands, findings, or sessions found.
            </div>
          ) : (
            filteredCommands.map((cmd, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={cmd.id}
                  onClick={() => {
                    cmd.onSelect();
                    setShowCommandPalette(false);
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    padding: '10px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                    backgroundColor: isSelected ? 'var(--color-accent-soft)' : 'transparent',
                    borderLeft: `3px solid ${isSelected ? 'var(--color-accent)' : 'transparent'}`,
                    transition: 'background-color var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        color: isSelected ? 'var(--color-accent)' : 'var(--color-ink-muted)',
                        display: 'flex',
                        alignItems: 'center',
                      }}
                    >
                      {cmd.icon}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: 'var(--text-sm)',
                          fontWeight: isSelected ? 600 : 500,
                          color: 'var(--color-ink)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {cmd.title}
                      </div>
                      {cmd.subtitle && (
                        <div
                          style={{
                            fontSize: '11px',
                            color: 'var(--color-ink-muted)',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {cmd.subtitle}
                        </div>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginLeft: '12px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        textTransform: 'uppercase',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-ink-faint)',
                      }}
                    >
                      {cmd.category}
                    </span>
                    {cmd.badge && (
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          fontFamily: 'var(--font-mono)',
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-xs)',
                          backgroundColor: isSelected ? '#ffffff' : 'var(--color-panel)',
                          border: '1px solid var(--color-border)',
                          color: 'var(--color-ink-secondary)',
                        }}
                      >
                        {cmd.badge}
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '8px 18px',
            borderTop: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '11px',
            color: 'var(--color-ink-faint)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <span>Use ↑↓ to navigate</span>
          <span>Press Enter to select</span>
          <span>ESC to dismiss</span>
        </div>
      </div>
    </div>
  );
};
