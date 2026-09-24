import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { PosturePill } from '../common/PosturePill';
import { ForensicHash } from '../common/ForensicHash';
import { X, Search } from 'lucide-react';

interface RunSelectorModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const RunSelectorModal: React.FC<RunSelectorModalProps> = ({ isOpen, onClose }) => {
  const { runs, activeRunId, selectRun, setActiveView } = useInvestigation();
  const [filter, setFilter] = React.useState('');

  if (!isOpen) return null;

  const filtered = [...runs]
    .sort((a, b) => {
      if (a.state === 'COMPLETED' && b.state !== 'COMPLETED') return -1;
      if (b.state === 'COMPLETED' && a.state !== 'COMPLETED') return 1;
      return 0;
    })
    .filter(
      (r) =>
        r.source_filename.toLowerCase().includes(filter.toLowerCase()) ||
        r.capture_id.toLowerCase().includes(filter.toLowerCase()) ||
        (r.overall_posture && r.overall_posture.toLowerCase().includes(filter.toLowerCase()))
    );

  const handleSelect = async (runId: string) => {
    await selectRun(runId);
    setActiveView('workbench');
    onClose();
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(21, 25, 30, 0.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '640px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border-strong)',
          boxShadow: 'var(--shadow-flyout)',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '80vh',
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
          <div>
            <div
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                color: 'var(--color-ink-muted)',
              }}
            >
              Forensic Catalog
            </div>
            <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Select Active Investigation Run
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{ padding: '4px', color: 'var(--color-ink-muted)' }}
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Search */}
        <div
          style={{
            padding: '12px 20px',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Search size={14} style={{ color: 'var(--color-ink-muted)' }} />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by filename, SHA-256, or posture..."
            style={{
              flex: 1,
              border: 'none',
              outline: 'none',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-ink)',
              backgroundColor: 'transparent',
            }}
            autoFocus
          />
        </div>

        {/* List */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
          {filtered.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '30px',
                color: 'var(--color-ink-muted)',
                fontSize: 'var(--text-sm)',
              }}
            >
              No matching investigation runs found.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {filtered.map((run) => {
                const isActive = run.run_id === activeRunId;
                return (
                  <div
                    key={run.run_id}
                    onClick={() => handleSelect(run.run_id)}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 'var(--radius-sm)',
                      border: `1px solid ${isActive ? 'var(--color-accent)' : 'var(--color-border)'}`,
                      backgroundColor: isActive ? 'var(--color-accent-soft)' : 'var(--color-surface)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      transition: 'all var(--transition-fast)',
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                      <div
                        style={{
                          fontSize: 'var(--text-sm)',
                          fontWeight: isActive ? 700 : 600,
                          color: 'var(--color-ink)',
                        }}
                      >
                        {run.source_filename}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <ForensicHash value={run.capture_id} length={12} label="SHA-256" />
                        <span style={{ fontSize: '11px', color: 'var(--color-ink-faint)' }}>
                          {run.duration_ms ? `${run.duration_ms}ms` : ''}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {run.overall_posture ? (
                        <PosturePill
                          band={run.overall_posture}
                          score={run.score_value}
                          size="sm"
                        />
                      ) : (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-ink-muted)',
                            backgroundColor: 'var(--color-panel)',
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-xs)',
                            border: '1px solid var(--color-border)',
                          }}
                        >
                          {run.state}
                        </span>
                      )}
                      {isActive && (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-accent)',
                            backgroundColor: '#ffffff',
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-xs)',
                            border: '1px solid var(--color-accent-border)',
                          }}
                        >
                          ACTIVE
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
