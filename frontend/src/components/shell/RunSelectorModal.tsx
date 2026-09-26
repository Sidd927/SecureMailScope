import React, { useEffect, useRef, useState } from 'react';
import { Search } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { relativeTime } from '../../utils/time';
import { Modal } from '../common/Modal';
import { PosturePill } from '../common/PosturePill';

interface RunSelectorModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const RunSelectorModal: React.FC<RunSelectorModalProps> = ({ isOpen, onClose }) => {
  const { runs, activeRunId, selectRun, setActiveView, setActiveTab } = useInvestigation();
  const [filter, setFilter] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  // Modal focuses its dialog on mount; move focus to the filter on the next frame.
  useEffect(() => {
    if (isOpen) requestAnimationFrame(() => inputRef.current?.focus());
  }, [isOpen]);

  if (!isOpen) return null;

  const q = filter.trim().toLowerCase();
  const filtered = [...runs]
    .sort((a, b) => Number(b.state === 'COMPLETED') - Number(a.state === 'COMPLETED') || Date.parse(b.created_at) - Date.parse(a.created_at))
    .filter((r) => !q || [r.source_filename, r.capture_id, r.overall_posture ?? ''].some((t) => t.toLowerCase().includes(q)));

  const open = (runId: string) => {
    setActiveTab('overview');
    setActiveView('workbench');
    onClose();
    selectRun(runId);
  };

  return (
    <Modal title="Open an analysis" onClose={onClose} width={720}>
      <div className="sms-palette__search" style={{ margin: 'calc(-1 * var(--ds-space-16)) calc(-1 * var(--ds-space-16)) var(--ds-space-8)' }}>
        <Search size={14} aria-hidden="true" />
        <input
          ref={inputRef}
          className="sms-palette__input"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by filename, SHA-256 or posture"
          aria-label="Filter analyses"
        />
      </div>
      {filtered.length === 0 ? (
        <p className="sms-muted" style={{ padding: 'var(--ds-space-24)', textAlign: 'center', fontSize: 'var(--ds-text-13)' }}>No analyses match "{filter}".</p>
      ) : (
        <ul className="sms-recent__list" aria-label="Analyses">
          {filtered.map((r) => {
            const openable = r.state === 'COMPLETED';
            return (
              <li key={r.run_id}>
                <button
                  type="button"
                  className="sms-recent__row"
                  onClick={() => open(r.run_id)}
                  disabled={!openable}
                  aria-current={r.run_id === activeRunId ? 'true' : undefined}
                  style={{
                    gridTemplateColumns: 'minmax(0, 1fr) 150px 64px 96px',
                    boxShadow: r.run_id === activeRunId ? 'inset 2px 0 0 var(--ds-carbon)' : undefined,
                    cursor: openable ? 'pointer' : 'not-allowed',
                  }}
                >
                  <span style={{ minWidth: 0 }}>
                    <span className="sms-recent__file" style={{ display: 'block' }}>{r.source_filename}</span>
                    <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{r.capture_id.slice(0, 16)}…</span>
                  </span>
                  <span>
                    {openable
                      ? <PosturePill band={r.overall_posture} size="sm" />
                      : <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{r.state}</span>}
                  </span>
                  <span className="sms-recent__score">{r.score_value != null ? r.score_value.toFixed(2) : '—'}</span>
                  <time className="sms-recent__time" dateTime={r.created_at} title={r.created_at}>{relativeTime(r.created_at)}</time>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Modal>
  );
};
