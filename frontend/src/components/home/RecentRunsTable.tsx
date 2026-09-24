import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { PosturePill } from '../common/PosturePill';
import { ForensicHash } from '../common/ForensicHash';
import { Clock, Layers } from 'lucide-react';
import type { RunResponse } from '../../api/types';

export const RecentRunsTable: React.FC = () => {
  const { runs, activeRunId, selectRun, setActiveView } = useInvestigation();

  const handleOpenRun = async (run: RunResponse) => {
    await selectRun(run.run_id);
    setActiveView('workbench');
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--color-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--color-border)',
        overflow: 'hidden',
        boxShadow: 'var(--shadow-subtle)',
      }}
    >
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-panel)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              color: 'var(--color-ink-muted)',
              letterSpacing: '0.06em',
            }}
          >
            Catalog Registry
          </span>
          <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
            Recent Forensic Analyses ({runs.length})
          </h2>
        </div>
        <span
          style={{
            fontSize: '11px',
            color: 'var(--color-ink-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          Immutable Assessments
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            textAlign: 'left',
            fontSize: 'var(--text-xs)',
          }}
        >
          <thead>
            <tr
              style={{
                backgroundColor: 'var(--color-panel-card)',
                borderBottom: '1px solid var(--color-border)',
                color: 'var(--color-ink-muted)',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                fontSize: '11px',
                letterSpacing: '0.04em',
              }}
            >
              <th style={{ padding: '10px 16px', fontWeight: 600 }}>Artifact / Filename</th>
              <th style={{ padding: '10px 16px', fontWeight: 600 }}>Capture SHA-256</th>
              <th style={{ padding: '10px 16px', fontWeight: 600 }}>Calculated Posture</th>
              <th style={{ padding: '10px 16px', fontWeight: 600 }}>Duration</th>
              <th style={{ padding: '10px 16px', fontWeight: 600 }}>Timestamp</th>
              <th style={{ padding: '10px 16px', textAlign: 'right', fontWeight: 600 }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  style={{
                    padding: '36px',
                    textAlign: 'center',
                    color: 'var(--color-ink-muted)',
                    fontSize: 'var(--text-sm)',
                  }}
                >
                  No prior analyses recorded. Upload a PCAP capture above to begin.
                </td>
              </tr>
            ) : (
              runs.map((run) => {
                const isActive = run.run_id === activeRunId;
                return (
                  <tr
                    key={run.run_id}
                    onClick={() => handleOpenRun(run)}
                    style={{
                      borderBottom: '1px solid var(--color-border-subtle)',
                      backgroundColor: isActive ? 'var(--color-accent-soft)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background-color var(--transition-fast)',
                    }}
                  >
                    {/* Filename & AI flag */}
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          style={{
                            fontWeight: 600,
                            color: 'var(--color-ink)',
                            fontFamily: 'var(--font-sans)',
                          }}
                        >
                          {run.source_filename}
                        </span>
                        {run.ai_enabled && (
                          <span
                            style={{
                              fontSize: '9px',
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 700,
                              backgroundColor: 'var(--color-panel-muted)',
                              color: 'var(--color-ink-secondary)',
                              padding: '1px 4px',
                              borderRadius: 'var(--radius-xs)',
                            }}
                          >
                            AI
                          </span>
                        )}
                        {isActive && (
                          <span
                            style={{
                              fontSize: '9px',
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 700,
                              backgroundColor: 'var(--color-accent)',
                              color: '#ffffff',
                              padding: '1px 5px',
                              borderRadius: 'var(--radius-xs)',
                            }}
                          >
                            ACTIVE
                          </span>
                        )}
                      </div>
                    </td>

                    {/* SHA-256 */}
                    <td style={{ padding: '12px 16px' }}>
                      <ForensicHash value={run.capture_id} length={14} />
                    </td>

                    {/* Posture */}
                    <td style={{ padding: '12px 16px' }}>
                      {run.overall_posture ? (
                        <PosturePill
                          band={run.overall_posture}
                          score={run.score_value}
                          size="sm"
                        />
                      ) : (
                        <span style={{ color: 'var(--color-ink-faint)' }}>—</span>
                      )}
                    </td>

                    {/* Duration */}
                    <td
                      style={{
                        padding: '12px 16px',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-ink-secondary)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Clock size={12} style={{ color: 'var(--color-ink-faint)' }} />
                        <span>{run.duration_ms ? `${run.duration_ms} ms` : '—'}</span>
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td
                      style={{
                        padding: '12px 16px',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-ink-muted)',
                      }}
                    >
                      {new Date(run.created_at).toLocaleString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>

                    {/* Action */}
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenRun(run);
                        }}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '4px 10px',
                          backgroundColor: isActive ? 'var(--color-accent)' : 'var(--color-panel)',
                          color: isActive ? '#ffffff' : 'var(--color-ink)',
                          border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius-xs)',
                          fontSize: '11px',
                          fontWeight: 600,
                          transition: 'all var(--transition-fast)',
                        }}
                      >
                        <Layers size={11} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
