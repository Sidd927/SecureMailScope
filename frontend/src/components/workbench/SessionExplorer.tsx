import React, { useMemo } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { Search, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { formatEndpoint, formatProtocol } from '../../utils/formatters';

export const SessionExplorer: React.FC = () => {
  const {
    sessions,
    selectedStreamKey,
    selectSession,
    dashboard,
    selectedFinding,
    filterProtocol,
    setFilterProtocol,
    searchQuery,
    setSearchQuery,
  } = useInvestigation();

  // Calculate findings per session from dashboard.findings
  const sessionFindingMap = useMemo(() => {
    const map: Record<string, { count: number; maxSeverity: string }> = {};
    if (!dashboard?.findings) return map;

    for (const f of dashboard.findings) {
      for (const sk of f.affected_stream_keys || []) {
        if (!map[sk]) {
          map[sk] = { count: 0, maxSeverity: f.severity || 'INFO' };
        }
        map[sk].count += 1;
        // Prioritize critical/high
        const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        const currentRank = sevOrder.indexOf(map[sk].maxSeverity);
        const newRank = sevOrder.indexOf(f.severity || 'INFO');
        if (newRank !== -1 && (currentRank === -1 || newRank < currentRank)) {
          map[sk].maxSeverity = f.severity || 'INFO';
        }
      }
    }
    return map;
  }, [dashboard]);

  // Filter sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      // Protocol filter
      if (filterProtocol && s.protocol?.toLowerCase() !== filterProtocol.toLowerCase()) {
        return false;
      }
      // Search filter (stream_key, client ip, server ip, port)
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesStream = s.stream_key?.toLowerCase().includes(q);
        const matchesClient = `${s.client?.ip}:${s.client?.port}`.includes(q);
        const matchesServer = `${s.server?.ip}:${s.server?.port}`.includes(q);
        const matchesProto = s.protocol?.toLowerCase().includes(q);
        if (!matchesStream && !matchesClient && !matchesServer && !matchesProto) {
          return false;
        }
      }
      return true;
    });
  }, [sessions, filterProtocol, searchQuery]);

  // Protocol options with counts
  const protocolCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: sessions.length };
    for (const s of sessions) {
      const p = (s.protocol || 'UNKNOWN').toUpperCase();
      counts[p] = (counts[p] || 0) + 1;
    }
    return counts;
  }, [sessions]);

  return (
    <aside
      aria-label="Session Explorer"
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        backgroundColor: 'var(--color-surface)',
        borderRight: '1px solid var(--color-border)',
        width: '320px',
        flexShrink: 0,
        overflow: 'hidden',
      }}
    >
      {/* Pane Header */}
      <div
        style={{
          padding: '14px 16px',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-panel)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div
            style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              color: 'var(--color-ink-muted)',
              letterSpacing: '0.06em',
            }}
          >
            Stream Directory
          </div>
          <h2
            style={{
              fontSize: 'var(--text-sm)',
              fontWeight: 700,
              color: 'var(--color-ink)',
              marginTop: '1px',
            }}
          >
            Dissected Sessions ({sessions.length})
          </h2>
        </div>

        <span
          style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            padding: '1px 6px',
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-xs)',
            color: 'var(--color-ink-secondary)',
          }}
        >
          {filteredSessions.length} listed
        </span>
      </div>

      {/* Filter / Search Bar */}
      <div
        style={{
          padding: '10px 14px',
          borderBottom: '1px solid var(--color-border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          backgroundColor: 'var(--color-panel-card)',
        }}
      >
        {/* Search Input */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-xs)',
            padding: '4px 8px',
          }}
        >
          <Search size={12} style={{ color: 'var(--color-ink-muted)' }} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP, port, stream..."
            style={{
              border: 'none',
              outline: 'none',
              fontSize: 'var(--text-xs)',
              width: '100%',
              backgroundColor: 'transparent',
              color: 'var(--color-ink)',
            }}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              style={{
                fontSize: '10px',
                color: 'var(--color-ink-muted)',
                padding: '0 4px',
              }}
            >
              ×
            </button>
          )}
        </div>

        {/* Protocol Filter Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
          {Object.entries(protocolCounts).map(([proto, count]) => {
            const isSelected =
              (proto === 'ALL' && !filterProtocol) ||
              filterProtocol?.toUpperCase() === proto;
            return (
              <button
                key={proto}
                type="button"
                onClick={() => setFilterProtocol(proto === 'ALL' ? null : proto)}
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: isSelected ? 700 : 500,
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: isSelected ? 'var(--color-accent)' : 'var(--color-surface)',
                  color: isSelected ? '#ffffff' : 'var(--color-ink-secondary)',
                  border: `1px solid ${isSelected ? 'var(--color-accent)' : 'var(--color-border)'}`,
                  transition: 'all var(--transition-fast)',
                }}
              >
                {proto} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Finding Context Banner (Cross-filter indicator) */}
      {selectedFinding && (
        <div
          style={{
            padding: '8px 14px',
            backgroundColor: 'var(--color-sev-critical-bg)',
            borderBottom: '1px solid var(--color-sev-critical-border)',
            fontSize: '11px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--color-sev-critical)', fontWeight: 700 }}>Filter:</span>
            <span
              style={{
                color: 'var(--color-ink)',
                fontWeight: 600,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                maxWidth: '180px',
              }}
              title={selectedFinding.title}
            >
              {selectedFinding.title}
            </span>
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--color-sev-critical)' }}>
            {selectedFinding.affected_stream_keys.length} sess
          </span>
        </div>
      )}

      {/* Session Item List */}
      <div
        role="listbox"
        aria-label="Dissected TCP Sessions"
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '6px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px',
        }}
      >
        {filteredSessions.length === 0 ? (
          <div
            style={{
              padding: '32px 16px',
              textAlign: 'center',
              color: 'var(--color-ink-muted)',
              fontSize: 'var(--text-xs)',
            }}
          >
            No sessions match current filter criteria.
          </div>
        ) : (
          filteredSessions.map((session) => {
            const isSelected = session.stream_key === selectedStreamKey;
            const findingData = sessionFindingMap[session.stream_key];
            const isAffectedBySelectedFinding =
              selectedFinding &&
              selectedFinding.affected_stream_keys.includes(session.stream_key);

            return (
              <div
                key={session.stream_key}
                role="option"
                aria-selected={isSelected}
                tabIndex={0}
                onClick={() => selectSession(session.stream_key)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    selectSession(session.stream_key);
                  }
                }}
                style={{
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isSelected
                    ? 'var(--color-accent-soft)'
                    : isAffectedBySelectedFinding
                      ? 'var(--color-sev-critical-bg)'
                      : 'var(--color-surface)',
                  border: `1px solid ${
                    isSelected
                      ? 'var(--color-accent)'
                      : isAffectedBySelectedFinding
                        ? 'var(--color-sev-critical-border)'
                        : 'var(--color-border-subtle)'
                  }`,
                  borderLeft: isSelected
                    ? '3px solid var(--color-accent)'
                    : isAffectedBySelectedFinding
                      ? '3px solid var(--color-sev-critical)'
                      : '1px solid var(--color-border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'all var(--transition-fast)',
                }}
              >
                {/* Row 1: Protocol tag, Stream ID & Issues indicator */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        backgroundColor: session.implicit_tls ? 'var(--color-accent-soft)' : 'var(--color-panel)',
                        color: session.implicit_tls ? 'var(--color-accent)' : 'var(--color-ink)',
                        border: '1px solid var(--color-border)',
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-xs)',
                      }}
                    >
                      {formatProtocol(session.protocol, session.implicit_tls)}
                    </span>

                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        color: 'var(--color-ink-muted)',
                      }}
                    >
                      #{session.tcp_stream_id}
                    </span>
                  </div>

                  {findingData && findingData.count > 0 ? (
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '3px',
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor:
                          findingData.maxSeverity === 'CRITICAL'
                            ? 'var(--color-sev-critical-bg)'
                            : findingData.maxSeverity === 'HIGH'
                              ? 'var(--color-sev-high-bg)'
                              : 'var(--color-sev-medium-bg)',
                        color:
                          findingData.maxSeverity === 'CRITICAL'
                            ? 'var(--color-sev-critical)'
                            : findingData.maxSeverity === 'HIGH'
                              ? 'var(--color-sev-high)'
                              : 'var(--color-sev-medium)',
                        border: '1px solid currentColor',
                      }}
                    >
                      <ShieldAlert size={10} />
                      <span>{findingData.count}</span>
                    </span>
                  ) : (
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '3px',
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-sev-low)',
                      }}
                    >
                      <CheckCircle2 size={10} />
                    </span>
                  )}
                </div>

                {/* Row 2: Endpoints Client -> Server */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    color: 'var(--color-ink)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ color: 'var(--color-ink-secondary)' }}>
                    {formatEndpoint(session.client)}
                  </span>
                  <span style={{ color: 'var(--color-ink-faint)' }}>→</span>
                  <span style={{ fontWeight: 600 }}>
                    {formatEndpoint(session.server)}
                  </span>
                </div>

                {/* Row 3: TLS State / Packet count */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '10px',
                    color: 'var(--color-ink-muted)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                    {session.tls_state || session.app_state || 'TCP'}
                  </span>
                  <span>{session.timing?.packet_count ?? '—'} pkts</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
};
