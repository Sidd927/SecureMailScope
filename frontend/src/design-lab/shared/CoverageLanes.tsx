import React from 'react';

interface CoverageLanesProps {
  darkTheme?: boolean;
}

export const CoverageLanes: React.FC<CoverageLanesProps> = ({ darkTheme = true }) => {
  const lanes = [
    { label: 'Transport Layer (L4 TCP)', state: 'OBSERVED', pct: 100, note: 'Complete handshake & teardown observed (14 pkts)' },
    { label: 'Application Upgrade (L7 STARTTLS)', state: 'NOT_OBSERVABLE', pct: 0, note: 'Implicit TLS on port 465 (no cleartext greeting banner)' },
    { label: 'Cryptographic Handshake (TLS 1.2)', state: 'OBSERVED', pct: 85, note: 'ClientHello + ServerHello observed; ServerKeyExchange ECDHE' },
    { label: 'PKI Certificate Structure', state: 'OBSERVED', pct: 75, note: '1 certificate parsed; RSA 1024-bit modulus & SHA-1 extracted' },
    { label: 'Trust & Revocation Boundary', state: 'NOT_OBSERVABLE', pct: 0, note: 'Passive capture limitation: Trust anchors & OCSP require external boundary' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%' }}>
      {lanes.map((lane) => {
        const isObserved = lane.state === 'OBSERVED';
        const barColor = isObserved
          ? '#10b981'
          : darkTheme ? '#475569' : '#94a3b8';
        const badgeBg = isObserved
          ? (darkTheme ? 'rgba(16, 185, 129, 0.15)' : '#dcfce7')
          : (darkTheme ? 'rgba(100, 116, 139, 0.2)' : '#f1f5f9');
        const badgeColor = isObserved
          ? (darkTheme ? '#34d399' : '#15803d')
          : (darkTheme ? '#94a3b8' : '#64748b');

        return (
          <div
            key={lane.label}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
              padding: '8px 12px',
              borderRadius: '6px',
              backgroundColor: darkTheme ? 'rgba(15, 23, 42, 0.6)' : 'rgba(241, 245, 249, 0.7)',
              border: `1px solid ${darkTheme ? '#1e293b' : '#e2e8f0'}`,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: darkTheme ? '#e2e8f0' : '#1e293b' }}>
                {lane.label}
              </span>
              <span
                style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: '3px',
                  backgroundColor: badgeBg,
                  color: badgeColor,
                  letterSpacing: '0.04em',
                }}
              >
                {lane.state}
              </span>
            </div>

            {/* Meter Bar */}
            <div
              style={{
                width: '100%',
                height: '4px',
                borderRadius: '2px',
                backgroundColor: darkTheme ? '#1e293b' : '#e2e8f0',
                overflow: 'hidden',
                position: 'relative',
              }}
            >
              <div
                style={{
                  width: `${lane.pct}%`,
                  height: '100%',
                  backgroundColor: barColor,
                  borderRadius: '2px',
                  transition: 'width 0.4s ease',
                }}
              />
            </div>

            <span style={{ fontSize: '10px', color: darkTheme ? '#94a3b8' : '#64748b', fontStyle: 'normal' }}>
              {lane.note}
            </span>
          </div>
        );
      })}
    </div>
  );
};
