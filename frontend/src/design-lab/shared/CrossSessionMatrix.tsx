import { CheckCircle2, ShieldAlert } from 'lucide-react';

interface CrossSessionMatrixProps {
  darkTheme?: boolean;
}

export const CrossSessionMatrix: React.FC<CrossSessionMatrixProps> = () => {
  const subjectSessions = [
    { id: 'Stream #0', client: '10.0.0.6:40041', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
    { id: 'Stream #1', client: '10.0.0.6:40042', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
    { id: 'Stream #2', client: '10.0.0.6:40043', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
    { id: 'Stream #3', client: '10.0.0.6:40044', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
    { id: 'Stream #4', client: '10.0.0.6:40045', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
    { id: 'Stream #5', client: '10.0.0.6:40046', capability: 'STARTTLS OMITTED', state: 'PLAINTEXT AUTH', defect: true },
  ];

  const controlSessions = [
    { id: 'Stream #6', client: '10.0.0.7:40047', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
    { id: 'Stream #7', client: '10.0.0.7:40048', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
    { id: 'Stream #8', client: '10.0.0.7:40049', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
    { id: 'Stream #9', client: '10.0.0.7:40050', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
    { id: 'Stream #10', client: '10.0.0.7:40051', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
    { id: 'Stream #11', client: '10.0.0.7:40052', capability: '250 STARTTLS ADVERTISED', state: 'TLS 1.3 UPGRADED' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* High-Impact Behavioral Deviation Callout */}
      <div
        style={{
          padding: '16px 20px',
          borderRadius: '8px',
          backgroundColor: '#fef2f2',
          border: '1px solid #fecaca',
          borderLeft: '4px solid #dc2626',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              padding: '2px 7px',
              borderRadius: '3px',
              backgroundColor: '#dc2626',
              color: '#ffffff',
              fontSize: '10px',
              fontWeight: 800,
              fontFamily: 'var(--ds-font-mono)',
            }}
          >
            RULE CS-STARTTLS-001
          </span>
          <span style={{ fontSize: '13px', fontWeight: 800, color: '#991b1b', letterSpacing: '-0.01em' }}>
            SELECTIVE STARTTLS CAPABILITY SUPPRESSION (BEHAVIOURAL DEVIATION DETECTED)
          </span>
        </div>
        <p style={{ fontSize: '12px', color: '#7f1d1d', lineHeight: 1.5 }}>
          Subject client <code>10.0.0.6</code> was repeatedly denied the <code>250 STARTTLS</code> capability across 6 consecutive sessions (streams 0–5) connecting to <code>10.0.0.80:587</code>, forcing plaintext authentication.
          Concurrently, control baseline client <code>10.0.0.7</code> connecting to the identical mail server was offered STARTTLS and negotiated TLS 1.3 across 6 sessions (streams 6–11) without failure (RFC 3207 §6).
        </p>
      </div>

      {/* Behavioral Comparison Instrument: Subject vs Control Baseline */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 60px 1fr',
          gap: '16px',
          alignItems: 'stretch',
        }}
      >
        {/* Left Deck: Subject Endpoint (Victim / Target) */}
        <div
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #fca5a5',
            borderRadius: '8px',
            padding: '18px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            boxShadow: '0 1px 3px rgba(220, 38, 38, 0.06)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #fee2e2', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={16} color="#dc2626" />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 800, color: '#991b1b' }}>
                  SUBJECT CLIENT: 10.0.0.6
                </div>
                <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--ds-font-mono)' }}>
                  6 consecutive sessions &bull; Port 587
                </div>
              </div>
            </div>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 7px',
                borderRadius: '3px',
                backgroundColor: '#fee2e2',
                color: '#991b1b',
                fontFamily: 'var(--ds-font-mono)',
              }}
            >
              UPGRADE STRIPPED
            </span>
          </div>

          {/* Session List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {subjectSessions.map((s, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  backgroundColor: '#fff5f5',
                  border: '1px solid #fed7d7',
                  borderLeft: '3px solid #dc2626',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                }}
              >
                <div>
                  <strong style={{ color: '#090d16' }}>{s.id}</strong>
                  <span style={{ color: '#64748b', marginLeft: '6px' }}>({s.client})</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ color: '#dc2626', fontWeight: 700 }}>{s.capability}</span>
                  <span style={{ color: '#991b1b', backgroundColor: '#fee2e2', padding: '1px 5px', borderRadius: '2px', fontSize: '9px', fontWeight: 700 }}>
                    {s.state}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Center Divider: VS Rail */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
          <div style={{ width: '1px', flex: 1, backgroundColor: '#cbd5e1' }} />
          <div
            style={{
              padding: '6px 8px',
              borderRadius: '50%',
              backgroundColor: '#0f172a',
              color: '#ffffff',
              fontFamily: 'var(--ds-font-mono)',
              fontSize: '10px',
              fontWeight: 800,
            }}
          >
            VS
          </div>
          <div style={{ width: '1px', flex: 1, backgroundColor: '#cbd5e1' }} />
        </div>

        {/* Right Deck: Control Endpoints (Baseline) */}
        <div
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #a7f3d0',
            borderRadius: '8px',
            padding: '18px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            boxShadow: '0 1px 3px rgba(5, 150, 105, 0.06)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #d1fae5', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={16} color="#059669" />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 800, color: '#065f46' }}>
                  CONTROL BASELINE CLIENT
                </div>
                <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--ds-font-mono)' }}>
                  10.0.0.7 &bull; 6 sessions &bull; Port 587
                </div>
              </div>
            </div>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 7px',
                borderRadius: '3px',
                backgroundColor: '#ecfdf5',
                color: '#065f46',
                fontFamily: 'var(--ds-font-mono)',
              }}
            >
              BASELINE COMPLIANT
            </span>
          </div>

          {/* Session List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {controlSessions.map((s, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  backgroundColor: '#f0fdf4',
                  border: '1px solid #bbf7d0',
                  borderLeft: '3px solid #059669',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                }}
              >
                <div>
                  <strong style={{ color: '#090d16' }}>{s.id}</strong>
                  <span style={{ color: '#64748b', marginLeft: '6px' }}>({s.client})</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ color: '#059669', fontWeight: 700 }}>{s.capability}</span>
                  <span style={{ color: '#065f46', backgroundColor: '#dcfce7', padding: '1px 5px', borderRadius: '2px', fontSize: '9px', fontWeight: 700 }}>
                    {s.state}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
