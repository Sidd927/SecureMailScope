import React, { useState } from 'react';

export interface ProtocolMessage {
  frame: number;
  direction: 'client_to_server' | 'server_to_client';
  label: string;
  details?: string;
  hasIssue?: boolean;
  issueSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  issueText?: string;
  epoch?: number;
}

interface ProtocolLadderSvgProps {
  clientIp?: string;
  serverIp?: string;
  selectedFrame?: number | null;
  onSelectFrame?: (frame: number) => void;
  accentColor?: string;
  darkTheme?: boolean;
  messages?: ProtocolMessage[];
}

const DEFAULT_MESSAGES: ProtocolMessage[] = [
  { frame: 1, direction: 'client_to_server', label: 'TCP SYN', details: 'Seq=0 Win=65495 Len=0 MSS=65475' },
  { frame: 2, direction: 'server_to_client', label: 'TCP SYN, ACK', details: 'Seq=0 Ack=1 Win=65483 Len=0' },
  { frame: 3, direction: 'client_to_server', label: 'TCP ACK', details: 'Seq=1 Ack=1 Win=65536 Len=0' },
  { frame: 4, direction: 'client_to_server', label: 'TLSv1.2 ClientHello', details: 'Ciphers: 17 suites, SNI: localhost, ECDHE supported' },
  { frame: 5, direction: 'server_to_client', label: 'TCP ACK', details: 'Seq=1 Ack=518 Win=65536 Len=0' },
  {
    frame: 6,
    direction: 'server_to_client',
    label: 'TLSv1.2 ServerHello, Certificate, ServerKeyExchange',
    details: 'Cipher: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Cert: RSA-1024 / SHA-1',
    hasIssue: true,
    issueSeverity: 'CRITICAL',
    issueText: 'CRITICAL FINDING #01: RSA 1024-bit Modulus (<112 bits) + sha1WithRSAEncryption (-28 pts)'
  },
  { frame: 8, direction: 'client_to_server', label: 'ClientKeyExchange, ChangeCipherSpec', details: 'ECDH PubKey (32 bytes)' },
  { frame: 10, direction: 'server_to_client', label: 'ChangeCipherSpec, EncryptedHandshakeMessage', details: 'Handshake Finished (Encrypted VerifyData)' },
  { frame: 12, direction: 'client_to_server', label: 'Application Data (TLS Encrypted)', details: 'Len=85 bytes SMTP command traffic' },
  { frame: 14, direction: 'server_to_client', label: 'TCP FIN, ACK', details: 'Connection teardown initiated by server' }
];

export const ProtocolLadderSvg: React.FC<ProtocolLadderSvgProps> = ({
  clientIp = '127.0.0.1:36568 (Client)',
  serverIp = '127.0.0.1:465 (Mail Server)',
  selectedFrame = 6,
  onSelectFrame,
  darkTheme: _darkTheme = false,
  messages,
}) => {
  const activeMessages = messages || DEFAULT_MESSAGES;
  const [hoveredFrame, setHoveredFrame] = useState<number | null>(null);

  const width = 940;
  const clientX = 180;
  const serverX = 760;
  const rowHeight = 52;
  const topOffset = 70;
  const totalHeight = topOffset + activeMessages.length * rowHeight + 50;

  return (
    <div style={{ width: '100%', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
      <svg
        viewBox={`0 0 ${width} ${totalHeight}`}
        style={{
          width: '100%',
          maxWidth: `${width}px`,
          height: 'auto',
          display: 'block',
          margin: '0 auto',
          fontFamily: 'var(--ds-font-mono, monospace)',
          userSelect: 'none',
        }}
      >
        <defs>
          {/* Arrowheads */}
          <marker
            id="arrow-to-server"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155" />
          </marker>
          <marker
            id="arrow-to-client"
            viewBox="0 0 10 10"
            refX="1"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 10 1 L 0 5 L 10 9 z" fill="#334155" />
          </marker>
          <marker
            id="arrow-to-client-critical"
            viewBox="0 0 10 10"
            refX="1"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto"
          >
            <path d="M 10 1 L 0 5 L 10 9 z" fill="#dc2626" />
          </marker>

          {/* Glow Filters for Selected / Alert Frames */}
          <filter id="glow-crimson" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" floodColor="rgba(220, 38, 38, 0.25)" />
          </filter>
          <filter id="glow-selected" x="-10%" y="-10%" width="120%" height="120%">
            <feDropShadow dx="0" dy="1" stdDeviation="3" floodColor="rgba(15, 23, 42, 0.18)" />
          </filter>
        </defs>

        {/* Dual Lifelines (Client & Server Rails) */}
        <line
          x1={clientX}
          y1={topOffset - 15}
          x2={clientX}
          y2={totalHeight - 30}
          stroke="#cbd5e1"
          strokeWidth="2"
          strokeDasharray="4 4"
        />
        <line
          x1={serverX}
          y1={topOffset - 15}
          x2={serverX}
          y2={totalHeight - 30}
          stroke="#cbd5e1"
          strokeWidth="2"
          strokeDasharray="4 4"
        />

        {/* Lifeline Top Headers */}
        {/* Client Entity Card */}
        <g transform={`translate(${clientX - 110}, 16)`}>
          <rect
            width="220"
            height="36"
            rx="6"
            fill="#ffffff"
            stroke="#cbd5e1"
            strokeWidth="1.5"
            filter="drop-shadow(0 1px 2px rgba(15,23,42,0.04))"
          />
          <circle cx="20" cy="18" r="4" fill="#0284c7" />
          <text x="32" y="16" fill="#64748b" fontSize="9.5" fontWeight="600" letterSpacing="0.05em">
            CLIENT ENDPOINT
          </text>
          <text x="32" y="27" fill="#090d16" fontSize="11" fontWeight="700">
            {clientIp}
          </text>
        </g>

        {/* Server Entity Card */}
        <g transform={`translate(${serverX - 110}, 16)`}>
          <rect
            width="220"
            height="36"
            rx="6"
            fill="#ffffff"
            stroke="#cbd5e1"
            strokeWidth="1.5"
            filter="drop-shadow(0 1px 2px rgba(15,23,42,0.04))"
          />
          <circle cx="20" cy="18" r="4" fill="#059669" />
          <text x="32" y="16" fill="#64748b" fontSize="9.5" fontWeight="600" letterSpacing="0.05em">
            MAIL SERVER SERVICE
          </text>
          <text x="32" y="27" fill="#090d16" fontSize="11" fontWeight="700">
            {serverIp}
          </text>
        </g>

        {/* Messages & Handshake Chronology */}
        {activeMessages.map((msg, index) => {
          const y = topOffset + index * rowHeight + 20;
          const isClientToServer = msg.direction === 'client_to_server';
          const isSelected = selectedFrame === msg.frame;
          const isHovered = hoveredFrame === msg.frame;
          const isCritical = msg.hasIssue;

          const startX = isClientToServer ? clientX + 10 : serverX - 10;
          const endX = isClientToServer ? serverX - 10 : clientX + 10;
          const markerId = isCritical
            ? 'arrow-to-client-critical'
            : isClientToServer
            ? 'arrow-to-server'
            : 'arrow-to-client';

          return (
            <g
              key={msg.frame}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelectFrame?.(msg.frame)}
              onMouseEnter={() => setHoveredFrame(msg.frame)}
              onMouseLeave={() => setHoveredFrame(null)}
            >
              {/* Row Highlight Background */}
              <rect
                x="20"
                y={y - 20}
                width={width - 40}
                height={rowHeight - 6}
                rx="6"
                fill={
                  isSelected
                    ? isCritical
                      ? '#fef2f2'
                      : '#f1f5f9'
                    : isHovered
                    ? '#f8fafc'
                    : 'transparent'
                }
                stroke={
                  isSelected
                    ? isCritical
                      ? '#dc2626'
                      : '#0f172a'
                    : isHovered
                    ? '#cbd5e1'
                    : 'transparent'
                }
                strokeWidth={isSelected ? '1.5' : '1'}
                strokeDasharray={isSelected && !isCritical ? 'none' : 'none'}
              />

              {/* Frame Number Tag (Left Rail) */}
              <rect
                x="32"
                y={y - 12}
                width="42"
                height="22"
                rx="4"
                fill={isCritical ? '#fee2e2' : isSelected ? '#0f172a' : '#f1f5f9'}
                stroke={isCritical ? '#fca5a5' : isSelected ? '#0f172a' : '#e2e8f0'}
                strokeWidth="1"
              />
              <text
                x="53"
                y={y + 3}
                textAnchor="middle"
                fill={isCritical ? '#991b1b' : isSelected ? '#ffffff' : '#475569'}
                fontSize="10"
                fontWeight="700"
              >
                #{msg.frame}
              </text>

              {/* Timestamp Offset (Relative) */}
              <text
                x="84"
                y={y + 2}
                fill="#94a3b8"
                fontSize="9"
                fontWeight="500"
              >
                +{((msg.frame - 1) * 0.003).toFixed(3)}s
              </text>

              {/* Connecting Message Line / Arrow */}
              <line
                x1={startX}
                y1={y - 1}
                x2={endX}
                y2={y - 1}
                stroke={isCritical ? '#dc2626' : isSelected ? '#0f172a' : '#475569'}
                strokeWidth={isCritical ? '2.5' : isSelected ? '2' : '1.5'}
                markerEnd={`url(#${markerId})`}
              />

              {/* Message Label (Above Arrow) */}
              <text
                x={(clientX + serverX) / 2}
                y={y - 7}
                textAnchor="middle"
                fill={isCritical ? '#991b1b' : '#090d16'}
                fontSize="11.5"
                fontWeight={isCritical || isSelected ? '700' : '600'}
                letterSpacing="-0.01em"
              >
                {msg.label}
              </text>

              {/* Message Technical Details (Below Arrow) */}
              <text
                x={(clientX + serverX) / 2}
                y={y + 11}
                textAnchor="middle"
                fill={isCritical ? '#b91c1c' : '#64748b'}
                fontSize="9.5"
                fontWeight="500"
              >
                {msg.details}
              </text>

              {/* Inline Finding Callout Pill if hasIssue */}
              {msg.hasIssue && (
                <g transform={`translate(${serverX + 18}, ${y - 14})`}>
                  <rect
                    width="128"
                    height="26"
                    rx="4"
                    fill="#fee2e2"
                    stroke="#ef4444"
                    strokeWidth="1.2"
                  />
                  <circle cx="12" cy="13" r="3.5" fill="#dc2626" />
                  <text x="22" y="16" fill="#991b1b" fontSize="9" fontWeight="800" letterSpacing="0.02em">
                    DEFECT: -28 PTS
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
};
