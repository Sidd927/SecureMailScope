import React, { useState } from 'react';

interface ProvenanceGraphSvgProps {
  darkTheme?: boolean;
  activeFindingTitle?: string;
  onSelectNode?: (nodeId: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  category: string;
  detail: string;
  x: number;
  y: number;
  w: number;
  h: number;
  isPrimary?: boolean;
  isDefect?: boolean;
  isVerdict?: boolean;
}

export const ProvenanceGraphSvg: React.FC<ProvenanceGraphSvgProps> = ({
  darkTheme: _darkTheme = false,
  activeFindingTitle = 'Certificate public key strength',
  onSelectNode,
}) => {
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Spatial layout nodes adhering to forensic branching topology:
  // PCAP -> Stream -> Frame -> [Cert, TLS Param, Protocol Event] -> Finding -> [Standard, Score] -> Posture
  const nodes: GraphNode[] = [
    {
      id: 'pcap',
      category: 'FORENSIC CAPTURE',
      label: 'backup_weak_certificate.pcap',
      detail: 'SHA-256: 58d5f7... (14 pkts)',
      x: 75,
      y: 160,
      w: 130,
      h: 56,
    },
    {
      id: 'stream',
      category: 'TCP STREAM #0',
      label: 'SMTPS Protocol Stream',
      detail: '127.0.0.1:36568 → :465',
      x: 235,
      y: 160,
      w: 130,
      h: 56,
    },
    {
      id: 'frame',
      category: 'OBSERVED EVIDENCE',
      label: 'FRAME #6',
      detail: 'ServerHello + Cert Record',
      x: 395,
      y: 160,
      w: 130,
      h: 58,
      isPrimary: true,
    },
    // Branch 1: Upward -> Certificate Artifact
    {
      id: 'cert',
      category: 'DERIVED SPECIMEN',
      label: 'X.509 Certificate',
      detail: 'RSA-1024 Modulus · SHA-1',
      x: 565,
      y: 65,
      w: 145,
      h: 58,
      isDefect: true,
    },
    // Branch 2: Center -> TLS Negotiated Parameter
    {
      id: 'tls_param',
      category: 'NEGOTIATED PARAMETER',
      label: 'TLS Cipher Suite',
      detail: 'TLS_ECDHE_RSA_AES_256',
      x: 565,
      y: 160,
      w: 145,
      h: 54,
    },
    // Branch 3: Downward -> Protocol Event
    {
      id: 'event',
      category: 'STATE TRANSITION',
      label: 'Handshake Event',
      detail: 'TLSv1.2 ServerHello (0x02)',
      x: 565,
      y: 255,
      w: 145,
      h: 54,
    },
    // Convergence: Finding #01
    {
      id: 'finding',
      category: 'CONFIRMED DEFECT',
      label: 'FINDING SEC-CERT-003',
      detail: activeFindingTitle || 'Sub-112-bit RSA Modulus',
      x: 755,
      y: 160,
      w: 155,
      h: 62,
      isPrimary: true,
      isDefect: true,
    },
    // Divergence 1: Standard
    {
      id: 'standard',
      category: 'AUTHORITATIVE BASIS',
      label: 'NIST SP 800-57 §5.6.1',
      detail: 'Mandates ≥2048-bit RSA',
      x: 940,
      y: 85,
      w: 145,
      h: 56,
    },
    // Divergence 2: Score Deduction
    {
      id: 'score',
      category: 'QUANTITATIVE IMPACT',
      label: 'Penalty Deduction',
      detail: '−28.0 pts (F2-Damped)',
      x: 940,
      y: 235,
      w: 145,
      h: 56,
      isDefect: true,
    },
    // Final Convergence: Posture Verdict
    {
      id: 'posture',
      category: 'EVALUATED VERDICT',
      label: 'CRITICAL POSTURE',
      detail: 'Score: 44.0 / 100.0',
      x: 1115,
      y: 160,
      w: 145,
      h: 64,
      isPrimary: true,
      isVerdict: true,
    },
  ];

  // Defined lineage connections
  const links = [
    { from: 'pcap', to: 'stream' },
    { from: 'stream', to: 'frame' },
    { from: 'frame', to: 'cert' },
    { from: 'frame', to: 'tls_param' },
    { from: 'frame', to: 'event' },
    { from: 'cert', to: 'finding' },
    { from: 'tls_param', to: 'finding' },
    { from: 'event', to: 'finding' },
    { from: 'finding', to: 'standard' },
    { from: 'finding', to: 'score' },
    { from: 'standard', to: 'posture' },
    { from: 'score', to: 'posture' },
  ];

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  return (
    <div style={{ width: '100%', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
      <svg
        viewBox="0 0 1210 325"
        style={{
          width: '100%',
          maxWidth: '1210px',
          height: 'auto',
          display: 'block',
          margin: '0 auto',
          fontFamily: 'var(--ds-font-mono, monospace)',
          userSelect: 'none',
        }}
      >
        <defs>
          <marker
            id="prov-arrow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="5"
            markerHeight="5"
            orient="auto"
          >
            <path d="M 0 1 L 7 4 L 0 7 z" fill="#94a3b8" />
          </marker>
          <marker
            id="prov-arrow-crit"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 1 L 7 4 L 0 7 z" fill="#dc2626" />
          </marker>
          <marker
            id="prov-arrow-glow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 1 L 7 4 L 0 7 z" fill="#0f172a" />
          </marker>
        </defs>

        {/* Section Context Header */}
        <text x="605" y="24" textAnchor="middle" fill="#64748b" fontSize="10" fontWeight="700" letterSpacing="0.08em">
          END-TO-END INVESTIGATION PROVENANCE GRAPH // DETERMINISTIC CAUSALITY CHAIN
        </text>

        {/* Directed Evidence Connectors */}
        {links.map((link, idx) => {
          const fromNode = nodeMap.get(link.from)!;
          const toNode = nodeMap.get(link.to)!;

          const startX = fromNode.x + fromNode.w / 2;
          const startY = fromNode.y;
          const endX = toNode.x - toNode.w / 2;
          const endY = toNode.y;

          const isDefectPath =
            (link.from === 'frame' && link.to === 'cert') ||
            (link.from === 'cert' && link.to === 'finding') ||
            (link.from === 'finding' && link.to === 'score') ||
            (link.from === 'score' && link.to === 'posture');

          const isHighlighted =
            hoveredNodeId === link.from ||
            hoveredNodeId === link.to ||
            hoveredNodeId === 'finding' ||
            hoveredNodeId === 'frame';

          // Curved bezier connector for branching paths
          const deltaX = endX - startX;
          const pathD = `M ${startX} ${startY} C ${startX + deltaX * 0.45} ${startY}, ${endX - deltaX * 0.45} ${endY}, ${endX} ${endY}`;

          return (
            <path
              key={idx}
              d={pathD}
              fill="none"
              stroke={
                isHighlighted
                  ? '#0f172a'
                  : isDefectPath
                  ? '#ef4444'
                  : '#cbd5e1'
              }
              strokeWidth={isHighlighted ? 2.5 : isDefectPath ? 2 : 1.5}
              strokeDasharray={!isDefectPath && !isHighlighted ? '3 3' : 'none'}
              markerEnd={`url(#${isHighlighted ? 'prov-arrow-glow' : isDefectPath ? 'prov-arrow-crit' : 'prov-arrow'})`}
              style={{ transition: 'all 0.2s ease' }}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map((node) => {
          const isHovered = hoveredNodeId === node.id;
          const isDefect = node.isDefect;
          const isPrimary = node.isPrimary;
          const isVerdict = node.isVerdict;

          const bg = isVerdict
            ? '#fef2f2'
            : isDefect
            ? '#fff5f5'
            : isPrimary
            ? '#f8fafc'
            : '#ffffff';

          const stroke = isVerdict
            ? '#dc2626'
            : isDefect
            ? '#f87171'
            : isPrimary
            ? '#0f172a'
            : isHovered
            ? '#475569'
            : '#e2e8f0';

          return (
            <g
              key={node.id}
              transform={`translate(${node.x - node.w / 2}, ${node.y - node.h / 2})`}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelectNode?.(node.id)}
              onMouseEnter={() => setHoveredNodeId(node.id)}
              onMouseLeave={() => setHoveredNodeId(null)}
            >
              {/* Node Card Box */}
              <rect
                width={node.w}
                height={node.h}
                rx="6"
                fill={bg}
                stroke={stroke}
                strokeWidth={isVerdict || isPrimary || isHovered ? 2 : 1.2}
                filter={isHovered ? 'drop-shadow(0 4px 10px rgba(15,23,42,0.12))' : 'drop-shadow(0 1px 2px rgba(15,23,42,0.04))'}
              />

              {/* Node Category Strip */}
              <text
                x={node.w / 2}
                y={15}
                textAnchor="middle"
                fill={isVerdict || isDefect ? '#991b1b' : '#64748b'}
                fontSize="8"
                fontWeight="800"
                letterSpacing="0.05em"
              >
                {node.category}
              </text>

              {/* Node Main Title */}
              <text
                x={node.w / 2}
                y={31}
                textAnchor="middle"
                fill={isVerdict ? '#991b1b' : '#090d16'}
                fontSize="10"
                fontWeight="700"
                letterSpacing="-0.01em"
              >
                {node.label}
              </text>

              {/* Node Subtitle / Detail */}
              <text
                x={node.w / 2}
                y={45}
                textAnchor="middle"
                fill={isVerdict ? '#b91c1c' : '#64748b'}
                fontSize="8.5"
                fontWeight="500"
              >
                {node.detail}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
