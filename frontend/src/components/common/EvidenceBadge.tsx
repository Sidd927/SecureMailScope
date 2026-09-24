import React from 'react';
import type { EvidenceState } from '../../api/types';

interface EvidenceBadgeProps {
  state: EvidenceState | string;
  size?: 'sm' | 'md';
  showGlyph?: boolean;
}

const GLYPHS: Record<EvidenceState, string> = {
  OBSERVED: '●',
  INFERRED: '⊢',
  UNKNOWN: '?',
  AMBIGUOUS: '⧖',
  INCOMPLETE: '⇥',
  NOT_OBSERVABLE: '⊘',
};

const LABELS: Record<EvidenceState, string> = {
  OBSERVED: 'OBSERVED',
  INFERRED: 'INFERRED',
  UNKNOWN: 'UNKNOWN',
  AMBIGUOUS: 'AMBIGUOUS',
  INCOMPLETE: 'INCOMPLETE',
  NOT_OBSERVABLE: 'NOT OBSERVABLE',
};

export const EvidenceBadge: React.FC<EvidenceBadgeProps> = ({
  state,
  size = 'md',
  showGlyph = true,
}) => {
  const normState = (state as EvidenceState) || 'UNKNOWN';
  const glyph = GLYPHS[normState] || '•';
  const label = LABELS[normState] || String(state);

  const styleMap: Record<EvidenceState, React.CSSProperties> = {
    OBSERVED: {
      color: 'var(--evidence-observed-color)',
      backgroundColor: 'var(--evidence-observed-bg)',
      borderColor: 'var(--evidence-observed-border)',
      borderStyle: 'solid',
    },
    INFERRED: {
      color: 'var(--evidence-inferred-color)',
      backgroundColor: 'var(--evidence-inferred-bg)',
      borderColor: 'var(--evidence-inferred-border)',
      borderStyle: 'dashed',
    },
    NOT_OBSERVABLE: {
      color: 'var(--evidence-not-observable-color)',
      backgroundColor: 'var(--evidence-not-observable-bg)',
      borderColor: 'var(--evidence-not-observable-border)',
      borderStyle: 'solid',
    },
    AMBIGUOUS: {
      color: 'var(--evidence-ambiguous-color)',
      backgroundColor: 'var(--evidence-ambiguous-bg)',
      borderColor: 'var(--evidence-ambiguous-border)',
      borderStyle: 'solid',
    },
    UNKNOWN: {
      color: 'var(--evidence-unknown-color)',
      backgroundColor: 'var(--evidence-unknown-bg)',
      borderColor: 'var(--evidence-unknown-border)',
      borderStyle: 'dotted',
    },
    INCOMPLETE: {
      color: 'var(--evidence-incomplete-color)',
      backgroundColor: 'var(--evidence-incomplete-bg)',
      borderColor: 'var(--evidence-incomplete-border)',
      borderStyle: 'solid',
    },
  };

  const currentStyle = styleMap[normState] || styleMap.UNKNOWN;
  const isSm = size === 'sm';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: isSm ? '3px' : '5px',
        padding: isSm ? '1px 5px' : '2px 7px',
        fontSize: isSm ? 'var(--text-2xs)' : 'var(--text-xs)',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.04em',
        borderRadius: 'var(--radius-xs)',
        borderWidth: '1px',
        lineHeight: 1.2,
        userSelect: 'none',
        whiteSpace: 'nowrap',
        ...currentStyle,
      }}
      title={`Evidence status: ${label}`}
    >
      {showGlyph && (
        <span
          style={{
            fontSize: isSm ? '8px' : '10px',
            opacity: 0.85,
            fontWeight: 800,
          }}
          aria-hidden="true"
        >
          {glyph}
        </span>
      )}
      <span>{label}</span>
    </span>
  );
};
