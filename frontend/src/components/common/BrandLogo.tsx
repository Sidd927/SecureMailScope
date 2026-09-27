import React from 'react';

interface BrandLogoProps {
  variant?: 'mark' | 'compact' | 'full';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showSubtitle?: boolean;
  className?: string;
  onClick?: () => void;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  variant = 'compact',
  size = 'md',
  showSubtitle = false,
  className = '',
  onClick,
}) => {
  // Dimension mapping for mark
  const markDimensions: Record<string, { width: number; height: number; iconSize: number }> = {
    sm: { width: 22, height: 22, iconSize: 22 },
    md: { width: 28, height: 28, iconSize: 28 },
    lg: { width: 38, height: 38, iconSize: 38 },
    xl: { width: 52, height: 52, iconSize: 52 },
  };

  const currentDim = markDimensions[size] || markDimensions.md;

  const markSvg = (
    <svg
      width={currentDim.width}
      height={currentDim.height}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="sms-brand-logo__svg"
      aria-hidden="true"
    >
      <defs>
        {/* Core Brand Accent Gradient: Cyan -> Blue -> Purple */}
        <linearGradient id="sms-logo-accent" x1="2" y1="2" x2="34" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00d2ff" />
          <stop offset="50%" stopColor="#3b82f6" />
          <stop offset="100%" stopColor="#a855f7" />
        </linearGradient>

        {/* Shield Ambient Fill */}
        <linearGradient id="sms-shield-bg" x1="18" y1="4" x2="18" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0c1729" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#080e1b" stopOpacity="0.98" />
        </linearGradient>

        {/* Orbital Glow */}
        <filter id="sms-orbital-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="0.8" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Orbital Ring Back Arc (behind shield) */}
      <path
        d="M 6.5 13.5 C 10.5 8.5 25.5 8.5 29.5 13.5"
        stroke="url(#sms-logo-accent)"
        strokeWidth="1.25"
        strokeDasharray="2 1.5"
        strokeOpacity="0.45"
      />

      {/* Shield Silhouette */}
      <path
        d="M 18 4.2 L 28.5 8.5 C 28.5 18 24 25.5 18 29.8 C 12 25.5 7.5 18 7.5 8.5 L 18 4.2 Z"
        fill="url(#sms-shield-bg)"
        stroke="url(#sms-logo-accent)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />

      {/* Mail / Envelope Symbolism Inside Shield */}
      <g stroke="#94a3b8" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
        {/* Envelope Outer Perimeter */}
        <rect x="11.5" y="12" width="13" height="9" rx="1" fill="#0f1929" stroke="url(#sms-logo-accent)" strokeWidth="1.1" />
        {/* Envelope V-Flap */}
        <path d="M 11.8 12.5 L 18 17.2 L 24.2 12.5" stroke="#38bdf8" strokeWidth="1.25" />
        {/* Subtle Bottom Fold */}
        <path d="M 12.5 20.2 L 15.5 17.5" stroke="#38bdf8" strokeOpacity="0.5" strokeWidth="0.9" />
        <path d="M 23.5 20.2 L 20.5 17.5" stroke="#38bdf8" strokeOpacity="0.5" strokeWidth="0.9" />
      </g>

      {/* Orbital Ring Fore Arc (wrapping over shield) */}
      <g filter="url(#sms-orbital-glow)">
        <path
          d="M 4 19.5 C 6 25 18 29 32 17.5"
          stroke="url(#sms-logo-accent)"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        {/* Orbital Node / Spark */}
        <circle cx="31.2" cy="18" r="1.75" fill="#00d2ff" />
        <circle cx="31.2" cy="18" r="3" stroke="#00d2ff" strokeWidth="0.75" strokeOpacity="0.5" />
      </g>
    </svg>
  );

  if (variant === 'mark') {
    return (
      <div
        className={`sms-brand-logo sms-brand-logo--mark sms-brand-logo--${size} ${className}`}
        onClick={onClick}
        role={onClick ? 'button' : undefined}
        tabIndex={onClick ? 0 : undefined}
      >
        {markSvg}
      </div>
    );
  }

  return (
    <div
      className={`sms-brand-logo sms-brand-logo--${variant} sms-brand-logo--${size} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      style={{ display: 'inline-flex', alignItems: 'center', gap: size === 'sm' ? 8 : 10, cursor: onClick ? 'pointer' : 'default' }}
    >
      <div className="sms-brand-logo__mark-wrap">
        {markSvg}
      </div>
      <div className="sms-brand-logo__text-wrap" style={{ display: 'flex', flexDirection: 'column', lineHeight: 1 }}>
        <div className="sms-brand-logo__wordmark" style={{ display: 'flex', alignItems: 'baseline', letterSpacing: '-0.02em' }}>
          <span style={{ fontWeight: 700, color: 'var(--sms-text-primary, #f8fafc)', fontSize: size === 'sm' ? '0.875rem' : size === 'lg' ? '1.25rem' : size === 'xl' ? '1.5rem' : '1rem' }}>
            Secure
          </span>
          <span style={{ fontWeight: 600, color: 'var(--sms-brand-cyan, #00d2ff)', fontSize: size === 'sm' ? '0.875rem' : size === 'lg' ? '1.25rem' : size === 'xl' ? '1.5rem' : '1rem' }}>
            Mail
          </span>
          <span style={{ fontWeight: 500, color: 'var(--sms-text-secondary, #94a3b8)', fontSize: size === 'sm' ? '0.875rem' : size === 'lg' ? '1.25rem' : size === 'xl' ? '1.5rem' : '1rem' }}>
            Scope
          </span>
        </div>
        {(showSubtitle || variant === 'full') && (
          <span
            className="sms-brand-logo__subtitle"
            style={{
              fontSize: size === 'sm' ? '0.625rem' : '0.6875rem',
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--sms-text-muted, #64748b)',
              marginTop: 3,
            }}
          >
            Forensic Cryptographic Engine
          </span>
        )}
      </div>
    </div>
  );
};
