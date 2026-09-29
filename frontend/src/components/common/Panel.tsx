import React from 'react';

interface PanelProps {
  title?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  flush?: boolean;
  className?: string;
  children: React.ReactNode;
  'aria-label'?: string;
}

export const Panel: React.FC<PanelProps> = ({ title, meta, actions, flush, className, children, ...rest }) => (
  <section className={`sms-panel${className ? ` ${className}` : ''}`} aria-label={rest['aria-label'] ?? (typeof title === 'string' ? title : undefined)}>
    {(title || meta || actions) && (
      <header className="sms-panel__head">
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--ds-space-8)', minWidth: 0 }}>
          {title && <h3 className="sms-panel__title">{title}</h3>}
          {meta && <span className="sms-panel__meta">{meta}</span>}
        </div>
        {actions}
      </header>
    )}
    <div className={flush ? 'sms-panel__body sms-panel__body--flush' : 'sms-panel__body'}>{children}</div>
  </section>
);
