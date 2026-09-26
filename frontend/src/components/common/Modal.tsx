import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  title: string;
  onClose: () => void;
  width?: number;
  children: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({ title, onClose, width, children }) => {
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      previous?.focus();
    };
  }, [onClose]);

  return (
    <div className="sms-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={dialogRef} className="sms-modal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} style={width ? { maxWidth: width } : undefined}>
        <header className="sms-modal__head">
          <h2 className="sms-modal__title">{title}</h2>
          <button type="button" className="sms-btn sms-btn--ghost sms-btn--sm" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </button>
        </header>
        <div className="sms-modal__body">{children}</div>
      </div>
    </div>
  );
};
