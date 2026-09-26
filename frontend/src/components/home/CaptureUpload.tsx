import React, { useRef, useState } from 'react';
import { AlertTriangle, Loader2, Upload } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

const ACCEPTED = ['pcap', 'pcapng', 'cap'];

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(0)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(0)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}

interface Props {
  /** From GET /health; the limits line is omitted when health is unavailable. */
  maxUploadBytes: number | null;
  maxAnalysisSeconds: number | null;
  disabled?: boolean;
}

type Phase = { kind: 'idle' } | { kind: 'analysing'; file: File } | { kind: 'error'; message: string };

export const CaptureUpload: React.FC<Props> = ({ maxUploadBytes, maxAnalysisSeconds, disabled }) => {
  const { uploadCapture, setActiveTab } = useInvestigation();
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const busy = phase.kind === 'analysing';

  const start = async (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
    if (!ACCEPTED.includes(ext)) {
      setPhase({ kind: 'error', message: `${file.name} is not a packet capture. Choose a .pcap or .pcapng file.` });
      return;
    }
    if (maxUploadBytes != null && file.size > maxUploadBytes) {
      setPhase({ kind: 'error', message: `${file.name} is ${formatBytes(file.size)}; the engine accepts up to ${formatBytes(maxUploadBytes)}.` });
      return;
    }
    setPhase({ kind: 'analysing', file });
    try {
      // The backend analyses synchronously and returns the finished run, so there is
      // no real progress to report: the zone shows an indeterminate state until it returns.
      await uploadCapture(file, { ai: false });
      setActiveTab('overview');
    } catch (err: any) {
      setPhase({ kind: 'error', message: err?.message || 'Capture analysis failed' });
    } finally {
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  const openPicker = () => { if (!busy && !disabled) inputRef.current?.click(); };

  const onDrag = (e: React.DragEvent, over: boolean) => {
    e.preventDefault();
    if (!busy && !disabled) setDragging(over);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file && !busy && !disabled) start(file);
  };

  const cls = ['sms-drop', dragging && 'is-dragging', busy && 'is-busy', phase.kind === 'error' && 'is-error'].filter(Boolean).join(' ');

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED.map((e) => `.${e}`).join(',')}
        onChange={(e) => { const f = e.target.files?.[0]; if (f) start(f); }}
        hidden
        aria-hidden="true"
        tabIndex={-1}
      />
      <button
        type="button"
        className={cls}
        onClick={openPicker}
        onDragEnter={(e) => onDrag(e, true)}
        onDragOver={(e) => onDrag(e, true)}
        onDragLeave={(e) => onDrag(e, false)}
        onDrop={onDrop}
        disabled={disabled}
        aria-busy={busy}
        aria-describedby="sms-drop-status"
      >
        {phase.kind === 'analysing' ? (
          <>
            <Loader2 size={48} strokeWidth={1.25} className="sms-drop__icon sms-spin" aria-hidden="true" />
            <span className="sms-drop__title">Analysing {phase.file.name}</span>
            <span id="sms-drop-status" className="sms-drop__hint" role="status">
              {formatBytes(phase.file.size)} uploaded. The engine is dissecting sessions and scoring posture
              {maxAnalysisSeconds != null ? `; it stops after ${Math.round(maxAnalysisSeconds / 60)} minutes.` : '.'}
            </span>
          </>
        ) : phase.kind === 'error' ? (
          <>
            <AlertTriangle size={48} strokeWidth={1.25} className="sms-drop__icon" style={{ color: 'var(--ds-crimson-ink)' }} aria-hidden="true" />
            <span className="sms-drop__title">Analysis did not complete</span>
            <span id="sms-drop-status" className="sms-drop__hint" role="alert">{phase.message}</span>
            <span className="sms-drop__hint">Drop another capture or click to choose one.</span>
          </>
        ) : (
          <>
            <Upload size={48} strokeWidth={1.25} className="sms-drop__icon" aria-hidden="true" />
            <span className="sms-drop__title">Drop a .pcap capture file</span>
            <span id="sms-drop-status" className="sms-drop__hint">or click to browse</span>
            <span className="sms-drop__formats">
              Supports: PCAP, PCAPNG{maxUploadBytes != null && ` · up to ${formatBytes(maxUploadBytes)}`}
            </span>
          </>
        )}
      </button>
    </>
  );
};
