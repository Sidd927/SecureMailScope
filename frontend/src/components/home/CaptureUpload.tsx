import React, { useRef, useState } from 'react';
import { AlertCircle, ArrowRight, CheckCircle2, ChevronDown, ChevronUp, FileCode, HardDrive, Loader2, RefreshCw, UploadCloud, X } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

const ACCEPTED_EXTENSIONS = ['pcap', 'pcapng', 'cap'];

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

async function computeSha256(file: File): Promise<string> {
  try {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return '';
  }
}

interface CaptureUploadProps {
  maxUploadBytes: number | null;
  maxAnalysisSeconds: number | null;
  disabled?: boolean;
}

type IngestPhase =
  | { kind: 'idle' }
  | { kind: 'staged'; file: File; sha256: string; isComputingHash: boolean }
  | { kind: 'analyzing'; file: File; sha256: string }
  | { kind: 'error'; message: string; technicalDetail?: string; file?: File };

export const CaptureUpload: React.FC<CaptureUploadProps> = ({
  maxUploadBytes,
  maxAnalysisSeconds,
  disabled,
}) => {
  const { uploadCapture, setActiveTab } = useInvestigation();
  const [phase, setPhase] = useState<IngestPhase>({ kind: 'idle' });
  const [dragging, setDragging] = useState(false);
  const [showTechError, setShowTechError] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const busy = phase.kind === 'analyzing';

  const validateFile = (file: File): string | null => {
    const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      return `"${file.name}" is not a recognized packet capture format. Please provide a .pcap or .pcapng file.`;
    }
    if (maxUploadBytes != null && file.size > maxUploadBytes) {
      return `"${file.name}" (${formatBytes(file.size)}) exceeds the maximum allowed upload limit of ${formatBytes(maxUploadBytes)}.`;
    }
    return null;
  };

  const stageFile = async (file: File) => {
    const errorMsg = validateFile(file);
    if (errorMsg) {
      setPhase({ kind: 'error', message: errorMsg, file });
      return;
    }

    setPhase({ kind: 'staged', file, sha256: '', isComputingHash: true });

    // Compute SHA-256 in browser asynchronously
    const hash = await computeSha256(file);
    setPhase({ kind: 'staged', file, sha256: hash, isComputingHash: false });
  };

  const handleStartAnalysis = async () => {
    if (phase.kind !== 'staged') return;
    const { file, sha256 } = phase;

    setPhase({ kind: 'analyzing', file, sha256 });
    setShowTechError(false);

    try {
      // Synchronous backend pipeline: upload -> dissection -> rules -> posture
      await uploadCapture(file, { ai: false });
      setActiveTab('overview');
    } catch (err: any) {
      setPhase({
        kind: 'error',
        message: 'The cryptographic analysis engine could not complete processing for this capture.',
        technicalDetail: err?.message || String(err),
        file,
      });
    } finally {
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  const resetToIdle = () => {
    setPhase({ kind: 'idle' });
    setShowTechError(false);
    if (inputRef.current) inputRef.current.value = '';
  };

  const openPicker = () => {
    if (!busy && !disabled) {
      inputRef.current?.click();
    }
  };

  const onDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    if (!busy && !disabled) setDragging(true);
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!busy && !disabled) setDragging(true);
  };

  const onDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    if (!busy && !disabled) setDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (busy || disabled) return;
    const file = e.dataTransfer.files?.[0];
    if (file) {
      stageFile(file);
    }
  };

  return (
    <section className="sms-ingest-bay" aria-labelledby="sms-ingest-title">
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED_EXTENSIONS.map((e) => `.${e}`).join(',')}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) stageFile(f);
        }}
        hidden
        aria-hidden="true"
        tabIndex={-1}
      />

      {/* IDLE STATE: Primary Ingest Action */}
      {phase.kind === 'idle' && (
        <div
          className={`sms-ingest-drop ${dragging ? 'is-dragging' : ''} ${disabled ? 'is-disabled' : ''}`}
          onDragEnter={onDragEnter}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          role="region"
          aria-label="Packet capture ingestion dropzone"
        >
          <div className="sms-ingest-drop__body">
            <div className="sms-ingest-drop__icon-wrap" aria-hidden="true">
              <UploadCloud size={32} className="sms-ingest-drop__icon" />
            </div>

            <div className="sms-ingest-drop__content">
              <h2 id="sms-ingest-title" className="sms-ingest-drop__title">
                Start an Investigation
              </h2>
              <p className="sms-ingest-drop__desc">
                Analyze an email packet capture and produce a cryptographic security posture assessment.
              </p>
            </div>

            <div className="sms-ingest-drop__actions">
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-ingest-btn"
                onClick={openPicker}
                disabled={disabled}
              >
                <HardDrive size={15} aria-hidden="true" />
                <span>Choose PCAP Capture</span>
              </button>
              <span className="sms-ingest-drop__subtext">or drag and drop capture file directly</span>
            </div>

            <div className="sms-ingest-drop__meta-bar">
              <div className="sms-ingest-meta-item">
                <span className="sms-ingest-meta-label">Supported:</span>
                <span className="sms-mono sms-ingest-meta-val">PCAP, PCAPNG, CAP</span>
              </div>
              <span className="sms-header__sep" aria-hidden="true">•</span>
              <div className="sms-ingest-meta-item">
                <span className="sms-ingest-meta-label">Capacity:</span>
                <span className="sms-mono sms-ingest-meta-val">
                  {maxUploadBytes != null ? `Up to ${formatBytes(maxUploadBytes)}` : 'Up to 256 MB'}
                </span>
              </div>
              <span className="sms-header__sep" aria-hidden="true">•</span>
              <div className="sms-ingest-meta-item">
                <span className="sms-ingest-meta-label">Architecture:</span>
                <span className="sms-mono sms-ingest-meta-val">Passive TShark Ingest</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* STAGED STATE: Capture Inspected in Browser, Ready for Backend Ingest */}
      {phase.kind === 'staged' && (
        <div className="sms-ingest-staged" role="region" aria-label="Staged capture confirmation">
          <div className="sms-ingest-staged__head">
            <div className="sms-ingest-staged__title-wrap">
              <CheckCircle2 size={18} className="sms-emerald-icon" aria-hidden="true" />
              <span className="sms-ingest-staged__title">Capture Staged for Forensic Analysis</span>
            </div>
            <button
              type="button"
              className="sms-btn sms-btn--ghost sms-btn--sm"
              onClick={resetToIdle}
              aria-label="Cancel and choose a different capture"
            >
              <X size={14} aria-hidden="true" />
              <span>Change file</span>
            </button>
          </div>

          <div className="sms-ingest-staged__body">
            <div className="sms-ingest-file-card">
              <div className="sms-ingest-file-card__main">
                <FileCode size={24} className="sms-brand-icon" aria-hidden="true" />
                <div className="sms-ingest-file-card__details">
                  <span className="sms-mono sms-ingest-file-card__name" title={phase.file.name}>
                    {phase.file.name}
                  </span>
                  <div className="sms-ingest-file-card__specs">
                    <span className="sms-mono">{formatBytes(phase.file.size)}</span>
                    <span className="sms-header__sep" aria-hidden="true">•</span>
                    <span className="sms-mono">Format: {phase.file.name.split('.').pop()?.toUpperCase()}</span>
                  </div>
                </div>
              </div>

              {/* In-Browser Computed Hash */}
              <div className="sms-ingest-hash-row">
                <span className="sms-mono sms-ingest-hash-label">SHA-256 (computed):</span>
                {phase.isComputingHash ? (
                  <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>
                    Computing cryptographic digest…
                  </span>
                ) : (
                  <span className="sms-mono sms-ingest-hash-val" title={phase.sha256}>
                    {phase.sha256}
                  </span>
                )}
              </div>
            </div>

            <div className="sms-ingest-staged__footer">
              <div className="sms-ingest-staged__assurance">
                <span className="sms-dot" style={{ background: 'var(--ds-emerald-rail)' }} aria-hidden="true" />
                <span>Deterministic rules & cross-session reasoning will be executed locally.</span>
              </div>
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-ingest-execute-btn"
                onClick={handleStartAnalysis}
              >
                <span>Analyze Capture</span>
                <ArrowRight size={15} aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ANALYZING STATE: Honest Indeterminate Analysis Progress */}
      {phase.kind === 'analyzing' && (
        <div className="sms-ingest-analyzing" role="status" aria-live="polite">
          <div className="sms-ingest-analyzing__spinner-wrap">
            <Loader2 size={36} className="sms-spin sms-brand-cyan" aria-hidden="true" />
          </div>
          <div className="sms-ingest-analyzing__content">
            <h3 className="sms-ingest-analyzing__title">
              Dissecting & Scoring {phase.file.name}
            </h3>
            <p className="sms-ingest-analyzing__desc">
              TShark is reconstructing TCP streams, isolating email protocol flows (SMTP, IMAP, POP3), and computing cryptographic posture penalties.
            </p>
            <div className="sms-ingest-analyzing__meta">
              <span className="sms-mono">{formatBytes(phase.file.size)}</span>
              <span className="sms-header__sep" aria-hidden="true">•</span>
              <span className="sms-mono">
                {maxAnalysisSeconds != null
                  ? `Timeout threshold: ${Math.round(maxAnalysisSeconds)}s`
                  : 'Deterministic single-pass pipeline'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ERROR STATE: Human-Readable Forensic Error with Expandable Tech Details */}
      {phase.kind === 'error' && (
        <div className="sms-ingest-error" role="alert">
          <div className="sms-ingest-error__head">
            <div className="sms-ingest-error__title-wrap">
              <AlertCircle size={20} className="sms-crimson-icon" aria-hidden="true" />
              <span className="sms-ingest-error__title">Analysis Could Not Complete</span>
            </div>
            <button
              type="button"
              className="sms-btn sms-btn--ghost sms-btn--sm"
              onClick={resetToIdle}
              aria-label="Dismiss error and return to idle"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>

          <p className="sms-ingest-error__message">{phase.message}</p>

          {phase.technicalDetail && (
            <div className="sms-ingest-error__tech-wrap">
              <button
                type="button"
                className="sms-ingest-error__tech-toggle"
                onClick={() => setShowTechError(!showTechError)}
                aria-expanded={showTechError}
              >
                <span>Technical diagnostic details</span>
                {showTechError ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
              </button>
              {showTechError && (
                <pre className="sms-mono sms-ingest-error__tech-pre">
                  {phase.technicalDetail}
                </pre>
              )}
            </div>
          )}

          <div className="sms-ingest-error__actions">
            {phase.file && (
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-btn--sm"
                onClick={() => stageFile(phase.file!)}
              >
                <RefreshCw size={13} aria-hidden="true" />
                <span>Retry Analysis</span>
              </button>
            )}
            <button
              type="button"
              className="sms-btn sms-btn--sm"
              onClick={openPicker}
            >
              <HardDrive size={13} aria-hidden="true" />
              <span>Choose Different Capture</span>
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
