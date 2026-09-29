import React, { useRef, useState } from 'react';
import { AlertCircle, ArrowRight, CheckCircle2, ChevronDown, ChevronUp, FileCode, RefreshCw, Upload, X } from 'lucide-react';
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

const ANALYSIS_STAGES = [
  'Reading capture',
  'Analyzing packets',
  'Reconstructing sessions',
  'Inspecting protocols',
  'Building security assessment',
] as const;

type IngestPhase =
  | { kind: 'idle' }
  | { kind: 'staged'; file: File; sha256: string; isComputingHash: boolean }
  | { kind: 'analyzing'; file: File; sha256: string; stage: number }
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

    setPhase({ kind: 'analyzing', file, sha256, stage: 0 });
    setShowTechError(false);
    const started = performance.now();
    const timer = window.setInterval(() => {
      setPhase((current) => (
        current.kind === 'analyzing'
          ? { ...current, stage: Math.min(current.stage + 1, ANALYSIS_STAGES.length - 1) }
          : current
      ));
    }, 720);

    try {
      await uploadCapture(file, { ai: false });
      const remain = 3600 - (performance.now() - started);
      if (remain > 0) await new Promise((resolve) => window.setTimeout(resolve, remain));
      setActiveTab('overview');
    } catch (err: any) {
      setPhase({
        kind: 'error',
        message: 'This recording could not be checked.',
        technicalDetail: err?.message || String(err),
        file,
      });
    } finally {
      window.clearInterval(timer);
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
    <section id="sms-intake" className="sms-ingest-bay" aria-labelledby="sms-ingest-title">
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
          aria-label="Upload a saved email recording"
        >
          <div className="sms-ingest-drop__body">
            <div className="sms-ingest-drop__icon-wrap" aria-hidden="true">
              <Upload size={18} className="sms-ingest-drop__icon" />
            </div>

            <div className="sms-ingest-drop__content">
              <h2 id="sms-ingest-title" className="sms-ingest-drop__title">
                Check a recording
              </h2>
              <p className="sms-ingest-drop__desc">
                Upload a saved email capture. You get a score and a short report.
              </p>
            </div>

            <div className="sms-ingest-drop__actions">
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-ingest-btn"
                onClick={openPicker}
                disabled={disabled}
              >
                <Upload size={15} aria-hidden="true" />
                <span>Choose file</span>
              </button>
              <span className="sms-ingest-drop__subtext">or drag and drop it here</span>
            </div>

            <p className="sms-ingest-drop__foot">
              .pcap, .pcapng, or .cap
              <span aria-hidden="true"> · </span>
              {maxUploadBytes != null ? `up to ${formatBytes(maxUploadBytes)}` : 'up to 256 MB'}
            </p>
          </div>
        </div>
      )}

      {/* STAGED STATE: Capture Inspected in Browser, Ready for Backend Ingest */}
      {phase.kind === 'staged' && (
        <div className="sms-ingest-staged" role="region" aria-label="Staged capture confirmation">
          <div className="sms-ingest-staged__head">
            <div className="sms-ingest-staged__title-wrap">
              <CheckCircle2 size={18} className="sms-emerald-icon" aria-hidden="true" />
              <span className="sms-ingest-staged__title">Capture staged for forensic analysis</span>
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
                <span className="sms-ingest-hash-label">SHA-256</span>
                {phase.isComputingHash ? (
                  <span className="sms-mono sms-ingest-hash-val">Computing…</span>
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
          <div className="sms-analyze-visual" aria-hidden="true">
            <span className="sms-analyze-ring" />
            <span className="sms-analyze-scan" />
            <span className="sms-analyze-packet" />
            <span className="sms-analyze-packet sms-analyze-packet--b" />
          </div>
          <div className="sms-ingest-analyzing__content">
            <h3 className="sms-ingest-analyzing__title">{ANALYSIS_STAGES[phase.stage]}</h3>
            <ol className="sms-analyze-stages">
              {ANALYSIS_STAGES.map((label, index) => (
                <li key={label} className={index === phase.stage ? 'is-on' : index < phase.stage ? 'is-done' : ''}>
                  {label}
                </li>
              ))}
            </ol>
            <div className="sms-ingest-analyzing__meta">
              <span className="sms-mono">{phase.file.name}</span>
              <span className="sms-header__sep" aria-hidden="true">·</span>
              <span className="sms-mono">{formatBytes(phase.file.size)}</span>
              {maxAnalysisSeconds != null && (
                <span className="sms-mono">({Math.round(maxAnalysisSeconds)}s limit)</span>
              )}
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
              <span className="sms-ingest-error__title">This recording could not be checked</span>
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
              <Upload size={13} aria-hidden="true" />
              <span>Choose a different file</span>
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
