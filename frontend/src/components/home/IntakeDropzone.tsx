import React, { useState, useRef } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { Upload, FileCode, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

interface IntakeDropzoneProps {
  onSuccess?: () => void;
}

export const IntakeDropzone: React.FC<IntakeDropzoneProps> = ({ onSuccess }) => {
  const { uploadCapture, isLoading } = useInvestigation();
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [enableAi, setEnableAi] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (isValidPcap(file.name)) {
        setSelectedFile(file);
        setUploadError(null);
      } else {
        setUploadError('Selected file must be a packet capture (.pcap, .pcapng, .cap)');
      }
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (isValidPcap(file.name)) {
        setSelectedFile(file);
        setUploadError(null);
      } else {
        setUploadError('Selected file must be a packet capture (.pcap, .pcapng, .cap)');
      }
    }
  };

  const isValidPcap = (name: string) => {
    const ext = name.split('.').pop()?.toLowerCase();
    return ext === 'pcap' || ext === 'pcapng' || ext === 'cap';
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;
    setUploadError(null);
    try {
      await uploadCapture(selectedFile, { ai: enableAi });
      if (onSuccess) onSuccess();
    } catch (err: any) {
      setUploadError(err.message || 'Analysis failed to process capture');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--color-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--color-border)',
        overflow: 'hidden',
        boxShadow: 'var(--shadow-subtle)',
      }}
    >
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-panel)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              color: 'var(--color-ink-muted)',
              letterSpacing: '0.06em',
            }}
          >
            Investigation Intake
          </span>
          <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
            Submit Packet Capture Artifact
          </h2>
        </div>
        <span
          style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            padding: '2px 8px',
            backgroundColor: 'var(--color-panel-card)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-xs)',
            color: 'var(--color-ink-muted)',
          }}
        >
          Passive Offline Analysis
        </span>
      </div>

      <div style={{ padding: '20px' }}>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleChange}
          style={{ display: 'none' }}
        />

        {/* Drop Target */}
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: `2px dashed ${
              dragActive
                ? 'var(--color-accent)'
                : selectedFile
                  ? 'var(--color-border-strong)'
                  : 'var(--color-border)'
            }`,
            backgroundColor: dragActive
              ? 'var(--color-accent-soft)'
              : selectedFile
                ? 'var(--color-panel-card)'
                : 'var(--color-page)',
            borderRadius: 'var(--radius-sm)',
            padding: '28px 20px',
            textAlign: 'center',
            cursor: 'pointer',
            transition: 'all var(--transition-fast)',
          }}
        >
          {selectedFile ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
              <div
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--color-accent-soft)',
                  color: 'var(--color-accent)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <FileCode size={22} />
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-ink)' }}>
                  {selectedFile.name}
                </div>
                <div
                  style={{
                    fontSize: 'var(--text-xs)',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-ink-muted)',
                    marginTop: '2px',
                  }}
                >
                  Size: {formatBytes(selectedFile.size)} • Type: PCAP
                </div>
              </div>
              <span
                style={{
                  fontSize: '11px',
                  color: 'var(--color-accent)',
                  fontWeight: 600,
                  marginTop: '4px',
                }}
              >
                Click to change file
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--color-panel)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-ink-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Upload size={18} />
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-ink)' }}>
                  Drop PCAP capture file here or click to browse
                </div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-ink-muted)', marginTop: '4px' }}>
                  Supports SMTP, IMAP, and POP3 captures (.pcap, .pcapng) up to 256 MB
                </div>
              </div>
            </div>
          )}
        </div>

        {uploadError && (
          <div
            style={{
              marginTop: '12px',
              padding: '10px 14px',
              backgroundColor: 'var(--color-sev-critical-bg)',
              border: '1px solid var(--color-sev-critical-border)',
              borderRadius: 'var(--radius-xs)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              color: 'var(--color-sev-critical)',
              fontSize: 'var(--text-xs)',
            }}
          >
            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
            <span>{uploadError}</span>
          </div>
        )}

        {/* Options & Action Row */}
        <div
          style={{
            marginTop: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '16px',
            borderTop: '1px solid var(--color-border)',
          }}
        >
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: 'var(--text-xs)',
              color: 'var(--color-ink-secondary)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              checked={enableAi}
              onChange={(e) => setEnableAi(e.target.checked)}
              style={{ accentColor: 'var(--color-accent)' }}
            />
            <span>Enable secondary AI anomaly lane (?ai=true)</span>
          </label>

          <button
            type="button"
            disabled={!selectedFile || isLoading}
            onClick={handleAnalyze}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 18px',
              backgroundColor: selectedFile && !isLoading ? 'var(--color-accent)' : 'var(--color-panel-muted)',
              color: selectedFile && !isLoading ? '#ffffff' : 'var(--color-ink-faint)',
              fontSize: 'var(--text-xs)',
              fontWeight: 700,
              borderRadius: 'var(--radius-sm)',
              cursor: selectedFile && !isLoading ? 'pointer' : 'not-allowed',
              boxShadow: selectedFile && !isLoading ? 'var(--shadow-subtle)' : 'none',
              transition: 'all var(--transition-fast)',
            }}
          >
            {isLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                <span>Running Forensic Pipeline…</span>
              </>
            ) : (
              <>
                <CheckCircle2 size={14} />
                <span>Execute Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
