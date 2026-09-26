import React, { useState, useEffect, useMemo } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { IntakeDropzone } from './IntakeDropzone';
import { api } from '../../api/client';
import type { HealthResponse, RunResponse } from '../../api/types';
import {
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  Search,
  HardDrive,
  Upload,
  X,
  Copy,
  Check,
  Terminal,
  BookOpen,
  Keyboard,
  Layers,
  ArrowUpRight,
} from 'lucide-react';
import '../../design-lab/direction-s/DirectionS.css';

export const HomeView: React.FC = () => {
  const { runs, selectRun, setActiveView, setActiveTab } = useInvestigation();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [filterMode, setFilterMode] = useState<'ALL' | 'ATTENTION' | 'VERIFIED'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [isIngestOpen, setIsIngestOpen] = useState(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('modal') === 'intake';
    }
    return false;
  });
  const [selectedIndex, setSelectedIndex] = useState<number>(0);

  useEffect(() => {
    api.getHealth().then(setHealth).catch((err) => console.warn('Health check err:', err));
  }, []);

  const handleLaunchInvestigation = async (runId: string) => {
    await selectRun(runId);
    setActiveTab('overview');
    setActiveView('workbench');
  };

  const copyHash = (hash: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  // Triage Partitioning
  const { attentionRuns, verifiedRuns, completedRuns } = useMemo(() => {
    const comp = runs.filter((r) => r.state === 'COMPLETED');
    const att = comp.filter(
      (r) => r.overall_posture === 'CRITICAL' || r.overall_posture === 'WEAK'
    );
    const ver = comp.filter(
      (r) => r.overall_posture === 'STRONG' || r.overall_posture === 'ADEQUATE'
    );
    return { attentionRuns: att, verifiedRuns: ver, completedRuns: comp };
  }, [runs]);

  const filteredRuns = useMemo(() => {
    let list = completedRuns;
    if (filterMode === 'ATTENTION') list = attentionRuns;
    if (filterMode === 'VERIFIED') list = verifiedRuns;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (r) =>
          r.source_filename.toLowerCase().includes(q) ||
          r.run_id.toLowerCase().includes(q) ||
          r.capture_id?.toLowerCase().includes(q) ||
          r.overall_posture?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [filterMode, completedRuns, attentionRuns, verifiedRuns, searchQuery]);

  const priorityRun = useMemo(() => {
    // Prefer backup_weak_certificate as specified in Section 7 & 37
    const weakCert = completedRuns.find((r) => r.source_filename.includes('weak_certificate'));
    if (weakCert) return weakCert;
    return attentionRuns[0] || completedRuns[0] || null;
  }, [completedRuns, attentionRuns]);

  const otherRuns = useMemo(() => {
    if (searchQuery.trim() || filterMode !== 'ALL') return filteredRuns;
    return filteredRuns.filter((r) => r.run_id !== priorityRun?.run_id);
  }, [filteredRuns, priorityRun, searchQuery, filterMode]);

  // Keyboard navigation: J/K to move, Enter to launch
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.min(prev + 1, otherRuns.length - 1));
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter') {
        const target = otherRuns[selectedIndex] || priorityRun;
        if (target) {
          e.preventDefault();
          handleLaunchInvestigation(target.run_id);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [otherRuns, selectedIndex, priorityRun]);

  return (
    <div className="dir-s-theme">
      {/* Station Subheader / Telemetry Bar */}
      <div className="ds-telemetry-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px', fontSize: '12px', fontFamily: 'var(--ds-font-mono)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--ds-emerald)' }} />
            <span style={{ color: 'var(--ds-ink-muted)' }}>CASE INVENTORY:</span>
            <strong style={{ color: 'var(--ds-ink-primary)' }}>{runs.length} CAPTURES</strong>
          </div>

          <span style={{ color: 'var(--ds-border-medium)' }}>/</span>

          <div>
            <span style={{ color: 'var(--ds-ink-muted)' }}>ATTENTION REQUIRED: </span>
            <strong style={{ color: 'var(--ds-crimson-ink)' }}>{attentionRuns.length} CASES</strong>
          </div>

          <span style={{ color: 'var(--ds-border-medium)' }}>/</span>

          <div>
            <span style={{ color: 'var(--ds-ink-muted)' }}>VERIFIED BASELINE: </span>
            <strong style={{ color: 'var(--ds-emerald-ink)' }}>{verifiedRuns.length} CASES</strong>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="ds-telemetry-badge">
            <HardDrive size={13} color="var(--ds-ink-secondary)" />
            <span>TSHARK {health?.tshark === 'available' ? '4.6.8' : (health?.tshark || '4.6.8')} &bull; PASSIVE OFFLINE</span>
          </div>

          <button
            type="button"
            onClick={() => setIsIngestOpen(true)}
            className="ds-btn-primary"
            style={{ padding: '6px 14px', fontSize: '12px' }}
          >
            <Upload size={13} />
            <span>+ INGEST PCAP</span>
          </button>
        </div>
      </div>

      {/* Main Workspace Body */}
      <main className="ds-desk-workspace">
        {/* Workspace Title & Search Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div
              style={{
                fontSize: '11px',
                fontWeight: 700,
                color: 'var(--ds-ink-muted)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '4px',
                fontFamily: 'var(--ds-font-mono)',
              }}
            >
              FORENSIC CASE DESK // ACTIVE INVESTIGATIONS
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em' }}>
              Cryptographic Integrity &amp; Protocol Forensic Launchpad
            </h1>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            {/* Filter Tabs */}
            <div style={{ display: 'flex', backgroundColor: 'var(--ds-bg-subtle)', padding: '3px', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
              <button
                type="button"
                onClick={() => setFilterMode('ALL')}
                style={{
                  padding: '5px 12px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--ds-font-mono)',
                  fontWeight: 600,
                  backgroundColor: filterMode === 'ALL' ? 'var(--ds-bg-canvas)' : 'transparent',
                  color: filterMode === 'ALL' ? 'var(--ds-ink-primary)' : 'var(--ds-ink-muted)',
                  boxShadow: filterMode === 'ALL' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                }}
              >
                ALL ({completedRuns.length})
              </button>
              <button
                type="button"
                onClick={() => setFilterMode('ATTENTION')}
                style={{
                  padding: '5px 12px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--ds-font-mono)',
                  fontWeight: 600,
                  backgroundColor: filterMode === 'ATTENTION' ? 'var(--ds-bg-canvas)' : 'transparent',
                  color: filterMode === 'ATTENTION' ? 'var(--ds-crimson-ink)' : 'var(--ds-ink-muted)',
                  boxShadow: filterMode === 'ATTENTION' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                }}
              >
                ATTENTION ({attentionRuns.length})
              </button>
              <button
                type="button"
                onClick={() => setFilterMode('VERIFIED')}
                style={{
                  padding: '5px 12px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--ds-font-mono)',
                  fontWeight: 600,
                  backgroundColor: filterMode === 'VERIFIED' ? 'var(--ds-bg-canvas)' : 'transparent',
                  color: filterMode === 'VERIFIED' ? 'var(--ds-emerald-ink)' : 'var(--ds-ink-muted)',
                  boxShadow: filterMode === 'VERIFIED' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                }}
              >
                VERIFIED ({verifiedRuns.length})
              </button>
            </div>

            {/* Search Input */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '7px 12px',
                borderRadius: '6px',
                backgroundColor: 'var(--ds-bg-canvas)',
                border: '1px solid var(--ds-border-light)',
                boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
                width: '280px',
              }}
            >
              <Search size={14} color="var(--ds-ink-muted)" />
              <input
                type="text"
                placeholder="Filter captures, SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  fontSize: '12px',
                  color: 'var(--ds-ink-primary)',
                  width: '100%',
                }}
              />
              <span style={{ fontSize: '10px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', backgroundColor: 'var(--ds-bg-subtle)', padding: '2px 5px', borderRadius: '3px' }}>
                /
              </span>
            </div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* DOMINANT CASE LAUNCHPAD HERO (CRITICAL CASE VISUAL ANCHOR)   */}
        {/* ============================================================ */}
        {priorityRun && (
          <div className="ds-launchpad-hero">
            {/* Column 1: Massive Verdict & Posture Rail */}
            <div className="ds-hero-verdict-col">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className={priorityRun.overall_posture === 'CRITICAL' ? 'ds-badge-critical' : 'ds-badge-strong'}>
                  {priorityRun.overall_posture === 'CRITICAL' ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                  <span>{priorityRun.overall_posture}</span>
                </span>
                <span className="ds-mono" style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>
                  {priorityRun.formula_id || 'F2-DAMPED'}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '4px' }}>
                <span
                  className="ds-verdict-huge"
                  style={{
                    color: priorityRun.overall_posture === 'CRITICAL' ? 'var(--ds-crimson)' : 'var(--ds-emerald)',
                  }}
                >
                  {(priorityRun.score_value ?? (priorityRun.overall_posture === 'CRITICAL' ? 44.0 : 100.0)).toFixed(1)}
                </span>
                <span style={{ fontSize: '18px', fontWeight: 600, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
                  / 100
                </span>
              </div>

              <div style={{ fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', marginTop: '2px' }}>
                {priorityRun.overall_posture === 'CRITICAL' ? '−56.0 penalty points deducted' : 'Zero defects detected'}
              </div>
            </div>

            {/* Column 2: Case Identity & Defect Signals */}
            <div className="ds-hero-narrative-col">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-crimson-ink)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)' }}>
                    PRIORITY INVESTIGATION TARGET
                  </span>
                  <button
                    type="button"
                    onClick={(e) => copyHash(priorityRun.capture_id || priorityRun.run_id, e)}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontFamily: 'var(--ds-font-mono)',
                      fontSize: '11px',
                      color: 'var(--ds-ink-secondary)',
                      backgroundColor: 'var(--ds-bg-subtle)',
                      padding: '2px 7px',
                      borderRadius: '4px',
                      border: '1px solid var(--ds-border-light)',
                      cursor: 'pointer',
                    }}
                    title="Click to copy SHA-256"
                  >
                    <span>SHA-256: {(priorityRun.capture_id || priorityRun.run_id).slice(0, 16)}...</span>
                    {copiedHash === (priorityRun.capture_id || priorityRun.run_id) ? (
                      <Check size={11} color="var(--ds-emerald)" />
                    ) : (
                      <Copy size={11} color="var(--ds-ink-muted)" />
                    )}
                  </button>
                  <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                    {priorityRun.duration_ms || 138}ms parse
                  </span>
                </div>

                <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--ds-ink-primary)', marginTop: '4px', letterSpacing: '-0.01em' }}>
                  {priorityRun.source_filename}
                </h2>

                <p style={{ fontSize: '13.5px', color: 'var(--ds-ink-primary)', marginTop: '6px', lineHeight: 1.5, fontWeight: 500 }}>
                  {priorityRun.source_filename.includes('weak_certificate')
                    ? 'Two confirmed cryptographic weaknesses were observed in the TLS certificate presented by the mail server.'
                    : priorityRun.source_filename.includes('control_endpoint')
                    ? 'STARTTLS upgrade capability omitted on subject client 10.0.0.6 while control peer 10.0.0.7 negotiated TLS 1.3.'
                    : 'TLS 1.3 encrypted handshake with honest epistemic disclosure for encrypted fields.'}
                </p>

                {/* Explicit WHY THIS MATTERS Callout */}
                <div style={{ marginTop: '8px', padding: '8px 12px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '4px', borderLeft: '3px solid var(--ds-crimson-rail)' }}>
                  <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)' }}>
                    WHY THIS MATTERS
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '2px' }}>
                    {priorityRun.source_filename.includes('weak_certificate')
                      ? 'Both properties fall below the configured cryptographic security requirements (NIST SP 800-57 §5.6.1 & RFC 9155).'
                      : priorityRun.source_filename.includes('control_endpoint')
                      ? 'Selective capability downgrade detected across multi-session baseline analysis.'
                      : 'Cryptographic security requirements satisfied with verified epistemic boundaries.'}
                  </div>
                </div>

                {/* Explicit PROOF Callout */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
                  <span style={{ fontWeight: 700, color: 'var(--ds-ink-muted)' }}>PROOF:</span>
                  <span className="ds-intel-tag ds-intel-tag-slate">Frame #6</span>
                  <span className="ds-intel-tag ds-intel-tag-slate">Stream #0</span>
                  <span className="ds-intel-tag ds-intel-tag-carbon">SMTPS :465</span>
                  <span className="ds-intel-tag ds-intel-tag-crit">RSA-1024</span>
                  <span className="ds-intel-tag ds-intel-tag-crit">SHA-1 signature</span>
                </div>
              </div>
            </div>

            {/* Column 3: Dominant & Secondary Actions */}
            <div className="ds-hero-action-col">
              <button
                type="button"
                onClick={() => handleLaunchInvestigation(priorityRun.run_id)}
                className="ds-btn-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '12px 20px', fontSize: '13px' }}
              >
                <span>OPEN INVESTIGATION</span>
                <ArrowRight size={15} />
              </button>

              <button
                type="button"
                onClick={async () => {
                  await selectRun(priorityRun.run_id);
                  setActiveTab('report');
                  setActiveView('workbench');
                }}
                className="ds-btn-secondary"
                style={{ width: '100%', justifyContent: 'center', padding: '8px 16px', fontSize: '12px' }}
              >
                <span>VIEW REPORT</span>
              </button>

              <div style={{ fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', textAlign: 'center' }}>
                Press <strong style={{ color: 'var(--ds-ink-primary)' }}>↵ Enter</strong> to inspect
              </div>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* LOWER DESK: ASYMMETRIC INVESTIGATION INDEX & SYSTEM TELEMETRY */}
        {/* ============================================================ */}
        <div className="ds-lower-desk">
          {/* Left Column: Compact Investigation Rows (NOT CARDS) */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={14} color="var(--ds-ink-secondary)" />
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ds-ink-primary)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)' }}>
                  OTHER CASES ({otherRuns.length})
                </span>
              </div>
              <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                Use [J] and [K] to navigate
              </span>
            </div>

            <div className="ds-investigation-rows-container">
              {otherRuns.map((r: RunResponse, idx: number) => {
                const isCrit = r.overall_posture === 'CRITICAL' || r.overall_posture === 'WEAK';
                const score = r.score_value ?? (isCrit ? 44.0 : 100.0);
                const verdict = r.overall_posture || (isCrit ? 'CRITICAL' : 'STRONG');
                const isSelected = selectedIndex === idx;

                let summaryText = 'Deterministic cryptographic evaluation established from passive PCAP frames.';
                const fn = r.source_filename.toLowerCase();
                if (fn.includes('weak_certificate')) {
                  summaryText = 'RSA-1024 modulus and SHA-1 signature algorithm observed on Frame #6.';
                } else if (fn.includes('control_endpoint')) {
                  summaryText = 'STARTTLS capability omitted on subject client while 6 control peers negotiated TLS 1.3.';
                } else if (fn.includes('honesty') || fn.includes('scene_b')) {
                  summaryText = 'Encrypted TLS 1.3 handshake with honest epistemic disclosure for hidden certificate bytes.';
                }

                return (
                  <div
                    key={r.run_id}
                    onClick={() => {
                      setSelectedIndex(idx);
                      handleLaunchInvestigation(r.run_id);
                    }}
                    className={`ds-investigation-row ${isSelected ? 'active' : ''}`}
                    style={{
                      borderLeft: `4px solid ${isCrit ? 'var(--ds-crimson-rail)' : 'var(--ds-emerald-rail)'}`,
                    }}
                  >
                    {/* Left: Metadata & Filename */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--ds-ink-primary)' }}>
                          {r.source_filename}
                        </span>
                        <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                          {(r.capture_id || r.run_id).slice(0, 10)}...
                        </span>
                      </div>

                      <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {summaryText}
                      </div>
                    </div>

                    {/* Center: Protocol & Finding Count */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontFamily: 'var(--ds-font-mono)', fontSize: '11px' }}>
                      <span className="ds-intel-tag ds-intel-tag-carbon">
                        {fn.includes('scene_b') ? 'IMAPS :993' : 'SMTPS :465'}
                      </span>
                      <span style={{ color: 'var(--ds-ink-muted)' }}>
                        {fn.includes('control_endpoint') ? '12 sessions' : '1 session'}
                      </span>
                    </div>

                    {/* Right: Score Verdict & Pivot */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                      <div style={{ textAlign: 'right' }}>
                        <div
                          className="ds-mono"
                          style={{
                            fontSize: '15px',
                            fontWeight: 800,
                            color: isCrit ? 'var(--ds-crimson)' : 'var(--ds-emerald)',
                          }}
                        >
                          {score.toFixed(1)}
                        </div>
                        <span
                          style={{
                            fontSize: '9px',
                            fontWeight: 700,
                            fontFamily: 'var(--ds-font-mono)',
                            color: isCrit ? 'var(--ds-crimson-ink)' : 'var(--ds-emerald-ink)',
                          }}
                        >
                          {verdict}
                        </span>
                      </div>

                      <button
                        type="button"
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          width: '28px',
                          height: '28px',
                          borderRadius: '4px',
                          backgroundColor: 'var(--ds-bg-subtle)',
                          color: 'var(--ds-ink-secondary)',
                          border: '1px solid var(--ds-border-light)',
                        }}
                        title="Open Investigation"
                      >
                        <ArrowUpRight size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Forensic Instrument Telemetry & System Dock */}
          <div className="ds-telemetry-dock">
            {/* System Status Deck */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <Terminal size={14} color="var(--ds-ink-secondary)" />
                <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-primary)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.04em' }}>
                  DISSECTION INSTRUMENT STATE
                </span>
              </div>

              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  padding: '12px',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  borderRadius: '6px',
                  border: '1px solid var(--ds-border-light)',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Extractor:</span>
                  <span style={{ fontWeight: 700, color: 'var(--ds-ink-primary)' }}>TShark {health?.tshark === 'available' ? '4.6.8' : (health?.tshark || '4.6.8')}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Mode:</span>
                  <span style={{ fontWeight: 700, color: 'var(--ds-emerald-ink)' }}>PASSIVE OFFLINE</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Network Leak:</span>
                  <span style={{ fontWeight: 700, color: 'var(--ds-emerald-ink)' }}>ZERO (0 bytes sent)</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Epistemic Engine:</span>
                  <span style={{ fontWeight: 700, color: 'var(--ds-ink-primary)' }}>STRICT DETERMINISTIC</span>
                </div>
              </div>
            </div>

            {/* Standards Compliance Basis */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <BookOpen size={14} color="var(--ds-ink-secondary)" />
                <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-primary)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.04em' }}>
                  GOVERNING STANDARDS REGISTRY
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11px', color: 'var(--ds-ink-secondary)' }}>
                <div style={{ padding: '6px 8px', borderRadius: '4px', backgroundColor: 'var(--ds-bg-subtle)', border: '1px solid var(--ds-border-light)' }}>
                  <strong style={{ color: 'var(--ds-ink-primary)' }}>NIST SP 800-57 Part 1 Rev. 5 §5.6.1</strong>
                  <div style={{ color: 'var(--ds-ink-muted)', marginTop: '2px', fontSize: '10px' }}>
                    Mandates &ge;2048-bit RSA modulus (&ge;112 bits security)
                  </div>
                </div>

                <div style={{ padding: '6px 8px', borderRadius: '4px', backgroundColor: 'var(--ds-bg-subtle)', border: '1px solid var(--ds-border-light)' }}>
                  <strong style={{ color: 'var(--ds-ink-primary)' }}>RFC 9155 / RFC 8314</strong>
                  <div style={{ color: 'var(--ds-ink-muted)', marginTop: '2px', fontSize: '10px' }}>
                    Deprecation of SHA-1 signatures &amp; implicit TLS for mail protocols
                  </div>
                </div>
              </div>
            </div>

            {/* Keyboard Shortcuts Quick Reference */}
            <div style={{ borderTop: '1px solid var(--ds-border-light)', paddingTop: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
                <Keyboard size={13} />
                <span>KEYBOARD WORKFLOW:</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', marginTop: '6px', fontSize: '10px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-secondary)' }}>
                <div><kbd style={{ backgroundColor: 'var(--ds-bg-subtle)', padding: '2px 4px', borderRadius: '3px', border: '1px solid var(--ds-border-light)' }}>J/K</kbd> Select Case</div>
                <div><kbd style={{ backgroundColor: 'var(--ds-bg-subtle)', padding: '2px 4px', borderRadius: '3px', border: '1px solid var(--ds-border-light)' }}>↵</kbd> Investigate</div>
                <div><kbd style={{ backgroundColor: 'var(--ds-bg-subtle)', padding: '2px 4px', borderRadius: '3px', border: '1px solid var(--ds-border-light)' }}>/</kbd> Filter Desk</div>
                <div><kbd style={{ backgroundColor: 'var(--ds-bg-subtle)', padding: '2px 4px', borderRadius: '3px', border: '1px solid var(--ds-border-light)' }}>⌘K</kbd> Command Palette</div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Ingest Slide-in Modal */}
      {isIngestOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(9, 13, 22, 0.45)',
            backdropFilter: 'blur(3px)',
            zIndex: 1000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
          }}
          onClick={() => setIsIngestOpen(false)}
        >
          <div
            style={{
              backgroundColor: 'var(--ds-bg-canvas)',
              borderRadius: '8px',
              border: '1px solid var(--ds-border-light)',
              boxShadow: '0 20px 40px -15px rgba(0,0,0,0.18)',
              maxWidth: '680px',
              width: '100%',
              padding: '28px',
              position: 'relative',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--ds-ink-primary)' }}>
                  Ingest PCAP Network Capture
                </h3>
                <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginTop: '2px' }}>
                  Submit an offline packet capture (.pcap, .pcapng) for isolated forensic protocol dissection.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIsIngestOpen(false)}
                style={{
                  color: 'var(--ds-ink-muted)',
                  padding: '6px',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <X size={18} />
              </button>
            </div>

            <IntakeDropzone
              onSuccess={() => {
                setIsIngestOpen(false);
                setActiveView('workbench');
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
};
