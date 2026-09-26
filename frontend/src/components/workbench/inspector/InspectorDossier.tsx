import React, { useEffect } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  X,
  ExternalLink,
  ArrowRight,
  KeyRound,
} from 'lucide-react';

interface InspectorDossierProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const InspectorDossier: React.FC<InspectorDossierProps> = ({
  isOpen: propsIsOpen,
  onClose: propsOnClose,
}) => {
  const {
    selectedFinding,
    selectFinding,
    selectedEventFrame,
    selectEventFrame,
    selectedSession,
    dossierOpen,
    setDossierOpen,
    pivotToJourney,
    pivotToCerts,
    pivotToProvenance,
    dashboard,
  } = useInvestigation();

  const isOpen = propsIsOpen ?? dossierOpen;

  const handleClose = () => {
    selectFinding(null);
    selectEventFrame(null);
    setDossierOpen(false);
    if (propsOnClose) propsOnClose();
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  if (!isOpen) return null;

  // Resolve matching finding on selected frame if no explicit finding
  const activeFinding = selectedFinding || (
    selectedEventFrame !== null && dashboard?.findings
      ? dashboard.findings.find((f) => (f.frames || []).includes(selectedEventFrame))
      : null
  );

  const isCertRelated = activeFinding?.issue_class?.startsWith('CERTIFICATE') || !!selectedSession?.certificates?.length;

  return (
    <>
      {/* Light Backdrop */}
      <div
        onClick={handleClose}
        style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(18, 22, 26, 0.25)',
          backdropFilter: 'blur(2px)',
          zIndex: 900,
        }}
      />

      {/* Sliding Investigation Dossier */}
      <aside
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: '100%',
          maxWidth: '480px',
          backgroundColor: 'var(--bg-surface)',
          borderLeft: '1px solid var(--rule-strong)',
          boxShadow: 'var(--shadow-flyout)',
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
        }}
        className="animate-drawer-in"
      >
        {/* Dossier Header */}
        <div
          style={{
            padding: '16px 22px',
            borderBottom: '1px solid var(--rule-base)',
            backgroundColor: 'var(--bg-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            position: 'sticky',
            top: 0,
            zIndex: 10,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-3xs)',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--ink-muted)',
              }}
            >
              Investigation Dossier
            </span>
            {activeFinding && (
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-3xs)',
                  fontWeight: 700,
                  padding: '2px 6px',
                  backgroundColor: 'var(--sev-critical-bg)',
                  border: '1px solid var(--sev-critical-border)',
                  color: 'var(--sev-critical-ink)',
                  borderRadius: 'var(--radius-xs)',
                }}
              >
                {activeFinding.severity || 'HIGH'}
              </span>
            )}
          </div>

          <button
            type="button"
            onClick={handleClose}
            style={{
              padding: '4px',
              borderRadius: 'var(--radius-xs)',
              color: 'var(--ink-muted)',
            }}
            aria-label="Close Dossier"
          >
            <X size={16} />
          </button>
        </div>

        {/* Dossier Body */}
        <div style={{ padding: '24px 22px', display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Finding Title & Rank */}
          {activeFinding ? (
            <>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '2px' }}>
                  Finding #{activeFinding.rank || 1} · {activeFinding.issue_class}
                </div>
                <h3
                  style={{
                    fontFamily: 'var(--font-sans)',
                    fontSize: 'var(--text-lg)',
                    fontWeight: 700,
                    color: 'var(--ink-primary)',
                    lineHeight: 1.3,
                  }}
                >
                  {activeFinding.title}
                </h3>
              </div>

              {/* DETERMINATION */}
              <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '16px' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Factual Determination
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--ink-primary)', lineHeight: 1.5, fontWeight: 500 }}>
                  {activeFinding.conclusion}
                </p>
                {activeFinding.explanation && (
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--ink-secondary)', marginTop: '6px', lineHeight: 1.45 }}>
                    {activeFinding.explanation}
                  </p>
                )}
              </div>

              {/* WHY THIS MATTERS */}
              {activeFinding.remediation?.why_it_matters && (
                <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '16px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    Why This Matters
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--ink-secondary)', lineHeight: 1.5 }}>
                    {activeFinding.remediation.why_it_matters}
                  </p>
                </div>
              )}

              {/* AUTHORITATIVE BASIS */}
              {activeFinding.citations && activeFinding.citations.length > 0 && (
                <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '16px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    Authoritative Basis & Standards
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {activeFinding.citations.map((c, i) => (
                      <div
                        key={i}
                        style={{
                          padding: '8px 12px',
                          backgroundColor: 'var(--bg-subtle)',
                          borderRadius: 'var(--radius-xs)',
                          border: '1px solid var(--rule-subtle)',
                        }}
                      >
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--ink-primary)' }}>
                          {c.text || c.standard} {c.section ? `§${c.section}` : ''}
                        </div>
                        {c.reason && (
                          <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--ink-secondary)', marginTop: '2px' }}>
                            {c.reason}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* EVIDENCE ANCHORS */}
              <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '16px' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
                  Observed Frame Evidence
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  {(activeFinding.frames || []).map((fr) => (
                    <button
                      key={fr}
                      type="button"
                      onClick={() => pivotToJourney(fr, selectedSession?.stream_key)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '3px 8px',
                        backgroundColor: 'var(--accent-soft)',
                        border: '1px solid var(--accent-border)',
                        color: 'var(--accent-ink)',
                        borderRadius: 'var(--radius-xs)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 'var(--text-xs)',
                        fontWeight: 600,
                      }}
                    >
                      <span>Frame #{fr}</span>
                      <ExternalLink size={10} />
                    </button>
                  ))}
                  <span style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--ink-muted)' }}>
                    Stream #{activeFinding.tcp_stream_id ?? selectedSession?.tcp_stream_id ?? 0}
                  </span>
                </div>
              </div>

              {/* RECOMMENDED ACTION */}
              {activeFinding.remediation?.recommended_action && (
                <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '16px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    Remediation Guidance
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--ink-secondary)', lineHeight: 1.5 }}>
                    {activeFinding.remediation.recommended_action}
                  </p>
                </div>
              )}

              {/* ACTIONS: PIVOT BUTTONS */}
              <div style={{ borderTop: '2px solid var(--rule-heavy)', paddingTop: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => pivotToJourney(activeFinding.frames?.[0], selectedSession?.stream_key)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 14px',
                    backgroundColor: 'var(--accent-primary)',
                    color: '#fff',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                  }}
                >
                  <span>View in Protocol Journey Ladder</span>
                  <ArrowRight size={13} />
                </button>

                {isCertRelated && (
                  <button
                    type="button"
                    onClick={() => pivotToCerts(0)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 14px',
                      backgroundColor: 'var(--bg-subtle)',
                      border: '1px solid var(--rule-base)',
                      color: 'var(--ink-primary)',
                      borderRadius: 'var(--radius-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'var(--text-xs)',
                      fontWeight: 600,
                    }}
                  >
                    <span>View X.509 Certificate Artifact</span>
                    <KeyRound size={13} />
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => pivotToProvenance(activeFinding.title)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 14px',
                    backgroundColor: 'var(--bg-subtle)',
                    border: '1px solid var(--rule-base)',
                    color: 'var(--ink-primary)',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                  }}
                >
                  <span>View Provenance Lineage Trace</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </>
          ) : selectedEventFrame !== null ? (
            /* Selected Frame details when no finding */
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-3xs)', color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: '2px' }}>
                Packet Frame Dissection
              </div>
              <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink-primary)', marginBottom: '14px' }}>
                Frame #{selectedEventFrame}
              </h3>

              <div style={{ borderTop: '1px solid var(--rule-subtle)', paddingTop: '14px', fontSize: 'var(--text-xs)', color: 'var(--ink-secondary)' }}>
                Observed in Stream #{selectedSession?.tcp_stream_id ?? 0} ({selectedSession?.protocol.toUpperCase()}).
                No security violation was triggered on this specific frame.
              </div>

              <div style={{ marginTop: '20px' }}>
                <button
                  type="button"
                  onClick={() => pivotToJourney(selectedEventFrame, selectedSession?.stream_key)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '7px 14px',
                    backgroundColor: 'var(--accent-primary)',
                    color: '#fff',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                  }}
                >
                  <span>Anchor in Protocol Journey</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--ink-muted)', fontSize: 'var(--text-xs)' }}>
              Select a finding or packet frame in the workspace to inspect its full forensic dossier.
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
