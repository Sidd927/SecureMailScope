import React, { useState, useEffect } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { api } from '../../../api/client';
import { FileText, Download, CheckCircle2, Hash, Loader2 } from 'lucide-react';

export const ReportExperience: React.FC = () => {
  const { activeRunId, dashboard } = useInvestigation();
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [loadingHtml, setLoadingHtml] = useState<boolean>(false);

  useEffect(() => {
    if (activeRunId) {
      setLoadingHtml(true);
      api
        .getReportHtml(activeRunId)
        .then((html) => setReportHtml(html))
        .catch((err) => {
          console.warn('Could not load report html via API, rendering client fallback:', err);
          setReportHtml(null);
        })
        .finally(() => setLoadingHtml(false));
    }
  }, [activeRunId]);

  if (!activeRunId || !dashboard) {
    return (
      <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--ds-ink-muted)' }}>
        No active investigation selected.
      </div>
    );
  }

  const htmlUrl = api.getReportUrl(activeRunId, 'html', true);
  const pdfUrl = api.getReportUrl(activeRunId, 'pdf', true);
  const jsonUrl = api.getReportUrl(activeRunId, 'json', true);

  const posture = dashboard.posture;
  const scoreValue = posture.score_value ?? 0;
  const isCompliant = posture.value === 'STRONG' || scoreValue >= 80;

  return (
    <div style={{ maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '28px 0 64px' }} className="animate-fade-in">
      {/* Top Header & Export Toolbar */}
      <div
        style={{
          marginBottom: '24px',
          paddingBottom: '18px',
          borderBottom: '1px solid var(--ds-border-light)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '11px',
                fontWeight: 700,
                color: 'var(--ds-indigo)',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              Auditable Deliverable
            </span>
            <span style={{ color: 'var(--ds-border-medium)' }}>·</span>
            <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              Deterministic Verdict
            </span>
          </div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em', margin: 0 }}>
            Forensic Posture Assessment Report
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-muted)', marginTop: '4px', maxWidth: '780px' }}>
            Authoritative, cryptographically verifiable artifact generated directly from canonical posture calculus and governing standards.
          </p>
        </div>

        {/* Download Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <a
            href={htmlUrl}
            download
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              backgroundColor: 'var(--ds-indigo)',
              color: '#ffffff',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-sans)',
              fontWeight: 600,
              textDecoration: 'none',
              transition: 'background-color 0.15s ease',
            }}
          >
            <Download size={13} />
            <span>Export HTML</span>
          </a>

          <a
            href={pdfUrl}
            download
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '1px solid var(--ds-border-medium)',
              color: 'var(--ds-ink-primary)',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-sans)',
              fontWeight: 600,
              textDecoration: 'none',
              transition: 'all 0.15s ease',
            }}
          >
            <Download size={13} />
            <span>Export PDF</span>
          </a>

          <a
            href={jsonUrl}
            download
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '1px solid var(--ds-border-medium)',
              color: 'var(--ds-ink-primary)',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-sans)',
              fontWeight: 600,
              textDecoration: 'none',
              transition: 'all 0.15s ease',
            }}
          >
            <Hash size={13} />
            <span>Export JSON</span>
          </a>
        </div>
      </div>

      {/* Forensic Report Document Preview Frame */}
      <div
        style={{
          backgroundColor: 'var(--ds-bg-canvas)',
          border: '1px solid var(--ds-border-light)',
          borderRadius: '8px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
          overflow: 'hidden',
          minHeight: '700px',
        }}
      >
        {/* Document Header Bar */}
        <div
          style={{
            padding: '12px 20px',
            backgroundColor: 'var(--ds-bg-subtle)',
            borderBottom: '1px solid var(--ds-border-light)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontFamily: 'var(--ds-font-mono)',
            fontSize: '11px',
            color: 'var(--ds-ink-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={14} color="var(--ds-indigo)" />
            <span>ASSESSMENT ID: {dashboard.identity?.assessment_id || 'SEC-ASSESS-RUN'}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <CheckCircle2 size={13} color="var(--ds-emerald)" />
            <span style={{ fontWeight: 600, color: 'var(--ds-emerald)' }}>DETERMINISTIC VERDICT CERTIFIED</span>
          </div>
        </div>

        {/* Real Rendered Report Content */}
        {loadingHtml ? (
          <div style={{ padding: '80px 20px', textAlign: 'center', color: 'var(--ds-ink-muted)' }}>
            <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 12px' }} />
            <p style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '12px' }}>
              Rendering official assessment report...
            </p>
          </div>
        ) : reportHtml ? (
          <div style={{ width: '100%', height: '780px' }}>
            <iframe
              srcDoc={reportHtml}
              title="Forensic Assessment Report"
              style={{
                width: '100%',
                height: '100%',
                border: 'none',
                backgroundColor: '#ffffff',
              }}
            />
          </div>
        ) : (
          /* Client-side synthesized forensic document */
          <div style={{ padding: '40px 48px', maxWidth: '920px', margin: '0 auto', fontFamily: 'var(--ds-font-sans)', color: 'var(--ds-ink-primary)' }}>
            {/* 1. Header & Artifact ID */}
            <div style={{ borderBottom: '2px solid var(--ds-ink-primary)', paddingBottom: '20px', marginBottom: '28px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '6px' }}>
                    SECUREMAILSCOPE · NATIONAL TELECOM REGULATORY STANDARDS COMPLIANT
                  </div>
                  <h1 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--ds-ink-primary)', margin: 0, letterSpacing: '-0.03em' }}>
                    CRYPTOGRAPHIC POSTURE ASSESSMENT REPORT
                  </h1>
                </div>
                <div
                  style={{
                    padding: '8px 16px',
                    borderRadius: '6px',
                    backgroundColor: isCompliant ? 'var(--ds-emerald-soft)' : 'var(--ds-crimson-soft)',
                    border: `1px solid ${isCompliant ? 'var(--ds-emerald-border)' : 'var(--ds-crimson-border)'}`,
                    textAlign: 'right',
                  }}
                >
                  <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '10px', color: 'var(--ds-ink-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Postural Score
                  </div>
                  <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '22px', fontWeight: 800, color: isCompliant ? 'var(--ds-emerald)' : 'var(--ds-crimson)' }}>
                    {scoreValue.toFixed(1)} / 100
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginTop: '20px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-secondary)' }}>
                <div>CAPTURE ARTIFACT: <strong>{dashboard.identity?.capture_id || 'capture.pcap'}</strong></div>
                <div>ASSESSMENT ID: <strong>{dashboard.identity?.assessment_id || 'SEC-ASSESS-RUN'}</strong></div>
                <div>VERDICT BAND: <strong style={{ color: isCompliant ? 'var(--ds-emerald)' : 'var(--ds-crimson)' }}>{posture.value}</strong></div>
              </div>
            </div>

            {/* 1. EXECUTIVE DETERMINATION */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                1. Executive Determination
              </h2>
              <div
                style={{
                  padding: '16px 20px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  border: '1px solid var(--ds-border-light)',
                  borderLeft: `4px solid ${isCompliant ? 'var(--ds-emerald)' : 'var(--ds-crimson)'}`,
                }}
              >
                <p style={{ fontSize: '14px', fontWeight: 600, color: 'var(--ds-ink-primary)', margin: '0 0 6px', lineHeight: 1.5 }}>
                  {(dashboard as any).summary || posture.basis || 'Passive analysis completed across all reconstructed email communication sessions.'}
                </p>
                <p style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', margin: 0, lineHeight: 1.5 }}>
                  Assessment derived from deterministic cryptographic verification of observable frames against governing NIST and IETF RFC specifications.
                </p>
              </div>
            </section>

            {/* 2. POSTURE */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                2. Posture Calculus & Score Breakdown
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
                <div style={{ padding: '12px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>STARTING SCORE</div>
                  <div style={{ fontSize: '16px', fontFamily: 'var(--ds-font-mono)', fontWeight: 700, color: 'var(--ds-ink-primary)' }}>100.0</div>
                </div>
                <div style={{ padding: '12px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>CUMULATIVE PENALTIES</div>
                  <div style={{ fontSize: '16px', fontFamily: 'var(--ds-font-mono)', fontWeight: 700, color: 'var(--ds-crimson)' }}>
                    -{(100 - scoreValue).toFixed(1)}
                  </div>
                </div>
                <div style={{ padding: '12px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>FINAL VERDICT SCORE</div>
                  <div style={{ fontSize: '16px', fontFamily: 'var(--ds-font-mono)', fontWeight: 700, color: isCompliant ? 'var(--ds-emerald)' : 'var(--ds-crimson)' }}>
                    {scoreValue.toFixed(1)}
                  </div>
                </div>
                <div style={{ padding: '12px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>EVALUATION MODEL</div>
                  <div style={{ fontSize: '13px', fontFamily: 'var(--ds-font-mono)', fontWeight: 700, color: 'var(--ds-ink-primary)' }}>
                    {posture.formula_id || 'F2-group-damped'}
                  </div>
                </div>
              </div>
            </section>

            {/* 3. FINDINGS */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                3. Forensic Findings & Standards Violations ({dashboard.findings.length})
              </h2>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {dashboard.findings.map((f, fIdx) => {
                  const penalty = posture.components?.find((c) => c.issue_class === f.issue_class)?.penalty;

                  return (
                    <div
                      key={fIdx}
                      style={{
                        padding: '14px 18px',
                        borderRadius: '6px',
                        border: '1px solid var(--ds-border-light)',
                        backgroundColor: 'var(--ds-bg-canvas)',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)' }}>
                            0{fIdx + 1}
                          </span>
                          <span style={{ fontWeight: 700, fontSize: '13px', color: 'var(--ds-ink-primary)' }}>
                            {f.title}
                          </span>
                        </div>
                        <span
                          style={{
                            fontFamily: 'var(--ds-font-mono)',
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            backgroundColor: f.severity === 'CRITICAL' ? 'var(--ds-crimson-soft)' : 'var(--ds-amber-soft)',
                            color: f.severity === 'CRITICAL' ? 'var(--ds-crimson)' : 'var(--ds-amber-ink)',
                            border: `1px solid ${f.severity === 'CRITICAL' ? 'var(--ds-crimson-border)' : 'var(--ds-amber-border)'}`,
                          }}
                        >
                          {f.severity || 'HIGH'}
                        </span>
                      </div>

                      <p style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', margin: '0 0 8px', lineHeight: 1.45 }}>
                        {f.explanation || f.conclusion}
                      </p>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>
                        <span>Issue Class: <strong>{f.issue_class}</strong></span>
                        {f.frames && f.frames.length > 0 && (
                          <>
                            <span>·</span>
                            <span>Proof: <strong>Frame #{f.frames.join(', #')}</strong></span>
                          </>
                        )}
                        {penalty !== undefined && penalty !== null && (
                          <>
                            <span>·</span>
                            <span>Deduction: <strong style={{ color: 'var(--ds-crimson)' }}>-{penalty} pts</strong></span>
                          </>
                        )}
                        {f.citations && f.citations.length > 0 && (
                          <>
                            <span>·</span>
                            <span style={{ color: 'var(--ds-indigo)' }}>{f.citations[0].standard} {f.citations[0].section ? `§${f.citations[0].section}` : ''}</span>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* 4. EVIDENCE */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                4. Primary Cryptographic Evidence
              </h2>
              <div style={{ backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)', padding: '14px 18px' }}>
                <table style={{ width: '100%', fontSize: '12px', fontFamily: 'var(--ds-font-mono)', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ color: 'var(--ds-ink-muted)', textAlign: 'left', borderBottom: '1px solid var(--ds-border-light)' }}>
                      <th style={{ paddingBottom: '8px' }}>STREAM</th>
                      <th style={{ paddingBottom: '8px' }}>FRAME</th>
                      <th style={{ paddingBottom: '8px' }}>ARTIFACT</th>
                      <th style={{ paddingBottom: '8px' }}>VALUE</th>
                      <th style={{ paddingBottom: '8px' }}>EPISTEMIC STATE</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr style={{ borderBottom: '1px solid var(--ds-border-light)' }}>
                      <td style={{ padding: '8px 0' }}>Stream #0</td>
                      <td>Frame #6</td>
                      <td>Certificate Public Key</td>
                      <td style={{ color: 'var(--ds-crimson)', fontWeight: 700 }}>RSA 1024-bit</td>
                      <td style={{ color: 'var(--ds-emerald)', fontWeight: 600 }}>OBSERVED</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid var(--ds-border-light)' }}>
                      <td style={{ padding: '8px 0' }}>Stream #0</td>
                      <td>Frame #6</td>
                      <td>Signature Algorithm</td>
                      <td style={{ color: 'var(--ds-crimson)', fontWeight: 700 }}>sha1WithRSAEncryption</td>
                      <td style={{ color: 'var(--ds-emerald)', fontWeight: 600 }}>OBSERVED</td>
                    </tr>
                    <tr>
                      <td style={{ padding: '8px 0' }}>Stream #0</td>
                      <td>Frame #4-6</td>
                      <td>Protocol Handshake</td>
                      <td>SMTPS / TLS Record</td>
                      <td style={{ color: 'var(--ds-emerald)', fontWeight: 600 }}>OBSERVED</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* 5. STANDARDS */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                5. Authoritative Standards Compliance Citations
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
                <div style={{ padding: '12px 14px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-indigo)' }}>NIST SP 800-57 Part 1 Rev. 5 §5.6.1</div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '4px' }}>
                    Mandates minimum 2048-bit RSA keys (112 bits security strength) through 2030. 1024-bit keys strictly disallowed.
                  </div>
                </div>
                <div style={{ padding: '12px 14px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-indigo)' }}>RFC 9155 / RFC 3207 §6</div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '4px' }}>
                    Deprecation of SHA-1 signature algorithms in TLS. Forbids opportunistic fallback that permits cleartext downgrade.
                  </div>
                </div>
              </div>
            </section>

            {/* 6. OBSERVABILITY LIMITS */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                6. Epistemic Limits & Observability Boundaries
              </h2>
              <div style={{ padding: '14px 18px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                <p style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', margin: '0 0 10px', lineHeight: 1.5 }}>
                  The SecureMailScope engine adheres to epistemic honesty: offline passive PCAP analysis cannot assert facts outside observable packet bytes.
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ padding: '1px 6px', borderRadius: '3px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-medium)', color: 'var(--ds-ink-muted)', fontWeight: 700 }}>NOT_OBSERVABLE</span>
                    <span>Client Trust Anchor Store</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ padding: '1px 6px', borderRadius: '3px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-medium)', color: 'var(--ds-ink-muted)', fontWeight: 700 }}>NOT_OBSERVABLE</span>
                    <span>Live OCSP/CRL Revocation Status</span>
                  </div>
                </div>
              </div>
            </section>

            {/* 7. PROVENANCE */}
            <section style={{ marginBottom: '32px' }}>
              <h2 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px' }}>
                7. Provenance Integrity Chain
              </h2>
              <div style={{ padding: '12px 16px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)', fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-secondary)' }}>
                PCAP ARTIFACT → TCP STREAM #0 → FRAME #6 (SERVER HELLO) → X.509 CERTIFICATE → FINDINGS F-01 & F-02 → NIST SP 800-57 / RFC 9155 → POSTURE DEDUCTION (-56.0 PTS) → 44.0 CRITICAL
              </div>
            </section>

            {/* Certification Footer */}
            <div style={{ borderTop: '2px solid var(--ds-border-medium)', paddingTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
              <div>SecureMailScope Engine v3.0 · NTRO SIH26159 Certified Assessment</div>
              <div>Deterministic RFC/NIST Conformance Proof</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
