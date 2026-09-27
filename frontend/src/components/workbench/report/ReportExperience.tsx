import React, { useEffect, useMemo } from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import { api } from '../../../api/client';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { ReportDocument } from '../../../api/types';
import { ForensicHash } from '../../common/ForensicHash';
import { Panel } from '../../common/Panel';
import { PosturePill } from '../../common/PosturePill';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { ReportDocumentView } from './ReportDocumentView';

const FORMATS = [
  { fmt: 'pdf' as const, label: 'PDF', icon: Download, primary: true },
  { fmt: 'html' as const, label: 'HTML', icon: FileText, primary: false },
  { fmt: 'json' as const, label: 'JSON', icon: FileJson, primary: false },
];

export const ReportExperience: React.FC = () => {
  const {
    activeRunId,
    activeRun,
    dashboard,
    assessment,
    sessions,
    reports,
    reportDoc,
    reportStatus,
    reportError,
    loadReport,
    isUsingFixtures,
  } = useInvestigation();

  useEffect(() => {
    if (reportStatus === 'idle' && !isUsingFixtures) loadReport();
  }, [reportStatus, isUsingFixtures, loadReport]);

  const fallbackDoc: ReportDocument | null = useMemo(() => {
    if (!dashboard || !activeRun) return null;
    return {
      assessment_id: assessment?.assessment_id ?? `asm-${activeRun.run_id}`,
      capture_id: activeRun.capture_id,
      run_id: activeRun.run_id,
      generated_at: activeRun.created_at,
      overall_posture: dashboard.posture.value,
      ai_enabled: activeRun.ai_enabled ?? false,
      score: {
        band: dashboard.posture.value,
        value: dashboard.posture.score_value,
        basis: dashboard.posture.basis || 'Evaluation under deterministic rule engine',
        formula_id: dashboard.posture.formula_id,
        starting_value: dashboard.posture.starting_value,
        total_penalty: dashboard.posture.total_penalty,
      },
      issue_groups: dashboard.findings.map((f) => ({
        title: f.title,
        severity: f.severity,
        certainty: f.certainty,
        recurrence: f.affected_sessions,
        issue_class: f.issue_class || '',
        penalising: f.penalising,
        citations: f.citations || [],
      })),
      remediation_summary: dashboard.findings
        .map((f) => f.remediation)
        .filter((r): r is NonNullable<typeof r> => Boolean(r)),
      limitations: dashboard.limitations || assessment?.limitations || [],
      provenance: {
        rule_ids: Array.from(new Set(dashboard.findings.flatMap((f) => f.source_rule_ids || []))),
        note: 'Complete deterministic provenance chain from wire frames to posture assessment.',
      },
      versions: { engine: '0.8.0', schema: '0.8.0' },
    };
  }, [dashboard, activeRun, assessment]);

  if (!activeRunId) {
    return (
      <div className="sms-page">
        <Panel><EmptyState title="Run an analysis to generate a report" /></Panel>
      </div>
    );
  }

  const finalDoc = reportDoc ?? fallbackDoc;

  let preview: React.ReactNode;
  if (reportStatus === 'error' && !fallbackDoc) {
    preview = <ErrorState title="Report generation failed" detail={reportError} onRetry={loadReport} />;
  } else if (!finalDoc && reportStatus === 'loading') {
    preview = (
      <div className="sms-stack" style={{ padding: 'var(--ds-space-24)' }}>
        <p className="sms-muted" role="status" style={{ fontSize: 'var(--ds-text-13)' }}>Rendering report…</p>
        <SkeletonRows rows={8} height={20} gap="var(--ds-space-12)" />
      </div>
    );
  } else if (finalDoc) {
    preview = <ReportDocumentView doc={finalDoc} run={activeRun} />;
  } else {
    preview = <EmptyState title="Report unavailable" detail="No assessment data is loaded for this capture." />;
  }

  const postureBand = dashboard?.posture.value ?? activeRun?.overall_posture ?? 'CRITICAL';
  const scoreVal = dashboard?.posture.score_value ?? activeRun?.score_value;

  return (
    <div className="sms-page">
      {/* DELIVERABLE WORKSPACE HEADER */}
      <header className="sms-report-workspace-header" aria-label="Forensic Report Header">
        <div className="sms-report-top-bar">
          <div className="sms-report-title-group">
            <span className="sms-label sms-report-kicker">
              FORENSIC ASSESSMENT
            </span>
            <div className="sms-report-verdict-row">
              <PosturePill band={postureBand} size="lg" />
              {scoreVal != null && (
                <span className="sms-mono sms-report-score-display">
                  {scoreVal.toFixed(2)} / 100
                </span>
              )}
            </div>
          </div>

          <div className="sms-report-actions">
            {FORMATS.map(({ fmt, label, icon: Icon, primary }) => (
              <a
                key={fmt}
                className={`sms-btn${primary ? ' sms-btn--primary' : ''}`}
                href={api.getReportUrl(activeRunId, fmt, true)}
                download
                title={`Download forensic report as ${label}`}
              >
                <Icon size={14} aria-hidden="true" />
                <span>Download {label}</span>
              </a>
            ))}
          </div>
        </div>

        <div className="sms-report-meta-strip">
          <span>Capture: <strong>{activeRun?.source_filename || 'capture.pcap'}</strong></span>
          <span>Sessions: <strong>{sessions.length} evaluated</strong></span>
          <span>Findings: <strong>{dashboard?.findings.length ?? 0} confirmed</strong></span>
          <span>Engine: <strong>0.8.0</strong></span>
          {activeRun?.capture_id && (
            <span>SHA-256: <strong className="sms-mono">{activeRun.capture_id.slice(0, 16)}…</strong></span>
          )}
        </div>
      </header>

      {/* Clean Flagship Report Preview */}
      <main className="sms-report-deliverable-wrap" aria-label="Official report document preview">
        {preview}
      </main>

      {reports.length > 0 && (
        <section className="sms-report-artifacts-section" aria-label="Report signatures and hashes">
          <div className="sms-report-artifacts-head">
            <span className="sms-label">Report artifacts & verifiable signatures</span>
          </div>
          <table className="sms-table" aria-label="Report formats and hashes">
            <thead>
              <tr><th>Format</th><th>Renderer</th><th>Schema</th><th>Status</th><th>SHA-256 Digest</th></tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.format}>
                  <td className="sms-mono sms-cell-title">{r.format.toUpperCase()}</td>
                  <td className="sms-mono">{r.renderer_version ?? '0.8.0'}</td>
                  <td className="sms-mono">{r.report_schema_version ?? '0.8.0'}</td>
                  <td>{r.generated ? 'Rendered' : 'Ready'}</td>
                  <td>{r.report_sha256 ? <ForensicHash value={r.report_sha256} length={16} /> : <span className="sms-muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
};

