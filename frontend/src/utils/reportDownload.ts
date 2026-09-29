import type { ReportDocument } from '../api/types';
import { api } from '../api/client';

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function filenameFromDisposition(header: string | null, fallback: string) {
  const match = header?.match(/filename="([^"]+)"/);
  return match?.[1] || fallback;
}

function pdfEscape(text: string) {
  return text.replace(/[^\x20-\x7E]/g, '?').replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function linesFor(doc: ReportDocument, captureName?: string | null): string[] {
  const lines = [
    'SecureMailScope forensic assessment',
    captureName ? `Capture: ${captureName}` : '',
    `Posture: ${doc.score?.band || doc.overall_posture || 'UNRATED'}`,
    doc.score?.value != null ? `Score: ${doc.score.value.toFixed(2)} / 100` : '',
    doc.score?.basis || '',
    '',
    'Findings',
  ];
  for (const group of doc.issue_groups ?? []) {
    if (!group.penalising) continue;
    lines.push(`${group.severity || 'INFO'}  ${group.title}`);
    const cite = group.citations?.[0];
    if (cite) lines.push(`  ${cite.text || cite.standard || ''}`);
  }
  if ((doc.remediation_summary?.length ?? 0) > 0) {
    lines.push('', 'Recorded actions');
    for (const item of doc.remediation_summary ?? []) {
      if (item.recommended_action) lines.push(item.recommended_action);
    }
  }
  return lines.filter((line) => line !== undefined);
}

/** Minimal PDF of the on-screen report. Used when the analysis API has no stored rendition. */
export function reportPdfBytes(doc: ReportDocument, captureName?: string | null): Uint8Array {
  const wrapped: string[] = [];
  for (const line of linesFor(doc, captureName)) {
    const text = line || ' ';
    for (let i = 0; i < text.length; i += 90) wrapped.push(text.slice(i, i + 90));
  }
  if (wrapped.length === 0) wrapped.push('SecureMailScope report');
  const perPage = 42;
  const pages: string[][] = [];
  for (let i = 0; i < wrapped.length; i += perPage) pages.push(wrapped.slice(i, i + perPage));

  const fontId = 3 + pages.length * 2;
  const objects: string[] = [];
  const pageIds: number[] = [];
  let id = 3;
  for (const page of pages) {
    const contentId = id + 1;
    pageIds.push(id);
    const commands = ['BT', `/F1 11 Tf`, '50 760 Td', '14 TL'];
    page.forEach((line, index) => {
      commands.push(index === 0 ? `(${pdfEscape(line)}) Tj` : `T* (${pdfEscape(line)}) Tj`);
    });
    commands.push('ET');
    const stream = commands.join('\n');
    objects.push(`${id} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${contentId} 0 R /Resources << /Font << /F1 ${fontId} 0 R >> >> >> endobj`);
    objects.push(`${contentId} 0 obj << /Length ${stream.length} >> stream\n${stream}\nendstream endobj`);
    id += 2;
  }
  const catalog = `1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj`;
  const pageTree = `2 0 obj << /Type /Pages /Kids [${pageIds.map((n) => `${n} 0 R`).join(' ')}] /Count ${pageIds.length} >> endobj`;
  const font = `${fontId} 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj`;
  const body = [catalog, pageTree, ...objects, font];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const obj of body) {
    offsets.push(pdf.length);
    pdf += `${obj}\n`;
  }
  const xrefAt = pdf.length;
  const size = body.length + 1;
  let xref = `xref\n0 ${size}\n`;
  xref += '0000000000 65535 f \n';
  for (let n = 1; n < size; n += 1) {
    const at = offsets[n] ?? offsets[offsets.length - 1];
    xref += `${String(at).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `${xref}trailer << /Size ${size} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function reportHtml(doc: ReportDocument, captureName?: string | null): string {
  const findings = (doc.issue_groups ?? [])
    .filter((group) => group.penalising)
    .map((group) => `<li><strong>${escapeHtml(group.severity || 'INFO')}</strong> ${escapeHtml(group.title)}</li>`)
    .join('');
  const actions = (doc.remediation_summary ?? [])
    .filter((item) => item.recommended_action)
    .map((item) => `<li>${escapeHtml(item.recommended_action as string)}</li>`)
    .join('');
  const posture = escapeHtml(doc.score?.band || doc.overall_posture || 'UNRATED');
  const basis = escapeHtml(doc.score?.basis || '');
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SecureMailScope report</title></head><body>
<h1>SecureMailScope forensic assessment</h1>
<p>${captureName ? `Capture: ${escapeHtml(captureName)}<br>` : ''}Posture: ${posture}${doc.score?.value != null ? ` · ${doc.score.value.toFixed(2)} / 100` : ''}</p>
<p>${basis}</p>
<h2>Findings</h2><ul>${findings || '<li>None recorded</li>'}</ul>
${actions ? `<h2>Recorded actions</h2><ul>${actions}</ul>` : ''}
</body></html>`;
}

export async function downloadReport(options: {
  runId: string;
  format: 'pdf' | 'html' | 'json';
  doc: ReportDocument;
  captureName?: string | null;
  useApi: boolean;
}) {
  const fallbackName = `securemailscope-report.${options.format}`;
  if (options.useApi) {
    try {
      const response = await fetch(api.getReportUrl(options.runId, options.format, true), { cache: 'no-store' });
      if (response.ok) {
        saveBlob(await response.blob(), filenameFromDisposition(response.headers.get('content-disposition'), fallbackName));
        return;
      }
    } catch {
      // The on-screen report is still downloadable when the API is unreachable.
    }
  }
  if (options.format === 'json') {
    saveBlob(new Blob([JSON.stringify(options.doc, null, 2)], { type: 'application/json' }), fallbackName);
    return;
  }
  if (options.format === 'html') {
    saveBlob(new Blob([reportHtml(options.doc, options.captureName)], { type: 'text/html' }), fallbackName);
    return;
  }
  const bytes = reportPdfBytes(options.doc, options.captureName);
  const pdf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  saveBlob(new Blob([pdf], { type: 'application/pdf' }), fallbackName);
}
