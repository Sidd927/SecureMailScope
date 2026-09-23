/**
 * About — what this product is, in the fewest words that are still accurate.
 *
 * Deliberately short. It is orientation for someone opening the console for the first
 * time, not a project description, and it makes no claim the engine does not make.
 * The only numbers on this screen come from `GET /api/v1/health`, which reports what
 * this instance actually is.
 */
import { health } from '../api.js';
import { el, facts, mount, notice, section, text } from '../dom.js';

function summary() {
  const points = [
    ['Passive analysis', 'A packet capture is the only input. The system never '
      + 'connects to a mail server, never authenticates, and never probes.'],
    ['Email cryptography', 'SMTP, IMAP and POP3 — STARTTLS upgrades and implicit '
      + 'TLS on SMTPS, IMAPS and POP3S alike.'],
    ['Security posture', 'TLS version, cipher selection, forward secrecy, '
      + 'certificate properties and plaintext exposure, each against a published '
      + 'standard.'],
    ['Evidence-aware conclusions', 'Observations are classified by what the capture '
      + 'actually supports. Where a question cannot be settled the assessment '
      + 'abstains and records what would settle it.'],
    ['Cross-session reasoning', 'An endpoint can be compared against comparable '
      + 'sessions to the same server, so a behaviour that is only anomalous in '
      + 'context can be described as such — when enough history exists.'],
    ['Offline operation', 'The console loads no external font, script, style or '
      + 'image, and the analysis makes no network call of its own.'],
  ];
  const list = el('dl', { className: 'about-list' });
  for (const [term, body] of points) {
    list.appendChild(el('dt', { text: term }));
    list.appendChild(el('dd', { text: body }));
  }
  return list;
}

export async function render(root, _ctx) {
  let info = null;
  try {
    info = await health();
  } catch (error) {
    info = null;
  }

  const blocks = [
    section('about', 'About SecureMailScope', [
      el('p', {
        className: 'lead-strong',
        text: 'SecureMailScope assesses the cryptographic security posture of email '
          + 'infrastructure from a packet capture alone.',
      }),
      summary(),
      notice('This console displays the canonical assessment and computes no '
        + 'security conclusion of its own. Severity, posture, coverage and every '
        + 'abstention arrive already decided by the analysis engine.'),
    ]),
  ];

  if (info) {
    blocks.push(section('instance', 'This instance', [
      facts([
        ['Version', text(info.version)],
        ['Posture engine', text(info.posture_engine_version)],
        ['Posture schema', text(info.posture_schema_version)],
        ['Backend schema', text(info.backend_schema_version)],
        ['Database', text(info.database)],
        ['Dissection backend', text(info.tshark),
          'TShark is required; without it no capture can be analysed'],
        ['Stored artifacts', text(info.artifact_count, '0')],
      ]),
    ], { lead: 'Reported by this deployment, not assumed by the console.' }));
  } else {
    blocks.push(notice('The instance details could not be retrieved. That is a '
      + 'connection problem with this deployment, not a statement about any '
      + 'assessment.'));
  }

  mount(root, blocks);
}
