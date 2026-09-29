import React from 'react';
import type { SessionEvidence } from '../../../api/types';

interface StoryNode {
  id: string;
  label: string;
  sublabel?: string;
  frame: number | null;
  status: 'critical' | 'good' | 'warning' | 'neutral';
  iconType?: 'alert' | 'lock' | 'shield' | 'check' | 'dot';
}

interface Props {
  session: SessionEvidence;
  focusFrame: number | null;
  onSelectFrame: (frame: number) => void;
}

export const ProtocolStateMachineStory: React.FC<Props> = ({
  session,
  focusFrame,
  onSelectFrame,
}) => {
  const nodes: StoryNode[] = [];
  const events = session.events ?? [];
  const evidence = session.evidence ?? {};

  // 1. Connection established
  const firstFrame = session.timing?.first_frame ?? (events[0]?.frame ?? 1);
    nodes.push({
      id: 'connected',
      label: 'CONNECTION',
      sublabel: 'TCP session up',
      frame: firstFrame,
      status: 'neutral',
      iconType: 'dot',
    });

  // 2. Greeting
  const greetingEv = events.find((e) => e.kind === 'greeting');
  if (greetingEv) {
    nodes.push({
      id: 'greeting',
      label: 'GREETING',
      sublabel: greetingEv.detail || 'Server greeting',
      frame: greetingEv.frame,
      status: 'neutral',
      iconType: 'dot',
    });
  }

  // 3. EHLO / Capability Request
  const ehloEv = events.find((e) => e.kind === 'capability_request');
  if (ehloEv) {
    nodes.push({
      id: 'ehlo',
      label: 'EHLO',
      sublabel: ehloEv.detail || 'Client EHLO',
      frame: ehloEv.frame,
      status: 'neutral',
      iconType: 'dot',
    });
  }

  // 4. Capabilities & STARTTLS Advertisement Check
  const capRespEv = events.find((e) => e.kind === 'capability_response');
  const starttlsAdvEv = events.find((e) => e.kind === 'starttls_advertised');
  const starttlsOffered = evidence.starttls_advertised?.value === true || Boolean(starttlsAdvEv);

  if (capRespEv) {
    nodes.push({
      id: 'capabilities',
      label: 'CAPABILITIES',
      sublabel: capRespEv.detail || 'Server capabilities',
      frame: capRespEv.frame,
      status: 'neutral',
      iconType: 'dot',
    });
  }

  // STARTTLS decision point
  const implicitTls = /implicit/i.test(`${session.app_state ?? ''} ${session.protocol ?? ''}`);
  if (starttlsOffered) {
    const advFrame = starttlsAdvEv?.frame ?? capRespEv?.frame ?? null;
    nodes.push({
      id: 'starttls-offered',
      label: 'STARTTLS STATUS',
      sublabel: 'Upgrade offered',
      frame: advFrame,
      status: 'good',
      iconType: 'shield',
    });

    const starttlsCmdEv = events.find((e) => e.kind === 'starttls_command');
    const starttlsAcceptEv = events.find((e) => e.kind === 'starttls_accepted');
    if (starttlsCmdEv || starttlsAcceptEv) {
      nodes.push({
        id: 'starttls-upgrade',
        label: 'TLS UPGRADE',
        sublabel: 'STARTTLS accepted',
        frame: starttlsAcceptEv?.frame ?? starttlsCmdEv?.frame ?? null,
        status: 'good',
        iconType: 'lock',
      });
    }

    if (session.tls_state === 'ESTABLISHED' || session.tls_state === 'TLS_ESTABLISHED' || session.protocol === 'smtp-tls') {
      nodes.push({
        id: 'tls-protected',
        label: 'PROTECTED CHANNEL',
        sublabel: session.certificates?.length ? `${session.certificates.length} certificate${session.certificates.length === 1 ? '' : 's'} in the handshake` : 'TLS established',
        frame: starttlsAcceptEv ? starttlsAcceptEv.frame + 1 : null,
        status: 'good',
        iconType: 'check',
      });
    }
  } else {
    // STARTTLS NOT ADVERTISED (Attack vector / downgrade)
    const missFrame = capRespEv?.frame ?? evidence.starttls_advertised?.frames?.[0] ?? null;
    const capDetail = capRespEv?.detail ?? '';
    nodes.push({
      id: 'starttls-missing',
      label: 'STARTTLS STATUS',
      sublabel: implicitTls
        ? 'Does not apply. Session opened in TLS.'
        : capDetail.startsWith('250') ? 'Absent from the 250 reply' : 'Upgrade not advertised',
      frame: missFrame,
      status: implicitTls ? 'neutral' : 'warning',
      iconType: implicitTls ? 'lock' : 'alert',
    });
  }

  // 5. Authentication Activity
  const authEv = events.find((e) => e.kind === 'auth_command' || e.kind === 'auth_plain' || e.kind === 'auth_login');
  const authActivityObserved = evidence.auth_activity?.value === true || Boolean(authEv);
  const isPlaintextAuth = authActivityObserved && !starttlsOffered && !implicitTls;

  if (authActivityObserved) {
    const authFrame = authEv?.frame ?? (evidence.auth_activity?.frames?.[0] ?? 7);
    nodes.push({
      id: 'auth',
      label: 'AUTH',
      sublabel: isPlaintextAuth ? 'Credentials without TLS' : 'Protected authentication',
      frame: authFrame,
      status: isPlaintextAuth ? 'warning' : 'good',
      iconType: isPlaintextAuth ? 'alert' : 'lock',
    });

    if (isPlaintextAuth) {
      nodes.push({
        id: 'plaintext-continuation',
        label: 'PLAINTEXT CONSEQUENCE',
        sublabel: 'Cleartext after AUTH',
        frame: authFrame + 1,
        status: 'warning',
        iconType: 'alert',
      });
    }
  }

  // 6. Teardown / Close
  const lastFrame = session.timing?.last_frame ?? (events[events.length - 1]?.frame ?? null);
  nodes.push({
    id: 'closed',
      label: 'SESSION CLOSE',
      sublabel: 'Session ended',
    frame: lastFrame,
    status: 'neutral',
    iconType: 'dot',
  });

  return (
    <section className="sms-progress-card" aria-label="Protocol progression">
      <header className="sms-progress-card__head">
        <h2>Protocol progression</h2>
        <p>Click a row to open that frame.</p>
      </header>
      <div className="sms-progress-table-wrap">
        <table className="sms-progress-table">
          <thead>
            <tr>
              <th>Frame</th>
              <th>State</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => {
              const isActive = focusFrame != null && node.frame != null && focusFrame === node.frame;
              return (
                <tr
                  key={node.id}
                  className={`sms-progress-row sms-progress-row--${node.status}${isActive ? ' is-active' : ''}${node.frame != null ? ' is-clickable' : ''}`}
                  tabIndex={node.frame != null ? 0 : -1}
                  onClick={() => { if (node.frame != null) onSelectFrame(node.frame); }}
                  onKeyDown={(e) => {
                    if ((e.key === 'Enter' || e.key === ' ') && node.frame != null) {
                      e.preventDefault();
                      onSelectFrame(node.frame);
                    }
                  }}
                >
                  <td className="sms-mono sms-progress-frame">{node.frame != null ? `#${node.frame}` : '—'}</td>
                  <td>
                    <span className={`sms-progress-state sms-progress-state--${node.status}`}>
                      <span className="sms-progress-state__dot" aria-hidden="true" />
                      {node.label}
                    </span>
                  </td>
                  <td>{node.sublabel}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};
