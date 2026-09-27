import React from 'react';
import { AlertTriangle, ShieldCheck, CheckCircle2, Lock } from 'lucide-react';
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
    label: 'CONNECTED',
    sublabel: 'TCP Stream Established',
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
      sublabel: greetingEv.detail || '220 Service Ready',
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
      sublabel: ehloEv.detail || 'Client Handshake',
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
      sublabel: capRespEv.detail || 'Server 250 Response',
      frame: capRespEv.frame,
      status: 'neutral',
      iconType: 'dot',
    });
  }

  // STARTTLS decision point
  if (starttlsOffered) {
    const advFrame = starttlsAdvEv?.frame ?? capRespEv?.frame ?? null;
    nodes.push({
      id: 'starttls-offered',
      label: 'STARTTLS ADVERTISED',
      sublabel: 'Upgrade Capability Offered',
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
        sublabel: 'STARTTLS Accepted (220)',
        frame: starttlsAcceptEv?.frame ?? starttlsCmdEv?.frame ?? null,
        status: 'good',
        iconType: 'lock',
      });
    }

    if (session.tls_state === 'ESTABLISHED' || session.tls_state === 'TLS_ESTABLISHED' || session.protocol === 'smtp-tls') {
      nodes.push({
        id: 'tls-protected',
        label: 'PROTECTED CHANNEL',
        sublabel: session.certificates?.length ? `${session.certificates.length} Cert(s) Inspected` : 'TLS 1.3 Active',
        frame: starttlsAcceptEv ? starttlsAcceptEv.frame + 1 : null,
        status: 'good',
        iconType: 'check',
      });
    }
  } else {
    // STARTTLS NOT ADVERTISED (Attack vector / downgrade)
    const missFrame = capRespEv?.frame ?? 6;
    nodes.push({
      id: 'starttls-missing',
      label: 'STARTTLS NOT ADVERTISED',
      sublabel: 'No upgrade capability in 250',
      frame: missFrame,
      status: 'critical',
      iconType: 'alert',
    });
  }

  // 5. Authentication Activity
  const authEv = events.find((e) => e.kind === 'auth_command' || e.kind === 'auth_plain' || e.kind === 'auth_login');
  const authActivityObserved = evidence.auth_activity?.value === true || Boolean(authEv);
  const isPlaintextAuth = authActivityObserved && !starttlsOffered;

  if (authActivityObserved) {
    const authFrame = authEv?.frame ?? (evidence.auth_activity?.frames?.[0] ?? 7);
    nodes.push({
      id: 'auth',
      label: isPlaintextAuth ? 'PLAINTEXT AUTH' : 'AUTHENTICATION',
      sublabel: isPlaintextAuth ? 'Credentials sent without TLS' : 'Protected Authentication',
      frame: authFrame,
      status: isPlaintextAuth ? 'critical' : 'good',
      iconType: isPlaintextAuth ? 'alert' : 'lock',
    });

    if (isPlaintextAuth) {
      nodes.push({
        id: 'plaintext-continuation',
        label: 'PLAINTEXT CONTINUATION',
        sublabel: 'Unencrypted session traffic',
        frame: authFrame + 1,
        status: 'critical',
        iconType: 'alert',
      });
    }
  }

  // 6. Teardown / Close
  const lastFrame = session.timing?.last_frame ?? (events[events.length - 1]?.frame ?? null);
  nodes.push({
    id: 'closed',
    label: 'CLOSED',
    sublabel: 'Session Terminated',
    frame: lastFrame,
    status: 'neutral',
    iconType: 'dot',
  });

  return (
    <div className="sms-protocol-timeline-card" aria-label="Visual protocol state machine timeline">
      <div className="sms-protocol-timeline-head">
        <span className="sms-label">Protocol progression timeline</span>
        <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
          Chronological protocol states and packet evidence. Click any event to focus wire dissection.
        </span>
      </div>

      <div className="sms-protocol-vtimeline" role="list">
        {nodes.map((node, idx) => {
          const isActive = focusFrame != null && node.frame != null && focusFrame === node.frame;
          const isLast = idx === nodes.length - 1;

          return (
            <div key={node.id} className="sms-vtimeline-row">
              {/* Left Column: Anchored Frame Number */}
              <div className="sms-vtimeline-frame-col">
                {node.frame != null ? (
                  <span className={`sms-mono sms-vtimeline-frame${isActive ? ' is-active' : ''}`}>
                    #{node.frame}
                  </span>
                ) : (
                  <span className="sms-mono sms-vtimeline-frame-dash">—</span>
                )}
              </div>

              {/* Center Spine: Dot and Connecting Vertical Line */}
              <div className="sms-vtimeline-spine" aria-hidden="true">
                <span className={`sms-vtimeline-dot sms-vtimeline-dot--${node.status}${isActive ? ' is-active' : ''}`}>
                  {node.iconType === 'alert' && <AlertTriangle size={10} />}
                  {node.iconType === 'shield' && <ShieldCheck size={10} />}
                  {node.iconType === 'lock' && <Lock size={10} />}
                  {node.iconType === 'check' && <CheckCircle2 size={10} />}
                </span>
                {!isLast && <span className="sms-vtimeline-line" />}
              </div>

              {/* Right Column: Event Content Card */}
              <div
                role="listitem"
                tabIndex={node.frame != null ? 0 : -1}
                className={`sms-vtimeline-node sms-vtimeline-node--${node.status}${isActive ? ' is-active' : ''}${node.frame != null ? ' is-clickable' : ''}`}
                onClick={() => {
                  if (node.frame != null) onSelectFrame(node.frame);
                }}
                onKeyDown={(e) => {
                  if ((e.key === 'Enter' || e.key === ' ') && node.frame != null) {
                    e.preventDefault();
                    onSelectFrame(node.frame);
                  }
                }}
                title={node.frame != null ? `Focus Frame #${node.frame} evidence` : undefined}
              >
                <div className="sms-vtimeline-node__head">
                  <span className="sms-vtimeline-node__label">{node.label}</span>
                  {isActive && <span className="sms-badge sms-badge--cyan sms-badge--xs">Focused</span>}
                </div>
                {node.sublabel && (
                  <span className="sms-vtimeline-node__sublabel sms-mono">{node.sublabel}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
