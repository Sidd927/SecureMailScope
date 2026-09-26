import rawFixtures from '../fixtures/real_fixtures.json';

export interface FixtureData {
  run: {
    run_id: string;
    state: string;
    source_filename: string;
    overall_posture: 'STRONG' | 'ADEQUATE' | 'WEAK' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
    score_value: number;
    created_at: string;
    duration_ms: number;
  };
  assessment: any;
  dashboard: any;
  sessions: {
    run_id: string;
    capture_id: string;
    total: number;
    items: any[];
  };
}

export type FixtureKey = 'backup_weak_certificate' | 'scene_b_certificate_honesty' | 'deepdive_cross_session_control_endpoint';

export const FIXTURES = rawFixtures as Record<FixtureKey, FixtureData>;

export const FIXTURE_METADATA: Record<FixtureKey, {
  label: string;
  pcap: string;
  verdict: 'CRITICAL' | 'STRONG' | 'ADEQUATE';
  score: number;
  sessions: number;
  findingsCount: number;
  headline: string;
  tagline: string;
}> = {
  backup_weak_certificate: {
    label: 'Weak Certificate (RSA-1024 + SHA-1)',
    pcap: 'backup_weak_certificate.pcap',
    verdict: 'CRITICAL',
    score: 44.0,
    sessions: 1,
    findingsCount: 2,
    headline: 'Sub-112-bit RSA Modulus & Deprecated SHA-1 Signature in SMTPS',
    tagline: 'Deterministic violation of NIST SP 800-57 §5.6.1 and RFC 9155',
  },
  scene_b_certificate_honesty: {
    label: 'Certificate Honesty (TLS 1.3 IMAP)',
    pcap: 'scene_b_certificate_honesty.pcap',
    verdict: 'STRONG',
    score: 100.0,
    sessions: 1,
    findingsCount: 0,
    headline: 'Encrypted Handshake with Honest Epistemic Abstentions',
    tagline: 'TLS 1.3 passive capture limits: Certificate payload structurally hidden',
  },
  deepdive_cross_session_control_endpoint: {
    label: 'STARTTLS Inversion with Control Endpoint',
    pcap: 'deepdive_cross_session_control_endpoint.pcap',
    verdict: 'CRITICAL',
    score: 22.15,
    sessions: 12,
    findingsCount: 3,
    headline: 'Multi-Session Behavioral Deviation Against Baseline',
    tagline: 'Client denied STARTTLS capability offered to other clients at same server',
  },
};
