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
