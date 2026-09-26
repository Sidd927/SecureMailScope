import React, { useEffect, useState } from 'react';
import { ShieldHalf } from 'lucide-react';
import { api } from '../../api/client';
import type { HealthResponse } from '../../api/types';
import { OfflineBanner } from '../common/OfflineBanner';
import { CaptureUpload } from './CaptureUpload';
import { RecentAnalyses } from './RecentAnalyses';

export const HomeView: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => setHealthFailed(true));
  }, []);

  return (
    <>
      <OfflineBanner />
      <main className="sms-home">
        <div className="sms-home__inner">
          <header className="sms-home__brand">
            <h1 className="sms-home__title">
              <span className="sms-brand__mark" aria-hidden="true"><ShieldHalf size={18} /></span>
              SecureMailScope
            </h1>
            <p className="sms-home__tagline">PCAP forensic analysis for email protocols</p>
          </header>

          <CaptureUpload
            maxUploadBytes={health?.limits.max_upload_bytes ?? null}
            maxAnalysisSeconds={health?.limits.max_analysis_seconds ?? null}
            disabled={healthFailed}
          />
          {healthFailed && (
            <p className="sms-recent__note" role="status" style={{ textAlign: 'center', marginTop: 'calc(-1 * var(--ds-space-16))' }}>
              The analysis engine is not responding, so new captures cannot be analysed right now.
            </p>
          )}

          <RecentAnalyses />
        </div>
      </main>
    </>
  );
};
