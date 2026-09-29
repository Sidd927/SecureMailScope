import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { HealthResponse } from '../../api/types';
import { CaptureUpload } from './CaptureUpload';
import { ForensicProcessPipeline } from './ForensicProcessPipeline';
import { RecentAnalyses } from './RecentAnalyses';

export const HomeView: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);

  useEffect(() => {
    api.getHealth()
      .then(setHealth)
      .catch(() => setHealthFailed(true));
  }, []);

  return (
    <main className="sms-case-desk" role="main" aria-label="Secure email analysis">
        <div className="sms-case-desk__inner">
        <ForensicProcessPipeline />

        <CaptureUpload
          maxUploadBytes={health?.limits.max_upload_bytes ?? null}
          maxAnalysisSeconds={health?.limits.max_analysis_seconds ?? null}
          disabled={healthFailed}
        />

        {healthFailed && (
          <div className="sms-case-desk__alert" role="alert">
            <span className="sms-dot" style={{ background: 'var(--ds-crimson-rail)' }} aria-hidden="true" />
            <span>
              The analysis service is unavailable. Saved checks can still be opened. New recordings cannot be checked until it is back.
            </span>
          </div>
        )}

        <RecentAnalyses />
        </div>
      </main>
  );
};
