import React, { useState } from 'react';
import { BarChart3, ChevronRight, FileUp, Search } from 'lucide-react';

interface Step {
  id: string;
  name: string;
  detail: string;
  icon: React.ComponentType<{ size?: number; className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>;
}

const STEPS: Step[] = [
  {
    id: 'upload',
    name: 'Upload a recording',
    detail: 'Select a .pcap, .pcapng or .cap file.',
    icon: FileUp,
  },
  {
    id: 'check',
    name: 'Check security',
    detail: 'We analyse the recording locally.',
    icon: Search,
  },
  {
    id: 'report',
    name: 'Read the score and report',
    detail: 'Get a score with a short report.',
    icon: BarChart3,
  },
];

export const ForensicProcessPipeline: React.FC = () => {
  const [activeStageId, setActiveStageId] = useState<string | null>(null);

  return (
    <section id="sms-how" className="sms-steps" aria-label="How a check works">
      <div className="sms-steps__track">
        {STEPS.map((step, idx) => {
          const isActive = activeStageId === step.id;
          const Icon = step.icon;
          return (
            <button
              key={step.id}
              type="button"
              className={`sms-step${isActive ? ' is-active' : ''}${!activeStageId && idx === 0 ? ' is-lead' : ''}`}
              onClick={() => {
                setActiveStageId(step.id);
                if (step.id === 'report') {
                  document.getElementById('sms-recent')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                  return;
                }
                document.getElementById('sms-intake')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                if (step.id === 'upload') {
                  document.querySelector<HTMLInputElement>('#sms-intake input[type="file"]')?.click();
                }
              }}
              aria-pressed={isActive}
            >
              <span className="sms-step__num" aria-hidden="true">{idx + 1}</span>
              <Icon size={16} className="sms-step__icon" aria-hidden="true" />
              <span className="sms-step__copy">
                <span className="sms-step__name">{step.name}</span>
                <span className="sms-step__detail">{step.detail}</span>
              </span>
              <ChevronRight size={16} className="sms-step__chev" aria-hidden="true" />
            </button>
          );
        })}
      </div>
    </section>
  );
};
