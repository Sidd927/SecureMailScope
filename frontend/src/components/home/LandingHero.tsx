import { ArrowRight } from 'lucide-react';
import { BrandLogo } from '../common/BrandLogo';
import { BinaryWaterfall } from './BinaryWaterfall';
import { enterApplication } from './openIngestion';

const LINKS = ['Product', 'How it Works', 'Security', 'Documentation'];

export const LandingHero: React.FC = () => {
  return (
    <div className="sms-landing">
      <header className="sms-gate__nav">
        <a className="sms-gate__brand" href="#sms-hero" onClick={(event) => event.preventDefault()}>
          <BrandLogo variant="compact" size="sm" />
        </a>
        <nav className="sms-gate__links" aria-label="Product">
          {LINKS.map((label) => (
            <a key={label} href="#sms-hero" onClick={(event) => event.preventDefault()}>{label}</a>
          ))}
        </nav>
        <button type="button" className="sms-gate__cta sms-gate__cta--nav" onClick={enterApplication}>
          Get Started
          <ArrowRight size={15} aria-hidden="true" />
        </button>
      </header>

      <section className="sms-gate" id="sms-hero" aria-labelledby="sms-gate-title">
        <BinaryWaterfall />
        <div className="sms-gate__vignette" aria-hidden="true" />
        <div className="sms-gate__bloom" aria-hidden="true" />
        <div className="sms-gate__copy">
          <p className="sms-gate__eyebrow">Passive analysis · Real evidence · Stronger email security</p>
          <h1 id="sms-gate-title" className="sms-gate__title">
            Secure<span className="is-mail">Mail</span>Scope
          </h1>
          <p className="sms-gate__sub">Cryptographic Security Posture Assessment for Email Traffic</p>
          <p className="sms-gate__desc">
            Analyze captured email traffic to identify cryptographic and transport-security weaknesses from the evidence visible on the wire.
          </p>
          <button type="button" className="sms-gate__cta" onClick={enterApplication}>
            Get Started
            <ArrowRight size={16} aria-hidden="true" />
          </button>
        </div>
      </section>
    </div>
  );
};
