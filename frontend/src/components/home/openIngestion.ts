/** Open the existing ingestion page as its own history entry. */
export function openIngestion() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('view') === 'home') return;
  params.delete('modal');
  params.set('view', 'home');
  if (!params.get('tab')) params.set('tab', 'overview');
  window.history.pushState(null, '', `${window.location.pathname}?${params.toString()}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

let entering = false;

/** Landing → ingestion. One transition for both Get Started buttons. */
export function enterApplication() {
  if (entering) return;
  if (new URLSearchParams(window.location.search).get('view') === 'home') return;
  entering = true;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.querySelector('.sms-landing')?.classList.add('is-leaving');
  window.dispatchEvent(new CustomEvent('sms-depart'));
  const pass = (phase: 'cover' | 'reveal' | 'idle') => {
    window.dispatchEvent(new CustomEvent('sms-pass', { detail: phase }));
  };
  pass('cover');
  const swap = reduce ? 40 : 440;
  const done = reduce ? 120 : 920;
  window.setTimeout(() => {
    pass('reveal');
    openIngestion();
  }, swap);
  window.setTimeout(() => {
    pass('idle');
    entering = false;
  }, done);
}
