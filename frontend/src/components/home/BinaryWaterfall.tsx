import { useEffect, useRef } from 'react';

type Impact = { x: number; z: number; age: number; life: number };

type Stream = {
  x: number;
  z: number;
  y: number;
  vy: number;
  g: number;
  gap: number;
  bits: string;
  fade: number;
  hold: number;
  bright: number;
};

const FOCAL = 1.22;
const CAM_Y = 1.32;
const DROP = 0.22;
const HORIZON = 0.58;

function makeBits(length: number): string {
  let bits = '';
  for (let i = 0; i < length; i += 1) bits += Math.random() > 0.46 ? '1' : '0';
  return bits;
}

function streamCount(width: number, quiet: boolean): number {
  if (quiet) return Math.max(8, Math.round(width / 140));
  if (width < 700) return Math.max(12, Math.round(width / 52));
  if (width < 1100) return Math.round(width / 30);
  return Math.round(width / 20);
}

function xLimit(z: number): number {
  const s = FOCAL / Math.max(0.55, z);
  return Math.min(1.45, 0.46 / (s * 0.48));
}

function placeX(z: number, side: number): number {
  const limit = xLimit(z);
  if (z < 3.3) return side * limit * (0.58 + Math.random() * 0.4);
  if (Math.random() < 0.34) return (Math.random() - 0.5) * limit * 0.42;
  return side * Math.random() * limit;
}

function makeStream(index: number): Stream {
  const roll = (index * 17 + 3) % 10;
  const z = roll < 4 ? 1.45 + Math.random() * 0.7 : roll < 7 ? 2.2 + Math.random() * 1.5 : 3.8 + Math.random() * 3.2;
  const len = (z < 2.3 ? 22 : z < 3.6 ? 16 : 10) + Math.floor(Math.random() * (z < 2.3 ? 14 : 8));
  const near = Math.max(0, 3.1 - z);
  return {
    x: placeX(z, index % 2 === 0 ? -1 : 1),
    z,
    y: Math.random() * (z < 2.4 ? 1.6 : 3.2),
    vy: 0.2 + Math.random() * 0.85 + near * 0.12,
    g: 1.35 + Math.random() * 1.5 + near * 0.22,
    gap: 0.072 + Math.random() * 0.05,
    bits: makeBits(len),
    fade: 1,
    hold: 0,
    bright: z < 2 ? 1 : z < 3.6 ? 0.55 + Math.random() * 0.2 : 0.28 + Math.random() * 0.16,
  };
}

function respawn(stream: Stream) {
  stream.y = 2.8 + Math.random() * 1.6;
  stream.vy = 0.08 + Math.random() * 0.4;
  const near = Math.max(0, 3.2 - stream.z);
  stream.g = 1.05 + Math.random() * 1.15 + near * 0.12;
  stream.hold = 0;
  stream.fade = 0;
  stream.gap = 0.072 + Math.random() * 0.05;
  stream.bits = makeBits((stream.z < 2.3 ? 22 : 12) + Math.floor(Math.random() * 10));
  if (Math.random() < 0.2) stream.x = placeX(stream.z, stream.x < 0 ? -1 : 1);
}

function project(x: number, y: number, z: number, w: number, h: number, camX: number) {
  const s = FOCAL / Math.max(0.55, z);
  return {
    sx: w * 0.5 + (x - camX) * s * w * 0.48,
    sy: h * HORIZON + (CAM_Y - y) * s * DROP * h,
    s,
  };
}

function glyphFill(z: number, along: number, head: boolean): string {
  if (head && z < 2.5) return '#f3f9ff';
  if (head) return '#d7e7fb';
  if (along < 0.22) return z < 2.6 ? '#8fd4f8' : '#67b4f0';
  if (along < 0.55) return '#3b82f6';
  return '#1e4fa8';
}

export const BinaryWaterfall: React.FC = () => {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const parent = canvas?.parentElement;
    const ctx = canvas?.getContext('2d', { alpha: false });
    if (!canvas || !parent || !ctx) return;

    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let streams: Stream[] = [];
    let impacts: Impact[] = [];
    let running = true;
    let lastW = 0;
    let lastH = 0;
    let last = performance.now();
    let clock = 0;
    let frame = 0;

    const resize = () => {
      const width = parent.clientWidth;
      const height = parent.clientHeight;
      if (width === lastW && height === lastH && streams.length > 0) return;
      lastW = width;
      lastH = height;
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = streamCount(width, motion.matches);
      streams = Array.from({ length: count }, (_, index) => makeStream(index));
      impacts = [];
    };

    const paint = (dt: number) => {
      const width = parent.clientWidth;
      const height = parent.clientHeight;
      const camX = motion.matches ? 0 : Math.sin(clock * 0.13) * 0.04;
      clock += dt;

      const sky = ctx.createLinearGradient(0, 0, 0, height);
      sky.addColorStop(0, '#08131f');
      sky.addColorStop(0.42, '#060b14');
      sky.addColorStop(1, '#04070d');
      ctx.globalAlpha = 1;
      ctx.shadowBlur = 0;
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, width, height);

      const haze = ctx.createRadialGradient(width * 0.5, height * 0.74, 0, width * 0.5, height * 0.78, width * 0.62);
      haze.addColorStop(0, 'rgba(28, 72, 140, 0.28)');
      haze.addColorStop(0.45, 'rgba(14, 36, 78, 0.12)');
      haze.addColorStop(1, 'rgba(8, 16, 32, 0)');
      ctx.fillStyle = haze;
      ctx.fillRect(0, 0, width, height);

      const farL = project(-2.8, 0, 7.6, width, height, camX);
      const farR = project(2.8, 0, 7.6, width, height, camX);
      const nearL = project(-2.8, 0, 1.4, width, height, camX);
      const nearR = project(2.8, 0, 1.4, width, height, camX);
      const floor = ctx.createLinearGradient(0, farL.sy, 0, height);
      floor.addColorStop(0, 'rgba(10, 22, 42, 0.15)');
      floor.addColorStop(0.35, 'rgba(8, 18, 36, 0.55)');
      floor.addColorStop(1, '#05080e');
      ctx.beginPath();
      ctx.moveTo(farL.sx, farL.sy);
      ctx.lineTo(farR.sx, farR.sy);
      ctx.lineTo(nearR.sx, Math.max(nearR.sy, height));
      ctx.lineTo(nearL.sx, Math.max(nearL.sy, height));
      ctx.closePath();
      ctx.fillStyle = floor;
      ctx.fill();

      ctx.lineWidth = 1;
      for (let z = 1.45; z <= 7.8; z += 0.42) {
        const a = project(-2.5, 0, z, width, height, camX);
        const b = project(2.5, 0, z, width, height, camX);
        const fade = Math.max(0, 0.2 - (z - 1.3) * 0.024);
        ctx.strokeStyle = `rgba(96, 165, 250, ${fade})`;
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy);
        ctx.lineTo(b.sx, b.sy);
        ctx.stroke();
      }
      for (let x = -2.2; x <= 2.2; x += 0.36) {
        const a = project(x, 0, 1.4, width, height, camX);
        const b = project(x, 0, 7.6, width, height, camX);
        ctx.strokeStyle = 'rgba(96, 165, 250, 0.08)';
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy);
        ctx.lineTo(b.sx, b.sy);
        ctx.stroke();
      }

      const wash = ctx.createRadialGradient(width * 0.5, height * 0.86, 0, width * 0.5, height * 0.9, width * 0.34);
      wash.addColorStop(0, 'rgba(34, 211, 238, 0.07)');
      wash.addColorStop(1, 'rgba(34, 211, 238, 0)');
      ctx.fillStyle = wash;
      ctx.fillRect(0, 0, width, height);

      const rush = boostAt ? Math.min(2.15, 1 + (performance.now() - boostAt) / 260) : 1;
      if (!motion.matches) {
        for (const stream of streams) {
          if (stream.hold > 0) {
            stream.hold -= dt;
            stream.fade = Math.max(0, stream.hold / 0.28);
            if (stream.hold <= 0) respawn(stream);
            continue;
          }
          stream.vy = Math.min(rush > 1 ? 5 : 3.1, stream.vy + stream.g * dt * rush);
          stream.y -= stream.vy * dt;
          if (rush > 1) stream.x *= 1 - dt * 0.9;
          if (stream.fade < 1) stream.fade = Math.min(1, stream.fade + dt * 1.1);
          if (stream.y <= 0) {
            stream.y = 0;
            stream.vy = 0;
            stream.hold = 0.16 + Math.random() * 0.24;
            impacts.push({ x: stream.x, z: stream.z, age: 0, life: 0.42 + Math.random() * 0.25 });
          }
          if (Math.random() < dt * 0.35) {
            const i = Math.floor(Math.random() * stream.bits.length);
            stream.bits = stream.bits.slice(0, i) + (Math.random() > 0.5 ? '1' : '0') + stream.bits.slice(i + 1);
          }
        }
        impacts = impacts.filter((hit) => {
          hit.age += dt;
          return hit.age < hit.life;
        });
      }

      for (const hit of impacts) {
        const p = project(hit.x, 0, hit.z, width, height, camX);
        const t = hit.age / hit.life;
        const rx = (10 + t * 34) * p.s;
        const ry = rx * 0.22;
        ctx.globalAlpha = (1 - t) * 0.55 * Math.min(1, p.s);
        const glow = ctx.createRadialGradient(p.sx, p.sy, 0, p.sx, p.sy, Math.max(8, rx));
        glow.addColorStop(0, 'rgba(186, 230, 253, 0.85)');
        glow.addColorStop(0.45, 'rgba(56, 189, 248, 0.35)');
        glow.addColorStop(1, 'rgba(37, 99, 235, 0)');
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.ellipse(p.sx, p.sy, Math.max(2, rx), Math.max(1.2, ry), 0, 0, Math.PI * 2);
        ctx.fill();
      }

      const ordered = streams.slice().sort((a, b) => b.z - a.z);
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      for (const stream of ordered) {
        const fog = Math.exp(-(stream.z - 1.1) * 0.15);
        const len = stream.bits.length;
        for (let i = len - 1; i >= 0; i -= 1) {
          const gy = stream.y + i * stream.gap;
          if (gy < -0.05) continue;
          const p = project(stream.x, gy, stream.z, width, height, camX);
          if (p.sy < -30 || p.sy > height + 20 || p.sx < -40 || p.sx > width + 40) continue;
          const along = len <= 1 ? 0 : i / (len - 1);
          const head = i === 0;
          const falloff = head ? 1 : 0.2 + (1 - along) * 0.75;
          let alpha = stream.bright * fog * stream.fade * falloff * (rush > 1 ? Math.min(1.2, rush) : 1);
          const dx = Math.abs(p.sx - width * 0.5) / width;
          const dy = Math.abs(p.sy - height * 0.42) / height;
          if (dx < 0.15 && dy < 0.16) alpha *= 0.42 + dx * 2.2;
          if (alpha < 0.035) continue;
          const size = Math.max(stream.z > 5.5 ? 5 : 7, Math.min(28, 28 * p.s));
          ctx.font = `600 ${size}px "IBM Plex Mono", ui-monospace, monospace`;
          ctx.globalAlpha = Math.min(1, alpha);
          ctx.shadowBlur = head && stream.z < 2.15 ? 8 : 0;
          ctx.shadowColor = 'rgba(125, 211, 252, 0.85)';
          ctx.fillStyle = glyphFill(stream.z, along, head);
          if (head && stream.z < 2.3 && !motion.matches && stream.vy > 0.4) {
            const trail = Math.min(rush > 1 ? 34 : 18, stream.vy * p.s * (rush > 1 ? 15 : 11));
            ctx.shadowBlur = 0;
            ctx.globalAlpha = alpha * 0.28;
            ctx.strokeStyle = 'rgba(147, 197, 253, 0.9)';
            ctx.lineWidth = Math.max(1, size * 0.12);
            ctx.beginPath();
            ctx.moveTo(p.sx, p.sy - trail);
            ctx.lineTo(p.sx, p.sy);
            ctx.stroke();
            ctx.globalAlpha = Math.min(1, alpha);
            ctx.shadowBlur = 8;
          }
          ctx.fillText(stream.bits[i], p.sx, p.sy);

          if (gy < 0.9 && stream.z < 3.6 && stream.y < 0.35) {
            const mirror = project(stream.x, -0.08 - gy * 0.55, stream.z, width, height, camX);
            if (mirror.sy < height - 2 && mirror.sy > p.sy) {
              ctx.shadowBlur = 0;
              ctx.globalAlpha = alpha * 0.22 * (1 - gy / 0.9);
              ctx.fillStyle = '#7dd3fc';
              ctx.fillText(stream.bits[i], mirror.sx, mirror.sy);
            }
          }
        }
      }
      ctx.globalAlpha = 1;
      ctx.shadowBlur = 0;
    };

    let boostAt = 0;
    const onDepart = () => {
      if (!motion.matches) boostAt = performance.now();
    };
    window.addEventListener('sms-depart', onDepart);

    let lastPaint = 0;
    const step = (now: number) => {
      if (now - lastPaint < 15) return;
      const dt = Math.min(0.034, (now - last) / 1000 || 0.016);
      last = now;
      lastPaint = now;
      const rect = parent.getBoundingClientRect();
      if (rect.bottom > 0 && rect.top < window.innerHeight) paint(motion.matches ? 0 : dt);
    };
    const loop = (now: number) => {
      if (!running || motion.matches) return;
      step(now);
      frame = requestAnimationFrame(loop);
    };

    resize();
    paint(0);
    if (!motion.matches) frame = requestAnimationFrame(loop);
    // ponytail: embedded browsers can skip rAF; interval paints only when a frame was missed
    const backup = window.setInterval(() => {
      if (!running || motion.matches) return;
      if (performance.now() - lastPaint > 40) step(performance.now());
    }, 32);

    const observer = new ResizeObserver(() => {
      resize();
      paint(0);
    });
    observer.observe(parent);
    const onMotion = () => {
      resize();
      paint(0);
      if (!motion.matches) frame = requestAnimationFrame(loop);
      else cancelAnimationFrame(frame);
    };
    motion.addEventListener('change', onMotion);
    void document.fonts?.load('600 16px "IBM Plex Mono"').then(() => {
      if (running) paint(0);
    });

    return () => {
      running = false;
      cancelAnimationFrame(frame);
      window.clearInterval(backup);
      observer.disconnect();
      motion.removeEventListener('change', onMotion);
      window.removeEventListener('sms-depart', onDepart);
    };
  }, []);

  return <canvas ref={ref} className="sms-gate__rain" aria-hidden="true" />;
};
