import React, { memo, useState, useEffect } from 'react';
import type { RiskLevel } from '../types';

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = memo(({ score, level }) => {
  // ── Animated count-up ──
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    let frame: number;
    const duration = 800; // ms
    const start = performance.now();
    const from = 0;
    const to = score;

    const animate = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.round(from + (to - from) * eased));
      if (progress < 1) {
        frame = requestAnimationFrame(animate);
      }
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  let colorClass = 'text-zinc-400';
  let strokeClass = 'stroke-zinc-600';
  let shadowColor = 'transparent';

  switch (level) {
    case 'SAFE':
      colorClass = 'text-cyber-light-accent-data dark:text-ornex-green drop-shadow-[0_0_8px_rgba(0,168,70,0.3)] dark:drop-shadow-[0_0_8px_rgba(57,255,20,0.8)]';
      strokeClass = 'stroke-cyber-light-accent dark:stroke-[#39FF14]';
      shadowColor = 'rgba(0, 168, 70, 0.2)';
      break;
    case 'SUSPICIOUS':
      colorClass = 'text-amber-500 dark:text-amber-400 drop-shadow-[0_0_8px_rgba(245,158,11,0.8)]';
      strokeClass = 'stroke-amber-500 dark:stroke-[#fbbf24]';
      shadowColor = 'rgba(245, 158, 11, 0.4)';
      break;
    case 'MALICIOUS':
      colorClass = 'text-rose-600 dark:text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.8)]';
      strokeClass = 'stroke-rose-500 dark:stroke-[#f43f5e]';
      shadowColor = 'rgba(244, 63, 94, 0.4)';
      break;
  }

  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (displayScore / 100) * circumference;

  return (
    <div className="relative flex flex-col items-center justify-center">
      <div className="relative w-32 h-32 transform -rotate-90">
        <svg className="w-full h-full" viewBox="0 0 120 120" aria-label={`Risk score: ${score}`}>
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            className="stroke-cyber-light-border dark:stroke-white/10 transition-colors duration-300"
            strokeWidth="8"
          />
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className={`transition-all duration-1000 ease-out ${strokeClass}`}
            style={{ filter: `drop-shadow(0 0 4px ${shadowColor})` }}
          />
        </svg>
      </div>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`text-4xl font-bold font-mono tracking-tighter ${colorClass}`}>{displayScore}</span>
        <span className="text-[10px] text-cyber-light-text dark:text-zinc-500 uppercase tracking-widest font-bold mt-1">Risk Score</span>
      </div>
    </div>
  );
});

RiskGauge.displayName = 'RiskGauge';
