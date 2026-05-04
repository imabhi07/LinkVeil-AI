import React, { memo, useState, useEffect } from 'react';
import type { RiskLevel } from '../types';
import { InfoTip } from './InfoTip';

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
      colorClass = 'text-cyber-light-accent-data dark:text-ornex-green drop-shadow-[0_0_10px_rgba(0,168,70,0.4)] dark:drop-shadow-[0_0_15px_rgba(57,255,20,0.6)]';
      strokeClass = 'stroke-cyber-light-accent dark:stroke-[#39FF14]';
      shadowColor = 'rgba(0, 168, 70, 0.3)';
      break;
    case 'SUSPICIOUS':
      colorClass = 'text-amber-500 dark:text-amber-400 drop-shadow-[0_0_12px_rgba(245,158,11,0.6)]';
      strokeClass = 'stroke-amber-500 dark:stroke-amber-400';
      shadowColor = 'rgba(245, 158, 11, 0.5)';
      break;
    case 'MALICIOUS':
      colorClass = 'text-rose-600 dark:text-rose-500 drop-shadow-[0_0_12px_rgba(244,63,94,0.6)]';
      strokeClass = 'stroke-rose-500 dark:stroke-rose-400';
      shadowColor = 'rgba(244, 63, 94, 0.5)';
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
            style={{ filter: `drop-shadow(0 0 6px ${shadowColor})` }}
          />
        </svg>
      </div>

      {/* Centered Score & Label */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <InfoTip 
          title="Risk Intelligence" 
          content="A composite forensic score (0-100) blending LLM reasoning, heuristic threat markers, and behavioral probe signals."
          className="flex flex-col items-center justify-center text-center cursor-help pointer-events-auto"
        >
          <div className="flex flex-col items-center leading-none select-none">
            <span className={`text-5xl font-black font-mono tracking-tighter transition-all duration-500 ${colorClass}`}>
              {displayScore}
            </span>
            <div className="flex flex-col items-center mt-1">
              <span className="text-[9px] text-cyber-light-text dark:text-zinc-400 uppercase tracking-[0.25em] font-black opacity-90">Risk</span>
              <span className="text-[9px] text-cyber-light-text dark:text-zinc-400 uppercase tracking-[0.25em] font-black opacity-90 mt-0.5">Score</span>
            </div>
          </div>
        </InfoTip>
      </div>
    </div>
  );
});

RiskGauge.displayName = 'RiskGauge';
