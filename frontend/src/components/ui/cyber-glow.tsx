"use client";

import { motion } from "framer-motion";
import { useEffect, useState } from "react";

interface Cell {
  id: number;
  x: number;
  y: number;
  delay: number;
  duration: number;
}

export function CyberGlow() {
  const [cells, setCells] = useState<Cell[]>([]);

  useEffect(() => {
    // Generate active grid cells
    const newCells = Array.from({ length: 60 }, (_, i) => ({
      id: i,
      x: Math.floor(Math.random() * 20),
      y: Math.floor(Math.random() * 20),
      delay: Math.random() * 10,
      duration: Math.random() * 4 + 2,
    }));
    setCells(newCells);
  }, []);

  return (
    <div
      className="absolute inset-0 pointer-events-none overflow-hidden"
      style={{
        maskImage: 'linear-gradient(200deg, black 45%, transparent 75%)',
        WebkitMaskImage: 'linear-gradient(200deg, black 45%, transparent 75%)',
      }}
    >
      {/* Subtle Base Grid */}
      <div
        className="absolute inset-0 opacity-[0.05] dark:opacity-[0.08]"
        style={{
          backgroundImage: `linear-gradient(var(--color-primary, #00C853) 1px, transparent 1px), linear-gradient(90deg, var(--color-primary, #00C853) 1px, transparent 1px)`,
          backgroundSize: '5vw 5vw'
        }}
      />

      {/* Active Scanning Cells */}
      <div
        className="absolute inset-0"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(20, 1fr)',
          gridAutoRows: '5vw', // Keep cells square by linking height to viewport width
        }}
      >
        {cells.map((cell) => (
          <motion.div
            key={cell.id}
            className="bg-ornex-green/30 border border-ornex-green/40 shadow-[0_0_10px_rgba(57,255,20,0.1)] aspect-square" // aspect-square to force squareness
            style={{
              gridColumnStart: cell.x + 1,
              gridRowStart: cell.y + 1,
            }}
            animate={{
              opacity: [0, 0.6, 0],
              scale: [0.95, 1, 0.95],
              backgroundColor: ['rgba(57, 255, 20, 0)', 'rgba(57, 255, 20, 0.25)', 'rgba(57, 255, 20, 0)'],
            }}
            transition={{
              duration: cell.duration,
              repeat: Infinity,
              delay: cell.delay,
              ease: "easeInOut",
            }}
          />
        ))}
      </div>

      {/* Sweeping Scan Beam - Horizontal (Constrained to clipping) */}
      <motion.div
        className="absolute inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-ornex-green to-transparent opacity-20 shadow-[0_0_15px_#39FF14]"
        animate={{
          top: ['-10%', '110%'],
        }}
        transition={{
          duration: 12,
          repeat: Infinity,
          ease: "linear",
        }}
      />

      {/* Ambient Glow Gradient - Anchored to top right */}
      <div className="absolute top-0 right-0 w-[1000px] h-[1000px] bg-ornex-green/[0.07] blur-[160px] rounded-full translate-x-1/3 -translate-y-1/3" />
    </div>
  );
}
