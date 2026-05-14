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
    const newCells = Array.from({ length: 80 }, (_, i) => ({
      id: i,
      x: Math.floor(Math.random() * 40),
      y: Math.floor(Math.random() * 40),
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
        className="absolute inset-0 opacity-[0.1] dark:opacity-[0.08]"
        style={{
          backgroundImage: `linear-gradient(var(--color-primary, #059669) 1px, transparent 1px), linear-gradient(90deg, var(--color-primary, #059669) 1px, transparent 1px)`,
          backgroundSize: 'min(5vw, 5vh) min(5vw, 5vh)'
        }}
      />

      {/* Active Scanning Cells */}
      <div
        className="absolute inset-0"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, min(5vw, 5vh))',
          gridAutoRows: 'min(5vw, 5vh)',
        }}
      >
        {cells.map((cell) => (
          <motion.div
            key={cell.id}
            className="bg-[var(--color-primary,#059669)]/30 border border-[var(--color-primary,#059669)]/40 shadow-[0_0_20px_var(--color-primary-glow,rgba(5,150,105,0.3))] aspect-square" 
            style={{
              gridColumnStart: cell.x + 1,
              gridRowStart: cell.y + 1,
            }}
            animate={{
              opacity: [0, 0.8, 0],
              scale: [0.95, 1.05, 0.95],
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

    

      {/* Ambient Glow Gradient - Anchored to top right */}
      <div className="absolute top-0 right-0 w-[1000px] h-[1000px] bg-[var(--color-primary,#059669)]/[0.12] blur-[160px] rounded-full translate-x-1/3 -translate-y-1/3" />
    </div>
  );
}
