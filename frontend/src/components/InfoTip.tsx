import React, { useState, useRef, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import { Info } from 'lucide-react';
import { motion, AnimatePresence, type Variants } from 'framer-motion';

interface InfoTipProps {
  title: string;
  content: string | React.ReactNode;
  children?: React.ReactNode;
  placement?: 'top' | 'bottom' | 'left' | 'right';
  className?: string;
}

export const InfoTip: React.FC<InfoTipProps> = ({ 
  title, 
  content, 
  children, 
  placement = 'top',
  className = "relative inline-flex items-center"
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0 });
  const triggerRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (isVisible && triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      const scrollY = window.scrollY;
      const scrollX = window.scrollX;
      
      let top = 0;
      let left = 0;

      // Basic positioning logic
      switch (placement) {
        case 'top':
          top = rect.top + scrollY - 10;
          left = rect.left + scrollX + rect.width / 2;
          break;
        case 'bottom':
          top = rect.bottom + scrollY + 10;
          left = rect.left + scrollX + rect.width / 2;
          break;
        case 'left':
          top = rect.top + scrollY + rect.height / 2;
          left = rect.left + scrollX - 10;
          break;
        case 'right':
          top = rect.top + scrollY + rect.height / 2;
          left = rect.right + scrollX + 10;
          break;
      }
      
      setCoords({ top, left });
    }
  }, [isVisible, placement]);

  const variants: Variants = {
    hidden: { 
      opacity: 0, 
      scale: 0.95,
      y: placement === 'top' ? '-95%' : placement === 'bottom' ? '5%' : '-50%',
      x: placement === 'left' ? '-95%' : placement === 'right' ? '5%' : '-50%',
    },
    visible: { 
      opacity: 1, 
      scale: 1,
      y: placement === 'top' ? '-100%' : placement === 'bottom' ? '0%' : '-50%',
      x: (placement === 'top' || placement === 'bottom') ? '-50%' : placement === 'left' ? '-100%' : '0%',
      transition: {
        type: 'spring',
        damping: 25,
        stiffness: 400
      }
    },
    exit: { 
      opacity: 0, 
      scale: 0.95,
      transition: { duration: 0.1 }
    }
  };

  const tooltipContent = (
    <AnimatePresence mode="wait">
      {isVisible && (
        <motion.div
          initial="hidden"
          animate="visible"
          exit="exit"
          variants={variants}
          style={{ 
            position: 'absolute',
            top: coords.top,
            left: coords.left,
            zIndex: 99999
          }}
          className="w-64 pointer-events-none"
        >
          <div className="p-3.5 rounded-2xl bg-white/95 dark:bg-zinc-950/95 border border-zinc-200 dark:border-white/20 shadow-xl dark:shadow-[0_30px_60px_-15px_rgba(0,0,0,0.8)] backdrop-blur-3xl overflow-hidden relative group">
            {/* Animated Border Glow */}
            <div className="absolute inset-0 bg-gradient-to-br from-cyber-light-accent/10 dark:from-emerald-500/10 via-transparent to-transparent opacity-100" />
            
            <div className="relative space-y-2.5">
              <div className="flex items-center gap-2">
                <div className="w-1 h-3.5 bg-cyber-light-accent dark:bg-emerald-500 rounded-full shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-cyber-light-accent dark:text-emerald-400">
                  {title}
                </h4>
              </div>
              <div className="text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-100 font-medium">
                {content}
              </div>
            </div>

            {/* Arrow */}
            <div className={`absolute w-3 h-3 bg-white/95 dark:bg-zinc-950/95 border-r border-b border-zinc-200 dark:border-white/20 rotate-45 ${
              placement === 'top' ? 'top-full -mt-1.5 left-1/2 -translate-x-1/2' :
              placement === 'bottom' ? 'bottom-full -mb-1.5 left-1/2 -translate-x-1/2 rotate-[225deg]' :
              placement === 'left' ? 'left-full -ml-1.5 top-1/2 -translate-y-1/2 rotate-[-45deg]' :
              'right-full -mr-1.5 top-1/2 -translate-y-1/2 rotate-[135deg]'
            }`} />
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  return (
    <div 
      ref={triggerRef}
      className={className}
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
      onFocus={() => setIsVisible(true)}
      onBlur={() => setIsVisible(false)}
    >
      {children ? (
        <div className={`cursor-help ${className.includes('w-full') ? 'w-full' : ''}`}>
          {children}
        </div>
      ) : (
        <button
          type="button"
          className="p-1 rounded-full hover:bg-emerald-500/10 transition-all duration-300 text-white/30 hover:text-emerald-400 group/tip"
          aria-label="More information"
        >
          <Info size={13} className="group-hover/tip:scale-110 transition-transform" />
        </button>
      )}

      {typeof document !== 'undefined' && createPortal(tooltipContent, document.body)}
    </div>
  );
};
