import React, { useRef, useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface CardCarouselProps {
  children: React.ReactNode[];
  className?: string;
}

export function CardCarousel({ children, className = "" }: CardCarouselProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const [activeIndex, setActiveIndex] = useState(0);

  const checkScroll = () => {
    if (scrollRef.current) {
      const { scrollLeft, scrollWidth, clientWidth } = scrollRef.current;
      setCanScrollLeft(scrollLeft > 0);
      setCanScrollRight(scrollLeft < scrollWidth - clientWidth - 5);
      
      // Calculate which item is most visible
      // We use the scrollWidth / children.length as an approximation of item width + gap
      const itemWidth = scrollWidth / children.length;
      const index = Math.round(scrollLeft / itemWidth);
      setActiveIndex(index);
    }
  };

  useEffect(() => {
    checkScroll();
    window.addEventListener('resize', checkScroll);
    return () => window.removeEventListener('resize', checkScroll);
  }, [children]);

  const scrollTo = (index: number) => {
    if (scrollRef.current) {
      const { scrollWidth } = scrollRef.current;
      const itemWidth = scrollWidth / children.length;
      scrollRef.current.scrollTo({ left: index * itemWidth, behavior: 'smooth' });
    }
  };

  const scroll = (direction: 'left' | 'right') => {
    if (scrollRef.current) {
      const { clientWidth } = scrollRef.current;
      const scrollAmount = direction === 'left' ? -clientWidth : clientWidth;
      scrollRef.current.scrollBy({ left: scrollAmount, behavior: 'smooth' });
    }
  };

  return (
    <div className={`relative group/carousel ${className}`}>
      {/* Navigation Buttons - Only show on hover or if scrollable */}
      {children.length > 1 && canScrollLeft && (
        <button
          onClick={() => scroll('left')}
          className="absolute -left-4 top-1/2 -translate-y-1/2 z-10 p-2 rounded-full bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-white/10 shadow-xl text-zinc-600 dark:text-zinc-400 opacity-0 group-hover/carousel:opacity-100 transition-opacity backdrop-blur-md hover:scale-110 active:scale-95"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
      )}
      
      {children.length > 1 && canScrollRight && (
        <button
          onClick={() => scroll('right')}
          className="absolute -right-4 top-1/2 -translate-y-1/2 z-10 p-2 rounded-full bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-white/10 shadow-xl text-zinc-600 dark:text-zinc-400 opacity-0 group-hover/carousel:opacity-100 transition-opacity backdrop-blur-md hover:scale-110 active:scale-95"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      )}

      {/* Carousel Container */}
      <div
        ref={scrollRef}
        onScroll={checkScroll}
        className="flex gap-4 overflow-x-auto snap-x snap-mandatory scrollbar-none pb-4 -mb-4 px-1 scroll-smooth"
        style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
      >
        {React.Children.map(children, (child, i) => (
          <motion.div
            key={i}
            className="flex-shrink-0 snap-start w-full first:ml-0 last:mr-0"
            initial={{ opacity: 0, y: 10 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.05 }}
          >
            {child}
          </motion.div>
        ))}
      </div>

      {/* Progress Indicator Dots - Only show if multiple items */}
      {children.length > 1 && (
        <div className="flex justify-center gap-2 mt-4">
          {Array.from({ length: children.length }).map((_, i) => (
            <button 
              key={i} 
              onClick={() => scrollTo(i)}
              className={`h-1.5 rounded-full transition-all duration-300 ${
                activeIndex === i 
                  ? 'w-4 bg-cyber-light-accent dark:bg-ornex-green opacity-100' 
                  : 'w-1.5 bg-zinc-300 dark:bg-zinc-700 opacity-30 hover:opacity-50'
              }`}
            />
          ))}
        </div>
      )}
    </div>
  );
}
