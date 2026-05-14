import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, Lock, EyeOff, Server, Globe } from 'lucide-react';

interface PrivacyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PrivacyModal = ({ isOpen, onClose }: PrivacyModalProps) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] cursor-pointer"
          />

          {/* Modal Container */}
          <div className="fixed inset-0 flex items-center justify-center z-[101] p-4 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              role="dialog"
              aria-modal="true"
              aria-labelledby="privacy-modal-title"
              onKeyDown={(e) => { if (e.key === 'Escape') onClose(); }}
              tabIndex={-1}
              className="w-full max-w-2xl max-h-[85vh] bg-white/95 dark:bg-zinc-900/90 backdrop-blur-xl rounded-3xl overflow-hidden pointer-events-auto flex flex-col shadow-[0_20px_50px_rgba(0,0,0,0.1),0_0_30px_rgba(0,200,83,0.05)] border border-cyber-light-accent/20 dark:border-ornex-green/20 relative outline-none"
            >
              {/* Active Scanline Effect */}
              <motion.div 
                animate={{ top: ['-10%', '110%'] }}
                transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
                className="absolute left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyber-light-accent/20 dark:via-ornex-green/20 to-transparent z-[102] pointer-events-none"
              />

              {/* Shimmer Background */}
              <div className="absolute inset-0 bg-gradient-to-br from-cyber-light-accent/5 via-transparent to-transparent opacity-30 pointer-events-none" />
              {/* Header */}
              <div className="p-6 border-b border-zinc-100 dark:border-white/10 flex items-center justify-between bg-white/60 dark:bg-black/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-xl">
                    <Shield className="w-5 h-5 text-cyber-light-accent-deep dark:text-ornex-green" />
                  </div>
                  <div>
                    <h2 id="privacy-modal-title" className="text-lg font-black uppercase tracking-widest font-tektur text-cyber-light-heading dark:text-white">
                      Privacy Protocol
                    </h2>
                    <p className="text-[10px] font-mono text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                      Version 1.0.4 // Forensic Standards
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  aria-label="Close Privacy Modal"
                  className="p-2 hover:bg-zinc-100 dark:hover:bg-white/10 rounded-full transition-colors text-zinc-500 dark:text-zinc-400 group/close relative"
                >
                  <X className="w-5 h-5 group-hover/close:rotate-90 transition-transform duration-300" />
                  <div className="absolute inset-0 bg-cyber-light-accent dark:bg-ornex-green rounded-full blur-sm opacity-0 group-hover/close:opacity-20 transition-opacity" />
                </button>
              </div>

              {/* Content */}
              <motion.div 
                initial="hidden"
                animate="visible"
                variants={{
                  hidden: { opacity: 0 },
                  visible: {
                    opacity: 1,
                    transition: { staggerChildren: 0.1, delayChildren: 0.2 }
                  }
                }}
                className="flex-1 overflow-y-auto overscroll-contain p-8 space-y-8 custom-scrollbar font-sans relative"
              >
                {[
                  {
                    icon: Lock,
                    title: "Data Sovereignty",
                    content: <>PhishGuard is designed with a <span className="text-cyber-light-heading dark:text-zinc-200 font-semibold">Zero-Retention architecture</span>. We do not store your personal emails, passwords, or scanned content on our permanent servers. The forensic analysis is performed in volatile memory and purged immediately after the session concludes.</>
                  },
                  {
                    icon: EyeOff,
                    title: "PII Scrubbing",
                    content: <>Our <span className="text-cyber-light-heading dark:text-zinc-200 font-semibold">Privacy Guard</span> automatically identifies and redacts Personally Identifiable Information (PII) before it reaches our analysis engine. Tokens, session IDs, and email addresses are masked to ensure your identity remains protected during threat correlation.</>
                  },
                  {
                    icon: Server,
                    title: "Local Persistence",
                    content: <>Your scan history is stored <span className="text-cyber-light-heading dark:text-zinc-200 font-semibold">locally in your browser</span> using standard Web Storage. This data never leaves your device and is not synced to any cloud accounts. You can clear this forensic history at any time using the "Clear History" function in the sidebar.</>
                  },
                  {
                    icon: Globe,
                    title: "Third-Party Intelligence",
                    content: <>We leverage global threat intelligence feeds and AI models (Google Gemini) to identify emerging threats. Communication with these services is secured via TLS 1.3 and is restricted to metadata required for classification.</>
                  }
                ].map((section, idx) => (
                  <motion.section 
                    key={idx}
                    variants={{
                      hidden: { opacity: 0, x: -10 },
                      visible: { opacity: 1, x: 0 }
                    }}
                    className="space-y-4 relative group"
                  >
                    <div className="flex items-center gap-3 text-cyber-light-accent-deep dark:text-ornex-green">
                      <div className="p-1.5 rounded-lg bg-cyber-light-accent/10 dark:bg-ornex-green/10 group-hover:scale-110 transition-transform">
                        <section.icon className="w-4 h-4" />
                      </div>
                      <h3 className="text-sm font-bold uppercase tracking-widest font-mono group-hover:translate-x-1 transition-transform">{section.title}</h3>
                    </div>
                    <p className="text-sm text-cyber-light-text dark:text-zinc-400 leading-relaxed pl-8 sm:pl-10">
                      {section.content}
                    </p>
                  </motion.section>
                ))}

                <motion.div 
                  variants={{
                    hidden: { opacity: 0, y: 10 },
                    visible: { opacity: 1, y: 0 }
                  }}
                  className="pt-6 border-t border-zinc-200 dark:border-white/10"
                >
                  <div className="p-4 rounded-2xl bg-cyber-light-accent/5 dark:bg-ornex-green/5 border border-cyber-light-accent/20 dark:border-ornex-green/10 relative overflow-hidden group">
                    <motion.div 
                      animate={{ opacity: [0.1, 0.2, 0.1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                      className="absolute inset-0 bg-cyber-light-accent/5 dark:bg-ornex-green/5 pointer-events-none"
                    />
                    <p className="text-[11px] text-cyber-light-text dark:text-zinc-500 italic text-center relative z-10">
                      "Security is a shared responsibility. While we protect your forensic data, always exercise caution when interacting with unknown digital assets."
                    </p>
                  </div>
                </motion.div>
              </motion.div>

              {/* Footer */}
              <div className="p-6 bg-white/80 dark:bg-black/40 border-t border-zinc-100 dark:border-white/10 flex justify-end">
                <button
                  onClick={onClose}
                  className="px-8 py-2.5 bg-cyber-light-accent dark:bg-ornex-green text-white dark:text-ornex-black rounded-full font-bold uppercase tracking-widest text-[10px] shadow-lg shadow-cyber-light-accent/20 dark:shadow-ornex-green/20 hover:scale-105 active:scale-95 transition-all"
                >
                  Acknowledge
                </button>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
};
