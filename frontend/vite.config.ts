import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // ── Chunk splitting: separate vendor libs from app code ──
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('framer-motion')) return 'vendor-motion';
            if (id.includes('lucide-react')) return 'vendor-icons';
            return 'vendor';
          }
        },
      },
    },
    // Inline assets smaller than 8KB
    assetsInlineLimit: 8192,
    // Target modern browsers for smaller output
    target: 'esnext',
    // Enable minification
    minify: 'esbuild',
    // Source maps for production debugging (disable for even smaller builds)
    sourcemap: false,
  },
  // ── Dev server optimizations ──
  server: {
    // Pre-bundle these deps for faster dev startup
    warmup: {
      clientFiles: ['./src/App.tsx', './src/components/ResultDetails.tsx'],
    },
  },
})
