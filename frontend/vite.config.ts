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
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-motion': ['framer-motion'],
          'vendor-icons': ['lucide-react'],
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
