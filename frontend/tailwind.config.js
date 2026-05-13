/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      container: {
        center: true,
        padding: {
          DEFAULT: '1rem',
          sm: '1.5rem',
          lg: '2rem',
          xl: '2.5rem',
        },
      },
      screens: {
        'xs': '480px',
      },
      colors: {
        ornex: {
          black: '#000000',
          dark: '#080808',
          panel: '#0C0C0C',
          green: '#00FF41',
          greenDim: 'rgba(0, 255, 65, 0.1)',
          border: '#1A1A1A',
        },
        cyber: {
          safegreen: '#34d399',
          suspiciousamber: '#fbbf24',
          maliciousred: '#fb7185',
          slatebg: '#020617',
          panelbg: '#0f172a',
          light: {
            bg: '#f1f5f1',       // Softer, less "blinding" off-white with hint of green
            border: '#e2e8e2',   // More defined borders for structure
            heading: '#020617',  // Deepest slate for maximum contrast (WCAG AAA)
            text: '#334155',     // Deep slate-700 for body text
            accent: '#10b981',   // Electric Emerald-500
            'accent-deep': '#059669', // Vibrant Emerald-600 for text
            'accent-data': '#047857', // High-focus Emerald-700
            'accent-code': '#10b981',
            'accent-bg': '#f0fdf4',   // Lighter Emerald-50 background
          }
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        blob: 'blob 10s infinite',
      },
      keyframes: {
        blob: {
          '0%': { transform: 'translate(0px, 0px) scale(1)' },
          '33%': { transform: 'translate(30px, -50px) scale(1.1)' },
          '66%': { transform: 'translate(-20px, 20px) scale(0.9)' },
          '100%': { transform: 'translate(0px, 0px) scale(1)' },
        },
      },
    },
  },
  plugins: [],
}
