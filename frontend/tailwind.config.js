/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
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
            bg: '#F0F4F0',
            border: '#D4E8D4',
            heading: '#0D1F0D',
            text: '#4A5E4A',
            accent: '#00A846', // Deeper, richer green for text contrast
            'accent-deep': '#006B2B', // For SAFE badges and chart labels
            'accent-data': '#005C2A', // For key data points like %
            'accent-code': '#007A35', // For payload/monospace text
            'accent-bg': '#C8F5DC',   // Light background for green badges
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
