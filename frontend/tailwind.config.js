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
          black: '#050505',
          dark: '#0A0A0A',
          panel: '#111111',
          green: '#39FF14',
          greenDim: 'rgba(57, 255, 20, 0.1)',
          border: '#222222',
        },
        cyber: {
          safegreen: '#34d399',
          suspiciousamber: '#fbbf24',
          maliciousred: '#fb7185',
          slatebg: '#020617',
          panelbg: '#0f172a',
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
