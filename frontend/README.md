# LinkVeil-AI — Frontend

React 19 + TypeScript + Vite forensic dashboard for the LinkVeil-AI phishing detection platform.

## Stack

- **React 19** with strict-mode rendering
- **TypeScript 6** for end-to-end type safety
- **Vite 8** for fast HMR development and optimised production builds
- **Tailwind CSS v4** with a custom "Cyber-Botanical" design system (light + dark modes)
- **Framer Motion** for animated background paths and micro-interactions
- **Lucide React** icon set

## Development

```bash
# Install dependencies
npm install

# Start dev server (http://localhost:5173)
npm run dev

# Production build (type-check + bundle)
npm run build   # tsc -b && vite build

# Lint
npm run lint
```

## Environment

Create a `.env.local` file in this directory and set the API base URL:

```env
VITE_API_BASE_URL=http://localhost:8000
```

## Project Layout

```
src/
├── App.tsx              # Root component — scan form, history, analytics overlay
├── types.ts             # Shared TypeScript interfaces (AnalysisResult, ScanHistoryItem…)
├── index.css            # Global styles, Tailwind imports, glass-panel utilities
├── components/
│   ├── ResultDetails.tsx     # Full forensic report panel
│   ├── HistorySidebar.tsx    # Scan history list
│   ├── AnalyticsPanel.tsx    # Intelligence dashboard overlay
│   ├── RiskGauge.tsx         # Animated SVG risk score gauge
│   └── ui/
│       └── background-paths.tsx  # Animated SVG background decoration
└── lib/
    └── utils.ts          # cn() Tailwind class merge helper
```

## Production Build

```bash
npm run build
# Output: dist/
```

The `dist/` directory can be served behind any static file server or Nginx (see `nginx.conf` for a reference configuration).
