# 🛡️ LinkVeil-AI 

**The ultimate real-time phishing detection system powered by Hybrid AI.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-19+-61DAFB.svg?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-v6+-3178C6.svg?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4+-06B6D4.svg?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.103+-009688.svg?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)

[![Gemini AI](https://img.shields.io/badge/Gemini_AI-Sentinel_Engine-8E75B2.svg?style=flat-square&logo=google-gemini&logoColor=white)](https://ai.google.dev/)
[![Playwright](https://img.shields.io/badge/Playwright-Deep_Probe-2EAD33.svg?style=flat-square&logo=playwright&logoColor=white)](https://playwright.dev/)
[![XGBoost](https://img.shields.io/badge/XGBoost-Lexical_Engine-FF6600.svg?style=flat-square)](https://xgboost.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

LinkVeil-AI is an advanced, multi-layered security platform that provides real-time protection against sophisticated phishing attacks. By orchestrating XGBoost (lexical analysis), Gemini LLM (cognitive reasoning), Gemini Vision (visual forensics), and active browser probing, LinkVeil delivers high-accuracy verdicts with human-readable explanations.

---

## 🔥 Key Highlights

*   **⚡ Hybrid Intelligence**: Combines XGBoost (Lexical), and Gemini AI (Cognitive + Visual).
*   **🕵️ Active Probing**: Real-time browser agent (Playwright) analyzes live page behavior and redirects.
*   **👁️ Multimodal Visual Forensics**: Integrated Gemini Vision for visual brand recognition and impersonation detection.
*   **📡 Intelligence Dashboard**: Real-time aggregation of forensic indicators, categories, and historical data.
*   **🛡️ Threat Intel Services**: Live feeds from OpenPhish/URLhaus plus WHOIS and brand reputation lookups.
*   **🎨 Cyber-Light UI**: A premium "Cyber-Botanical" light mode for accessibility without sacrificing aesthetic depth.

---

## 🏗️ Architecture at a Glance

![LinkVeil-AI Architecture](docs/assets/architecture-LinkVeilAI.png)

*A multi-layered defense strategy combining behavioral, lexical, and semantic intelligence.*

---

## 📂 Project Structure

```bash
.
├── backend/                # FastAPI High-Performance Backend
│   ├── app/
│   │   ├── features/       # Lexical URL Feature Extractor
│   │   ├── models/         # Pydantic Schemas & DB Models
│   │   ├── routes/         # API Endpoints (Scanning, Analytics)
│   │   ├── services/       # AI Engines: XGBoost, Vision, Whois, ThreatIntel, Probe
│   │   └── main.py         # Entry Point
│   └── requirements.txt    # Python Dependencies
├── frontend/               # React + Vite Forensic Dashboard
│   ├── src/
│   │   ├── components/     # UI/UX Glassmorphic Components
│   │   ├── types.ts        # Global Forensic Types
│   │   └── App.tsx         # Dashboard Orchestrator
│   └── tailwind.config.js  # Premium Design Tokens
├── ml/                     # Machine Learning Lab
│   ├── datasets/           # Data preparation scripts
│   ├── models/             # Local model weights (XGBoost)
│   ├── train.py            # DistilBERT training script
│   ├── train_xgboost.py    # XGBoost training script
│   └── xgb_features.py     # URL feature engineering
├── data/                   # Persistent Storage (SQLite + screenshots)
├── tests/                  # Pytest test suite
└── docs/                   # Technical Assets & Diagrams
```

---

## 🚀 Quick Start Instructions

### 1. Prerequisites
- **Python 3.11+** & **Node.js 18+**

### 2. Clone the Repository
```bash
git clone https://github.com/imabhi07/LinkVeil-AI.git
cd LinkVeil-AI
```

### 3. Backend Setup (The Brain)
1. **Configure Environment**: Create a `.env` file in the root directory.
   ```env
   GEMINI_API_KEY=your_gemini_api_key
   DATABASE_URL=sqlite:///./data/linkveil.db
   ```
2. **Install & Run**:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   # source venv/bin/activate  # macOS / Linux
   pip install -r backend/requirements.txt
   playwright install chromium
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### 4. Frontend Setup (The Face)
```bash
cd frontend
npm install
npm run dev
```

> **Windows shortcut**: After creating the `.env` file, double-click `start.bat` to launch both servers simultaneously.

---

## 🧪 Manual Model Training (Developer Mode)

Train the XGBoost phishing classifier from scratch:

1.  **Prepare Data**: `python ml/datasets/prepare_data.py`
2.  **Train XGBoost** (Fast — recommended):
    ```bash
    python ml/train_xgboost.py
    ```
3.  **Train DistilBERT** (Expensive — GPU recommended, optional):
    ```bash
    python ml/train.py
    ```

---

## 📖 Deep Dive Documentation

Looking for more details? Check out our specialized guides:
- 📘 **[Technical Architecture & ML Deep Dive](PROJECT_DETAILS.md)**
- 📝 **[Environment Variable Reference](backend/.env.example)**

---

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
