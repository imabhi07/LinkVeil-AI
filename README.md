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

*   **⚡ Hybrid Intelligence**: Tri-model ensemble combining XGBoost (Lexical), Gemini LLM (Cognitive), and Gemini Vision (Visual).
*   **📧 Email Forensic Scanner**: Deep analysis of `.eml` files and raw email text with header authentication (SPF/DKIM) and heuristic scoring.
*   **🕵️ Active Probing**: Real-time browser agent (Playwright) analyzes live page behavior and redirects.
*   **👁️ Visual Forensics**: Integrated Gemini Vision for visual brand recognition and impersonation detection.
*   **🔒 Privacy-First Forensics**: Automated PII scrubbing ("Privacy Protected") and intelligent log filtering ("Skipped") to protect sensitive forensic data.
*   **🛡️ Brand Mismatch Engine**: Local, zero-API-cost token matching for 20+ global brands.
*   **📡 Intelligence Dashboard**: Real-time aggregation of forensic indicators, categories, and historical trends.
*   **🎨 Premium UI**: A high-contrast "Cyber-Botanical" dashboard with enhanced light mode accessibility and professional glassmorphism.

---

## 🏗️ Architecture at a Glance

![LinkVeil-AI Architecture](docs/assets/architecture-LinkVeilAI-v1.png)

*A multi-layered defense strategy combining behavioral, lexical, and semantic intelligence.*

---

## 📂 Project Structure

```bash
.
├── backend/                # FastAPI High-Performance Backend
│   ├── app/
│   │   ├── features/       # Feature extraction: URL, Email, Link Triage
│   │   ├── models/         # Pydantic Schemas & DB Models
│   │   ├── routes/         # API Endpoints (Scanning, Analytics)
│   │   ├── services/       # AI Engines: XGBoost, Vision, Email, Brand, Probe
│   │   └── main.py         # Entry Point
│   └── requirements.txt    # Python Dependencies
├── frontend/               # React + Vite Forensic Dashboard
│   ├── src/
│   │   ├── components/     # Forensic UI: Analytics, EmailScan, RiskGauge
│   │   ├── types.ts        # Global Forensic Types
│   │   └── App.tsx         # Dashboard Orchestrator
│   └── tailwind.config.js  # Premium Design Tokens
├── ml/                     # Machine Learning Lab
├── extension/              # Browser Extension (In Progress)
├── data/                   # Persistent Storage (SQLite + screenshots)
├── tests/                  # 11+ Pytest test modules
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
   DATABASE_URL=sqlite:///./linkveil.db
   SECRET_KEY=your_random_secret_key
   MODEL_VARIANT=balanced
   LOG_LEVEL=INFO
   ```
2. **Setup Virtual Environment**:
   ```bash
   python -m venv venv
   ```
3. **Activate Environment**:
   ```bash
   .\venv\Scripts\activate  # Windows
   # source venv/bin/activate  # macOS / Linux
   ```
4. **Install Backend Dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```
5. **Install Browser Engine**:
   ```bash
   playwright install chromium
   ```
6. **Launch Backend Server**:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### 4. Frontend Setup
7. **Install Frontend Dependencies**:
   ```bash
   cd frontend
   npm install
   ```
8. **Launch Dashboard**:
   ```bash
   npm run dev
   ```

---

## 🛰️ API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | POST | Submit a URL for full forensic analysis |
| `/api/scan/email` | POST | Analyze raw email text for threats |
| `/api/scan/eml` | POST | Upload and analyze `.eml` forensic files |
| `/api/analytics/` | GET | Retrieve historical trends and stats |
| `/api/analytics/scans` | GET | Paginated list of recent forensic records |

---

## 🧪 Testing & Validation

LinkVeil-AI includes a comprehensive test suite covering all engines and integrations.

```bash
# Run all tests
pytest tests/ -v

# Run specific service tests
pytest tests/test_vision_service.py
pytest tests/test_email_scan.py
```

---

## 🧪 Manual Model Training (Developer Mode)

Train the XGBoost phishing classifier from scratch:

1.  **Prepare Data**: `python ml/datasets/prepare_data.py`
2.  **Train XGBoost** (Fast — recommended):
    ```bash
    python ml/train_xgboost.py
    ```
3.  **Train DistilBERT** (Optional — Research/Artifact only):
    > [!NOTE]
    > DistilBERT is provided as a training experiment. The live pipeline uses **XGBoost** and **Gemini** for inference to maintain high performance without GPU requirements.
    ```bash
    python ml/train.py
    ```

---

## 📖 Deep Dive Documentation

Looking for more details? Check out our specialized guides:
- 📘 **[Technical Architecture & Architecture Deep Dive](PROJECT_DETAILS.md)**
- 📝 **[Environment Variable Reference](backend/.env.example)**

---

## 🗺️ Roadmap

- [x] **Email Forensic Pipeline**: Full support for `.eml` and raw text analysis.
- [x] **Link Triage Engine**: Intelligent extraction and classification of email links.
- [x] **Intelligence Analytics**: Multi-dimensional trend tracking and dashboard.
- [ ] **Browser Extension**: Real-time protection while browsing (In Progress).
- [ ] **Collaborative Forensic Sharing**: Community-driven threat intelligence.

---

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
