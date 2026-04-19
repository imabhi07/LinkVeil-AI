# 🛡️ LinkVeil-AI 

**The ultimate real-time phishing detection system powered by Hybrid AI.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

LinkVeil-AI is an advanced, multi-layered security platform that provides real-time protection against sophisticated phishing attacks. By orchestrating Deep Learning, Gradient Boosting, LLMs, and Active Browser Probing, LinkVeil delivers high-accuracy verdicts with human-readable explanations.

---

## 🔥 Key Highlights

*   **⚡ Hybrid Intelligence**: Combines DistilBERT (Semantic), XGBoost (Lexical), and Gemini Pro (Cognitive).
*   **🕵️ Active Probing**: Real-time browser agent (Playwright) analyzes live page behavior and redirects.
*   **🧠 Cyber Analyst**: Receives detailed explanations of *why* a site was flagged, powered by Gemini.
*   **🎨 Premium UI**: Glassmorphic, animated React dashboard for a seamless security experience.
*   **✅ Verified Accuracy**: Optimized for 97%+ F1 score on modern phishing datasets.

---

## 🏗️ Architecture at a Glance

![LinkVeil-AI Architecture](docs/assets/architecture-LinkVeilAI.png)

*A multi-layered defense strategy combining behavioral, lexical, and semantic intelligence.*

---

## 🚀 Quick Start Instructions

### 1. Prerequisites
- **Python 3.11+** & **Node.js 18+**
- **Git LFS** (Required for pre-trained weights)

### 2. Initialization
```bash
git clone https://github.com/imabhi07/LinkVeil-AI.git
cd LinkVeil-AI
git lfs install
git lfs pull
```

### 3. Backend Setup (The Brain)
1. **Configure Environment**: Create a `.env` file in the root directory.
   ```env
   GOOGLE_API_KEY=your_gemini_api_key
   DATABASE_URL=sqlite:///./data/linkveil.db
   ```
2. **Install & Run**:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
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

---

## 🧪 Manual Model Training (Developer Mode)

If you prefer not to use Git LFS or wish to train your own version:

1.  **Prepare Data**: `python ml/datasets/prepare_data.py`
2.  **Train Models**: 
    - `python ml/train_xgboost.py` (Fast)
    - `python ml/train.py` (Expensive - GPU Recommended)

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
