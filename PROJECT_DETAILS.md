# LinkVeil-AI: Technical Deep Dive & Architecture

This document provides a comprehensive technical overview of LinkVeil-AI, explaining the design philosophy, machine learning pipelines, and the orchestration logic that makes it an industry-grade phishing detection system.

---

## 1. Project Philosophy
LinkVeil-AI was built on the premise that single-signal detection (like blacklisting or simple lexical analysis) is no longer sufficient for modern phishing attacks. Sophisticated attackers use:
- **Zero-hour domains** (not yet blacklisted).
- **Legitimate hosting** (GitHub Pages, Netlify).
- **Context-aware content** (Impersonating specific corporate portals).

LinkVeil-AI solves this using a **Defense-in-Depth** approach, combining four specialized engines into a single decision.

---

## 2. System Architecture

### 🛡️ High-Level Component View
1. **Frontend (React/Vite)**: Gathers the URL and provides a real-time "progress scan" visualizer.
2. **API Layer (FastAPI)**: Manages async orchestration of the four detection engines.
3. **Engine 1: XGBoost (Lexical)**: Checks the "DNA" of the URL string.
4. **Engine 2: DistilBERT (Semantic)**: Checks the "Meaning" of the URL.
5. **Engine 3: Playwright Agent (Live Probe)**: Checks the "Behavior" of the destination.
6. **Engine 4: Gemini Pro (LLM Analyst)**: Checks the "Context" and explains the risk.

---

## 3. The Machine Learning Pipeline

### A. Lexical Analysis (XGBoost)
The XGBoost engine focuses on the mathematical properties of the URL string. 
- **Features Extracted**: Entropy (randomness), character frequency (excessive dashes/dots), presence of sensitive keywords (login, bank, secure), and TLD (top-level domain) reputation.
- **Why XGBoost?**: It is exceptionally fast and handles non-linear relationships between these features better than simple logistic regression.

### B. Deep Learning (DistilBERT)
DistilBERT treates the URL as **natural language**. 
- **The Insight**: Phishing URLs often "sound" wrong or try to look like other brands (e.g., `paypal-security-update.com`).
- **Fine-tuning**: We fine-tuned the `distilbert-base-uncased` model on 100,000+ balanced phishing and benign URLs so it understands the semantic patterns of malicious links.

---

## 4. Real-Time Probing Agent (Active Defense)
The **Probe Agent** is the most advanced part of LinkVeil-AI. 
- **The Sandbox**: When a URL is submitted, the backend spins up a headless Chromium instance via **Playwright**.
- **Evidence Gathering**: 
  - It captures the final redirected URL (detecting sneaky redirect chains).
  - It checks the page title and metadata.
  - It detects common phishing techniques like "Input-masking" (fake login forms).
- **Hardening**: The agent uses timeouts and thread-safe executors to prevent malicious sites from crashing the server during analysis.

---

## 5. The Cyber Analyst (Gemini Pro)
Once the ML engines have their scores, the **Gemini 1.5 Pro** LLM is fed the raw evidence:
- "The Deep Learning model is 92% sure this is phishing."
- "The Probe Agent found a login form on a suspicious domain."
- "The URL contains the brand 'Netflix' but is not hosted on netflix.com."

Gemini acts as the "Decision Maker," synthesizing these signals into a human-readable explanation and a final verdict. This eliminates the "Black Box" problem of traditional AI.

---

## 6. Score Orchestration Logic
Scores are aggregated into a **Final Risk Score (0-100)** using a weighted priority system:
1. **Critical Flags**: If the Probe Agent detects a known phishing pattern, the score is immediately boosted.
2. **High-Confidence DL**: If DistilBERT and XGBoost both agree (>0.9), the verdict is locked as Malicious.
3. **Ambiguous Cases**: If signals are mixed, Gemini's reasoning takes the highest weight to decide if it's a creative new attack.

---

## 7. Frontend Design System
The UI was designed to feel like a high-end security operations center (SOC) tool:
- **Glassmorphism**: Elegant, transparent UI elements.
- **Micro-Animations**: Real-time progress bars and transition effects to keep the user engaged during the 2-4 second analysis window.
- **Accessibility**: High-contrast badges and clear typography for binary verdicts (Safe/Malicious).

---

## 8. Database & Caching
- **SQLite/Postgres**: Stores every scan result.
- **Caching**: If a URL was scanned in the last hour, the system returns the cached result instantly, saving API costs and compute time.

---

## 9. Future Roadmap
- [ ] **Visual Analysis**: Using computer vision to detect pixel-perfect clones of websites.
- [ ] **WHOIS Analysis**: Checking domain age (phishing sites are usually < 48 hours old).
- [ ] **Browser Extension**: Real-time protection while browsing.
