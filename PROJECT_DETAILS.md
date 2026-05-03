# LinkVeil-AI: Technical Deep Dive & Architecture

This document provides a comprehensive technical overview of LinkVeil-AI, explaining the design philosophy, machine learning pipelines, and the orchestration logic that makes it an industry-grade phishing detection system.

---

## 1. Project Philosophy
LinkVeil-AI was built on the premise that single-signal detection (like blacklisting or simple lexical analysis) is no longer sufficient for modern phishing attacks. Sophisticated attackers use:
- **Zero-hour domains** (not yet blacklisted).
- **Legitimate hosting** (GitHub Pages, Netlify).
- **Context-aware content** (Impersonating specific corporate portals).

LinkVeil-AI solves this using a **Defense-in-Depth** approach, combining seven specialized engines into a single decision.

---

## 2. System Architecture

### 🛡️ High-Level Component View
1. **Frontend (React/Vite)**: Gathers input (URL/Email) and provides a real-time forensic visualizer.
2. **API Layer (FastAPI)**: Manages async orchestration of seven forensic engines.
3. **Engine 1: XGBoost (Lexical)**: Checks the "DNA" of the URL string via 30+ features.
4. **Engine 2: Playwright Agent (Live Probe)**: Analyzes "Behavior" of the destination in a sandbox.
5. **Engine 3: Gemini AI (Cognitive Analyst)**: Synthesizes multi-engine evidence into explanations.
6. **Engine 4: Gemini Vision (Visual Forensics)**: Detects pixel-perfect brand impersonation.
7. **Engine 5: Threat Intel + WHOIS**: Checks live phishing feeds and domain registration.
8. **Engine 6: Email Forensic Analyzer**: Heuristic scoring of headers, authentication, and urgency.
9. **Engine 7: Brand Mismatch Detector**: Local, zero-cost token matching for 20+ major brands.

---

## 3. The Machine Learning Pipeline

### A. Lexical Analysis (XGBoost)
The XGBoost engine focuses on the mathematical properties of the URL string. 
- **Features Extracted**: Entropy (randomness), character frequency (excessive dashes/dots), presence of sensitive keywords (login, bank, secure), and TLD (top-level domain) reputation.
- **Why XGBoost?**: It is exceptionally fast and handles non-linear relationships between these features better than simple logistic regression.

### B. Deep Learning (DistilBERT — Training Only)
A DistilBERT model can optionally be trained on URL data using `ml/train.py`. 
- **The Insight**: Phishing URLs often "sound" wrong or try to look like other brands (e.g., `paypal-security-update.com`).
- **Fine-tuning**: The `distilbert-base-uncased` model is fine-tuned on balanced phishing and benign URLs so it understands the semantic patterns of malicious links.
- **Note**: The DistilBERT model is a training artifact only. At runtime the backend uses the XGBoost engine (`xgb_service.py`) alongside the Gemini LLM for all inference.

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

## 5. The Cyber Analyst (Gemini AI)
Once the ML engines have their scores, the **Gemini AI** LLM is fed the raw evidence:
- "The XGBoost model scores this URL at 87% phishing probability."
- "The Probe Agent found a login form on a suspicious domain."
- "The URL contains the brand 'Netflix' but is not hosted on netflix.com."
- "The Email headers show an SPF 'fail' for a purported Microsoft sender."

Gemini acts as the "Decision Maker," synthesizing these signals into a human-readable explanation and a final verdict.

---

## 6. Email Forensic Pipeline & Link Triage

When an email is submitted, LinkVeil-AI executes a multi-stage forensic extraction:

1. **Header Authentication**: Validates SPF and DKIM results to detect sender spoofing.
2. **Heuristic Scoring**: Analyzes body urgency, common phishing keywords, and impersonation flags (e.g., "PayPal" in name but `scam.com` in domain).
3. **Link Extraction & Triage**:
   - Extracts all URLs from the email body.
   - **Classification**: Categorizes links as `static_asset`, `tracking_wrapper`, `unsubscribe`, `content`, or `known_safe`.
   - **PII Scrubbing**: Automatically removes sensitive query parameters (email addresses, IDs) before analysis to protect user privacy.
   - **Unwrapping**: Detects and unwraps common email tracking/redirect services to find the final destination.
4. **SSRF Hardening**: All network-bound tasks in the triage layer use a threaded executor with strict timeouts and private IP rejection to protect the internal infrastructure.

---

## 6. Score Orchestration Logic
Scores are aggregated into a **Final Risk Score (0-100)** using a weighted fusion system:
1. **Base Blend**: LLM score (70%) + XGBoost score (30%) form the base risk value.
2. **Signal Boosts**: WHOIS age, brand mismatch (Engine 7), suspicious TLD, and visual forensics (Engine 4) add incremental risk.
3. **Probe Adjustment**: If the Playwright agent confirms credential harvesting, the score is boosted. If no login elements are found, the score is dampened.
4. **Threat Intel Short-Circuit**: Instant "High" risk if the URL appears in live phishing feeds.

---

## 7. Frontend Design System
The UI was designed to feel like a high-end security operations center (SOC) tool:
- **Glassmorphism**: Elegant, transparent UI elements with subtle motion.
- **Forensic Intelligence Dashboard**: A centralized panel featuring `AnalyticsPanel.tsx` for trend tracking and indicator aggregation.
- **Triple-Mode Email Scanner**: `EmailScan.tsx` allows for manual forensic entry, raw text pasting, or `.eml` file uploads.
- **Accessible Design**: High-contrast typography, theme-aware styling, and ARIA-compliant `InfoTip` components.
- **Animated Risk Visuals**: `RiskGauge.tsx` and real-time progress transitions provide immediate cognitive feedback.

---

## 8. Database & Caching
- **SQLite/Postgres**: Stores every scan result with full forensic context (WHOIS, probe artifacts, fusion trace).
- **In-Process Cache**: If a URL was scanned in the last 5 minutes, the system returns the cached result instantly, saving API costs and compute time.

---

## 9. Multimodal Visual Forensics (Engine 4)
Using Gemini Vision, LinkVeil-AI can now "see" like a human analyst:
- **Logo Recognition**: Identifies if a page is visually claiming to be Amazon, Google, or Microsoft.
- **Anti-SSO Heuristics**: Distinguishes between legitimate "Login with Google" buttons and malicious pages designed entirely around fake Google portals.
- **Confidence Scoring**: Each visual match is assigned a confidence value, which is fused with lexical and behavioral signals for the final verdict.

## 10. Intelligence Analytics & Historics
The platform now features a dedicated intelligence panel:
- **Indicator Aggregation**: Tracks category trends (Financial, Social Media, Tech) across all scans.
- **Historical Trends**: Visualizes scan volume and risk distribution over time.
- **Data Persistence**: Uses a forensic SQLite/Postgres store to ensure all intelligence is available for retroactive auditing.

## 11. Future Roadmap
- [x] **Email Forensic Pipeline**: Full header/body analysis and link triage.
- [ ] **Browser Extension**: Real-time protection while browsing (In Progress).
- [ ] **Collaborative Forensic Sharing**: Community-driven threat intelligence.

---

## 12. Testing & Quality Assurance

LinkVeil-AI maintains a robust test suite in `/tests` to ensure detection accuracy:
- **Service Isolation**: Individual tests for WHOIS, Vision, Brand, and LLM engines.
- **Fusion Integration**: End-to-end tests for the score orchestration logic.
- **Email Forensics**: Validation of `.eml` parsing and header authentication.
- **Continuous Validation**: `pytest tests/ -v`
