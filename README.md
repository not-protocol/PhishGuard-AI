# PhishGuard AI
## Project Documentation

**Version:** 1.0  
**Project Type:** AI-Powered Cybersecurity Web Application  
**Developer:** Rohan Kumar  
**Project Status:** Development  
**License:** To be determined

---

# 1. Introduction

PhishGuard AI is an intelligent phishing detection system that analyses suspicious messages and URLs using locally executed machine-learning models.

It calculates threat scores and identifies suspicious characteristics locally, then optionally uses external generative AI APIs to generate detailed explanations and security summaries.

The application supports OpenAI ChatGPT API and Google Gemini API.

# 2. Main Capabilities

## Message Analysis
Identifies potentially fraudulent messages, credential harvesting attempts, impersonation and social engineering indicators.

## URL Analysis
Examines URL structures and extracts suspicious characteristics to identify potentially malicious links.

## Risk Assessment
Calculates risk scores using locally processed evidence and machine-learning outputs.

## AI Security Reports
Uses an external generative AI provider to explain detection results in understandable language.

## Dashboard
Displays analysis results, system status, risk indicators and historical reports.

# 3. System Requirements

### Software
- Python 3.11 or newer.
- pip.
- Flask.
- Scikit-learn.
- SQLite.
- Modern web browser.
- Internet connection for external AI summaries.

### Hardware
- Modern 64-bit processor.
- 4 GB RAM recommended for development.
- Storage for datasets, models and application files.

A GPU is not required.

# 4. Installation

## Step 1: Clone the project

```bash
git clone YOUR_REPOSITORY_URL PhishGuard-AI
cd PhishGuard-AI
```

Replace the repository placeholder with the actual repository URL.

## Step 2: Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

## Step 3: Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Step 4: Configure environment variables

Create a `.env` file using `.env.example` as a template.

Example:

```env
AI_ENABLED=true
AI_PROVIDER=gemini

OPENAI_API_KEY=
OPENAI_MODEL=

GEMINI_API_KEY=
GEMINI_MODEL=

AI_TIMEOUT=20
```

Never upload the actual `.env` file to a public repository.

## Step 5: Train the models

After downloading and preparing the required datasets:

```bash
python train.py
```

The training script should:
- Validate datasets.
- Prepare training and testing partitions.
- Train the message classifier.
- Train the URL classifier.
- Evaluate model performance.
- Save the trained model artifacts.

## Step 6: Launch the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

# 5. AI Provider Configuration

PhishGuard AI supports two external generative AI providers.

## OpenAI

Set:

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=your_supported_model
```

## Google Gemini

Set:

```env
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=your_supported_model
```

The application should use the configured provider and must not require both API keys.

AI provider selection must not change local detection calculations.

# 6. Detection Workflow

## Message Detection

1. User submits a message.
2. Backend validates the text.
3. Text preprocessing is performed.
4. TF-IDF converts text into numerical features.
5. Logistic Regression performs classification.
6. Suspicious indicators are extracted.
7. Risk engine calculates the score.
8. AI provider optionally generates a summary.
9. Final report is displayed.

## URL Detection

1. User submits a URL.
2. Backend validates the input.
3. URL components are parsed safely.
4. Numerical features are extracted.
5. Random Forest performs classification.
6. Suspicious URL indicators are evaluated.
7. Risk engine calculates the score.
8. AI provider optionally generates an explanation.
9. Final report is displayed.

Submitted URLs must never be opened automatically.

# 7. API Documentation

## Backend Endpoints

### Health Check

```http
GET /api/health
```

Checks application availability.

### Message Analysis

```http
POST /api/analyze/message
Content-Type: application/json
```

Example request:

```json
{
  "message": "Your account is suspended. Verify your password immediately."
}
```

### URL Analysis

```http
POST /api/analyze/url
Content-Type: application/json
```

Example request:

```json
{
  "url": "https://example.com/login"
}
```

### AI Summary

```http
POST /api/summary
Content-Type: application/json
```

Receives structured local analysis findings and requests an AI-generated explanation.

### Model Status

```http
GET /api/models/status
```

Returns information about trained model availability.

# 8. Example Analysis Report

The following is a hypothetical output illustrating the intended report format.

```json
{
  "analysis_id": "PG-000001",
  "input_type": "message",
  "classification": "phishing",
  "risk_score": 82,
  "risk_level": "critical",
  "confidence": 0.91,
  "indicators": [
    "Urgent language",
    "Credential harvesting indicators",
    "Suspicious link"
  ],
  "ai_summary": {
    "provider": "gemini",
    "status": "generated",
    "summary": "This message exhibits several characteristics associated with phishing."
  }
}
```

These values are illustrative and are not actual predictions.

# 9. Dataset Management

Potential dataset sources:

- SMS Spam Collection.
- PhishTank.
- URLhaus.
- Other properly labelled phishing-message datasets.

Dataset preparation must include:
- Source documentation.
- Licensing verification.
- Label validation.
- Duplicate removal.
- Class distribution analysis.
- Training and testing separation.

Spam must not automatically be treated as phishing.

# 10. Research and Evaluation

The project must be evaluated using:

| Metric | Purpose |
|---|---|
| Accuracy | Overall classification correctness |
| Precision | Reliability of positive predictions |
| Recall | Ability to identify phishing samples |
| F1-score | Balance between precision and recall |
| Confusion matrix | Classification error analysis |
| False-positive rate | Frequency of legitimate samples incorrectly flagged |
| ROC-AUC | Ranking performance across thresholds |

The research report should document:
- Dataset sources and versions.
- Preprocessing decisions.
- Model configurations.
- Training methodology.
- Testing methodology.
- Evaluation results.
- Known limitations.

# 11. Security and Privacy

- API keys must remain on the backend.
- Raw messages must not be transmitted to AI providers by default.
- API requests must contain only necessary structured findings.
- User input must be validated.
- AI output must be treated as untrusted content.
- Submitted URLs must not be automatically opened.
- Analysis history must not retain raw message contents by default.
- Sensitive configuration files must be excluded from version control.

# 12. Limitations

PhishGuard AI is a detection-assistance tool, not a guarantee that a message or website is safe.

Potential limitations include:
- Previously unseen phishing techniques.
- Dataset bias.
- False-positive classifications.
- False-negative classifications.
- Evolving phishing infrastructure.
- Lack of live domain reputation checks when external intelligence is unavailable.
- Generative AI explanations that may occasionally be inaccurate.

Users should independently verify suspicious communications.

# 13. Future Development

Potential future features:

1. Hinglish phishing detection.
2. Browser extension.
3. Live threat-intelligence integration.
4. PDF security reports.
5. Advanced URL reputation checking.
6. Email header analysis.
7. Model comparison dashboard.
8. Explainable ML visualizations.
9. Additional language support.
10. Batch message and URL analysis.

# 14. Development Principles

PhishGuard AI follows these principles:

- Local calculations must remain independent of generative AI.
- Risk scores must be reproducible.
- Model performance must be measurable.
- AI explanations must be grounded in detection evidence.
- User data must be protected.
- Features must have real functionality.
- Research claims must be supported by experiments.

---

**End of Project Documentation — Version 1.0**
