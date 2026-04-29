# e-Sevai Intelligent Governance Middleware

A specialized middleware system designed to automate and secure the document verification process for government services. It leverages AI-driven OCR, fuzzy matching logic, and a cryptographically secured audit trail to reduce manual overhead and prevent fraud.

## 🚀 Key Features

### 1. Dual-Portal Architecture
- **Citizen Portal**: A clean, accessible interface for individuals to submit service applications and upload supporting proofs.
- **Official Portal**: A secured, authenticated dashboard for government officials to review AI-flagged applications and provide final approvals.

### 2. Intelligent Verification Engine
- **Multi-Document Aggregate OCR**: Extracts data from multiple uploaded documents (Aadhaar, Income Certificates, etc.) and merges them into a single verification profile.
- **Smart Fuzzy Matching**: Uses advanced string similarity algorithms (`thefuzz`) to handle name reordering (e.g., "Manoj S" vs "S Manoj") and complex address formats.
- **Double-Verification Fallback**: If structural extraction fails, the system performs a global search across the entire document text to find form data.

### 3. Governance & Audit
- **Blockchain Audit Trail**: Every action (submission, AI scan, officer decision) is hashed and chained, creating a tamper-evident ledger of the application's lifecycle.
- **SLA Monitoring**: Tracks processing times against predefined limits and flags delayed applications for escalation.
- **Human-in-the-Loop**: Mandatory manual approval for all applications, ensuring high-confidence AI results are still signed off by an authorized official.

## 🛠 Tech Stack
- **Backend**: Flask (Python)
- **OCR**: Pytesseract (Tesseract OCR Engine)
- **Image Processing**: Pillow, pdf2image (Poppler)
- **Fuzzy Logic**: `thefuzz` (Levenshtein distance)
- **Security**: SHA-256 Hashing / Audit Chaining

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/lokeshwaranselvam/Dhinesh.git
cd Dhinesh
```

### 2. Prerequisites
- **Python 3.8+**
- **Tesseract OCR**: 
    - [Download for Windows](https://github.com/UB-Mannheim/tesseract/wiki)
    - Ensure it is added to your system PATH.
- **Poppler**: (Required for PDF processing)
    - [Download for Windows](https://github.com/oschwartz10612/poppler-windows/releases)
    - Add the `/bin` folder to your system PATH.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and set your secret key. The application automatically creates necessary folders (`uploads/`, `database/`, `extracted_data/`) on launch.

### 4. Run the Application
```bash
python app.py
```
- **Citizen Portal**: `http://127.0.0.1:5000/`
- **Official Portal**: `http://127.0.0.1:5000/official/dashboard`
- **Default Official Credentials**: `admin` / `admin123`

## 📂 Project Structure
- `modules/`: Core logic for OCR, Validation, Audit, and SLA.
- `templates/`: HTML5/CSS3 UI for portals.
- `uploads/`: Temporary storage for submitted documents (git-ignored).
- `database/`: JSON-based state management and audit chain (git-ignored).
- `utils/`: Helper functions for ID generation and directory management.
