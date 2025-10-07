# 🛡️ DIDEPTES - Mini Web Application Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/OWASP-Top%2010-EE0000?style=for-the-badge&logo=owasp&logoColor=white)

**A comprehensive educational DAST (Dynamic Application Security Testing) tool for learning web security**

[Features](#-features) • [Why DIDEPTES?](#-why-dideptes) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Why DIDEPTES?](#-why-dideptes)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Report Formats](#-report-formats)
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [Contributing](#-contributing)

---

## 🎯 Overview

**DIDEPTES** (Dynamic Intrusion Detection & Exploitation Prevention Testing & Evaluation Scanner) is a Python-based educational vulnerability scanner designed to help security practitioners, students, and developers understand web application security vulnerabilities based on the **OWASP Top 10** framework.

This mini-DAST tool performs both **passive** and **active** security testing to identify common web vulnerabilities, making it an excellent learning resource for:
- 🎓 Cybersecurity students and enthusiasts
- 👨‍💻 Developers learning secure coding practices
- 🔒 Security researchers conducting authorized penetration tests
- 📚 Educational institutions teaching web security

---

## 💡 Why DIDEPTES?

### The Problem
Modern web applications face numerous security threats, but understanding these vulnerabilities requires hands-on experience. Many security tools are either:
- Too complex for beginners to understand
- Black-box solutions that don't explain how vulnerabilities are detected
- Expensive commercial tools not accessible for learning

### The Solution
DIDEPTES was created to bridge this gap by providing:

✅ **Educational Focus** - Clean, readable code that teaches security concepts  
✅ **Comprehensive Coverage** - Covers major OWASP Top 10 vulnerabilities  
✅ **Practical Learning** - Hands-on tool for understanding real-world vulnerabilities  
✅ **Transparent Detection** - See exactly how vulnerabilities are identified  
✅ **Free & Open Source** - Accessible to everyone for learning purposes  

### Key Benefits
- 🔍 **Learn by Doing**: Understand how scanners detect vulnerabilities
- 📊 **Detailed Reports**: Get actionable insights with remediation guidance
- 🛠️ **Extensible Design**: Easy to add custom checks and payloads
- 🌐 **Smart Crawling**: Automatically discovers endpoints, forms, and parameters
- 📈 **Severity Scoring**: Prioritize findings based on risk assessment

---

## ✨ Features

### 🔒 Passive Security Checks
Non-intrusive analysis of security configurations:

#### HTTP Security Headers Analysis
- **Content Security Policy (CSP)** - Detects missing or weak CSP
- **HTTP Strict Transport Security (HSTS)** - Validates HTTPS enforcement
- **X-Frame-Options** - Checks clickjacking protection
- **X-Content-Type-Options** - Verifies MIME-sniffing prevention
- **Referrer-Policy** - Analyzes referrer information leakage
- **Permissions-Policy** - Reviews feature policy restrictions

#### Cookie Security Analysis
- **HttpOnly Flag** - Prevents JavaScript access to cookies
- **Secure Flag** - Ensures cookies sent over HTTPS only
- **SameSite Attribute** - CSRF protection validation

#### CORS Configuration Review
- Wildcard (`*`) origin detection
- Unsafe `credentials=true` combinations
- Cross-origin policy validation

#### SSL/TLS Security Assessment
- Certificate validity and expiration checking
- Protocol version security (TLS 1.2+ enforcement)
- Cipher suite strength analysis
- Certificate chain validation
- Perfect Forward Secrecy support verification

### 🚀 Active Security Testing
Intelligent payload injection to detect vulnerabilities:

#### Cross-Site Scripting (XSS) Detection
- **Reflected XSS** - Token-based payload injection with context analysis
- **Stored XSS** - Persistent XSS detection across pages
- **GET/POST Parameter Testing** - Comprehensive input validation
- **Advanced Payloads** - Encoded variants, event handlers, and bypass techniques
- **Context-Aware Detection** - HTML/JavaScript execution context analysis

#### SQL Injection (SQLi) Detection
- **Error-Based Detection** - Identifies SQL error messages in responses
- **Time-Based Blind SQLi** - Uses `SLEEP()` payloads with latency analysis
- **Boolean-Based Blind SQLi** - Logical condition testing
- **Multiple Database Support** - MySQL, PostgreSQL, MSSQL, SQLite patterns

#### Local File Inclusion (LFI) Detection
- Path traversal vulnerability detection
- Directory traversal payloads (Linux/Windows)
- URL encoding bypass techniques
- Null byte injection testing
- PHP wrapper exploitation detection

#### Authentication & Session Security
- Session fixation vulnerability testing
- Weak session token analysis
- Authentication bypass detection
- Credential brute-force testing (optional)

#### Additional Checks
- **CSRF Protection** - Missing anti-CSRF token detection
- **Security Misconfiguration** - Common configuration errors
- **Server Information Disclosure** - Verbose error messages and headers

### 🕷️ Intelligent Web Crawler
Advanced discovery engine:

- **Domain-Scoped Crawling** - Respects same-domain/same-host boundaries
- **SPA Support** - Handles hash routes (`#/route`) and modern frameworks
- **Form Detection** - Automatically identifies GET/POST forms
- **Parameter Extraction** - Discovers URL parameters for testing
- **Configurable Depth** - Control crawl depth to manage scan time
- **Rate Limiting** - Prevents overwhelming target servers

### 📊 Comprehensive Reporting
Multiple output formats for different use cases:

#### JSON Reports
- Machine-readable format for automation
- Integration with CI/CD pipelines
- Custom tooling and analysis

#### HTML Reports
- Visual dashboard with severity breakdown
- Color-coded findings (High/Medium/Low/Info)
- Detailed vulnerability descriptions
- Actionable remediation recommendations
- Shareable and exportable format

#### PDF Reports (Professional)
- Executive-ready format
- Styled with severity indicators
- Clean, professional presentation
- Perfect for documentation and reporting

---

## 📦 Installation

### Prerequisites
- **Python 3.10+** - Required for modern Python features
- **pip** - Python package manager
- **Virtual Environment** (recommended)

### Step 1: Clone Repository
```bash
git clone https://github.com/DINGDONG-09/DIDEPTES.git
cd DIDEPTES
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation
```bash
python main.py --help
```

---

## 🚀 Usage

### Basic Scan
Run a standard security scan:
```bash
python main.py --target https://example.com
```

### Advanced Options

#### Full Scan with Deep Crawling
```bash
python main.py \
  --target https://example.com \
  --max-depth 3 \
  --rate 2.0 \
  --scope same-domain
```

#### Custom Output Files
```bash
python main.py \
  --target https://example.com \
  --out scan_results.json \
  --html scan_report.html
```

#### PDF Report Generation
```bash
python main.py \
  --target https://example.com \
  --pdf professional_report.pdf
```

#### Enable Authentication Testing
```bash
python main.py \
  --target https://example.com \
  --auth-bruteforce
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Base URL to scan (required) | - |
| `--max-depth` | Crawler depth limit | 1 |
| `--rate` | Request rate limit (RPS) | 2.0 |
| `--scope` | Crawl scope (same-domain/same-host) | same-domain |
| `--out` | JSON report output path | report.json |
| `--html` | HTML report output path | report.html |
| `--pdf` | PDF report output path | - |
| `--auth-bruteforce` | Enable auth bruteforce testing | disabled |

---

## 📊 Report Formats

### JSON Report Structure
```json
{
  "type": "SQL Injection (GET)",
  "severity": "HIGH",
  "url": "https://example.com/product?id=1",
  "parameter": "id",
  "payload": "' OR SLEEP(2)--",
  "evidence": "Response time: 2.3s (baseline: 0.2s)",
  "severity_score": 8,
  "description": "Time-based SQL injection detected",
  "recommendation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
}
```

### HTML Report Features
- 📊 Visual severity distribution
- 🎨 Color-coded findings
- 📝 Detailed descriptions
- 💡 Remediation guidance
- 🔗 Reference links

### PDF Report Features
- 📄 Professional layout
- 🎯 Executive summary
- 📈 Severity indicators
- 📋 Comprehensive findings list

---

## ⚖️ Disclaimer

### ⚠️ IMPORTANT - Legal Notice

This tool is designed **EXCLUSIVELY** for:
- ✅ Educational purposes and learning
- ✅ Authorized security assessments
- ✅ Your own applications and systems
- ✅ Controlled laboratory environments

### Legal Responsibilities

**YOU MUST:**
- 🔒 Obtain explicit written permission before scanning any system
- 📝 Ensure you have legal authorization for security testing
- 🎓 Use this tool ethically and responsibly

**YOU MUST NOT:**
- ❌ Scan websites or systems without authorization
- ❌ Use this tool for malicious purposes
- ❌ Attempt to exploit vulnerabilities you discover
- ❌ Share or distribute findings without permission

### Legal Consequences
> **Unauthorized security scanning may be illegal in your jurisdiction and could result in:**
> - Criminal prosecution
> - Civil liability
> - Financial penalties
> - Imprisonment

**The authors and contributors of DIDEPTES are not responsible for any misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository

### Development Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Contribution Ideas
- Add new vulnerability checks
- Improve detection accuracy
- Enhance reporting formats
- Optimize crawler performance
- Write tutorials and guides

---

## 👤 Author

**DINGDONG-09**
- Github: [@DINGDONG-09](https://github.com/DINGDONG-09)

**DaveMufadhal**
- GitHub: [@DaveMufadhal](https://github.com/DaveMufadhal)
---

<div align="center">

### ⭐ Star this project if you find it useful!

**Made with Passion for the cybersecurity education community**

*"Security through education, not obscurity"*

</div>
