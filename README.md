 # 🔍 Mini Web Application Vulnerability Scanner

Scanner sederhana untuk latihan **cyber security** dengan fokus pada **OWASP Top 10**.  
Dibuat dengan Python, project ini berfungsi sebagai **mini DAST (Dynamic Application Security Testing)** tool.

---

## ✨ Features

### ✅ Passive Checks
- **HTTP Security Headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **Cookie Flags** (HttpOnly, Secure, SameSite).
- **CORS Policy** (deteksi wildcard `*` + `credentials=true`).

### 🚀 Active Checks
- **Reflected XSS**: payload bertoken ke parameter/form → deteksi pantulan di konteks executable (HTML/JS).
- **SQL Injection**:
  - Error-based detection (pesan error SQL di response).
  - Time-based detection (payload `SLEEP()` dengan delta latensi).

### 🌐 Crawler
- Jelajahi halaman web dalam domain.
- Ikuti link normal + hash routes (SPA).
- Deteksi **form GET/POST** + input parameter.

### 📊 Reports
- Output ke **JSON** dan **HTML** dengan severity score & rekomendasi fix.

---

## 🛠️ Tech Stack
- **Python 3.10+**
- `requests` – HTTP client
- `beautifulsoup4` – HTML parser
- `json` / custom HTML template – reporting

---

## 📦 Installation

1. Clone repo:
```bash
git clone https://github.com/<username>/<repo>.git
cd <repo>


# Mini-Web-Application-Vulnerability-Scanner