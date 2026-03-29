# RedTeam-Agent

## 👤 Created by: Abdulwahab Hamoud Salah

---

## 📌 Description

**RedTeam-Agent** is a comprehensive, production-ready cybersecurity reconnaissance tool that automates security assessments. This project was designed and built by **Abdulwahab Hamoud Salah** as part of his cybersecurity portfolio.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing ONLY**.  
Use it only on systems you own or have explicit written permission to test.  
Unauthorized use is illegal.  
*Created by Abdulwahab Hamoud Salah for ethical cybersecurity research purposes only.*

---

## ✨ Features

- Subdomain discovery via DNS brute-force + Certificate Transparency logs
- Email address harvesting
- Technology & CMS fingerprinting
- Port scanning with service version detection
- SSL certificate analysis
- HTTP security headers analysis
- CVE vulnerability lookup (NIST NVD database)
- Intelligent risk scoring and recommendations
- Professional PDF report generation

---

## ⚙️ System Requirements

Install **nmap** before running:

```bash
# Linux
sudo apt-get install nmap -y

# Mac
brew install nmap
```

---

## 🚀 Installation

```bash
git clone https://github.com/your-username/RedTeam-Agent.git
cd RedTeam-Agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your API key
```

---

## 🔑 Configuration

Edit `.env`:

```
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

---

## 💻 Usage

```bash
# Basic scan
python main.py --target scanme.nmap.org

# Custom port range
python main.py -t example.com --ports 1-1000

# Skip CVE lookup
python main.py -t example.com --no-cve

# Skip analysis phase
python main.py -t example.com --no-analysis
```

---

## 📁 Project Structure

```
RedTeam-Agent/
├── main.py
├── config.py
├── requirements.txt
├── .env.example
├── modules/
│   ├── osint.py
│   ├── scanner.py
│   ├── cve_lookup.py
│   ├── ai_analyst.py
│   └── report_generator.py
└── utils/
    ├── logger.py
    └── validator.py
```

---

## 📊 Scan Phases

```
[PHASE 1] OSINT Reconnaissance
[PHASE 2] Port Scanning & Service Detection
[PHASE 3] CVE Vulnerability Lookup
[PHASE 4] Security Analysis
[PHASE 5] PDF Report Generation
```

---

## 📄 License

MIT License

---

© 2025 Abdulwahab Hamoud Salah — All Rights Reserved  
This project was designed and built by **Abdulwahab Hamoud Salah** as part of his cybersecurity portfolio.
