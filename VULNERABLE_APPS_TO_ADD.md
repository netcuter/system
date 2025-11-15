# 🎯 Vulnerable Applications To Add - Cross-Language Dataset

**Goal:** Have 2+ apps per language for proper 50/50 train/test split

**Date:** 2025-11-15

---

## Current State

| Language | Apps Available | Apps Needed | Status |
|----------|----------------|-------------|--------|
| **PHP** | 1 (DVWA) | +1-2 more | ❌ Need more |
| **Python** | 4 (PyGoat, Flask, Vulnpy, DVPWA) | None | ✅ Sufficient |
| **Node.js** | 1 (Juice Shop) | +1-2 more | ❌ Need more |
| **Java** | 1 (WebGoat) | +1-2 more | ❌ Need more |
| **C#/.NET** | 1 (ASP.NET) | +1-2 more | ❌ Need more |

---

## 📦 Recommended Apps to Download

### PHP Apps (Need +2)

| App | URL | Description | Stars | Status |
|-----|-----|-------------|-------|--------|
| **bWAPP** | https://github.com/raesene/bWAPP | Buggy Web Application (100+ vulns) | 400+ | ✅ Recommended |
| **Mutillidae II** | https://github.com/webpwnized/mutillidae | OWASP Training Platform | 1.1k | ✅ Recommended |
| **DVWA-PHP** | ✅ Already have | Damn Vulnerable Web App | - | ✅ Have |
| **Xtreme Vulnerable Web App** | https://github.com/s4n7h0/xvwa | PHP/MySQL vulnerable app | 600+ | ⚠️ Alternative |

**Download Priority:**
1. bWAPP (best alternative to DVWA)
2. Mutillidae II (OWASP official)

---

### Node.js Apps (Need +2)

| App | URL | Description | Stars | Status |
|-----|-----|-------------|-------|--------|
| **NodeGoat** | https://github.com/OWASP/NodeGoat | OWASP Node.js vulnerable app | 1.8k | ✅ Recommended |
| **Damn Vulnerable NodeJS App (DVNA)** | https://github.com/appsecco/dvna | GraphQL + REST vulnerabilities | 600+ | ✅ Recommended |
| **Juice Shop** | ✅ Already have | OWASP flagship vulnerable app | - | ✅ Have |
| **Vulnerable Node** | https://github.com/cr0hn/vulnerable-node | Intentionally vulnerable Node app | 100+ | ⚠️ Alternative |

**Download Priority:**
1. NodeGoat (OWASP official)
2. DVNA (modern GraphQL patterns)

---

### Java Apps (Need +2)

| App | URL | Description | Stars | Status |
|-----|-----|-------------|-------|--------|
| **Java Sec Code** | https://github.com/JoyChou93/java-sec-code | Spring Boot vulnerabilities | 2.2k | ✅ Recommended |
| **VulnerableApp** | https://github.com/SasanLabs/VulnerableApp | Modern Spring Boot vulns | 300+ | ✅ Recommended |
| **WebGoat** | ✅ Already have | OWASP training platform | - | ✅ Have |
| **WebGoat Legacy** | https://github.com/WebGoat/WebGoat-Legacy | Older WebGoat version | - | ⚠️ Alternative |

**Download Priority:**
1. Java Sec Code (2.2k stars, modern Spring Boot)
2. VulnerableApp (well-maintained, recent updates)

---

### C#/.NET Apps (Need +2)

| App | URL | Description | Stars | Status |
|-----|-----|-------------|-------|--------|
| **OWASP WebGoat.NET** | https://github.com/OWASP/WebGoat.NET | OWASP .NET training app | 800+ | ✅ Recommended |
| **VulnerableCore** | https://github.com/martinjt/VulnerableCore | ASP.NET Core vulnerabilities | 50+ | ✅ Recommended |
| **ASP.NET Vulnerable Lab** | ✅ Already have | - | - | ✅ Have |
| **Damn Vulnerable ASP.NET** | https://github.com/interference-security/DSVW | .NET vulnerable app | 100+ | ⚠️ Alternative |

**Download Priority:**
1. OWASP WebGoat.NET (OWASP official, 800+ stars)
2. VulnerableCore (modern ASP.NET Core)

---

## 🎯 Proposed 50/50 Split (After Downloading)

### After downloading recommended apps:

**Total Apps:** 13
- PHP: 3 apps (DVWA, bWAPP, Mutillidae)
- Python: 4 apps (PyGoat, Flask, Vulnpy, DVPWA)
- Node.js: 3 apps (Juice Shop, NodeGoat, DVNA)
- Java: 3 apps (WebGoat, Java Sec Code, VulnerableApp)
- .NET: 3 apps (ASP.NET Lab, WebGoat.NET, VulnerableCore)

### Proposed Train/Test Split:

| Language | Training Apps | Testing Apps |
|----------|--------------|--------------|
| **PHP** | DVWA, bWAPP | Mutillidae |
| **Python** | PyGoat, Flask | Vulnpy, DVPWA |
| **Node.js** | Juice Shop, NodeGoat | DVNA |
| **Java** | WebGoat, Java Sec Code | VulnerableApp |
| **.NET** | ASP.NET Lab, WebGoat.NET | VulnerableCore |

**Result:**
- Training: 2 PHP, 2 Python, 2 Node.js, 2 Java, 2 .NET = **10 apps**
- Testing: 1 PHP, 2 Python, 1 Node.js, 1 Java, 1 .NET = **6 apps**

**PERFECT!** Each language has representation in both training AND testing!

---

## 📥 Download Instructions

### 1. Create test_projects directory

```bash
mkdir -p test_projects
cd test_projects
```

### 2. Download PHP Apps

```bash
# bWAPP
git clone https://github.com/raesene/bWAPP.git

# Mutillidae II
git clone https://github.com/webpwnized/mutillidae.git
```

### 3. Download Node.js Apps

```bash
# NodeGoat
git clone https://github.com/OWASP/NodeGoat.git

# DVNA
git clone https://github.com/appsecco/dvna.git
```

### 4. Download Java Apps

```bash
# Java Sec Code
git clone https://github.com/JoyChou93/java-sec-code.git

# VulnerableApp
git clone https://github.com/SasanLabs/VulnerableApp.git
```

### 5. Download .NET Apps

```bash
# WebGoat.NET
git clone https://github.com/OWASP/WebGoat.NET.git

# VulnerableCore
git clone https://github.com/martinjt/VulnerableCore.git
```

---

## 🔍 Scan New Apps

### Scan all new apps:

```bash
cd /home/user/system

# PHP
python3 security_audit_cli.py --path test_projects/bWAPP --output test_results_bwapp.json
python3 security_audit_cli.py --path test_projects/mutillidae --output test_results_mutillidae.json

# Node.js
python3 security_audit_cli.py --path test_projects/NodeGoat --output test_results_nodegoat.json
python3 security_audit_cli.py --path test_projects/dvna --output test_results_dvna.json

# Java
python3 security_audit_cli.py --path test_projects/java-sec-code --output test_results_javaseccode.json
python3 security_audit_cli.py --path test_projects/VulnerableApp --output test_results_vulnerableapp.json

# .NET
python3 security_audit_cli.py --path test_projects/WebGoat.NET --output test_results_webgoatnet.json
python3 security_audit_cli.py --path test_projects/VulnerableCore --output test_results_vulnerablecore.json
```

---

## 🚀 Next Steps

1. ✅ **Download apps** (8 new apps)
2. ✅ **Scan apps** (generate test_results_*.json)
3. ✅ **Update validation_dataset_builder.py** (add new apps to train/test split)
4. ✅ **Retrain model** (10 apps for training)
5. ✅ **Test on unseen** (6 apps for testing)
6. ✅ **Measure cross-language performance**

**Expected Result:** 65-70% FP reduction across ALL languages with proper cross-language validation!

---

**Document Version:** 1.0
**Date:** 2025-11-15
**Status:** Ready to download

† **KOCHAM JEZUSA!** 🙏
