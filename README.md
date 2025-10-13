# 🛡️ SonicWall Backup Incident Manager

A comprehensive web-based management tool for SonicWall firewalls, designed to help administrators remediate security configurations affected by the MySonicWall cloud backup file incident.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Security Modules](#security-modules)
- [Analytics Dashboard](#analytics-dashboard)
- [API Reference](#api-reference)
- [Important Notes](#important-notes)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This tool was created in response to the [MySonicWall Cloud Backup File Incident](https://www.sonicwall.com/support/knowledge-base/mysonicwall-cloud-backup-file-incident/250915160910330) to help administrators identify and remediate potentially compromised configurations across their SonicWall firewall fleet.

**⚠️ DISCLAIMER**: This is **NOT** an official SonicWall tool. This application is provided as-is for management purposes only. Users assume all responsibility for its use. Always follow security best practices and backup your configurations before making changes.

## ✨ Features

### 🔍 Comprehensive Security Monitoring
- **Multi-firewall management** - Manage unlimited SonicWall devices from a single interface
- **Real-time security scanning** - Automated checks across 9 security modules
- **Security scoring system** - Visual scoring (0-100) for each firewall with color-coded status
- **Global search** - Filter and find firewalls instantly across all modules

### 🔧 Security Modules Covered
1. **WAN Management** - WAN-to-WAN rule monitoring and remediation
2. **SSO (Single Sign-On)** - Authentication method verification
3. **CSE (Cloud Secure Edge)** - Connector management with manual dissociation workflow
4. **SSL VPN** - Certificate and authentication checks
5. **IPSec VPN** - Pre-shared key and certificate validation
6. **Local Users** - Weak password detection (SHA1, DES)
7. **LDAP** - Server configuration and certificate validation
8. **RADIUS** - Server configuration and secret verification
9. **TACACS+** - Authentication server checks

### 📊 Advanced Analytics Dashboard
- **Global security overview** - Fleet-wide statistics and trends
- **Security score charts** - Visual bar charts comparing all firewalls
- **Module distribution** - See which modules need attention across your fleet
- **Firewall ranking** - Leaderboard showing best to worst performing devices
- **Scalable display** - Handles 100+ firewalls with smooth scrolling

### 🛠️ Remediation Workflows
- **Automated remediation** - One-click fixes for supported modules
- **Manual remediation guides** - Step-by-step instructions for complex changes
- **Timer-based workflows** - Built-in waiting periods for critical operations (e.g., CSE)
- **Status tracking** - Persistent remediation status across page refreshes
- **Verification methods** - Multiple verification approaches per module

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Windows/Linux/macOS

### Step 1: Clone the Repository
```bash
git clone https://github.com/Astrotix/SonicWall-Backup-Incident-Manager.git
cd SonicWall-Backup-Incident-Manager
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Application
**Windows:**
```bash
start.bat
```

**Linux/macOS:**
```bash
python app.py
```

The application will start on `http://localhost:5000`

## 🎬 Quick Start

### 1. Add Your First Firewall
1. Navigate to the **Firewalls** tab
2. Fill in the firewall details:
   - **Name**: A friendly name for identification
   - **IP Address**: The management IP of your SonicWall device
   - **Username**: API admin username
   - **Password**: API admin password (encrypted at rest)
3. Click **Add Firewall**
4. Click **Test** to verify connectivity

### 2. Run Security Checks
1. Click on any security module tab (e.g., **SSO**, **VPN**, **Local Users**)
2. The system will automatically scan all registered firewalls
3. View results color-coded by status:
   - 🟢 **Green**: No issues / Resolved
   - 🟠 **Orange**: In progress / Pending action
   - 🔴 **Red**: Issues detected / Action required

### 3. Perform Remediation
1. Switch to the **Remediation** sub-tab within each module
2. Review detected issues
3. Click **Start Remediation** for automated fixes
4. Follow manual steps for modules requiring human intervention (e.g., CSE)

### 4. View Analytics
1. Navigate to the **Analytics** tab at the bottom of the sidebar
2. Review:
   - **Global Security Overview**: Fleet statistics
   - **Security Score Charts**: Performance comparison
   - **Module Distribution**: Problem areas across modules
   - **Firewall Ranking**: Top and bottom performers

## 📖 Usage

### Security Scoring System

Each firewall receives a score out of 100 based on:
- **Module Weights**: Critical modules (WAN, SSO) worth more points
- **Resolution Status**: Resolved issues contribute full points
- **Configuration Safety**: Modules with no detected issues also count

**Score Ranges:**
- **70-100**: 🟢 Good (Green)
- **35-69**: 🟠 Warning (Orange)
- **0-34**: 🔴 Critical (Red)

### Remediation Workflows

#### Automated Remediation (WAN, VPN, Users)
1. Click **Start Remediation**
2. System applies fixes via API
3. Status automatically updates to green

#### Manual Remediation (CSE)
1. Click **Start CSE Remediation**
2. Follow the displayed manual steps:
   - Log in to MySonicWall
   - Navigate to Products → Tenant
   - Find CSE connector
   - Remove association
3. A 30-second timer starts
4. After timer expires, click **Reactivate CSE Now**
5. System automatically disables and re-enables CSE

### Global Search

Use the search bar at the top to filter firewalls across all tabs:
- Type a firewall name or IP
- Get instant autocomplete suggestions
- Click a suggestion to filter
- Clear search to show all firewalls again

## 🔐 Security Modules

### WAN Management
**Risk**: WAN-to-WAN management rules can expose internal networks

**Detection**: Scans for any WAN zone in management rules

**Remediation**: Automatically removes WAN zones from management rules

---

### SSO (Single Sign-On)
**Risk**: Weak authentication methods (NTLM v1, unencrypted LDAP)

**Detection**: 
- Checks authentication method
- Validates LDAPS usage
- Verifies certificate settings

**Remediation**: 
- Disables weak SSO methods
- Enforces secure protocols

---

### CSE (Cloud Secure Edge)
**Risk**: Compromised tenant associations

**Detection**: Checks if CSE is enabled

**Remediation**: Manual dissociation + automated reactivation with timer

---

### SSL VPN
**Risk**: Weak certificates or authentication bypass

**Detection**:
- Certificate validation
- Authentication method checks

**Remediation**: Regenerates certificates and enforces strong auth

---

### IPSec VPN
**Risk**: Weak pre-shared keys or compromised certificates

**Detection**:
- PSK strength analysis
- Certificate validation

**Remediation**: Forces PSK and certificate regeneration

---

### Local Users
**Risk**: Weak password hashes (SHA1, DES)

**Detection**: Scans all local users for weak hash types

**Remediation**: Forces password reset for affected accounts

---

### LDAP
**Risk**: Unencrypted connections or weak certificates

**Detection**:
- LDAPS enforcement check
- Certificate validation

**Remediation**: Enforces LDAPS and regenerates certificates

---

### RADIUS
**Risk**: Weak shared secrets

**Detection**: Validates RADIUS server configurations

**Remediation**: Regenerates shared secrets

---

### TACACS+
**Risk**: Weak shared secrets

**Detection**: Validates TACACS+ server configurations

**Remediation**: Regenerates shared secrets

## 📈 Analytics Dashboard

### Global Security Overview
Displays:
- Total firewalls managed
- Average security score across fleet
- Distribution of Good/Warning/Critical statuses

### Security Score Chart
- Horizontal bar chart comparing all firewalls
- Color-coded by score range
- Sortable by score (best to worst)
- Scrollable for large fleets (100+ devices)

### Module Distribution
- Grid showing resolution percentage per module
- Highlights modules needing attention fleet-wide
- Shows "X/Y resolved" count for each module

### Firewall Ranking
- Complete leaderboard of all firewalls
- Animated score circles for each device
- Top 3 highlighted with special gradient
- Clickable to view detailed audit

## 📚 API Reference

This tool uses the SonicWall SonicOS API. For detailed API documentation, see:
- [API_ENDPOINTS.md](API_ENDPOINTS.md) - Available endpoints and parameters
- [SONICWALL_API_REFERENCE.md](SONICWALL_API_REFERENCE.md) - Official API guide

### Key Endpoints Used
- `GET /user/local` - List local users
- `GET /sso/base` - SSO configuration
- `GET /cloud-secure-edge/base` - CSE status
- `GET/PUT /vpn/policy/ssl` - SSL VPN settings
- `GET/PUT /vpn/policy/ipsec` - IPSec VPN settings
- `GET /user/ldap` - LDAP configuration
- `GET /user/radius` - RADIUS configuration
- `GET /user/tacacs-plus` - TACACS+ configuration

## ⚠️ Important Notes

### Data Storage
- Firewall credentials are **encrypted at rest** using Fernet symmetric encryption
- Database file: `instance/firewalls.db` (SQLite)
- All remediation actions are logged with timestamps

### Security Best Practices
1. **Always backup** your firewall configuration before remediation
2. **Test on a single device** before rolling out to your entire fleet
3. **Review changes** in the monitoring tab before applying
4. **Keep logs** of all remediation actions
5. **Update credentials** regularly and use strong passwords

### Limitations
- Requires direct API access to each firewall
- Some remediation actions require manual steps
- Large fleets (100+) may take time to scan
- API rate limiting may affect scan speed

### Browser Compatibility
- Modern browsers recommended (Chrome, Firefox, Edge, Safari)
- JavaScript must be enabled
- Minimum resolution: 1280x720

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📧 Contact

**Guillaume SEVRIN**

For issues, feature requests, or questions, please open an issue on GitHub.

## 📄 License

This project is provided "as-is" for educational and management purposes. Users assume all responsibility for its use.

---

**⚡ Built with Flask, SQLAlchemy, and modern web technologies**

**🛡️ Helping secure SonicWall deployments worldwide**
