# JFrog Xray Security Automation Toolkit

A Python-based command-line toolkit for automating **JFrog Xray** vulnerability reporting, package analysis, and report management.

The toolkit simplifies common JFrog Xray operations by providing an interactive CLI for generating vulnerability reports, analyzing package versions across repositories, and managing stored reports.

---

## Features

- **Multi-CVE Vulnerability Report Generation**
- **Automated CSV Report Export**
- **Package Discovery Across Multiple Repositories**
- **Package Version & Usage Analysis**
- **Repository Security Context Detection**
- **Bulk Report Management**
- **Automatic Output File Management**
- **Authentication & Error Handling**

---

## Requirements

- Python 3.9+
- JFrog Artifactory
- JFrog Xray
- Valid JFrog Access Token

```bash
pip install -r requirements.txt
```

---

## Configuration

Update the following values inside the script before execution.

```python
JFROG_URL = "https://YOUR_ORG.jfrog.io"
API_TOKEN = "YOUR_ACCESS_TOKEN"
```

---

## Usage

```bash
python jfrog_xray_appsec_tool.py
```

---

# Screenshots

### Main Menu

![Main Menu](screenshots/main-menu.png)

### CVE Report Generation

![CVE Report Generation](screenshots/cve-report-generation.png)

### Package Discovery & Analysis

![Package Discovery & Analysis](screenshots/package-discovery-analysis.png)

### Report Management

![Report Management](screenshots/report-management.png)

### Generated CSV Report

![Generated CSV Report](screenshots/generated-csv-report.png)

---

## Repository Structure

```text
jfrog-xray-security-automation-toolkit/
│
├── jfrog_xray_appsec_tool.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
└── screenshots/
    ├── main-menu.png
    ├── cve-report-generation.png
    ├── package-discovery-analysis.png
    ├── report-management.png
    └── generated-csv-report.png
```

---

## Disclaimer

This project is intended for authorized JFrog administration, vulnerability management, and security automation. Use it only on systems and environments for which you have explicit authorization.

---

## License

This project is licensed under the MIT License.
