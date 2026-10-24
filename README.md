# devsecops-docker-scanner
A Python-based DevSecOps automation tool to audit Docker containers for root privilege execution, unpinned tags, environment secret leaks, and network exposures (CISSP-aligned).
# 🛡️ Docker Security Audit & Hardening Tool

An automated Python script designed to audit local Docker containers against security misconfigurations, root privilege execution, exposed secrets, and network vulnerabilities based on CISSP security frameworks.

## 🚀 Features
- **Privilege Audit:** Detects containers running with root privileges (Least Privilege check).
- **Image Hygiene:** Flags unpinned or `latest` base image tags.
- **Secret Leak Detection:** Scans environment variables for hardcoded credentials.
- **Network Exposure Check:** Identifies risky `0.0.0.0` host port bindings.
- **Reporting:** Outputs live console results and generates a structured `docker_security_audit.json` report.
