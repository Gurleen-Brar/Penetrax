#Penetrax
An Educational Penetration Testing Framework

#📌Overview
Penetrax is a Python-based penetration testing tool designed to simulate offensive security techniques in a safe, controlled environment. Developed for academic use, it combines scanning, exploitation, and reporting features into a single, modular framework.
This tool is ideal for security students and professionals looking to better understand the real-world attack process — from reconnaissance to exploitation to reporting.

⚠️Disclaimer
This tool is developed for educational and ethical purposes only.
Do not use Penetrax on any live systems or networks without explicit authorization. Misuse of this tool is strictly prohibited.

#🛠️Usage Notes
Use only in test labs or authorized systems.
For command injection, run the custom vulnerable Flask server built into Penetrax.
For reverse shell, ensure your Kali machine has a listener running via Metasploit.

#✅Key Features
1. 🔍Reconnaissance Module

Performs a basic port scan using Python sockets to detect open ports.
Runs an Nmap scan to gather operating system and service information.
Identifies live hosts in a target subnet using a ping sweep.

2. 🔒Vulnerability Scanning Module

Tests for default/weak credentials on common services (SSH, HTTP).
Scans for open SMB shares using smbclient.
Matches detected services with known CVE vulnerabilities using a local database.
Generates and saves reports in CSV and JSON format.

3. 💥Exploit Simulation Module

Brute Force Attack on SSH using user-provided credential lists.
Command Injection targeting a Flask-based web endpoint.
Reverse Shell Payload Delivery using msfvenom, FTP, and Metasploit listener.

4. 📊Advanced Reporting Module

Classifies vulnerabilities based on CVSS-like severity levels (Critical, High, Medium, Low).
Supports multi-format exports for integration or future review.
Includes real-time logging in both CLI and GUI modes.

5. 🖥User Interfaces

CLI Interface: Straightforward and function-driven. Supports module selection and execution.
GUI Interface (Tkinter): Allows dropdown module selection, real-time log viewing, report exporting, and dark mode.

#▶️How to Run

✅Prerequisites
Ensure the following are installed:

sudo apt install nmap smbclient ftp metasploit-framework
pip install paramiko flask requests beautifulsoup4

#✅Run CLI mode:
python3 penetrax.py

#✅Run GUI mode:
python3 gui.py







