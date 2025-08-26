import subprocess
import json
import csv
import os
import time
from typing import List, Tuple

def check_default_credentials(target: str) -> None:
    """Simulate default credential checks for common services."""
    weak_creds = {
        "ssh": [("root", "toor"), ("admin", "admin")],
        "http": [("admin", "admin"), ("admin", "password")]
    }
    print("\n--- Credential Testing ---")
    for service, creds in weak_creds.items():
        for user, passwd in creds:
            print(f"  Testing {service.upper()}: {user}/{passwd} (Simulated)")
    print("[!] No valid credentials found.")

def check_open_smb_shares(target: str) -> None:
    """Check for open SMB shares with parsed output."""
    print("\n--- SMB Share Enumeration ---")
    try:
        result = subprocess.run(
            ["smbclient", "-L", f"//{target}/", "--no-pass"],
            capture_output=True, text=True
        )
        if "Disk" in result.stdout:
            print("[+] Open SMB Shares:")
            shares = [
                line.split()[0] for line in result.stdout.split("\n") 
                if "Disk" in line and not line.startswith("--")
            ]
            for share in shares:
                print(f"  • {share}")
        else:
            print("[-] No open SMB shares found.")
    except FileNotFoundError:
        print("[!] smbclient not installed. Install with: sudo apt install smbclient")

def check_cve_vulnerabilities(target: str) -> List[Tuple[str, str, str]]:
    """Scan for CVEs using Nmap and a local database."""
    try:
        print("\n--- CVE Scan ---")
        nmap_cmd = ["nmap", "-Pn", "-sV", "--open", target]  # No sudo by default
        nmap_result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        
        if nmap_result.returncode != 0:
            print("[!] Nmap scan failed (try running with sudo).")
            return []
        
        services = [
            line.split()[2:4] for line in nmap_result.stdout.split("\n") 
            if "/tcp" in line and "open" in line
        ]
        
        cve_vulns = []
        with open("data/cve_database.txt", "r") as f:
            for line in f:
                if line.strip():
                    service, cve_id, severity, desc = line.strip().split(",")
                    if any(service.lower() in s[0].lower() for s in services):
                        cve_vulns.append((cve_id, severity, desc))
        
        return cve_vulns
    except Exception as e:
        print(f"[-] CVE scan error: {e}")
        return []

def save_report(target: str, vulnerabilities: List[Tuple[str, str, str]]) -> None:
    """Save results to CSV/JSON in a 'reports' directory."""
    os.makedirs("reports", exist_ok=True)
    base_path = f"reports/{target}_vuln_report"
    
    # CSV Export
    with open(f"{base_path}.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE ID", "Severity", "Description"])
        writer.writerows(vulnerabilities)
    
    # JSON Export
    with open(f"{base_path}.json", "w") as f:
        json.dump(
            [{"CVE ID": cve, "Severity": sev, "Description": desc} 
             for cve, sev, desc in vulnerabilities],
            f, indent=2
        )
    
    print(f"\n[+] Reports saved to: {base_path}.{{csv,json}}")

def run_vuln_scan(target: str) -> None:
    """Orchestrate the entire vulnerability scan."""
    start_time = time.time()
    print(f"\n[+] Starting Vulnerability Scan on {target}...")
    
    check_default_credentials(target)
    check_open_smb_shares(target)
    
    vulns = check_cve_vulnerabilities(target)
    if vulns:
        print("\n[!] Critical Vulnerabilities Detected:")
        for cve, sev, desc in vulns:
            print(f"  • [{cve}] {desc} ({sev})")
        save_report(target, vulns)
    else:
        print("\n[-] No known vulnerabilities detected.")
    
    print(f"\n[✓] Scan completed in {time.time() - start_time:.1f} seconds.")

# Example usage
if __name__ == "__main__":
    run_vuln_scan("10.0.2.5")  # Replace with target IP