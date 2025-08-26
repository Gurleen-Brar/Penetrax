import os
import sys

# Define the banner
BANNER = """
======================================
  PENETRAX - Automated Pentesting Tool
======================================
"""

def main():
    print(BANNER)
    print("Select a module to run:")
    print("1. Reconnaissance")
    print("2. Vulnerability Scanning")
    print("3. Exploit Simulations")
    print("4. Exit")

    choice = input("\nEnter your choice (1-4): ")

    if choice == "1":
        from modules.recon import run_recon_scan
        target = input("Enter target IP or domain: ")
        run_recon_scan(target)  # Now runs both basic and Nmap scans

    elif choice == "2":
        from modules.vuln import run_vuln_scan
        target = input("Enter target IP or domain: ")
        run_vuln_scan(target)

    elif choice == "3":
        # Exploit submenu
        from modules.exploits import brute_force_ssh, real_command_injection, msf_reverse_shell

        print("\nSelect Exploit Module:")
        print("1. Brute Force Login")
        print("2. Command Injection")
        print("3. Msfvenom Reverse Shell")
        print("4. Exit")

        exploit_choice = input("Enter choice (1-4): ")

        if exploit_choice == "1":
            usernames = ["msfadmin", "user", "root"]
            passwords = ["msfadmin", "toor", "1234", "password"]
            brute_force_ssh("10.0.2.5", 22, usernames, passwords, delay=1)

        elif exploit_choice == "2":
            from modules.exploits import real_command_injection
            real_command_injection()

        elif exploit_choice == "3":
            msf_reverse_shell()

        elif exploit_choice == "4":
            print("Returning to main menu...\n")
            main()

        else:
            print("Invalid exploit choice.")

    elif choice == "4":
        print("Exiting PENETRAX...")
        sys.exit(0)

    else:
        print("Invalid choice. Please enter a valid option.")
        main()


if __name__ == "__main__":    
    main()
