import socket  # Importing socket module for performing basic port scanning
import subprocess  # Importing subprocess to execute external commands like Nmap

def basic_port_scan(target, port_range=(1, 1024)):
    """
    Perform a basic port scan using Python's socket library.
    Scans the specified range of ports to check for open ones.

    Parameters:
        target (str): The IP address or domain name of the target.
        port_range (tuple): A tuple specifying the start and end port to scan.

    Returns:
        list: A list of open ports detected on the target.
    """

    open_ports = []  # List to store open ports

    print(f"\n[+] Scanning {target} for open ports...")

    for port in range(port_range[0], port_range[1] + 1):
        # Create a socket for communication (IPv4, TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)  # Timeout for connection attempts (prevents hanging)

        # Attempt to connect to the port
        result = s.connect_ex((target, port))  # Returns 0 if the port is open
        if result == 0:
            print(f"[+] Port {port} is OPEN.")  # Display open port
            open_ports.append(port)  # Add to the open ports list

        s.close()  # Close the socket connection after checking the port

    return open_ports  # Return the list of open ports found

def advanced_nmap_scan(target):
    """
    Perform an advanced scan using Nmap to identify services and OS details.

    Parameters:
        target (str): The IP address or domain name of the target.
    """

    print(f"\n[+] Running Nmap scan on {target}...")

    try:
        # Run Nmap with service version detection (-sV) and OS detection (-O)
        result = subprocess.run(["nmap", "-sV", "-O", target], 
                                stdout=subprocess.PIPE,  # Capture output
                                stderr=subprocess.PIPE,  # Capture error output
                                text=True)  # Convert output to string

        if result.returncode == 0:  # Check if Nmap executed successfully
            print("\n[+] Nmap Scan Results:\n")
            print(result.stdout)  # Print the scan output
        else:
            print("\n[-] Nmap encountered an error:")
            print(result.stderr)  # Print error message if scan failed

    except Exception as e:
        print(f"[-] Error running Nmap: {e}")  # Print exception if an error occurs

def live_host_detection(network_range):
    """
    Detect live hosts in a given network range using ARP requests and ICMP pings.
    
    Uses Nmap's ping scan (-sn) to detect active hosts in the subnet.

    Parameters:
        network_range (str): The subnet range to scan (e.g., "10.0.2.0/24").
    """

    print(f"\n[+] Detecting live hosts in the network range: {network_range}...")

    try:
        # Use Nmap's ping scan (-sn) to identify active devices on the network
        result = subprocess.run(["nmap", "-sn", network_range], 
                                stdout=subprocess.PIPE,  # Capture output
                                stderr=subprocess.PIPE,  # Capture error output
                                text=True)  # Convert output to string

        if result.returncode == 0:  # Check if scan executed successfully
            print("\n[+] Live Host Detection Results:\n")
            print(result.stdout)  # Print detected live hosts
        else:
            print("\n[-] Error during live host detection:")
            print(result.stderr)  # Print error message if scan failed

    except Exception as e:
        print(f"[-] Error running live host detection: {e}")  # Print exception if an error occurs

def run_recon_scan(target):
    """
    Runs the full reconnaissance module, including:
    1. Basic port scanning
    2. Advanced Nmap scanning
    3. Live host detection on the target's subnet.

    Parameters:
        target (str): The IP address or domain name of the target.
    """

    print("\n--- Running Reconnaissance Module ---")
    
    # Step 1: Perform a basic port scan
    open_ports = basic_port_scan(target)
    
    # Step 2: Perform an advanced Nmap scan
    advanced_nmap_scan(target)

    # Step 3: Detect live hosts in the network
    # Example: If the target is "10.0.2.15", generate "10.0.2.0/24" as the subnet
    network_range = ".".join(target.split(".")[:3]) + ".0/24"
    live_host_detection(network_range)

    print("\n[+] Reconnaissance Complete.")  # Indicate that all recon tasks are done
