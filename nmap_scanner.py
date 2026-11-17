import subprocess
import sys
import ipaddress
import os
import re
from datetime import datetime

def validate_target(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def validate_ports(ports):
    # Validates formats like: 80,443 or 1-1024 or mixed: 21,22,80-90
    return re.match(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$", ports) is not None

def run_nmap_scan(target, ports, output_file):
    if not validate_target(target):
        print(f"❌ Invalid IP address or CIDR: {target}")
        sys.exit(1)

    if not validate_ports(ports):
        print(f"❌ Invalid port range format: {ports}")
        sys.exit(1)

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    command = [
        "nmap",
        "-Pn",             # Treat all hosts as up
        "-sV",             # Service version detection
        "--open",          # Show only open ports
        f"--max-retries=2",    # Fewer retries for faster scans
        f"--host-timeout=3m",  # Timeout per host
        "-p", ports,
        target,
        "-oN", output_file
   ]



    log_path = "scan_logs.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        print(f"📡 [{timestamp}] Running Nmap command:")
        print("   " + " ".join(command))

        with open(log_path, "a") as logfile:
            logfile.write(f"\n[{timestamp}] Starting scan for {target} on ports {ports}\n")
            logfile.write(f"Command: {' '.join(command)}\n\n")
            logfile.flush()

            # Non-blocking subprocess (good for Flask & Gunicorn)
            process = subprocess.Popen(command, stdout=logfile, stderr=logfile)
            process.wait()

            if process.returncode == 0:
                logfile.write(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Scan complete. Report saved to: {output_file}\n")
                print(f"✅ Scan complete. Report saved to: {output_file}")
            else:
                logfile.write(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Scan failed. Return code: {process.returncode}\n")
                print(f"❌ Scan failed. Return code: {process.returncode}")
                sys.exit(1)

    except Exception as e:
        error_msg = f"❌ Unexpected error: {e}"
        print(error_msg)
        with open(log_path, "a") as logfile:
            logfile.write(error_msg + "\n")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 nmap_scanner.py <target> <port_range> <output_file>")
        print("Example: python3 nmap_scanner.py 192.168.1.0/24 22,80,443 scans/scan.txt")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2]
    output_file = sys.argv[3]

    run_nmap_scan(target, ports, output_file)
