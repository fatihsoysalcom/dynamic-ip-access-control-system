import ipaddress
import time
from datetime import datetime, timedelta

# --- Configuration for our "smart" access control system ---

# IPs that are always allowed, akin to a core, manually managed whitelist.
# This represents the traditional, static part of access control.
STATIC_CORE_WHITELIST = {
    "192.168.1.10",
    "10.0.0.5"
}

# Trusted subnet prefix. IPs from this range are automatically allowed.
# This demonstrates a shift from adding IPs one by one to rule-based access,
# allowing an entire internal network or a partner's network efficiently.
TRUSTED_SUBNET_PREFIX = "172.16.0.0/24" # Example: an internal network

# A dynamic blocklist for IPs that have shown suspicious activity.
# This list would typically be managed by an intrusion detection system or WAF.
# For this example, we simulate it with a temporary entry that expires.
TEMPORARY_BLOCKLIST = {
    "203.0.113.10": datetime.now() + timedelta(minutes=5) # Blocked until 5 mins from now
}

# --- Access Control Logic ---

def is_ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    """Checks if an IP address belongs to a given subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        return ip in subnet
    except ValueError:
        return False

def check_access(ip_address: str) -> bool:
    """
    Determines if an IP address is allowed access based on dynamic rules.
    This demonstrates a paradigm shift from simple static whitelisting
    to a more intelligent, rule-based access control.
    """
    current_time = datetime.now()

    # --- 1. Dynamic Blocklist Check (Higher Priority) ---
    # IPs on this list are denied, even if they match other allow rules.
    # This simulates an automated security response, demonstrating dynamic management.
    if ip_address in TEMPORARY_BLOCKLIST:
        block_expiry = TEMPORARY_BLOCKLIST[ip_address]
        if current_time < block_expiry:
            print(f"[{ip_address}] DENIED: Temporarily blocked until {block_expiry.strftime('%H:%M:%S')}.")
            return False
        else:
            # If block has expired, remove it (simulating automatic cleanup)
            del TEMPORARY_BLOCKLIST[ip_address]
            print(f"[{ip_address}] Block expired, proceeding with other checks.")

    # --- 2. Static Core Whitelist Check ---
    # These are critical IPs that are always allowed, representing the baseline.
    if ip_address in STATIC_CORE_WHITELIST:
        print(f"[{ip_address}] ALLOWED: Found in static core whitelist.")
        return True

    # --- 3. Trusted Subnet Rule Check ---
    # Automatically allow IPs from a predefined trusted network range.
    # This is a key aspect of moving beyond individual IP management to smarter rules.
    if is_ip_in_subnet(ip_address, TRUSTED_SUBNET_PREFIX):
        print(f"[{ip_address}] ALLOWED: Belongs to trusted subnet '{TRUSTED_SUBNET_PREFIX}'.")
        return True

    # --- 4. Default Deny ---
    # If no allow rules are met, access is denied.
    print(f"[{ip_address}] DENIED: No matching allow rules.")
    return False

# --- Simulation of incoming requests ---
if __name__ == "__main__":
    print("--- Simulating Access Control Checks ---")

    test_ips = [
        "192.168.1.10",     # In static whitelist
        "172.16.0.50",      # In trusted subnet
        "172.16.0.250",     # Also in trusted subnet
        "203.0.113.10",     # Temporarily blocked
        "198.51.100.1",     # Not allowed by any rule
        "10.0.0.5",         # In static whitelist
        "192.168.1.1",      # Not allowed
        "203.0.113.10"      # Check blocked IP again (should still be blocked)
    ]

    for ip in test_ips:
        print(f"\nChecking access for IP: {ip}")
        access_granted = check_access(ip)
        status = "GRANTED" if access_granted else "DENIED"
        print(f"Final decision for {ip}: {status}")
        time.sleep(0.1) # Small delay for readability

    print("\n--- End of Simulation ---")
