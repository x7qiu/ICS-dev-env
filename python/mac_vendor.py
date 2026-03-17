def load_offline_oui(filepath):
    print(f"Loading offline IEEE OUI database from {filepath}...")
    oui_map = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                # IEEE format puts "(hex)" on the line with the MAC prefix and Vendor
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    if len(parts) == 2:
                        # Convert "00-1A-2B" to "00:1a:2b" to match Zeek's lowercase format
                        mac_prefix = parts[0].strip().replace('-', ':').lower()
                        vendor_name = parts[1].strip()
                        oui_map[mac_prefix] = vendor_name
    except FileNotFoundError:
        print(f"[!] Offline OUI table '{filepath}' not found. Vendors will default to 'Unknown'.")
    return oui_map

# Load it into memory once at startup
OUI_DB = load_offline_oui('/app/oui.txt')

def lookup_vendor(mac_address):
    """Extracts the 24-bit OUI prefix and checks the offline database."""
    if not mac_address: return "Unknown"
    # Slice the first 8 characters: "00:11:22:33:44:55" -> "00:11:22"
    prefix = mac_address[:8].lower()
    return OUI_DB.get(prefix, "Unknown")