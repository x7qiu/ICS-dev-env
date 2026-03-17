ASSETS_DB = {}

def get_or_create_asset(ip):
    """Retrieves an asset or initializes a blank profile if seen for the first time."""
    if ip not in ASSETS_DB:
        ASSETS_DB[ip] = {
            "IP": ip,
            "Hostname": "Unknown",
            "MAC": set(),
            "Vendor": set(),
            "Open_ports": set(),
            "Model": "Unknown",
            "OS_version": "Unknown",
            "Firmware_version": "Unknown",
            "Device_Type": "IT", 
            "Seen_Speaking_To": set(),
            # NEW: The Nested Protocols Block
            "Protocols": {
                "Modbus": {
                    "Roles": set(),
                    "Unit_IDs_Served": set(),
                    "Activity": {
                        "Reads_Sent_To": {},
                        "Writes_Sent_To": {},
                        "Successful_Responses": 0,
                        "Exceptions_Triggered": {}
                    },
                    "Memory_Fingerprint": {
                        "Registers_Read": set(),
                        "Registers_Written": set()
                    }
                }
            }
        }
    return ASSETS_DB[ip]