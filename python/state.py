# state.py
import time

ASSETS_DB = {}

def get_or_create_asset(ip):
    """Retrieves an asset, initializes it if new, and updates its Last_Seen timestamp."""
    current_time = time.time()
    
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
            "First_Seen": current_time,
            "Last_Seen": current_time,
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
    else:
        ASSETS_DB[ip]["Last_Seen"] = current_time
        
    return ASSETS_DB[ip]

def prune_stale_assets(timeout_seconds=86400):
    """
    Sweeps the database and deletes assets that haven't been seen in `timeout_seconds`.
    Default is 86400 seconds (24 hours).
    """
    current_time = time.time()
    
    # We must cast keys() to a list so we don't encounter a RuntimeError 
    # for modifying the dictionary while iterating over it.
    for ip in list(ASSETS_DB.keys()):
        last_seen = ASSETS_DB[ip]["Last_Seen"]
        if (current_time - last_seen) > timeout_seconds:
            del ASSETS_DB[ip]