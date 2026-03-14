import json
import os
import glob

DATA_DIR = './dev_data'

# --- 1. SPECIFIC LOGIC HANDLERS ---
def ignore_log(zeek_data):
    pass

def handle_conn_log(zeek_data):
    """Processes network routing and base IP discovery"""
    # orig_ip = zeek_data.get('id.orig_h')
    # resp_ip = zeek_data.get('id.resp_h')
    # print(f"[CONN] Route: {orig_ip} -> {resp_ip}")
    # TODO: Add NetworkX node logic here
    pass

def handle_modbus_detailed(zeek_data):
    """modbus_detailed.log"""
    print("\n--- FOUND MODBUS DETAILED LOG ---")
    print(json.dumps(zeek_data, indent=4))

def handle_modbus_device_id(zeek_data):
    """Processes Modbus Function Code 43 DPI Data"""
    print(json.dumps(zeek_data, indent=4))

    if zeek_data.get('request_response') == 'RESPONSE':
        ip = zeek_data.get('id.resp_h')
        vendor = zeek_data.get('object_value')
        print(f"[MODBUS-DPI] Identified {ip} as {vendor}")

def handle_s7comm(zeek_data):
    """Processes Siemens S7 Comm Data"""
    # E.g., looking for PLC Stop commands
    pass 

# --- 2. THE DISPATCHER DICTIONARY ---

# Map the Zeek log filename to the specific Python function that handles it
LOG_DISPATCHER = {
    "conn.log": handle_conn_log,

    "modbus_detailed.log": handle_modbus_detailed,
    "modbus_read_device_identification.log": handle_modbus_device_id,
    

    "s7comm.log": handle_s7comm
}

# --- 3. THE MAIN ENGINE ---

def process_offline_logs():
    dump_files = glob.glob(os.path.join(DATA_DIR, '*.ndjson'))
    
    if not dump_files:
        print(f"Waiting for logs in {DATA_DIR}...")
        return

    for dump_file in sorted(dump_files):
        print(f"[*] Processing {dump_file}...")
        with open(dump_file, 'r') as f:
            for line in f:
                try:
                    message = json.loads(line.strip())
                    
                    # Extract metadata
                    log_path = message.get("log", {}).get("file", {}).get("path", "")
                    log_filename = log_path.split("/")[-1]
                    # print(log_filename)
                    zeek_data = message.get("zeek", {})
                    
                    if not zeek_data:
                        continue
                    
                    # MAGICAL ROUTING: If we have a function for this log, run it!
                    if log_filename in LOG_DISPATCHER:
                        LOG_DISPATCHER[log_filename](zeek_data)

                except json.JSONDecodeError:
                    continue

if __name__ == "__main__":
    process_offline_logs()