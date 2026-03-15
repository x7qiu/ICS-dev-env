import json
import uuid
from kafka import KafkaConsumer
from mac_vendor_lookup import MacLookup, VendorNotFoundError

# --- 1. INITIALIZE GLOBAL STATE ---
ASSETS_DB = {}
mac_lookup = MacLookup()

# Attempt to update the OUI database, but fail gracefully if the network drops it
try:
    print("Updating MAC OUI database...")
    mac_lookup.update_vendors()
except Exception as e:
    print(f"Warning: Could not update MAC OUI list over the network ({e}). Using cached/unknown vendors.")

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
            "Device_Type": "IT", # Default
            "Seen_Speaking_To": set()
        }
    return ASSETS_DB[ip]

# --- 2. THE LOGIC HANDLERS ---
def handle_conn(zeek_data):
    orig_ip = zeek_data.get('id.orig_h')
    resp_ip = zeek_data.get('id.resp_h')
    resp_p = zeek_data.get('id.resp_p')
    proto = zeek_data.get('proto')
    conn_state = zeek_data.get('conn_state')
    
    # Grab MAC addresses if Zeek captured them (requires L2 visibility)
    orig_mac = zeek_data.get('orig_l2_addr')
    resp_mac = zeek_data.get('resp_l2_addr')

    if not orig_ip or not resp_ip:
        return

    orig_asset = get_or_create_asset(orig_ip)
    resp_asset = get_or_create_asset(resp_ip)

    # Track relationships
    orig_asset["Seen_Speaking_To"].add(resp_ip)

    # Resolve and store MACs and Vendors
    if orig_mac:
        orig_asset["MAC"].add(orig_mac)
        try:
            orig_asset["Vendor"].add(mac_lookup.lookup(orig_mac))
        except VendorNotFoundError:
            pass
            
    if resp_mac:
        resp_asset["MAC"].add(resp_mac)
        try:
            resp_asset["Vendor"].add(mac_lookup.lookup(resp_mac))
        except VendorNotFoundError:
            pass

    # Verify Open Ports (TCP Handshake Completed or UDP traffic)
    if (proto == 'tcp' and conn_state in ['SF', 'S1']) or proto == 'udp':
        resp_asset["Open_ports"].add(resp_p)

        # BEHAVIORAL INFERENCE
        if resp_p in [102, 502, 44818]: # S7comm, Modbus, Ethernet/IP
            resp_asset["Device_Type"] = "PLC / RTU"
            if orig_asset["Device_Type"] == "IT": # Upgrade client from IT to OT
                orig_asset["Device_Type"] = "SCADA / HMI / EWS"

def handle_s7comm(zeek_data):
    resp_ip = zeek_data.get('id.resp_h')
    if not resp_ip: return
    
    asset = get_or_create_asset(resp_ip)
    
    # Extract hard facts from the payload to overwrite inferences
    if 'module_type' in zeek_data:
        asset["Model"] = zeek_data.get('module_type')
    if 'system_name' in zeek_data:
        asset["Hostname"] = zeek_data.get('system_name')

# --- 3. THE DISPATCHER & ENGINE ---
LOG_DISPATCHER = {
    "conn": handle_conn,
    "s7comm": handle_s7comm,
    # Add your modbus handlers here pointing to get_or_create_asset()
}

def print_global_state():
    """Helper function to print the DB cleanly, converting sets to lists for JSON."""
    print("\n" + "="*50)
    print("GLOBAL ASSET INVENTORY".center(50))
    print("="*50)
    
    clean_db = {}
    for ip, data in ASSETS_DB.items():
        clean_db[ip] = {k: (list(v) if isinstance(v, set) else v) for k, v in data.items()}
    
    print(json.dumps(clean_db, indent=4))

def process_live_stream():
    print("Connecting to Redpanda/Kafka...")
    
    consumer = KafkaConsumer(
        'conn', 's7comm',
        bootstrap_servers=['redpanda:9092'],
        auto_offset_reset='earliest',
        group_id=f"grapher_dev_{uuid.uuid4()}",
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )

    print("Building Asset Database... Press Ctrl+C to view the final table.")

    try:
        for message in consumer:
            topic = message.topic
            zeek_data = message.value.get(topic, {})
            
            if topic in LOG_DISPATCHER:
                LOG_DISPATCHER[topic](zeek_data)
                
    except KeyboardInterrupt:
        # When you stop the script, it dumps the final state!
        print_global_state()

if __name__ == "__main__":
    process_live_stream()