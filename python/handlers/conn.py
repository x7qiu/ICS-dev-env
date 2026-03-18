# handlers/conn.py
from state import get_or_create_asset
from mac_vendor import lookup_vendor
from behavior import infer_device_type

def handle_conn(zeek_data):
    """
    Analyzes Zeek conn.log data to build the baseline L2/L3 network topology.
    Accurately tracks active ports using TCP handshake history and UDP response bytes.
    """
    orig_ip = zeek_data.get('id.orig_h')
    resp_ip = zeek_data.get('id.resp_h')
    resp_p = zeek_data.get('id.resp_p')
    proto = zeek_data.get('proto')
    
    orig_mac = zeek_data.get('orig_l2_addr')
    resp_mac = zeek_data.get('resp_l2_addr')
    
    history = zeek_data.get('history', '')
    
    # Safely extract response bytes (safeguard against nulls or blanks)
    try:
        resp_bytes = int(zeek_data.get('resp_bytes', 0))
    except (ValueError, TypeError):
        resp_bytes = 0

    if not orig_ip or not resp_ip:
        return

    # Initialize or fetch the assets
    orig_asset = get_or_create_asset(orig_ip)
    resp_asset = get_or_create_asset(resp_ip)

    # Track logical communication paths
    orig_asset["Seen_Speaking_To"].add(resp_ip)

    # Update MAC and Hardware Vendor for the Originator
    if orig_mac and orig_mac not in orig_asset["MAC"]:
        orig_asset["MAC"].add(orig_mac)
        vendor = lookup_vendor(orig_mac)
        if vendor != "Unknown": 
            orig_asset["Vendor"].add(vendor)
            
    # Update MAC and Hardware Vendor for the Responder
    if resp_mac and resp_mac not in resp_asset["MAC"]:
        resp_asset["MAC"].add(resp_mac)
        vendor = lookup_vendor(resp_mac)
        if vendor != "Unknown": 
            resp_asset["Vendor"].add(vendor)

    # --- THE PORT VERIFICATION ENGINE ---
    is_open = False
    
    if proto == 'tcp':
        # 'h' = Responder sent SYN-ACK. resp_bytes > 0 = Responder sent data (catches mid-stream traffic)
        if 'h' in history or resp_bytes > 0:
            is_open = True
            
    elif proto == 'udp':
        # UDP is stateless. The ONLY way to prove it's open is if the server replied with data.
        if resp_bytes > 0:
            is_open = True

    # If proven open, log it and run behavior inference
    if is_open and resp_p is not None:
        # Format it as "port/protocol" (e.g., "502/tcp")
        port_string = f"{resp_p}/{proto}"
        resp_asset["Open_ports"].add(port_string)
        
        # Keep passing the raw integer to your behavior engine so your heuristics don't break!
        infer_device_type(orig_asset, resp_asset, resp_p)