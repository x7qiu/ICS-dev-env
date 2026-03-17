from state import get_or_create_asset
from mac_vendor import lookup_vendor

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

    # Only do the expensive lookup if this is a BRAND NEW MAC address
    if orig_mac and orig_mac not in orig_asset["MAC"]:
        orig_asset["MAC"].add(orig_mac)
        vendor = lookup_vendor(orig_mac)
        if vendor != "Unknown":
            orig_asset["Vendor"].add(vendor)
            
    if resp_mac and resp_mac not in resp_asset["MAC"]:
        resp_asset["MAC"].add(resp_mac)
        vendor = lookup_vendor(resp_mac)
        if vendor != "Unknown":
            resp_asset["Vendor"].add(vendor)

    # Verify Open Ports (TCP Handshake Completed or UDP traffic)
    if (proto == 'tcp' and conn_state in ['SF', 'S1']) or proto == 'udp':
        resp_asset["Open_ports"].add(resp_p)

        # BEHAVIORAL INFERENCE
        if resp_p in [102, 502, 44818]: # S7comm, Modbus, Ethernet/IP
            resp_asset["Device_Type"] = "PLC / RTU"
            if orig_asset["Device_Type"] == "IT": # Upgrade client from IT to OT
                orig_asset["Device_Type"] = "SCADA / HMI / EWS"