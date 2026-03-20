# handlers/conn.py
from state import get_or_create_asset, ROUTER_MACS, ASSETS_DB
from mac_vendor import lookup_vendor
from behavior import infer_device_type

def retroactively_filter_router_mac(router_mac):
    if not router_mac:
        return
    ROUTER_MACS.add(router_mac)
    for ip, asset in ASSETS_DB.items():
        asset["MAC"].discard(router_mac)

def assign_mac(asset, mac):
    if not mac or mac in ROUTER_MACS:
        return
    if mac not in asset["MAC"]:
        asset["MAC"].add(mac)
        vendor = lookup_vendor(mac)
        if vendor != "Unknown": 
            asset["Vendor"].add(vendor)

def process_macs(orig_ttl, orig_ip, resp_ip, orig_mac, resp_mac, orig_asset, resp_asset):
    """
    Determines if the MAC addresses in the frame belong to endpoints or routers.
    Prioritizes TTL: If TTL in [30, 64, 128, 255], originator is the real MAC.
    If TTL is not in that set, and IPs not in same /24, then originator is the router.
    """
    if not orig_ip or not resp_ip:
        return
        
    same_subnet = (orig_ip.split('.')[:3] == resp_ip.split('.')[:3])
    
    if orig_ttl in [30, 64, 128, 255]:
        # Originator has not crossed a router. It is the real MAC.
        assign_mac(orig_asset, orig_mac)
        
    else:
        # TTL is not one of the default starting TTLs.
        if not same_subnet:
            # Only if TTL is decremented AND IPs are in different /24s,
            # we conclude the originator is the router.
            retroactively_filter_router_mac(orig_mac)
            
            # Assuming the traffic is coming TO a local endpoint:
            assign_mac(resp_asset, resp_mac)
        else:
            # TTL is decremented but they are in the same /24 block.
            # Local L2 neighbors (weird TTL, but safe to assume local).
            assign_mac(orig_asset, orig_mac)
            assign_mac(resp_asset, resp_mac)

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
    
    # NEW: Grab the TTL injected by our custom Zeek script
    orig_ttl = zeek_data.get('orig_ttl') 
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



    # --- L2 / L3 GATEWAY INFERENCE ENGINE ---
    process_macs(orig_ttl, orig_ip, resp_ip, orig_mac, resp_mac, orig_asset, resp_asset)


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

    # Track attempted connections (just IPs, including icmp)
    orig_asset["Attempted_Connections"].add(resp_ip)

    # Track successful connections with port/protocol detail (tcp/udp only)
    if is_open and resp_p is not None and proto in ('tcp', 'udp'):
        if resp_ip not in orig_asset["Connected_To"]:
            orig_asset["Connected_To"][resp_ip] = {"tcp": set(), "udp": set()}
        orig_asset["Connected_To"][resp_ip][proto].add(resp_p)