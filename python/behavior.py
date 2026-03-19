# High-confidence Industrial Control Systems (ICS) ports
OT_PORTS = {
    502: "Modbus PLC / Gateway",
    102: "Siemens S7 PLC",
    44818: "EtherNet/IP Controller",
    2222: "EtherNet/IP IO Device",
    47808: "BACnet Building Controller",
    20000: "DNP3 Outstation / RTU",
    19118: "Foxboro DCS",
    4840: "OPC UA Server"
}

# Standard IT infrastructure ports
IT_PORTS = {
    22: "Linux/Unix Host (SSH)",
    3389: "Windows Host (RDP)",
    445: "Windows Server/PC (SMB)",
    161: "Network Switch/Router (SNMP)",
    389: "Domain Controller (LDAP)"
}

# Create a list of all IT labels so we know what is safe to overwrite
IT_LABELS = list(IT_PORTS.values()) + ["IT", "Unknown"]

def infer_device_type(orig_asset, resp_asset, dest_port):
    """
    Infers the role of the devices based on the destination port they are communicating over.
    Modifies the asset dictionaries in place.
    """
    
    # 1. OT Heuristics (Highest Priority - Overrides IT)
    if dest_port in OT_PORTS:
        # If it's listening on an OT port, it's a controller. 
        # We forcefully overwrite it if it currently just has a generic IT label.
        if resp_asset["Device_Type"] in IT_LABELS:
            resp_asset["Device_Type"] = OT_PORTS[dest_port]
            
        # If it's talking TO an OT port, it's an HMI/Master.
        if orig_asset["Device_Type"] in IT_LABELS:
            orig_asset["Device_Type"] = "SCADA / HMI / EWS"

    # 2. IT Heuristics (Secondary Priority)
    elif dest_port in IT_PORTS:
        # We ONLY apply IT labels if the device hasn't already been identified as an OT device.
        if resp_asset["Device_Type"] in ["IT", "Unknown"]:
            resp_asset["Device_Type"] = IT_PORTS[dest_port]


def refine_device_identities(assets_db):
    """
    Runs a post-processing pass over the entire asset database to upgrade
    generic device types into highly specific roles based on accumulated L7 behavior.
    """
    for ip, asset in assets_db.items():
        
        # We don't care what the current label is. If it has OT behavior, 
        # we let the behavior dictate its final identity.
        
        # Safely grab the Modbus Activity block if it exists
        modbus_activity = asset.get("Protocols", {}).get("Modbus", {}).get("Activity", {})
        
        if not modbus_activity:
            continue
            
        # Calculate total reads and writes initiated by this IP
        total_reads = sum(modbus_activity.get("Reads_Sent_To", {}).values())
        total_writes = sum(modbus_activity.get("Writes_Sent_To", {}).values())
        
        # If it has NO activity initiated, it's just a PLC/Slave, skip refinement
        if total_reads == 0 and total_writes == 0:
            continue
            
        # HEURISTIC 1: The Engineering Workstation (EWS)
        if total_writes > 0:
            asset["Device_Type"] = "Engineering Workstation (EWS)"
            
        # HEURISTIC 2: The SCADA / Polling Server
        elif total_reads > 100 and total_writes == 0:
            asset["Device_Type"] = "SCADA Server"
            
        # HEURISTIC 3: The Low-Volume Poller (Catch-all)
        elif total_reads > 0:
            # Only apply this if it hasn't already been locked in as EWS or SCADA
            if asset["Device_Type"] not in ["Engineering Workstation (EWS)", "SCADA Server"]:
                asset["Device_Type"] = "SCADA / HMI / EWS"