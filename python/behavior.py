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

def infer_device_type(orig_asset, resp_asset, dest_port):
    """
    Infers the role of the devices based on the destination port they are communicating over.
    Modifies the asset dictionaries in place.
    """
    
    # 1. OT Heuristics (Highest Priority)
    if dest_port in OT_PORTS:
        # If a device is LISTENING on an OT port, it is almost certainly a controller
        if resp_asset["Device_Type"] in ["IT", "Unknown"]:
            resp_asset["Device_Type"] = OT_PORTS[dest_port]
            
        # If a device is actively TALKING to an OT port, it is likely the Master/HMI
        if orig_asset["Device_Type"] in ["IT", "Unknown"]:
            orig_asset["Device_Type"] = "SCADA / HMI / EWS"

    # 2. IT Heuristics (Secondary Priority)
    elif dest_port in IT_PORTS:
        # We only apply IT labels if the device hasn't already been identified as an OT device.
        # (e.g., We don't want to relabel a Siemens PLC as a "Linux Host" just because it has SSH open).
        if resp_asset["Device_Type"] in ["IT", "Unknown"]:
            resp_asset["Device_Type"] = IT_PORTS[dest_port]