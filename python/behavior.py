from vendor_config import (
    IT_VENDOR_KEYWORDS, OT_VENDOR_KEYWORDS,
    OT_PORTS, IT_PORTS
)

# Create a list of all IT labels so we know what is safe to overwrite
IT_LABELS = list(IT_PORTS.values()) + ["IT", "Unknown"]


def classify_vendor(asset):
    """
    Classifies an asset as IT, OT, or Unknown based on its Vendor set.
    Uses case-insensitive keyword substring matching.
    """
    if not asset.get("Vendor"):
        return "Unknown"

    vendor_str = " ".join(asset["Vendor"]).lower()

    is_ot = any(kw in vendor_str for kw in OT_VENDOR_KEYWORDS)
    is_it = any(kw in vendor_str for kw in IT_VENDOR_KEYWORDS)

    if is_ot and not is_it:
        return "OT"
    elif is_it and not is_ot:
        return "IT"
    elif is_ot and is_it:
        return "OT"  # OT takes priority when ambiguous
    return "Unknown"


def set_device_type(asset, device_type, reason):
    """Helper to always set Device_Type and Device_Type_Reason together."""
    asset["Device_Type"] = device_type
    asset["Device_Type_Reason"] = reason


def infer_device_type(orig_asset, resp_asset, dest_port):
    """
    Infers the role of the devices based on the destination port they are communicating over.
    Modifies the asset dictionaries in place.
    """
    
    # 1. OT Heuristics (Highest Priority - Overrides IT)
    if dest_port in OT_PORTS:
        # If it's listening on an OT port, it's a controller. 
        if resp_asset["Device_Type"] in IT_LABELS:
            set_device_type(resp_asset, OT_PORTS[dest_port],
                            f"Listening on OT port {dest_port}/tcp")
            
        # If it's talking TO an OT port, it's an HMI/Master.
        if orig_asset["Device_Type"] in IT_LABELS:
            set_device_type(orig_asset, "SCADA / HMI / EWS",
                            f"Talks to OT port {dest_port}/tcp")

    # 2. IT Heuristics (Secondary Priority)
    elif dest_port in IT_PORTS:
        if resp_asset["Device_Type"] in ["IT", "Unknown"]:
            set_device_type(resp_asset, IT_PORTS[dest_port],
                            f"Listening on IT port {dest_port}/tcp")


def refine_device_identities(assets_db):
    """
    Runs a post-processing pass over the entire asset database to upgrade
    generic device types into highly specific roles based on accumulated L7 behavior.
    """
    for ip, asset in assets_db.items():
        
        # --- Vendor Classification (always runs) ---
        asset["Vendor_Class"] = classify_vendor(asset)
        
        # --- Modbus Refinement ---
        modbus_activity = asset.get("Protocols", {}).get("Modbus", {}).get("Activity", {})
        
        if modbus_activity:
            total_reads = sum(modbus_activity.get("Reads_Sent_To", {}).values())
            total_writes = sum(modbus_activity.get("Writes_Sent_To", {}).values())
            
            if total_writes > 0:
                set_device_type(asset, "Engineering Workstation (EWS)",
                                "Modbus write activity")
                continue
            elif total_reads > 100:
                set_device_type(asset, "SCADA Server",
                                f"Modbus high-volume polling ({total_reads} reads)")
                continue
            elif total_reads > 0:
                if asset["Device_Type"] not in ["Engineering Workstation (EWS)", "SCADA Server"]:
                    # Vendor tie-breaker
                    if asset["Vendor_Class"] == "IT":
                        set_device_type(asset, "Engineering Workstation (EWS)",
                                        "Modbus polling + IT vendor")
                    elif asset["Vendor_Class"] == "OT":
                        set_device_type(asset, "HMI",
                                        "Modbus polling + OT vendor")
                    else:
                        set_device_type(asset, "SCADA / HMI / EWS",
                                        "Modbus polling activity")
                    continue
            
        # --- S7comm Refinement ---
        s7_activity = asset.get("Protocols", {}).get("S7comm", {}).get("Activity", {})
        
        if not s7_activity:
            continue
        
        # HIGHEST PRIORITY: Upload/Download activity = EWS
        if s7_activity.get("Uploads_Downloads"):
            set_device_type(asset, "Engineering Workstation (EWS)",
                            "S7comm upload/download activity")
            continue
            
        s7_reads = sum(s7_activity.get("Reads_Sent_To", {}).values())
        s7_writes = sum(s7_activity.get("Writes_Sent_To", {}).values())
        
        if s7_reads == 0 and s7_writes == 0:
            continue
        
        if s7_writes > 0:
            set_device_type(asset, "Engineering Workstation (EWS)",
                            "S7comm write activity")
        elif s7_reads > 100:
            set_device_type(asset, "SCADA Server",
                            f"S7comm high-volume polling ({s7_reads} reads)")
        elif s7_reads > 0:
            if asset["Device_Type"] not in ["Engineering Workstation (EWS)", "SCADA Server"]:
                if asset["Vendor_Class"] == "IT":
                    set_device_type(asset, "Engineering Workstation (EWS)",
                                    "S7comm polling + IT vendor")
                elif asset["Vendor_Class"] == "OT":
                    set_device_type(asset, "HMI",
                                    "S7comm polling + OT vendor")
                else:
                    set_device_type(asset, "SCADA / HMI / EWS",
                                    "S7comm polling activity")