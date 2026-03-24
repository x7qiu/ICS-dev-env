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


# ==============================================================================
# SCORING-BASED DEVICE CLASSIFICATION ENGINE
# ==============================================================================
#
# Instead of hard-coded thresholds (e.g. "if reads > 100 → SCADA"), we use an
# evidence-based scoring system. Each piece of observed evidence adds points
# toward a particular device role. The role with the highest score wins.
#
# This approach is robust over long-running deployments because it uses RELATIVE
# metrics (rates, ratios, counts of unique targets) instead of absolute totals,
# which would inevitably be exceeded by any device left running long enough.
#
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                        SCORING EVIDENCE TABLE                              │
# ├──────────────────────────────┬─────┬───────┬─────┬─────────────────────────┤
# │ Evidence                     │ EWS │ SCADA │ HMI │ Rationale               │
# ├──────────────────────────────┼─────┼───────┼─────┼─────────────────────────┤
# │ Has write activity (any OT)  │ +5  │       │     │ Only EWS programs PLCs  │
# │ Upload/Download blocks (S7)  │ +5  │       │     │ Firmware transfer = EWS │
# │ IT ports open (RDP/SMB/SSH)  │ +3  │  +1   │     │ Windows PC = EWS/SCADA  │
# │ IT vendor (HP, Dell, etc.)   │ +2  │  +1   │     │ IT hardware = PC-based  │
# │ OT vendor (Siemens, etc.)    │     │       │ +3  │ OT hardware = panel/HMI │
# │ Many unique PLC targets (>3) │     │  +3   │     │ Polls many PLCs = SCADA │
# │ Few PLC targets (1-2)        │     │       │ +2  │ Talks to 1-2 = HMI      │
# │ High read rate (>1/sec)      │     │  +2   │     │ Fast polling = SCADA    │
# │ Low read rate (<=1/sec)      │     │       │ +1  │ Slow/on-demand = HMI    │
# │ Multi-protocol (Modbus+S7)   │ +2  │  +1   │     │ Multi-protocol = PC app │
# │ OT read activity (any)       │     │  +1   │ +1  │ Base evidence for both  │
# └──────────────────────────────┴─────┴───────┴─────┴─────────────────────────┘
#
# The winner is chosen by the highest score. Ties are broken by priority:
#   EWS > SCADA > HMI > "SCADA / HMI / EWS" (fallback)
#
# The reason string documents which evidence contributed, giving operators
# full transparency into why a device was classified a certain way.
# ==============================================================================

IT_PORT_NUMBERS = set(IT_PORTS.keys())


def _has_it_ports(asset):
    """Check if asset has any IT infrastructure ports open (RDP, SMB, SSH, etc.)."""
    for port_str in asset.get("Open_ports", set()):
        try:
            port_num = int(port_str.split("/")[0])
            if port_num in IT_PORT_NUMBERS:
                return True
        except (ValueError, IndexError):
            continue
    return False


def _get_ot_activity(asset):
    """
    Aggregate OT protocol activity across all protocols (Modbus + S7comm).
    Returns a dict with combined metrics for scoring.
    """
    protocols = asset.get("Protocols", {})
    
    total_reads = 0
    total_writes = 0
    unique_targets = set()
    has_uploads = False
    active_protocols = 0
    
    # --- Modbus ---
    mb = protocols.get("Modbus", {}).get("Activity", {})
    if mb:
        mb_reads = sum(mb.get("Reads_Sent_To", {}).values())
        mb_writes = sum(mb.get("Writes_Sent_To", {}).values())
        if mb_reads > 0 or mb_writes > 0:
            active_protocols += 1
        total_reads += mb_reads
        total_writes += mb_writes
        unique_targets.update(mb.get("Reads_Sent_To", {}).keys())
        unique_targets.update(mb.get("Writes_Sent_To", {}).keys())
    
    # --- S7comm ---
    s7 = protocols.get("S7comm", {}).get("Activity", {})
    if s7:
        s7_reads = sum(s7.get("Reads_Sent_To", {}).values())
        s7_writes = sum(s7.get("Writes_Sent_To", {}).values())
        if s7_reads > 0 or s7_writes > 0:
            active_protocols += 1
        total_reads += s7_reads
        total_writes += s7_writes
        unique_targets.update(s7.get("Reads_Sent_To", {}).keys())
        unique_targets.update(s7.get("Writes_Sent_To", {}).keys())
        if s7.get("Uploads_Downloads"):
            has_uploads = True
    
    return {
        "total_reads": total_reads,
        "total_writes": total_writes,
        "unique_targets": len(unique_targets),
        "has_uploads": has_uploads,
        "active_protocols": active_protocols,
    }


def _calculate_read_rate(asset, total_reads):
    """Calculate reads per minute based on asset lifetime."""
    first = asset.get("First_Seen", 0)
    last = asset.get("Last_Seen", 0)
    lifetime_minutes = max((last - first) / 60.0, 1.0)  # Avoid division by zero
    return total_reads / lifetime_minutes


def refine_device_identities(assets_db):
    """
    Runs a post-processing pass over the entire asset database.
    Uses a scoring system (see SCORING EVIDENCE TABLE above) to classify
    OT-participating devices into EWS, SCADA Server, or HMI.
    
    Only applies to devices that have OT protocol activity (reads/writes).
    Devices identified purely by port (e.g. "Modbus PLC / Gateway") are
    left unchanged — port-based identification is already high-confidence.
    """
    for ip, asset in assets_db.items():
        
        # --- Vendor Classification (always runs) ---
        asset["Vendor_Class"] = classify_vendor(asset)
        
        # --- Aggregate OT activity across all protocols ---
        ot = _get_ot_activity(asset)
        
        # Skip assets with zero OT-initiated activity (PLCs, passive devices)
        if ot["total_reads"] == 0 and ot["total_writes"] == 0 and not ot["has_uploads"]:
            continue
        
        # Skip assets already locked into a high-confidence port-based label
        # (e.g., "Modbus PLC / Gateway", "Siemens S7 PLC")
        if asset["Device_Type"] in OT_PORTS.values():
            continue
        
        # --- Compute scores ---
        ews_score = 0
        scada_score = 0
        hmi_score = 0
        evidence = []   # Human-readable reasons for the final decision
        
        vendor_class = asset.get("Vendor_Class", "Unknown")
        has_it_ports = _has_it_ports(asset)
        read_rate = _calculate_read_rate(asset, ot["total_reads"])
        
        # EVIDENCE 1: Write activity (strongest EWS signal)
        if ot["total_writes"] > 0:
            ews_score += 5
            evidence.append(f"OT writes ({ot['total_writes']})")
        
        # EVIDENCE 2: Upload/Download (strongest EWS signal)
        if ot["has_uploads"]:
            ews_score += 5
            evidence.append("S7 upload/download")
        
        # EVIDENCE 3: IT ports open (RDP, SMB, SSH → likely a Windows/Linux PC)
        if has_it_ports:
            ews_score += 3
            scada_score += 1
            evidence.append("IT ports open")
        
        # EVIDENCE 4: Vendor classification
        if vendor_class == "IT":
            ews_score += 2
            scada_score += 1
            evidence.append("IT vendor")
        elif vendor_class == "OT":
            hmi_score += 3
            evidence.append("OT vendor")
        
        # EVIDENCE 5: Number of unique PLC targets
        if ot["unique_targets"] > 3:
            scada_score += 3
            evidence.append(f"{ot['unique_targets']} PLC targets")
        elif ot["unique_targets"] <= 2 and ot["unique_targets"] > 0:
            hmi_score += 2
            evidence.append(f"{ot['unique_targets']} PLC target(s)")
        
        # EVIDENCE 6: Read rate (reads per minute)
        if read_rate > 1.0:
            scada_score += 2
            evidence.append(f"high read rate ({read_rate:.1f}/min)")
        elif ot["total_reads"] > 0:
            hmi_score += 1
            evidence.append(f"low read rate ({read_rate:.1f}/min)")
        
        # EVIDENCE 7: Multi-protocol usage (speaks Modbus AND S7)
        if ot["active_protocols"] > 1:
            ews_score += 2
            scada_score += 1
            evidence.append(f"multi-protocol ({ot['active_protocols']})")
        
        # EVIDENCE 8: Base read activity
        if ot["total_reads"] > 0:
            scada_score += 1
            hmi_score += 1
        
        # --- Pick the winner ---
        scores = {
            "Engineering Workstation (EWS)": ews_score,
            "SCADA Server": scada_score,
            "HMI": hmi_score,
        }
        
        max_score = max(scores.values())
        
        if max_score == 0:
            # No meaningful evidence collected
            continue
        
        # Priority tie-breaking: EWS > SCADA > HMI
        if ews_score == max_score:
            winner = "Engineering Workstation (EWS)"
        elif scada_score == max_score:
            winner = "SCADA Server"
        elif hmi_score == max_score:
            winner = "HMI"
        else:
            winner = "SCADA / HMI / EWS"
        
        reason = f"Score: EWS={ews_score} SCADA={scada_score} HMI={hmi_score} | {', '.join(evidence)}"
        set_device_type(asset, winner, reason)