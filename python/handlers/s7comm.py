# handlers/s7comm.py
from state import get_or_create_asset

# ---- S7comm functions that indicate read vs write operations ----
S7_WRITE_FUNCTIONS = {"WRITE_VAR", "DOWNLOAD_BLOCK", "PI_SERVICE"}
S7_READ_FUNCTIONS = {"READ_VAR", "READ_SZL"}


def handle_cotp(zeek_data):
    """
    Handles cotp.log. COTP is the transport layer for S7comm.
    Marks both endpoints as S7 participants.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')

    if not src or not dst:
        return

    src_asset = get_or_create_asset(src)
    dst_asset = get_or_create_asset(dst)

    # COTP Connection Request → src is requesting (SCADA/HMI/EWS)
    pdu_name = str(zeek_data.get('pdu_name', '')).upper()
    if 'CONNECTION_REQUEST' in pdu_name or 'CR' in pdu_name:
        src_asset["Protocols"]["S7comm"]["Roles"].add("SCADA / HMI / EWS")
        dst_asset["Protocols"]["S7comm"]["Roles"].add("Controller")


def handle_s7comm(zeek_data):
    """
    Handles s7comm.log. Core S7 header handler.
    Extracts rosctr (request/response roles), function codes, and errors.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')

    if not src or not dst:
        return

    src_asset = get_or_create_asset(src)
    dst_asset = get_or_create_asset(dst)
    s7_src = src_asset["Protocols"]["S7comm"]
    s7_dst = dst_asset["Protocols"]["S7comm"]

    # --- Role inference from rosctr ---
    rosctr = str(zeek_data.get('rosctr_name', '')).upper()
    if 'JOB' in rosctr:
        # Source is sending a request → it is the SCADA/HMI/EWS
        s7_src["Roles"].add("SCADA / HMI / EWS")
        s7_dst["Roles"].add("Controller")
    elif 'ACK_DATA' in rosctr:
        # Source is sending a response → it is the Controller/PLC
        s7_src["Roles"].add("Controller")
        s7_dst["Roles"].add("SCADA / HMI / EWS")

    # --- Track function codes ---
    func_name = zeek_data.get('function_name', '')
    if func_name:
        s7_src["Functions_Seen"].add(func_name)

    # --- Track read/write activity (only on requests) ---
    func_upper = str(func_name).upper()
    if 'JOB' in rosctr:
        if func_upper in S7_WRITE_FUNCTIONS or 'WRITE' in func_upper:
            s7_src["Activity"]["Writes_Sent_To"][dst] = s7_src["Activity"]["Writes_Sent_To"].get(dst, 0) + 1
        elif func_upper in S7_READ_FUNCTIONS or 'READ' in func_upper:
            s7_src["Activity"]["Reads_Sent_To"][dst] = s7_src["Activity"]["Reads_Sent_To"].get(dst, 0) + 1

    # --- Track errors ---
    error_class = zeek_data.get('error_class')
    error_code = zeek_data.get('error_code')
    if error_class and error_class != "No error":
        error_key = f"{error_class}:{error_code}" if error_code else error_class
        s7_dst["Activity"]["Errors"][error_key] = s7_dst["Activity"]["Errors"].get(error_key, 0) + 1
    elif 'ACK_DATA' in rosctr:
        s7_src["Activity"]["Successful_Responses"] += 1

    # --- Extract hard facts from SZL responses (existing stub logic) ---
    if 'module_type' in zeek_data:
        src_asset["Model"] = zeek_data.get('module_type')
    if 'system_name' in zeek_data:
        src_asset["Hostname"] = zeek_data.get('system_name')


def handle_s7comm_read_szl(zeek_data):
    """
    Handles s7comm_read_szl.log.
    Captures System Status List (SZL) data for hardware/firmware identification.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')
    method = str(zeek_data.get('method', '')).upper()

    if not src or not dst:
        return

    # We care about responses — the PLC is reporting its SZL data
    if method != 'RESPONSE':
        return

    plc_asset = get_or_create_asset(src)
    s7_plc = plc_asset["Protocols"]["S7comm"]

    szl_id_name = zeek_data.get('szl_id_name', '')
    return_code_name = zeek_data.get('return_code_name', '')

    if szl_id_name:
        s7_plc["SZL_Info"][szl_id_name] = return_code_name

    # Track success/failure
    if return_code_name and 'SUCCESS' in return_code_name.upper():
        s7_plc["Activity"]["Successful_Responses"] += 1


def handle_s7comm_upload_download(zeek_data):
    """
    Handles s7comm_upload_download.log.
    Logs program block transfers between EWS and PLCs.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')

    if not src or not dst:
        return

    src_asset = get_or_create_asset(src)
    dst_asset = get_or_create_asset(dst)
    s7_src = src_asset["Protocols"]["S7comm"]

    # Any upload/download activity means src is an EWS
    s7_src["Roles"].add("Engineering Workstation (EWS)")

    filename = zeek_data.get('filename', '')
    block_type = zeek_data.get('block_type', '')
    block_number = zeek_data.get('block_number', '')
    function_code = zeek_data.get('function_code')

    # Determine direction: upload = PLC→EWS, download = EWS→PLC
    func_str = str(function_code).upper() if function_code else ''
    if 'UPLOAD' in func_str:
        direction = "upload"
    elif 'DOWNLOAD' in func_str:
        direction = "download"
    else:
        direction = "unknown"

    transfer_record = {
        "filename": filename,
        "block_type": block_type,
        "block_number": block_number,
        "direction": direction
    }

    # Avoid duplicate records
    if transfer_record not in s7_src["Activity"]["Uploads_Downloads"]:
        s7_src["Activity"]["Uploads_Downloads"].append(transfer_record)


def handle_s7comm_plus(zeek_data):
    """
    Handles s7comm_plus.log.
    Tracks S7comm-Plus operations (Siemens 1200/1500 series).
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')

    if not src or not dst:
        return

    src_asset = get_or_create_asset(src)
    dst_asset = get_or_create_asset(dst)
    s7_src = src_asset["Protocols"]["S7comm"]
    s7_dst = dst_asset["Protocols"]["S7comm"]

    opcode_name = zeek_data.get('opcode_name', '')
    func_name = zeek_data.get('function_name', '')

    if func_name:
        s7_src["Functions_Seen"].add(func_name)

    # Role inference from opcode
    opcode_upper = str(opcode_name).upper()
    if 'REQUEST' in opcode_upper:
        s7_src["Roles"].add("SCADA / HMI / EWS")
        s7_dst["Roles"].add("Controller")
    elif 'RESPONSE' in opcode_upper:
        s7_src["Roles"].add("Controller")
        s7_dst["Roles"].add("SCADA / HMI / EWS")