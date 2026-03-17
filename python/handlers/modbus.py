# handlers/modbus.py
from state import get_or_create_asset

def handle_modbus_detailed(zeek_data):
    """
    Handles standard Modbus transactions. 
    Because Zeek merges the request and response into a single log, 
    id.orig_h is ALWAYS the Master, and id.resp_h is ALWAYS the Slave.
    """
    master_ip = zeek_data.get('id.orig_h')
    slave_ip = zeek_data.get('id.resp_h')
    
    if not master_ip or not slave_ip: 
        return
    
    master_asset = get_or_create_asset(master_ip)
    slave_asset = get_or_create_asset(slave_ip)
    
    mb_master = master_asset["Protocols"]["Modbus"]
    mb_slave = slave_asset["Protocols"]["Modbus"]
    
    # 1. Hardcode the roles based on the TCP flow
    mb_master["Roles"].add("Master")
    mb_slave["Roles"].add("Slave")
    
    func = str(zeek_data.get('func', '')).upper()
    unit = zeek_data.get('unit')
    address = zeek_data.get('address')
    exception = zeek_data.get('exception_code')
    
    if unit is not None:
        mb_slave["Unit_IDs_Served"].add(unit)
        
    # 2. Track the Activity and Memory Fingerprint
    # If the function explicitly says 'WRITE', it's a write. 
    # Everything else (READ, REPORT_SLAVE_ID, DIAGNOSTICS) is treated as a poll/read.
    if 'WRITE' in func:
        mb_master["Activity"]["Writes_Sent_To"][slave_ip] = mb_master["Activity"]["Writes_Sent_To"].get(slave_ip, 0) + 1
        if address is not None:
            mb_slave["Memory_Fingerprint"]["Registers_Written"].add(address)
    else:
        mb_master["Activity"]["Reads_Sent_To"][slave_ip] = mb_master["Activity"]["Reads_Sent_To"].get(slave_ip, 0) + 1
        if address is not None:
            mb_slave["Memory_Fingerprint"]["Registers_Read"].add(address)
            
    # 3. Track Health and Trust
    if exception:
        mb_slave["Activity"]["Exceptions_Triggered"][exception] = mb_slave["Activity"]["Exceptions_Triggered"].get(exception, 0) + 1
    else:
        mb_slave["Activity"]["Successful_Responses"] += 1


def handle_modbus_rw_multiple(zeek_data):
    """
    Handles modbus_read_write_multiple_registers.log.
    This log uses the ICSNPP custom directional fields.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')
    direction = zeek_data.get('request_response', '').upper()
    
    # We only need to map the registers once on the request
    if not src or not dst or direction != 'REQUEST': 
        return
        
    slave_asset = get_or_create_asset(dst)
    mb_slave = slave_asset["Protocols"]["Modbus"]
    
    r_addr = zeek_data.get('read_start_address')
    w_addr = zeek_data.get('write_start_address')
    
    if r_addr is not None: mb_slave["Memory_Fingerprint"]["Registers_Read"].add(r_addr)
    if w_addr is not None: mb_slave["Memory_Fingerprint"]["Registers_Written"].add(w_addr)


def handle_modbus_device_id(zeek_data):
    """
    Extracts cleartext hardware profiles from modbus_read_device_identification.log.
    This log uses the ICSNPP custom directional fields.
    """
    src = zeek_data.get('source_h')
    dst = zeek_data.get('destination_h')
    direction = zeek_data.get('request_response', '').upper()
    
    # We strictly want the RESPONSE, because the source is the actual PLC answering
    if not src or not dst or direction != 'RESPONSE': 
        return
        
    slave_asset = get_or_create_asset(src) 
    
    obj_id = str(zeek_data.get('object_id', '')).upper()
    obj_val = zeek_data.get('object_value', '')
    
    if not obj_val: return
    
    if 'VENDOR' in obj_id or zeek_data.get('object_id_code') == 0:
        slave_asset["Vendor"].add(obj_val)
    elif 'PRODUCT' in obj_id or zeek_data.get('object_id_code') == 1:
        slave_asset["Model"] = obj_val
    elif 'REVISION' in obj_id or zeek_data.get('object_id_code') == 2:
        slave_asset["Firmware_version"] = obj_val