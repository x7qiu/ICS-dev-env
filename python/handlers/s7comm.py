from state import get_or_create_asset

def handle_s7comm(zeek_data):
    resp_ip = zeek_data.get('id.resp_h')
    if not resp_ip: return
    
    asset = get_or_create_asset(resp_ip)
    
    # Extract hard facts from the payload to overwrite inferences
    if 'module_type' in zeek_data:
        asset["Model"] = zeek_data.get('module_type')
    if 'system_name' in zeek_data:
        asset["Hostname"] = zeek_data.get('system_name')