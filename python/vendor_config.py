# vendor_config.py
# Classification config for vendor keywords and port mappings.
# Matching is case-insensitive substring: "hp" matches "HP Inc.", "Hewlett-Packard", etc.
# Add new keywords as you encounter new vendors in your PCAPs.

IT_VENDOR_KEYWORDS = [
    "hp", "hewlett", "dell", "lenovo", "intel", "supermicro",
    "asus", "acer", "microsoft", "vmware", "realtek", "broadcom",
    "gigabyte", "asrock", "toshiba", "fujitsu", "ibm",
]

OT_VENDOR_KEYWORDS = [
    "siemens", "abb", "schneider", "rockwell", "allen-bradley",
    "honeywell", "emerson", "yokogawa", "mitsubishi", "omron",
    "beckhoff", "phoenix", "wago", "moxa", "advantech", "b&r",
    "ge fanuc", "danfoss", "endress", "pepperl", "turck",
    "hirschmann", "belden", 
]

# High-confidence Industrial Control Systems (ICS) ports
OT_PORTS = {
    502: "Modbus PLC / Gateway",
    102: "Siemens S7 PLC",
    44818: "EtherNet/IP Controller",
    2222: "EtherNet/IP IO Device",
    47808: "BACnet Building Controller",
    20000: "DNP3 Outstation / RTU",
    19118: "Foxboro DCS",
    4840: "OPC UA Server",
}

# Standard IT infrastructure ports
IT_PORTS = {
    22: "Linux/Unix Host (SSH)",
    3389: "Windows Host (RDP)",
    445: "Windows Server/PC (SMB)",
    161: "Network Switch/Router (SNMP)",
    389: "Domain Controller (LDAP)",
}
