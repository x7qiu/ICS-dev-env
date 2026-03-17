from .conn import handle_conn
from .s7comm import handle_s7comm

from .modbus import handle_modbus_detailed, handle_modbus_rw_multiple, handle_modbus_device_id

LOG_DISPATCHER = {
    "conn": handle_conn,
    "s7comm": handle_s7comm,

    "modbus_detailed": handle_modbus_detailed,
    "modbus_read_write_multiple_registers": handle_modbus_rw_multiple,
    "modbus_read_device_identification": handle_modbus_device_id
}