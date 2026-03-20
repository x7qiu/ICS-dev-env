@load packages
@load tuning/json-logs
@load protocols/conn/mac-logging

# ==============================================================================
# 1. CUSTOM LOGGING FIELDS (Injecting Originator TTL into conn.log)
# ==============================================================================
redef record Conn::Info += {
    orig_ttl: count &optional &log;
};

# Fires only ONCE per connection, making it extremely lightweight for production.
event new_connection(c: connection) {
    local p: raw_pkt_hdr = get_current_packet_header();
    
    if ( p?$ip ) {
        c$conn$orig_ttl = p$ip$ttl;
    } else if ( p?$ip6 ) {
        c$conn$orig_ttl = p$ip6$hlim;
    }
}

# ==============================================================================
# 2. KAFKA BROKER CONFIGURATION
# ==============================================================================
# Disable the default single-topic firehose
redef Kafka::topic_name = "";

# Tag the JSON (Wraps the data in {"s7comm": {...}} so Python knows the exact schema)
redef Kafka::tag_json = T;

# GLOBAL BROKER CONFIG
redef Kafka::kafka_conf = table(["metadata.broker.list"] = "redpanda:9092");

# ==============================================================================
# 3. KAFKA ROUTING FILTERS
# ==============================================================================
event zeek_init() &priority=-10 {

    # Route 1: Connection Logs
    Log::add_filter(Conn::LOG, [
        $name = "kafka-conn",
        $writer = Log::WRITER_KAFKAWRITER,
        $path = "conn",
        $config = table(["metadata.broker.list"] = "redpanda:9092")
    ]);

    # Route 2: Modbus Base Logs
    Log::add_filter(Modbus::LOG, [
        $name = "kafka-modbus",
        $writer = Log::WRITER_KAFKAWRITER,
        $path = "modbus",
        $config = table(["metadata.broker.list"] = "redpanda:9092")
    ]);

    # Route 3: Modbus Detailed Logs
    Log::add_filter(Modbus_Extended::LOG_DETAILED, [
        $name = "kafka-modbus-detailed",
        $writer = Log::WRITER_KAFKAWRITER,
        $path = "modbus_detailed",
        $config = table(["metadata.broker.list"] = "redpanda:9092")
    ]);

    # Route 4: Modbus Device Identification
    Log::add_filter(Modbus_Extended::LOG_READ_DEVICE_IDENTIFICATION, [
        $name = "kafka-modbus-id",
        $writer = Log::WRITER_KAFKAWRITER,
        $path = "modbus_read_device_identification",
        $config = table(["metadata.broker.list"] = "redpanda:9092")
    ]);

    # Route 5: S7comm Logs
    Log::add_filter(S7COMM::LOG_S7COMM, [
        $name = "kafka-s7comm",
        $writer = Log::WRITER_KAFKAWRITER,
        $path = "s7comm",
        $config = table(["metadata.broker.list"] = "redpanda:9092")
    ]);
}