@load packages
@load tuning/json-logs
@load protocols/conn/mac-logging

# 1. Disable the default single-topic firehose
redef Kafka::topic_name = "";

# 2. Tag the JSON (Wraps the data in {"s7comm": {...}} so Python knows the exact schema)
redef Kafka::tag_json = T;

# 3. GLOBAL BROKER CONFIG
redef Kafka::kafka_conf = table(["metadata.broker.list"] = "redpanda:9092");

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

    # Route 4: Modbus Device Identification (The Asset Goldmine)
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