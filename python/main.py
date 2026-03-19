import time
import orjson
import uuid
from kafka import KafkaConsumer

from state import ASSETS_DB, prune_stale_assets
from handlers import LOG_DISPATCHER
from behavior import refine_device_identities

def json_default_handler(obj):
    """Tells orjson how to handle unsupported types like sets."""
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def print_global_state():
    print("\n" + "="*50)
    print("GLOBAL ASSET INVENTORY".center(50))
    print("="*50)
    
    json_output = orjson.dumps(
        ASSETS_DB, 
        option=orjson.OPT_INDENT_2,
        default=json_default_handler
    ).decode('utf-8')
    
    output_path = '/app/output.json'
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f"\n[+] Successfully saved complete inventory to {output_path}")
    except Exception as e:
        print(f"\n[!] Failed to save output.json: {e}")

def process_live_stream():
    print("Connecting to Redpanda/Kafka...")
    
    consumer = KafkaConsumer(
        # We dynamically grab the exact topics to subscribe to from the dispatcher!
        *LOG_DISPATCHER.keys(),
        bootstrap_servers=['redpanda:9092'],
        auto_offset_reset='earliest',
        group_id=f"grapher_dev_{uuid.uuid4()}",
        value_deserializer=lambda x: orjson.loads(x)
    )

    print(f"Subscribed to topics: {list(LOG_DISPATCHER.keys())}")
    print("Building Asset Database in BATCH mode... Press Ctrl+C to view the final table.")

    # --- NEW: Set the maintenance timers ---
    LAST_MAINTENANCE = time.time()
    MAINTENANCE_INTERVAL = 60      # Run heuristic upgrades every 60 seconds
    STALE_TIMEOUT = 86400          # Drop assets quiet for 24 hours (86,400 seconds)

    try:
        total_processed = 0
        while True:
            # 1. Fetch up to 10,000 records at once (Non-blocking)
            raw_batch = consumer.poll(timeout_ms=1000, max_records=10000)
            
            if raw_batch:
                batch_count = 0
                for topic_partition, messages in raw_batch.items():
                    topic = topic_partition.topic
                    
                    if topic not in LOG_DISPATCHER:
                        continue
                        
                    for message in messages:
                        batch_count += 1
                        zeek_data = message.value.get(topic, {})
                        LOG_DISPATCHER[topic](zeek_data)
                
                # Print a heartbeat every time a batch finishes
                total_processed += batch_count
                print(f"Processed {total_processed} packets...", end='\r')
            
            # --- NEW: The Maintenance Cycle ---
            # This check happens instantly without pausing packet ingestion
            current_time = time.time()
            if (current_time - LAST_MAINTENANCE) > MAINTENANCE_INTERVAL:
                # Upgrade generic tags to EWS/SCADA based on behavior
                refine_device_identities(ASSETS_DB)
                
                # Drop assets that have gone offline
                prune_stale_assets(timeout_seconds=STALE_TIMEOUT)
                
                # Reset the clock
                LAST_MAINTENANCE = current_time
                    
    except KeyboardInterrupt:
        print("\nStopping ingestion...")
    finally:
        # Run one final refinement pass before saving the file
        # This guarantees you get the most accurate labels even if you stop it manually
        refine_device_identities(ASSETS_DB)
        print_global_state()

if __name__ == "__main__":
    process_live_stream()