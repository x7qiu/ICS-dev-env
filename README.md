## Workflow
- Place your pcap file into the `pcaps` folder
- `make zeek`: run zeek against the pcap and send logs to kafka/redpanda
- `make python`: Python will read from kafka and process them