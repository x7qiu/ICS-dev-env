## Workflow
- Place your pcap file into the `pcaps` folder
- `make zeek`: run zeek against the pcap and generate logs
    - `make list-logs`: list said logs 
- filebeat will automatically notice these logs and start processing them, writing ndjson files into `dev_data` folder. Note that this could take a long time
- `make run`: Python will read `dev_data/*ndjson` and process them