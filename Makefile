# Default PCAP file to use if one isn't specified
PCAP ?= 4SICS-GeekLounge-151022.pcap

.PHONY: help up build down zeek python shell-python shell-zeek

build:
	docker-compose up -d --build

up:
	docker-compose up -d

status:
	docker-compose ps

down:
	docker-compose down

update-oui:
	@echo "Downloading latest IEEE OUI database..."
	curl -o ./python/oui.txt https://standards-oui.ieee.org/oui/oui.txt
	@echo "Download complete. Saved to ./python/oui.txt"

# Runs Zeek against the PCAP. 
# Usage: 'make zeek' OR 'make zeek PCAP=my_custom_capture.pcap'
zeek:
	@echo "Wiping old Kafka topics for a clean run..."
	-docker-compose exec redpanda rpk topic delete conn s7comm modbus modbus_detailed modbus_read_device_identification
	@echo "Pre-creating Kafka topics to prevent race conditions..."
	-docker-compose exec redpanda rpk topic create conn s7comm modbus modbus_detailed modbus_read_device_identification
	@echo "Waiting 3 seconds for Redpanda partition leader elections..."
	@sleep 3
	@echo "Running Zeek against /pcaps/$(PCAP)..."
	docker-compose exec zeek bash -c "mkdir -p /tmp/zeek_run && cd /tmp/zeek_run && zeek -C -r /pcaps/$(PCAP) local /scripts/kafka-routing.zeek"

# 
topic:
	docker-compose exec redpanda rpk topic describe s7comm modbus modbus_detailed modbus_read_device_identification

# Instantly runs your locally modified Python script inside the container
python:
	@echo "Executing Python Engine..."
	docker-compose exec python-engine python main.py

# Handy shortcuts for debugging
shell-py:
	docker-compose exec python-engine /bin/bash

shell-zeek:
	docker-compose exec zeek /bin/bash