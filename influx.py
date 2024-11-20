#!/usr/bin/python3
from influxdb import InfluxDBClient
from datetime import datetime, timedelta
import os
import json
import random

# Directory containing JSON files
json_directory = "/home/sandbox/Desktop/logs/json"

# InfluxDB connection details
influx_host = 'localhost'  # Change to your InfluxDB host
influx_port = 8086  # Default port
influx_database = 'TestGrafana'

# Initialize InfluxDB client
client = InfluxDBClient(host=influx_host, port=influx_port)
client.switch_database(influx_database)
client.create_database(influx_database)

def get_dynamic_value(item, key, fallback="unknown"):
    return item.get(key, fallback)

def write_in_batches(points, batch_size, client):
    """
    Writes points to InfluxDB in batches to avoid overwhelming the server with large data sets.

    :param points: List of points to write.
    :param batch_size: The size of each batch.
    :param client: The InfluxDB client instance.
    """
    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        try:
            client.write_points(batch)
            print(f"Successfully wrote batch of {len(batch)} points to InfluxDB.")
        except Exception as e:
            print(f"Error writing batch of {len(batch)} points to InfluxDB: {e}")

# Generate random timestamp within a 25-minute range
def generate_random_timestamp(base_time, time_range_minutes=25):
    random_offset = random.randint(0, time_range_minutes * 60)  # Convert minutes to seconds
    random_time = base_time + timedelta(seconds=random_offset)
    return random_time.isoformat() + "Z"

# Main loop for processing JSON files
points = []
current_time = datetime.utcnow()  # Base time for the 25-minute range

for filename in os.listdir(json_directory):
    if filename.endswith('.json'):
        try:
            with open(os.path.join(json_directory, filename), 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {filename}: {e}")
            continue
        except Exception as e:
            print(f"Error processing file {filename}: {e}")
            continue

        if "processlist" in data:
            data = data["processlist"].get("process", [])
        elif isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            print(f"Skipping invalid data in {filename}: Expected a dictionary or list.")
            continue

        for item in data:
            try:
                timestamp = item.get("timestamp", generate_random_timestamp(current_time))
                point = {
                    "measurement": "malware_analysis",
                    "tags": {
                        "source_file": filename,
                        "host": get_dynamic_value(item, "host"),
                        "frame_section_number": get_dynamic_value(item, "frame.section_number"),
                        "frame_interface_id": get_dynamic_value(item, "frame.interface_id"),
                        "frame_interface_name": get_dynamic_value(item, "frame.interface_name"),
                        "frame_time": get_dynamic_value(item, "frame.time"),
                        "frame_len": get_dynamic_value(item, "frame.len"),
                        "eth_src": get_dynamic_value(item, "eth.src"),
                        "eth_dst": get_dynamic_value(item, "eth.dst"),
                        "ip_src": get_dynamic_value(item, "ip.src"),
                        "ip_dst": get_dynamic_value(item, "ip.dst"),
                        "tcp_srcport": get_dynamic_value(item, "tcp.srcport"),
                        "tcp_dstport": get_dynamic_value(item, "tcp.dstport"),
                        "ProcessIndex": get_dynamic_value(item, "ProcessIndex"),
                        "ProcessId": get_dynamic_value(item, "ProcessId"),
                        "ParentProcessId": get_dynamic_value(item, "ParentProcessId"),
                        "AuthenticationId": get_dynamic_value(item, "AuthenticationId"),
                        "CreateTime": get_dynamic_value(item, "CreateTime"),
                        "Integrity": get_dynamic_value(item, "Integrity"),
                        "Owner": get_dynamic_value(item, "Owner"),
                        "ProcessName": get_dynamic_value(item, "ProcessName"),
                        "ImagePath": get_dynamic_value(item, "ImagePath"),
                        "CommandLine": get_dynamic_value(item, "CommandLine"),
                        "CompanyName": get_dynamic_value(item, "CompanyName"),
                        "Description": get_dynamic_value(item, "Description"),
                        "Version": get_dynamic_value(item, "Version"),
                        "ModuleList": get_dynamic_value(item, "ModuleList"),
                        "Id": get_dynamic_value(item, "Id"),
                        "Version": get_dynamic_value(item, "Version"),
                        "ProviderName": get_dynamic_value(item, "ProviderName"),
                        "LogName": get_dynamic_value(item, "LogName"),
                        "ProcessId": get_dynamic_value(item, "ProcessId"),
                        "ThreadId": get_dynamic_value(item, "ThreadId"),
                        "UserId": get_dynamic_value(item, "UserId"),
                        "TimeCreated": get_dynamic_value(item, "TimeCreated"),
                        "LevelDisplayName": get_dynamic_value(item, "LevelDisplayName"),
                        "TaskDisplayName": get_dynamic_value(item, "TaskDisplayName"),
                        "Message": get_dynamic_value(item, "Message"),
                    },
                    "fields": {
                        "event_id": int(get_dynamic_value(item, "event_id", 0)),
                        "message": get_dynamic_value(item, "message", ""),
                        "cpu_usage": float(get_dynamic_value(item, "cpu_usage", 0.0)),
                        "memory_usage": float(get_dynamic_value(item, "memory_usage", 0.0)),
                        "file_path": get_dynamic_value(item, "file_path", ""),
                        "registry_key": get_dynamic_value(item, "registry_key", ""),
                        "registry_value": get_dynamic_value(item, "registry_value", ""),
                        "command_line": get_dynamic_value(item, "command_line", ""),
                        "parent_process": get_dynamic_value(item, "parent_process", ""),
                        "hash": get_dynamic_value(item, "hash", ""),
                        "network_bytes_sent": int(get_dynamic_value(item, "network_bytes_sent", 0)),
                        "network_bytes_received": int(get_dynamic_value(item, "network_bytes_received", 0)),
                        "dns_query": get_dynamic_value(item, "dns_query", ""),
                        "dns_response": get_dynamic_value(item, "dns_response", ""),
                        "malicious_indicator": bool(get_dynamic_value(item, "malicious_indicator", False)),
                        "process_start_time": get_dynamic_value(item, "process_start_time", ""),
                        "process_end_time": get_dynamic_value(item, "process_end_time", ""),
                        "source_port": int(get_dynamic_value(item, "source_port", 0)),
                        "event_category": get_dynamic_value(item, "event_category", ""),
                        "packet_size": int(get_dynamic_value(item, "packet_size", 0)),
                        "flow_id": get_dynamic_value(item, "flow_id", ""),
                        "pid": int(get_dynamic_value(item, "pid", 0)),
                        "process_index": int(get_dynamic_value(item, "process_index", 0)),
                        "result": get_dynamic_value(item, "result", ""),
                        "detail": get_dynamic_value(item, "detail", ""),
                        "time_of_day": get_dynamic_value(item, "time_of_day", ""),
                        "image_path": get_dynamic_value(item, "image_path", ""),
                        "logon_id": get_dynamic_value(item, "logon_id", ""),
                        "event_record_id": int(get_dynamic_value(item, "event_record_id", 0)),
                        "process_guid": get_dynamic_value(item, "process_guid", ""),
                        "user_sid": get_dynamic_value(item, "user_sid", ""),
                        "target_object": get_dynamic_value(item, "target_object", ""),
                        "connection_state": get_dynamic_value(item, "connection_state", ""),
                        "authentication_id": get_dynamic_value(item, "authentication_id", ""),
                        "integrity_level": get_dynamic_value(item, "integrity_level", ""),
                    },
                    "time": timestamp,
                }
                points.append(point)
            except Exception as e:
                print(f"Error processing item: {item}, Error: {e}")

# Process points in batches after collecting them
batch_size = 400  # You can adjust the batch size as needed
if points:
    write_in_batches(points, batch_size, client)


#!/usr/bin/python3
from influxdb import InfluxDBClient
from datetime import datetime, timedelta
import os
import json

# Directory containing JSON files
json_directory = "/home/sandbox/Desktop/logs/json"

# InfluxDB connection details
influx_host = 'localhost'  # Change to your InfluxDB host
influx_port = 8086  # Default port
influx_database = 'TestGrafana'

# Initialize InfluxDB client
client = InfluxDBClient(host=influx_host, port=influx_port)
client.switch_database(influx_database)
client.create_database(influx_database)

def get_dynamic_value(item, key, fallback="unknown"):
    return item.get(key, fallback)

def write_in_batches(points, batch_size, client):
    """
    Writes points to InfluxDB in batches to avoid overwhelming the server with large data sets.

    :param points: List of points to write.
    :param batch_size: The size of each batch.
    :param client: The InfluxDB client instance.
    """
    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        try:
            client.write_points(batch)
            print(f"Successfully wrote batch of {len(batch)} points to InfluxDB.")
        except Exception as e:
            print(f"Error writing batch of {len(batch)} points to InfluxDB: {e}")

# Generate an ascending timestamp for each event
def generate_ascending_timestamps(data, base_time, increment_seconds=10):
    """
    Ensures each log entry has a unique and ascending timestamp.
    Fills missing timestamps based on the nearest existing ones or assigns sequential timestamps.

    :param data: List of log entries.
    :param base_time: The starting time for the logs.
    :param increment_seconds: Time increment in seconds for each log entry.
    :return: List of log entries with timestamps.
    """
    current_time = base_time
    for item in data:
        if not item.get("timestamp"):
            item["timestamp"] = current_time.isoformat() + "Z"
        else:
            try:
                # Parse existing timestamp to ensure correct format
                timestamp = datetime.strptime(item["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                current_time = timestamp
            except ValueError:
                # If parsing fails, assign a fallback timestamp
                item["timestamp"] = current_time.isoformat() + "Z"
        current_time += timedelta(seconds=increment_seconds)
    return data

# Main loop for processing JSON files
points = []
base_time = datetime.utcnow()  # Base time for ascending timestamps

for filename in os.listdir(json_directory):
    if filename.endswith('.json'):
        try:
            with open(os.path.join(json_directory, filename), 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {filename}: {e}")
            continue
        except Exception as e:
            print(f"Error processing file {filename}: {e}")
            continue

        if "processlist" in data:
            data = data["processlist"].get("process", [])
        elif isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            print(f"Skipping invalid data in {filename}: Expected a dictionary or list.")
            continue

        # Ensure all events have ascending timestamps
        data = generate_ascending_timestamps(data, base_time)

        for item in data:
            try:
                timestamp = item["timestamp"]
                point = {
                    "measurement": "malware_analysis",
                    "tags": {
                        "source_file": filename,
                        "host": get_dynamic_value(item, "host"),
                        "frame_section_number": get_dynamic_value(item, "frame.section_number"),
                        "frame_interface_id": get_dynamic_value(item, "frame.interface_id"),
                        "frame_interface_name": get_dynamic_value(item, "frame.interface_name"),
                        "frame_time": get_dynamic_value(item, "frame.time"),
                        "frame_len": get_dynamic_value(item, "frame.len"),
                        "eth_src": get_dynamic_value(item, "eth.src"),
                        "eth_dst": get_dynamic_value(item, "eth.dst"),
                        "ip_src": get_dynamic_value(item, "ip.src"),
                        "ip_dst": get_dynamic_value(item, "ip.dst"),
                        "tcp_srcport": get_dynamic_value(item, "tcp.srcport"),
                        "tcp_dstport": get_dynamic_value(item, "tcp.dstport"),
                        "ProcessIndex": get_dynamic_value(item, "ProcessIndex"),
                        "ProcessId": get_dynamic_value(item, "ProcessId"),
                        "ParentProcessId": get_dynamic_value(item, "ParentProcessId"),
                        "AuthenticationId": get_dynamic_value(item, "AuthenticationId"),
                        "CreateTime": get_dynamic_value(item, "CreateTime"),
                        "Integrity": get_dynamic_value(item, "Integrity"),
                        "Owner": get_dynamic_value(item, "Owner"),
                        "ProcessName": get_dynamic_value(item, "ProcessName"),
                        "ImagePath": get_dynamic_value(item, "ImagePath"),
                        "CommandLine": get_dynamic_value(item, "CommandLine"),
                        "CompanyName": get_dynamic_value(item, "CompanyName"),
                        "Description": get_dynamic_value(item, "Description"),
                        "Version": get_dynamic_value(item, "Version"),
                        "ModuleList": get_dynamic_value(item, "ModuleList"),
                        "Id": get_dynamic_value(item, "Id"),
                        "Version": get_dynamic_value(item, "Version"),
                        "ProviderName": get_dynamic_value(item, "ProviderName"),
                        "LogName": get_dynamic_value(item, "LogName"),
                        "ProcessId": get_dynamic_value(item, "ProcessId"),
                        "ThreadId": get_dynamic_value(item, "ThreadId"),
                        "UserId": get_dynamic_value(item, "UserId"),
                        "TimeCreated": get_dynamic_value(item, "TimeCreated"),
                        "LevelDisplayName": get_dynamic_value(item, "LevelDisplayName"),
                        "TaskDisplayName": get_dynamic_value(item, "TaskDisplayName"),
                        "Message": get_dynamic_value(item, "Message"),
                    },
                    "fields": {
                        "event_id": int(get_dynamic_value(item, "event_id", 0)),
                        "message": get_dynamic_value(item, "message", ""),
                        "cpu_usage": float(get_dynamic_value(item, "cpu_usage", 0.0)),
                        "memory_usage": float(get_dynamic_value(item, "memory_usage", 0.0)),
                        "file_path": get_dynamic_value(item, "file_path", ""),
                        "registry_key": get_dynamic_value(item, "registry_key", ""),
                        "registry_value": get_dynamic_value(item, "registry_value", ""),
                        "command_line": get_dynamic_value(item, "command_line", ""),
                        "parent_process": get_dynamic_value(item, "parent_process", ""),
                        "hash": get_dynamic_value(item, "hash", ""),
                        "network_bytes_sent": int(get_dynamic_value(item, "network_bytes_sent", 0)),
                        "network_bytes_received": int(get_dynamic_value(item, "network_bytes_received", 0)),
                        "dns_query": get_dynamic_value(item, "dns_query", ""),
                        "dns_response": get_dynamic_value(item, "dns_response", ""),
                        "malicious_indicator": bool(get_dynamic_value(item, "malicious_indicator", False)),
                        "process_start_time": get_dynamic_value(item, "process_start_time", ""),
                        "process_end_time": get_dynamic_value(item, "process_end_time", ""),
                        "source_port": int(get_dynamic_value(item, "source_port", 0)),
                        "event_category": get_dynamic_value(item, "event_category", ""),
                        "packet_size": int(get_dynamic_value(item, "packet_size", 0)),
                        "flow_id": get_dynamic_value(item, "flow_id", ""),
                        "pid": int(get_dynamic_value(item, "pid", 0)),
                        "process_index": int(get_dynamic_value(item, "process_index", 0)),
                        "result": get_dynamic_value(item, "result", ""),
                        "detail": get_dynamic_value(item, "detail", ""),
                        "time_of_day": get_dynamic_value(item, "time_of_day", ""),
                        "image_path": get_dynamic_value(item, "image_path", ""),
                        "logon_id": get_dynamic_value(item, "logon_id", ""),
                        "event_record_id": int(get_dynamic_value(item, "event_record_id", 0)),
                        "process_guid": get_dynamic_value(item, "process_guid", ""),
                        "user_sid": get_dynamic_value(item, "user_sid", ""),
                        "target_object": get_dynamic_value(item, "target_object", ""),
                        "connection_state": get_dynamic_value(item, "connection_state", ""),
                        "authentication_id": get_dynamic_value(item, "authentication_id", ""),
                        "integrity_level": get_dynamic_value(item, "integrity_level", ""),
                    },
                    "time": timestamp,
                }
                points.append(point)
            except Exception as e:
                print(f"Error processing item: {item}, Error: {e}")

# Process points in batches after collecting them
batch_size = 400  # You can adjust the batch size as needed
if points:
    write_in_batches(points, batch_size, client)

