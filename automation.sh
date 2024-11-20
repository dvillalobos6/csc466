#!/bin/bash

# Variables
PASSWORD="<>"
MALWARE_DIR="/home/sandbox/malware/Unanalyzed"
IP_FILE="/home/sandbox/ip_address.txt"
WINDOWS_VM_NAME="WindowsSandbox"
LINUX_VM_NAME="ubuntu24.04"
WINDOWS_USERNAME="user"
LINUX_USERNAME="malware"
WINDOWS_MALWARE_DEST="C:\\Users\\user\\Downloads\\malware"
WINDOWS_IP_DEST="C:\\Users\\user\\Downloads"
LINUX_MALWARE_DEST="/home/malware/malware"
LINUX_IP_DEST="/home/malware/ip_address.txt"
LOG_DIR="/home/sandbox/Desktop/logs"
PROCMON_LOG_FILE="home/sandbox/Desktop/logs/ProcmonLog.xml"
TSHARK_PCAP_FILE="home/sandbox/Desktop/logs/NetworkCapture.pcap"
CONVERSION_SCRIPT="home/sandbox/Desktop/conversion.py"
INFLUXDB_SCRIPT="/home/sandbox/Desktop/influx.py"
# Create IP address text file for the host
echo "Grabbing host IP address"
ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1 > "$IP_FILE"

# Check for specific file types and start the appropriate VM
echo "Checking for files in $MALWARE_DIR"
FILE_FOUND=false
for FILE in "$MALWARE_DIR"/*; do
    if [[ -f "$FILE" ]]; then
        FILE_TYPE=$(file --mime-type -b "$FILE")
        case "$FILE_TYPE" in
            application/x-dosexec | text/x-msdos-batch | application/vnd.microsoft.portable-executable)
                echo "Found Windows portable / executable or batch file: $FILE"
                echo "Starting Windows VM"
		virsh snapshot-revert "$WINDOWS_VM_NAME" --snapshotname Keep
		virsh start "$WINDOWS_VM_NAME"
                FILE_FOUND=true
		VM_NAME="$WINDOWS_VM_NAME"
		MALWARE_DEST="$WINDOWS_MALWARE_DEST"
		IP_DEST="$WINDOWS_IP_DEST"
		VM_USERNAME="$WINDOWS_USERNAME"
                break
                ;;
            application/x-executable)
                echo "Found Linux ELF file: $FILE"
                echo "Starting Linux VM"
		virsh start "$LINUX_VM_NAME"
                FILE_FOUND=true
		VM_NAME="$LINUX_VM_NAME"
		MALWARE_DEST="$LINUX_MALWARE_DEST"
		IP_DEST="$LINUX_IP_DEST"
		VM_USERNAME="$LINUX_USERNAME"
                break
                ;;
            *)
                echo "Unrecognized or unsupported file type: $FILE"
                ;;
        esac
    fi
done

if ! $FILE_FOUND; then
    echo "No files found for analysis. Exiting."
    exit 1
fi

# Wait for VM to initialize and retrieve the IP address
echo "Waiting for VM to initialize and retrieve IP address..."
MAX_WAIT_TIME=120  # Maximum wait time in seconds
WAIT_INTERVAL=5    # Interval between checks
TOTAL_WAIT=0

VM_IP=""
while [ -z "$VM_IP" ]; do
    VM_IP=$(virsh domifaddr "$VM_NAME" | awk '/ipv4/ {print $4}' | cut -d'/' -f1)
    if [ -z "$VM_IP" ]; then
        sleep $WAIT_INTERVAL
        TOTAL_WAIT=$((TOTAL_WAIT + WAIT_INTERVAL))
        if [ "$TOTAL_WAIT" -ge "$MAX_WAIT_TIME" ]; then
            echo "Timeout waiting for VM IP address. Exiting."
            exit 1
        fi
        echo "Waiting for VM IP address to be assigned..."
    fi
done

echo 'The VM IP address is: $VM_IP'
echo "Sleeping for 45 seconds"
sleep 45
# Perform SCP transfer to the VM
echo "Transferring malware sample to $MALWARE_DEST"
sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no -r "$MALWARE_DIR"/* "$VM_USERNAME@$VM_IP:$MALWARE_DEST"

echo "Transferring IP address file to $IP_DEST"
sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no "$IP_FILE" "$VM_USERNAME@$VM_IP:$IP_DEST"

echo "Transfer complete."

while [ ! -d "/home/sandbox/Desktop/logs" ]; do
    echo "Waiting ..."
    sleep 5  # Check every 5 seconds
done
virsh shutdown "$WINDOWS_VM_NAME"
#!/bin/bash
echo "Creating JSON directory..."
mkdir /home/sandbox/Desktop/logs/json
# Convert ProcmonLog.xml to JSON using the conversion.py script
echo "Converting ProcmonLog.xml to JSON"
sudo /home/sandbox/Desktop/conversion.py
# Convert Tshark PCAP file to JSON
echo "Converting NetworkCapture.pcap to json"
tshark -r /home/sandbox/Desktop/logs/NetworkCapture.pcapng -T json > /home/sandbox/Desktop/logs/NetworkCapture.json
echo "Running all volatility analysis"
# Process Listings and Analysis
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 pslist --output=json > /home/sandbox/Desktop/logs/pslist.json
echo "Done with pslist"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 pstree --output=json > /home/sandbox/Desktop/logs/pstree.json
echo "Done with pstree"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 psscan --output=json > /home/sandbox/Desktop/logs/psscan.json
echo "Done with psscan"
# Network Connections (if applicable, for Windows 7 and later)
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 netscan --output=json > /home/sandbox/Desktop/logs/netscan.json
echo "Done with netscan"
# DLL Listings and Code Injection Detection
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 dlllist --output=json > /home/sandbox/Desktop/logs/dlllist.json
echo "Done with DllList"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 malfind --output=json > /home/sandbox/Desktop/logs/malfind.json
echo "Done with malfind"
# File and Handle Analysis
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 handles --output=json > /home/sandbox/Desktop/logs/handles.json
echo "Done with handles"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 filescan --output=json > /home/sandbox/Desktop/logs/filescan.json
echo "Done with filescan"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 modscan --output=json > /home/sandbox/Desktop/logs/modscan.json
echo "Done with modscan"
# Memory Regions and Mappings
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 vadinfo --output=json > /home/sandbox/Desktop/logs/vadinfo.json
echo "Done with vadinfo"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 ldrmodules --output=json > /home/sandbox/Desktop/logs/ldrmodules.json
echo "Done with ldrmodules"
# Code Injection Detection
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 apihooks --output=json > /home/sandbox/Desktop/logs/apihooks.json
echo "Done with apihooks"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 ssdt --output=json > /home/sandbox/Desktop/logs/ssdt.json
echo "Done with ssdt"
# Registry Analysis
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" --output=json > /home/sandbox/Desktop/logs/printkey.json
echo "Done with printkey"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 hivelist --output=json > /home/sandbox/Desktop/logs/hivelist.json
echo "Done with hivelist"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 hivedump --output=json > /home/sandbox/Desktop/logs/hivedump.json
echo "Done with hivedump"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 shimcache --output=json > /home/sandbox/Desktop/logs/shimcache.json
echo "Done with shimcache"
# Service and Driver Analysis
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 svcscan --output=json > /home/sandbox/Desktop/logs/svcscan.json
echo "Done with svcscan"
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 driverscan --output=json > /home/sandbox/Desktop/logs/driverscan.json
echo "Done with driverscan"
# YARA Scan
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 yarascan --output=json > /home/sandbox/Desktop/logs/yarascan.json
echo "Done with Yara Scan"
# Master File Table Analysis
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 mftparser --output=json > /home/sandbox/Desktop/logs/mftparser.json
echo "Done with mftparser"
# String Scan
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 strings --output=json > /home/sandbox/Desktop/logs/strings.json
echo "Done with strings"
# Process Memory Dump
volatility -f /home/sandbox/Desktop/logs/DumpItDirectory/DESKTOP-CS1ANPM-20241119-235635.raw --profile=Win10x64 procdump -D /home/sandbox/Desktop/logs/procdumps
echo "Done with procdump"

mkdir /home/sandbox/Desktop/logs/json
# Move all .json files into the JSON directory
echo "Moving all .json files into the JSON directory..."
mv /home/sandbox/Desktop/logs/*.json /home/sandbox/Desktop/logs/json/

# Call the InfluxDB script to send data to Grafana
echo "Sending data to InfluxDB..."
sudo /home/sandbox/Desktop/influx.py
echo 'Data sent to InfluxDB and Grafana integration complete.'
	

