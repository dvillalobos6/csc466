
### **README: Malware Analysis Sandbox Setup**

---

#### **Overview**
This repository contains instructions for installing a malware analysis sandbox using Linux and Windows virtual machines. The environment includes tools for static and dynamic malware analysis, log aggregation, and visualization with Grafana. Follow these steps to replicate the sandbox and begin analyzing malware samples safely in an isolated lab environment.

---

### **System Requirements**
- Ubuntu (Virtual Host Machine)
- Windows (Nested Virtual Machine)
- Nested virtualization enabled
- Minimum recommended specs:
  - 16GB RAM
  - 200GB disk space
  - Processor with VT-x or AMD-V support

---

### **Installation Instructions**

#### **1. System Updates**
Update the system packages before beginning:
```bash
sudo apt update
sudo apt upgrade
sudo snap refresh
```

---

#### **2. Installing Ghidra**
1. Download Ghidra from the [GitHub repository](https://github.com/NationalSecurityAgency/ghidra).
2. Unzip the downloaded file:
   ```bash
   unzip {file_name}.zip
   ```
3. Install dependencies:
   ```bash
   sudo apt install openjdk-21-jdk
   ```
4. Run Ghidra:
   ```bash
   cd ghidra_11.2_PUBLIC/
   ./ghidraRun
   ```

---

#### **3. Installing Radare2**
1. Clone the Radare2 repository:
   ```bash
   git clone https://github.com/radareorg/radare2.git
   ```
2. If `git` is not installed, install it:
   ```bash
   sudo apt install git
   ```
3. Navigate to the Radare2 directory and install it:
   ```bash
   cd radare2/sys
   sudo apt update
   sudo apt install build-essential
   ./install.sh
   ```

---

#### **4. Installing KVM**
Install and verify KVM for virtualization:
```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
lsmod | grep -i kvm
```

You should see either `kvm_amd` or `kvm_intel` in the output.

---

#### **5. Installing Grafana**
Install Grafana for visualization:
```bash
sudo snap install grafana
```
#### **5a. Installing InfluxDB**
Install InfluxDB to store the data:
```bash
sudo apt install influxdb
```
#### **5b. Installing volatility**
Install volatility to analyze data:
```
Follow their instructions (https://github.com/volatilityfoundation/volatility3)
```
---

#### **6. Setting Up Directories**
Organize your workspace with the following directories:
```bash
mkdir ISO-Images  # Store ISO files
mkdir malware     # Store malware samples
```

---

#### **7. Virtual Machine Configuration**
1. Install `virt-manager`:
   ```bash
   sudo apt install virt-manager
   ```
2. Use Virt-Manager to create a new virtual machine:
   - Select **"Local install media"**.
   - Browse to the `ISO-Images` directory and select the desired ISO.
   - Allocate processors and memory as needed.

**Optional:** Adjust Hyper-V machine resolution:
```powershell
Set-VMVideo -VMName {machine_name} -HorizontalResolution 2560 -VerticalResolution 1440 -ResolutionType single
```

---

#### **8. Tools for Windows Sandbox**
Install the following tools in the Windows virtual machine:
- [Process Monitor (Procmon)](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
- [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng)
- [Wireshark](https://www.wireshark.org/)
- [DumpIt.exe](https://www.moonsols.com/) or
- [FTK Imager](https://www.exterro.com/ftk-product-downloads/ftk-imager-4-7-3-81)
- [Sysmon for Windows](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

To install Sysmon with a configuration file:
```powershell
sysmon.exe -i C:\path\to\config\file --accepteula
```

---

#### **9. Tools for Ubuntu Sandbox(Later Add-in)**
Install the following tools:
```bash
sudo apt install inetsim wireshark tcpdump binwalk strace ltrace lsof
```
- Internal logs are stored in `/var/log`.
- Install Sysmon for Linux from its [GitHub repository](https://github.com/Sysinternals/SysmonForLinux).

---

### **Scripts**

#### **Automation Script**
The automation script (`automation.sh`) on the Ubuntu host performs the following:
1. Searches the `malware` directory for unanalyzed files.
2. Starts a Windows VM from a pre-configured snapshot.
3. Waits for required files (logs, dumps, etc.) from the Windows VM.
4. Processes and converts logs into JSON format:
   - Process Monitor logs (XML → JSON)
   - Wireshark PCAP files (PCAPNG → JSON)
5. Analyzes memory dumps using Volatility.
6. Sends processed files to the JSON directory.
7. Ingests JSON data into InfluxDB for visualization in Grafana.

#### **Supporting Scripts**
1. **`Conversion.py`**: Converts Process Monitor logs to JSON format.
2. **`Influx.py`**: Ingests JSON data into InfluxDB.
3. **`PowerShellScript.ps1`**: Runs on the Windows VM to handle file transfers and automation.

---

### **How to Use**

1. Extract samples into a separate malware directory, or you can change the variables to fit your environment. For samples, you can use [TheZoo repository](https://github.com/ytisf/theZoo).
2. Run the automation script:
   ```bash
   ./automation.sh
   ```
3. The script performs all analysis and processes the data into JSON format.
4. Configure Grafana to connect to InfluxDB:
   - Add InfluxDB as a data source in Grafana.
   - Import dashboards to visualize the analysis results.

---

### **Notes**
- Always work in an **isolated environment** to prevent accidental infections.
- Use snapshots for VMs to ensure you can revert to a clean state.
- Avoid using sensitive data or production systems in this sandbox.
- Do not use `sshpass` in production; it is included only for testing in lab environments.
- Future Addition will be automation on installation
- If you install additional tools or do not use the tools here, please ensure to adjust Influx.py to accomodate the keys found in your logs.

---

### **Considerations for Malware Containment**
- Each virtual machine acts as a barrier, and the malware would need to escape from the nested VM into the host VM, then from the host VM to the physical machine. This is complex and unlikely without exploiting advanced vulnerabilities.
- Keeping both hypervisor and virtualization tools helps to mitigate these risks. 
- Optimize the Hyper-V switch settings to your needs
- Ensure you have snapshots anr Rollback, in case VM is compromnised you can revert to a clean state. 
- Ensure there are no shared drives or folders accessible to the VM
