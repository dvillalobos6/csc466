# Define variables
$procmonPath = "C:\Users\user\Downloads\Procmon64.exe"
$TsharkPath = "C:\Program Files\Wireshark\tshark.exe"
$LogDirectory = "C:\Users\user\Desktop\logs"
$MalwarePath = "C:\Users\user\Downloads\malware" # Directory to check for malware files
$ExpectedIPFilePath = "C:\Users\user\Downloads\ip_address.txt" # Path to the expected IP file
$Timeout = 180 # Maximum wait time in seconds (adjust as necessary)
$Interval = 5 # Check every 5 seconds
$scpTargetDir = "/home/sandbox/Desktop" # Target directory for SCP on the remote machine
$Password = '<>' # For lab experimentation (controlled environment)
$PmlFilePath = "$LogDirectory\ProcmonLog.pml"
$DumpItPath = "C:\Users\user\Downloads\DumpIt.exe"
$DumpItOutput = "$LogDirectory\DumpItDirectory"
Write-Host "Waiting for the required files to be placed..."
$StartTime = [DateTime]::Now
while ($true) {
    $fileExists = Get-ChildItem -Path $MalwarePath -File | Select-Object -First 1
    $ipFileExists = Test-Path $ExpectedIPFilePath

    if ($fileExists -and $ipFileExists) {
        Write-Host "Required files have been placed. Proceeding with the rest of the instructions."
        break
     } elseif (([DateTime]::Now - $StartTime).TotalSeconds -ge $Timeout) {
        Write-Host "Timeout reached. Required files were not found."
        exit 1
    } else {
        Write-Host "Files not yet found. Checking again..."
        Start-Sleep -Seconds $Interval
    }
}
# Create log directory if not made
if (-not (Test-Path $LogDirectory)) {
    try {
        New-Item -Type Directory -Path $LogDirectory -ErrorAction Stop
        Write-Host "Log directory created at $LogDirectory."
    } catch {
        Write-Host "Failed to create log directory. Exiting."
        exit 1
    }
}
Write-Host "Clearing Logs"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
wevtutil cl "System"
wevtutil cl "Security"
wevtutil cl "Application"
# Start Procmon with logging
Write-Host "Starting Procmon..."
Start-Process $ProcmonPath -ArgumentList "/Minimized /Backingfile $LogDirectory\ProcmonLog.pml"
# Start Tshark network capture
Write-Host "Starting network capture with Tshark..."
$NetworkCapture = "$LogDirectory\NetworkCapture.pcap"
Start-Process $TsharkPath -ArgumentList "-i 4 -a duration:90 -w $NetworkCapture" -NoNewWindow -Wait
# Find the malware sample dynamically
$MalwareSample = Get-ChildItem -Path $MalwarePath -File | Select-Object -First 1
$FileCount = (Get-ChildItem -Path $MalwarePath -File).Count
if ($FileCount -eq 0) {
    Write-Host "No malware sample found in $MalwarePath. Exiting."
    exit 1
} elseif ($FileCount -gt 1) {
    Write-Host "Warning: More than one file found in $MalwarePath. Using the first file: $($MalwareSample.Name)"
}
# Execute the malware sample
try {
    Start-Process -FilePath $MalwareSample.FullName -ErrorAction Stop
    Write-Host "Malware execution started."
} catch {
    Write-Host "Failed to start the malware sample. Exiting."
    exit 1
}
Start-Sleep 30
# Monitor the execution for the specified runtime
Write-Host "Allowing Execution Time"
$MalwareStartTime = Get-Date
$MalwareRuntimeSeconds = 150 # 1.5 minutes
while (((Get-Date) - $MalwareStartTime).TotalSeconds -lt $MalwareRuntimeSeconds) {
    Start-Sleep 5
}
Write-Host "Running DumpIt.exe"
Start-Process -FilePath $DumpItPath -ArgumentList "/OUTPUT=$DumpItOutput" -NoNewWindow -Wait
Write-Host "Stopping Processes"
Write-Host "Converting Procmon file to json"
Start-Process -FilePath $ProcmonPath -ArgumentList "/Terminate" -Wait
Start-Sleep -Seconds 5
if (Test-Path -Path $PmlFilePath) {
    Write-Output "PML File exists and is ready for conversion."
} else {
    Write-Output "PML file is missing or corrupt."
}
# Convert PML to XML
$XmlFilePath = "$LogDirectory\ProcmonLog.xml"
Start-Process -FilePath $ProcmonPath -ArgumentList "/OpenLog", $PmlFilePath, "/SaveAs", $XmlFilePath -Wait
Write-Host "Grabbing Sysmon Logs"
# Process the Microsoft-Windows-Sysmon/Operational log
$LogName = "Microsoft-Windows-Sysmon/Operational"
$Events = Get-WinEvent -LogName $LogName
$Json = $Events | ConvertTo-Json -Depth 3
$FilePath = "$LogDirectory\$($LogName -replace '/','_').json"
Write-Output "Saving to: $FilePath"
$Json | Set-Content -Path $FilePath
if (Test-Path -Path $FilePath) {
    Write-Output "File saved successfully: $FilePath"
} else {
    Write-Output "Failed to save file: $FilePath"
}
Write-Host "Grabbing Security Logs"
# Process the Security log
$LogName = "Security"
$Events = Get-WinEvent -LogName $LogName
$Json = $Events | ConvertTo-Json -Depth 3
$FilePath = "$LogDirectory\$LogName.json"
Write-Output "Saving to: $FilePath"
$Json | Set-Content -Path $FilePath
if (Test-Path -Path $FilePath) {
    Write-Output "File saved successfully: $FilePath"
} else {
    Write-Output "Failed to save file: $FilePath"
}
Write-Host "Grabbing Applications Logs"
# Process the Applications log
$LogName = "Application"
$Events = Get-WinEvent -LogName $LogName
$Json = $Events | ConvertTo-Json -Depth 3
$FilePath = "$LogDirectory\$LogName.json"
Write-Output "Saving to: $FilePath"
$Json | Set-Content -Path $FilePath
if (Test-Path -Path $FilePath) {
    Write-Output "File saved successfully: $FilePath"
} else {
    Write-Output "Failed to save file: $FilePath"
}
Write-Host "Grabbing System Logs"
# Process the System log
$LogName = "System"
$Events = Get-WinEvent -LogName $LogName
$Json = $Events | ConvertTo-Json -Depth 3
$FilePath = "$LogDirectory\$LogName.json"
Write-Output "Saving to: $FilePath"
$Json | Set-Content -Path $FilePath
if (Test-Path -Path $FilePath) {
    Write-Output "File saved successfully: $FilePath"
} else {
    Write-Output "Failed to save file: $FilePath"
}
Write-Host "Searching for Ubuntu IP Address"
# Read the IP address from the file
$VmIpAddress = Get-Content $ExpectedIPFilePath | Select-Object -First 1
Write-Host "Retrieved IP address: $VmIpAddress"
Write-Host "Beginning File Transfer"
# SCP commands for transferring logs
$scpCommand = "scp -r $LogDirectory sandbox@'$VmIpAddress':$scpTargetDir"
$scpCommand2 = "scp $DumpItOutput/*.raw sandbox@$'VmIpAddress':$scpTargetDir"
InvokeCommand $scpCommand
InvokeCommand $scpCommand2
