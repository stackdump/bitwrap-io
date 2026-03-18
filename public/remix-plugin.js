// Bitwrap Remix IDE Plugin
// Generates Solidity contracts from Petri net ERC templates

// ============ Remix Client (postMessage protocol) ============

class RemixClient {
    constructor() {
        this.loaded = false;
        this.pendingRequests = {};
        this.requestId = 0;
        this._onLoadCallbacks = [];
        window.addEventListener('message', (e) => this.handleMessage(e));
    }

    handleMessage(event) {
        const msg = event.data;
        if (!msg || typeof msg !== 'object') return;

        // Remix handshake response
        if (msg.action === 'response' && msg.key === 'handshake') {
            this.loaded = true;
            this._onLoadCallbacks.forEach(cb => cb());
            this._onLoadCallbacks = [];
            return;
        }

        // Remix request (e.g., activate/deactivate)
        if (msg.action === 'request' && msg.key === 'activate') {
            parent.postMessage({
                action: 'response',
                name: msg.name,
                key: msg.key,
                id: msg.id,
                payload: true
            }, '*');
            return;
        }

        // Response to our calls
        if (msg.action === 'response' && this.pendingRequests[msg.id]) {
            this.pendingRequests[msg.id].resolve(msg.payload);
            delete this.pendingRequests[msg.id];
            return;
        }

        if (msg.action === 'response' && msg.error && this.pendingRequests[msg.id]) {
            this.pendingRequests[msg.id].reject(new Error(msg.error));
            delete this.pendingRequests[msg.id];
            return;
        }
    }

    init() {
        // Send handshake to Remix
        parent.postMessage({
            action: 'request',
            name: 'manager',
            key: 'handshake',
            id: this.requestId++,
            payload: ['bitwrap', ['fileManager', 'notification', 'editor']]
        }, '*');
    }

    onload(callback) {
        if (this.loaded) {
            callback();
        } else {
            this._onLoadCallbacks.push(callback);
        }
    }

    call(plugin, method, ...args) {
        return new Promise((resolve, reject) => {
            const id = ++this.requestId;
            this.pendingRequests[id] = { resolve, reject };
            parent.postMessage({
                action: 'request',
                name: plugin,
                key: method,
                id: id,
                payload: args
            }, '*');

            // Timeout after 10s
            setTimeout(() => {
                if (this.pendingRequests[id]) {
                    delete this.pendingRequests[id];
                    reject(new Error('Request timed out'));
                }
            }, 10000);
        });
    }

    async writeFile(path, content) {
        return this.call('fileManager', 'writeFile', path, content);
    }

    async toast(message) {
        return this.call('notification', 'toast', message);
    }
}

// ============ Template Definitions ============

const TEMPLATES = [
    {
        id: 'erc20',
        standard: 'ERC-20',
        name: 'Fungible Token',
        description: 'Standard fungible token with transfer, approve, mint, and burn operations.',
        filename: 'BitwrapERC20.sol',
    },
    {
        id: 'erc721',
        standard: 'ERC-721',
        name: 'Non-Fungible Token',
        description: 'Non-fungible token with ownership tracking, approvals, and operator support.',
        filename: 'BitwrapERC721.sol',
    },
    {
        id: 'erc1155',
        standard: 'ERC-1155',
        name: 'Multi Token',
        description: 'Multi-token standard supporting both fungible and non-fungible tokens in one contract.',
        filename: 'BitwrapERC1155.sol',
    },
    {
        id: 'erc4626',
        standard: 'ERC-4626',
        name: 'Tokenized Vault',
        description: 'Tokenized vault with deposit, withdraw, redeem, and yield harvesting.',
        filename: 'BitwrapERC4626.sol',
    },
    {
        id: 'erc5725',
        standard: 'ERC-5725',
        name: 'Transferable Vesting NFT',
        description: 'Transferable vesting NFT with create, claim, transfer, revoke, and burn.',
        filename: 'BitwrapERC5725.sol',
    },
];

// ============ Plugin State ============

let remixClient = null;
let isInRemix = false;
let selectedTemplate = null;
let generatedCode = null;
let generatedFilename = null;
let generatedVerifier = null;

// ============ API ============

function getApiBase() {
    // If running inside Remix as iframe, the API base is the origin of this page
    return window.location.origin;
}

async function generateSolidity(templateId) {
    const resp = await fetch(`${getApiBase()}/api/solgen`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ template: templateId }),
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Generation failed: ${text}`);
    }

    return resp.json();
}

async function fetchVerifier(circuit = 'transfer') {
    const resp = await fetch(`${getApiBase()}/api/vk/${circuit}/solidity`);
    if (!resp.ok) return null; // Verifier not available (no key-dir)
    return resp.text();
}

async function fetchBundle(templateId) {
    const resp = await fetch(`${getApiBase()}/api/bundle/${templateId}`);
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Bundle generation failed: ${text}`);
    }
    return resp.blob();
}

// ============ UI Logic ============

function initPlugin() {
    // Detect if we're inside an iframe (Remix)
    isInRemix = window.self !== window.top;

    if (isInRemix) {
        remixClient = new RemixClient();
        remixClient.init();
        remixClient.onload(() => {
            updateStatus('Connected to Remix IDE', 'connected');
        });

        // Timeout: if no handshake in 3s, still usable standalone
        setTimeout(() => {
            if (!remixClient.loaded) {
                updateStatus('Standalone mode (no Remix connection)', 'standalone');
                isInRemix = false;
            }
        }, 3000);
    } else {
        updateStatus('Standalone mode', 'standalone');
    }

    renderTemplateCards();
}

function renderTemplateCards() {
    const grid = document.getElementById('template-grid');
    grid.innerHTML = '';

    TEMPLATES.forEach(tmpl => {
        const card = document.createElement('div');
        card.className = 'tmpl-card' + (selectedTemplate === tmpl.id ? ' selected' : '');
        card.onclick = () => selectTemplate(tmpl.id);
        card.innerHTML = `
            <span class="tmpl-badge">${tmpl.standard}</span>
            <h3>${tmpl.name}</h3>
            <p>${tmpl.description}</p>
        `;
        grid.appendChild(card);
    });
}

function selectTemplate(id) {
    selectedTemplate = id;
    generatedCode = null;
    generatedFilename = null;
    renderTemplateCards();
    document.getElementById('code-output').textContent = '// Select a template and click Generate';
    document.getElementById('actions-bar').classList.remove('visible');
    document.getElementById('generate-btn').disabled = false;
}

async function handleGenerate() {
    if (!selectedTemplate) return;

    const btn = document.getElementById('generate-btn');
    const codeEl = document.getElementById('code-output');

    btn.disabled = true;
    btn.textContent = 'Generating...';
    codeEl.textContent = '// Generating Solidity contract...';

    try {
        const result = await generateSolidity(selectedTemplate);
        // Also fetch verifier if available
        const verifierCode = await fetchVerifier();
        generatedVerifier = verifierCode;
        generatedCode = result.solidity;
        generatedFilename = result.filename || TEMPLATES.find(t => t.id === selectedTemplate).filename;

        codeEl.textContent = generatedCode;
        document.getElementById('actions-bar').classList.add('visible');
        document.getElementById('filename-display').textContent = generatedFilename;
    } catch (err) {
        codeEl.textContent = `// Error: ${err.message}`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Generate';
    }
}

async function handleDeployToRemix() {
    if (!generatedCode || !remixClient || !remixClient.loaded) return;

    const deployBtn = document.getElementById('deploy-remix-btn');
    deployBtn.disabled = true;
    deployBtn.textContent = 'Writing...';

    try {
        const path = `contracts/${generatedFilename}`;
        await remixClient.writeFile(path, generatedCode);
        if (generatedVerifier) {
            await remixClient.writeFile('contracts/Verifier.sol', generatedVerifier);
        }
        await remixClient.toast(`Wrote ${path}${generatedVerifier ? ' + Verifier.sol' : ''} to workspace`);
        deployBtn.textContent = 'Written!';
        setTimeout(() => {
            deployBtn.textContent = 'Deploy to Remix';
            deployBtn.disabled = false;
        }, 2000);
    } catch (err) {
        deployBtn.textContent = 'Deploy to Remix';
        deployBtn.disabled = false;
        alert(`Failed to write to Remix: ${err.message}`);
    }
}

function handleDownload() {
    if (!generatedCode) return;

    const blob = new Blob([generatedCode], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = generatedFilename || 'contract.sol';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function handleDownloadBundle() {
    if (!selectedTemplate) return;
    const btn = document.getElementById('bundle-btn');
    btn.disabled = true;
    btn.textContent = 'Building...';
    try {
        const blob = await fetchBundle(selectedTemplate);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `bitwrap-${selectedTemplate}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        btn.textContent = 'Downloaded!';
        setTimeout(() => { btn.textContent = 'Foundry Bundle'; btn.disabled = false; }, 2000);
    } catch (err) {
        alert(`Bundle failed: ${err.message}`);
        btn.textContent = 'Foundry Bundle';
        btn.disabled = false;
    }
}

function handleCopy() {
    if (!generatedCode) return;
    navigator.clipboard.writeText(generatedCode).then(() => {
        const btn = document.getElementById('copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
}

function updateStatus(message, state) {
    const el = document.getElementById('status-indicator');
    el.textContent = message;
    el.className = 'status ' + state;

    // Show/hide the deploy button based on Remix connection
    const deployBtn = document.getElementById('deploy-remix-btn');
    if (state === 'connected') {
        deployBtn.style.display = '';
    } else {
        deployBtn.style.display = 'none';
    }
}

// ============ Init ============

document.addEventListener('DOMContentLoaded', initPlugin);
