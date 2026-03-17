// bitwrap.js — ZK + Solidity UI glue for the editor

const petriView = document.querySelector('petri-view');

// Save button
const btnSave = document.getElementById('btn-save');
if (btnSave) {
    btnSave.addEventListener('click', async () => {
        const model = getModel();
        if (!model) return;

        try {
            const resp = await fetch('/api/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(model)
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Save failed: ' + text);
                return;
            }

            const data = await resp.json();
            if (data.cid) {
                // Update URL with CID
                const url = new URL(window.location);
                url.searchParams.set('cid', data.cid);
                window.history.pushState({}, '', url);
                btnSave.textContent = 'Saved';
                setTimeout(() => { btnSave.textContent = 'Save'; }, 2000);
            }
        } catch (err) {
            alert('Save failed: ' + err.message);
        }
    });
}

// Solidity generation button
const btnSolgen = document.getElementById('btn-solgen');
if (btnSolgen) {
    btnSolgen.addEventListener('click', async () => {
        const model = getModel();
        if (!model) return;

        try {
            const resp = await fetch('/api/solgen', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(model)
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Solidity generation not available: ' + text);
                return;
            }

            const data = await resp.json();
            if (data.solidity) {
                downloadFile(data.name + '.sol', data.solidity);
            }
        } catch (err) {
            alert('Solidity generation failed: ' + err.message);
        }
    });
}

// ZK Proof button
const btnProve = document.getElementById('btn-prove');
if (btnProve) {
    btnProve.addEventListener('click', async () => {
        const model = getModel();
        if (!model) return;

        try {
            const resp = await fetch('/api/prove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(model)
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Proof generation not available: ' + text);
                return;
            }

            const data = await resp.json();
            alert('Proof generated: ' + JSON.stringify(data, null, 2));
        } catch (err) {
            alert('Proof generation failed: ' + err.message);
        }
    });
}

// Templates button
const btnTemplates = document.getElementById('btn-templates');
if (btnTemplates) {
    btnTemplates.addEventListener('click', async () => {
        try {
            const resp = await fetch('/api/templates');
            if (!resp.ok) return;

            const data = await resp.json();
            const templates = data.templates || [];

            const choice = prompt(
                'Available templates:\n' +
                templates.map((t, i) => `${i + 1}. ${t.name}`).join('\n') +
                '\n\nEnter number to load:'
            );

            if (!choice) return;
            const idx = parseInt(choice) - 1;
            if (idx < 0 || idx >= templates.length) return;

            const template = templates[idx];
            const tmplResp = await fetch('/api/templates/' + template.id);
            if (tmplResp.ok) {
                const tmplData = await tmplResp.json();
                // If petri-view supports loading data, trigger it
                if (petriView && petriView.loadModel) {
                    petriView.loadModel(tmplData);
                } else {
                    alert('Template loaded: ' + template.name + '\n(Reload editor to apply)');
                }
            }
        } catch (err) {
            console.error('Failed to load templates:', err);
        }
    });
}

// Helpers

function getModel() {
    if (petriView && petriView.getModel) {
        return petriView.getModel();
    }
    // Fallback: try to read the embedded JSON-LD
    const script = document.querySelector('petri-view script[type="application/ld+json"]');
    if (script) {
        try {
            return JSON.parse(script.textContent);
        } catch (e) {
            console.error('Failed to parse model:', e);
        }
    }
    return null;
}

function downloadFile(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// Load model from URL params on page load
(function() {
    const params = new URLSearchParams(window.location.search);
    const cid = params.get('cid');
    if (cid) {
        fetch('/o/' + cid)
            .then(r => r.ok ? r.json() : null)
            .then(data => {
                if (data && petriView && petriView.loadModel) {
                    petriView.loadModel(data);
                }
            })
            .catch(err => console.error('Failed to load model:', err));
    }
})();
