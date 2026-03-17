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

// Solidity generation button — shows template picker then generates
const btnSolgen = document.getElementById('btn-solgen');
if (btnSolgen) {
    btnSolgen.addEventListener('click', async () => {
        try {
            // Fetch available templates
            const listResp = await fetch('/api/templates');
            if (!listResp.ok) return;
            const listData = await listResp.json();
            const templates = listData.templates || [];

            const choice = prompt(
                'Generate Solidity from template:\n' +
                templates.map((t, i) => `${i + 1}. ${t.name}`).join('\n') +
                '\n\nEnter number:'
            );
            if (!choice) return;
            const idx = parseInt(choice) - 1;
            if (idx < 0 || idx >= templates.length) return;

            const template = templates[idx];
            btnSolgen.textContent = 'Generating...';

            const resp = await fetch('/api/solgen', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ template: template.id })
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Generation failed: ' + text);
                btnSolgen.textContent = 'Solidity';
                return;
            }

            const data = await resp.json();
            if (data.solidity) {
                downloadFile(data.filename || 'contract.sol', data.solidity);
                btnSolgen.textContent = 'Downloaded';
                setTimeout(() => { btnSolgen.textContent = 'Solidity'; }, 2000);
            }
        } catch (err) {
            alert('Generation failed: ' + err.message);
            btnSolgen.textContent = 'Solidity';
        }
    });
}

// ZK Proof button — shows circuit picker then describes proof requirements
const btnProve = document.getElementById('btn-prove');
if (btnProve) {
    btnProve.addEventListener('click', async () => {
        try {
            // Fetch available circuits
            const circResp = await fetch('/api/circuits');
            if (!circResp.ok) {
                alert('Failed to load circuits');
                return;
            }
            const circData = await circResp.json();
            const circuits = circData.circuits || [];

            const choice = prompt(
                'Available ZK circuits:\n' +
                circuits.map((c, i) => `${i + 1}. ${c.name} — ${c.description}`).join('\n') +
                '\n\nEnter number to see details:'
            );
            if (!choice) return;
            const idx = parseInt(choice) - 1;
            if (idx < 0 || idx >= circuits.length) return;

            const circuit = circuits[idx];
            alert(
                `Circuit: ${circuit.name}\n\n` +
                `${circuit.description}\n\n` +
                `Public inputs:\n` +
                circuit.public_inputs.map(p => `  - ${p}`).join('\n') +
                `\n\nUse POST /api/prove with circuit="${circuit.name}" and witness values.`
            );
        } catch (err) {
            alert('Failed: ' + err.message);
        }
    });
}

// Templates button — loads real Petri net model into editor
const btnTemplates = document.getElementById('btn-templates');
if (btnTemplates) {
    btnTemplates.addEventListener('click', async () => {
        try {
            const resp = await fetch('/api/templates');
            if (!resp.ok) return;

            const data = await resp.json();
            const templates = data.templates || [];

            const choice = prompt(
                'Load template into editor:\n' +
                templates.map((t, i) => `${i + 1}. ${t.name}`).join('\n') +
                '\n\nEnter number:'
            );

            if (!choice) return;
            const idx = parseInt(choice) - 1;
            if (idx < 0 || idx >= templates.length) return;

            const template = templates[idx];
            const tmplResp = await fetch('/api/templates/' + template.id);
            if (tmplResp.ok) {
                const tmplData = await tmplResp.json();
                if (petriView && petriView.loadModel) {
                    petriView.loadModel(tmplData);
                } else {
                    // Fallback: show as JSON
                    const json = JSON.stringify(tmplData, null, 2);
                    downloadFile(template.id + '.json', json);
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
