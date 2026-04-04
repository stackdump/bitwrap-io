// bitwrap.js — ZK + Solidity UI glue for the editor

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';
import {
    buildTransferWitness, buildMintWitness, buildBurnWitness,
    buildApproveWitness, buildTransferFromWitness, buildVestClaimWitness,
    buildVoteCastWitness
} from './witness-builder.js';

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

// ZK Proof button — builds witness client-side, then submits to prover
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
                'ZK Proof — select circuit:\n' +
                circuits.map((c, i) => `${i + 1}. ${c.name} — ${c.description}`).join('\n') +
                '\n\nEnter number:'
            );
            if (!choice) return;
            const idx = parseInt(choice) - 1;
            if (idx < 0 || idx >= circuits.length) return;

            const circuit = circuits[idx];

            // Collect witness parameters based on circuit type
            const witnessResult = collectWitness(circuit.name);
            if (!witnessResult) return;

            btnProve.textContent = 'Proving...';

            const resp = await fetch('/api/prove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    circuit: witnessResult.circuit,
                    witness: witnessResult.witness
                })
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Proof failed: ' + text);
                btnProve.textContent = 'ZK Proof';
                return;
            }

            const data = await resp.json();
            btnProve.textContent = 'Proved!';
            setTimeout(() => { btnProve.textContent = 'ZK Proof'; }, 3000);

            // Show proof result
            const proofJson = JSON.stringify(data, null, 2);
            downloadFile(`proof-${circuit.name}.json`, proofJson);
        } catch (err) {
            alert('Proof failed: ' + err.message);
            btnProve.textContent = 'ZK Proof';
        }
    });
}

// Collect witness inputs for a circuit via prompts
function collectWitness(circuitName) {
    switch (circuitName) {
    case 'transfer': {
        const input = prompt(
            'Transfer witness (comma-separated):\n' +
            'from, to, amount, balanceFrom, balanceTo\n\n' +
            'Example: 1, 2, 50, 1000, 500'
        );
        if (!input) return null;
        const [from, to, amount, balanceFrom, balanceTo] = input.split(',').map(s => BigInt(s.trim()));

        // Build Merkle tree with sender leaf
        const leaf0 = mimcHash(from, balanceFrom);
        const leaf1 = mimcHash(to, balanceTo);
        const tree = MerkleTree.fromLeaves([leaf0, leaf1], 20);

        return buildTransferWitness({ tree, fromIdx: 0, from, to, amount, balanceFrom, balanceTo });
    }
    case 'mint': {
        const input = prompt(
            'Mint witness (comma-separated):\n' +
            'minter, to, amount, balanceTo\n\n' +
            'Example: 1, 2, 100, 0'
        );
        if (!input) return null;
        const [minter, to, amount, balanceTo] = input.split(',').map(s => BigInt(s.trim()));
        return buildMintWitness({ caller: minter, minter, to, amount, balanceTo });
    }
    case 'burn': {
        const input = prompt(
            'Burn witness (comma-separated):\n' +
            'from, amount, balanceFrom\n\n' +
            'Example: 1, 50, 1000'
        );
        if (!input) return null;
        const [from, amount, balanceFrom] = input.split(',').map(s => BigInt(s.trim()));

        const leaf0 = mimcHash(from, balanceFrom);
        const tree = MerkleTree.fromLeaves([leaf0], 20);

        return buildBurnWitness({ tree, fromIdx: 0, from, amount, balanceFrom });
    }
    case 'approve': {
        const input = prompt(
            'Approve witness (comma-separated):\n' +
            'owner, spender, amount\n\n' +
            'Example: 1, 2, 500'
        );
        if (!input) return null;
        const [owner, spender, amount] = input.split(',').map(s => BigInt(s.trim()));
        return buildApproveWitness({ caller: owner, owner, spender, amount });
    }
    case 'transferFrom': {
        const input = prompt(
            'TransferFrom witness (comma-separated):\n' +
            'from, to, caller, amount, balanceFrom, allowanceFrom\n\n' +
            'Example: 1, 3, 2, 50, 1000, 500'
        );
        if (!input) return null;
        const [from, to, caller, amount, balanceFrom, allowanceFrom] = input.split(',').map(s => BigInt(s.trim()));

        const balanceLeaf = mimcHash(from, balanceFrom);
        const balanceTree = MerkleTree.fromLeaves([balanceLeaf], 10);

        const allowanceKey = mimcHash(from, caller);
        const allowanceLeaf = mimcHash(allowanceKey, allowanceFrom);
        const allowanceTree = MerkleTree.fromLeaves([allowanceLeaf], 10);

        return buildTransferFromWitness({
            balanceTree, allowanceTree, from, to, caller, amount,
            balanceFrom, allowanceFrom, balanceFromIdx: 0, allowanceFromIdx: 0
        });
    }
    case 'vestClaim': {
        const input = prompt(
            'VestClaim witness (comma-separated):\n' +
            'tokenID, owner, claimAmount, vestedAmount, claimed\n\n' +
            'Example: 1, 42, 25, 100, 50'
        );
        if (!input) return null;
        const [tokenID, owner, claimAmount, vestedAmount, claimed] = input.split(',').map(s => BigInt(s.trim()));

        const scheduleLeaf = mimcHash(tokenID, vestedAmount);
        const scheduleTree = MerkleTree.fromLeaves([scheduleLeaf], 10);

        const ownerLeaf = mimcHash(tokenID, owner);
        const ownerTree = MerkleTree.fromLeaves([ownerLeaf], 10);

        return buildVestClaimWitness({
            scheduleTree, ownerTree, tokenID, caller: owner, claimAmount,
            vestedAmount, claimed, owner, scheduleIdx: 0, ownerIdx: 0
        });
    }
    case 'voteCast': {
        const input = prompt(
            'VoteCast witness (comma-separated):\n' +
            'pollId, voterSecret, voteChoice, voterWeight\n\n' +
            'Example: 1, 12345, 2, 1'
        );
        if (!input) return null;
        const [pollId, voterSecret, voteChoice, voterWeight] = input.split(',').map(s => BigInt(s.trim()));

        // Build voter commitment leaf and Merkle tree
        const leaf = mimcHash(voterSecret, voterWeight);
        const tree = MerkleTree.fromLeaves([leaf], 20);

        return buildVoteCastWitness({ tree, voterIdx: 0, pollId, voterSecret, voteChoice, voterWeight, maxChoices: 256n });
    }
    default:
        alert(`No witness builder for circuit: ${circuitName}`);
        return null;
    }
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
                if (petriView && petriView.setModel) {
                    petriView.setModel(tmplData);
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

// Convert metamodel format (states/actions/arcs) to pflow.xyz format (places/transitions)
// with auto-generated circular layout positions.
function metamodelToPflow(schema) {
    const places = {};
    const transitions = {};
    const states = schema.states || [];
    const actions = schema.actions || [];
    const arcs = schema.arcs || [];
    const total = states.length + actions.length;
    const radius = Math.max(120, total * 30);
    const cx = 300, cy = 250;

    states.forEach((s, i) => {
        const angle = (2 * Math.PI * i) / total;
        places[s.id] = {
            x: Math.round(cx + radius * Math.cos(angle)),
            y: Math.round(cy + radius * Math.sin(angle)),
            initial: typeof s.initial === 'number' ? s.initial : 0,
        };
    });

    actions.forEach((a, i) => {
        const angle = (2 * Math.PI * (i + states.length)) / total;
        transitions[a.id] = {
            x: Math.round(cx + radius * Math.cos(angle)),
            y: Math.round(cy + radius * Math.sin(angle)),
        };
    });

    const pflowArcs = arcs.map(a => ({
        source: a.source,
        target: a.target,
        weight: [1],
        inhibitTransition: false,
        '@type': 'Arrow',
        ...(a.keys && a.keys.length ? { keys: a.keys } : {}),
        ...(a.value ? { value: a.value } : {}),
    }));

    return {
        '@context': 'https://pflow.xyz/schema',
        '@type': 'PetriNet',
        '@version': '1.1',
        name: schema.name || 'Model',
        version: schema.version || '1.0.0',
        token: ['https://pflow.xyz/tokens/black'],
        places,
        transitions,
        arcs: pflowArcs,
        ...(schema.events ? { events: schema.events } : {}),
        ...(schema.constraints ? { constraints: schema.constraints } : {}),
    };
}

// Inject poll-specific choices into the generic vote template model.
// Replaces the abstract "tallies" place with one place per choice,
// and fans out the castVote→tallies arc to each choice place.
function injectPollChoices(model, poll) {
    if (!poll.choices || poll.choices.length === 0) return model;

    const m = JSON.parse(JSON.stringify(model)); // deep clone
    const choices = poll.choices;

    // Remove the generic "tallies" place
    delete m.places['tallies'];

    // Add a place for each choice, arranged in a row below castVote
    const castVote = m.transitions['castVote'] || { x: 300, y: 50 };
    const startX = castVote.x - ((choices.length - 1) * 80) / 2;

    choices.forEach((name, i) => {
        const placeId = 'tally:' + name;
        m.places[placeId] = {
            x: Math.round(startX + i * 80),
            y: castVote.y + 180,
            initial: [0],
            '@type': 'Place',
            offset: 0,
            capacity: [null],
        };
    });

    // Replace castVote→tallies arc with one arc per choice
    m.arcs = m.arcs.filter(a => !(a.source === 'castVote' && a.target === 'tallies'));
    choices.forEach((name) => {
        m.arcs.push({
            source: 'castVote',
            target: 'tally:' + name,
            weight: [1],
            inhibitTransition: false,
            '@type': 'Arrow',
        });
    });

    // Update model name to poll title
    m.name = poll.title || m.name;

    return m;
}

// Load model from URL params on page load
(function() {
    const params = new URLSearchParams(window.location.search);

    // Load by CID: /editor?cid=<cid>
    const cid = params.get('cid');
    if (cid) {
        const loadCid = () => {
            fetch('/o/' + cid)
                .then(r => r.ok ? r.json() : null)
                .then(data => {
                    if (data && petriView && petriView.setModel) {
                        petriView.setModel(data);
                    }
                })
                .catch(err => console.error('Failed to load model:', err));
        };
        if (petriView && petriView.setModel) {
            loadCid();
        } else if (customElements) {
            customElements.whenDefined('petri-view').then(loadCid);
        }
        return;
    }

    // Load by template: /editor?template=<id>&poll=<pollId>
    const template = params.get('template');
    if (template) {
        const pollId = params.get('poll');

        const loadModel = async () => {
            try {
                const tmplResp = await fetch('/api/templates/' + template);
                if (!tmplResp.ok) return;
                const tmplData = await tmplResp.json();
                let model = metamodelToPflow(tmplData);

                // If a poll ID is provided, customize the model with poll-specific data
                if (pollId) {
                    try {
                        const pollResp = await fetch('/api/polls/' + pollId);
                        if (pollResp.ok) {
                            const pollData = await pollResp.json();
                            const poll = pollData.poll || pollData;
                            model = injectPollChoices(model, poll);

                            // Show poll info in toolbar
                            const info = document.createElement('span');
                            info.style.cssText = 'color:#aaa;font-size:13px;margin-left:12px;';
                            info.textContent = `${poll.title} (${poll.status})`;
                            const toolbar = document.querySelector('.toolbar, nav') || document.body;
                            toolbar.appendChild(info);
                        }
                    } catch (e) {
                        console.warn('Failed to load poll data:', e);
                    }
                }

                if (petriView && petriView.setModel) {
                    petriView.setModel(model);
                }
            } catch (err) {
                console.error('Failed to load template:', err);
            }
        };

        if (petriView && petriView.setModel) {
            loadModel();
        } else if (customElements) {
            customElements.whenDefined('petri-view').then(loadModel);
        }
        return;
    }
})();
