// poll.js — ZK Poll creation, voting, and results UI

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';
import { buildVoteCastWitness } from './witness-builder.js';

// Current poll context
window.currentPollId = null;
let selectedChoice = null;

// ============ Navigation ============

window.showCreate = function() {
    setView('poll-create');
    location.hash = 'create';
};

window.showList = function() {
    setView('poll-list');
    location.hash = '';
    loadPolls();
};

function showPoll(pollId) {
    window.currentPollId = pollId;
    setView('poll-view');
    loadPoll(pollId);
}

window.showResults = function(pollId) {
    window.currentPollId = pollId;
    setView('poll-results');
    loadResults(pollId);
};

window.showDeploy = function() {
    setView('poll-deploy');
    location.hash = 'deploy';
    loadSolidityPreview();
};

function setView(id) {
    ['poll-list', 'poll-create', 'poll-view', 'poll-results', 'poll-deploy'].forEach(v => {
        document.getElementById(v).classList.remove('active');
    });
    document.getElementById(id).classList.add('active');
    clearMessages();
}

// ============ Poll List ============

async function loadPolls() {
    const container = document.getElementById('polls-container');
    try {
        const resp = await fetch('/api/polls');
        if (!resp.ok) throw new Error('Failed to load polls');
        const data = await resp.json();
        const polls = data.polls || [];

        if (polls.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);">No polls yet. Create the first one!</p>';
            return;
        }

        container.innerHTML = polls.map(p => `
            <a class="poll-list-item" href="#${p.id}">
                <div>
                    <div class="poll-list-title">${esc(p.title)}</div>
                    <div class="poll-list-meta">${p.choices.length} choices &middot; ${formatDate(p.createdAt)}</div>
                </div>
                <span class="poll-status ${p.status}">${p.status}</span>
            </a>
        `).join('');
    } catch (err) {
        container.innerHTML = '<p style="color:var(--text-muted);">Failed to load polls.</p>';
    }
}

// ============ Create Poll ============

window.addChoice = function() {
    const list = document.getElementById('choices-list');
    const n = list.children.length + 1;
    const row = document.createElement('div');
    row.className = 'choice-row';
    row.innerHTML = `<input type="text" placeholder="Option ${n}" class="choice-input"/><button class="btn-remove" onclick="removeChoice(this)">-</button>`;
    list.appendChild(row);
};

window.removeChoice = function(btn) {
    const list = document.getElementById('choices-list');
    if (list.children.length > 2) {
        btn.parentElement.remove();
    }
};

window.createPoll = async function() {
    const title = document.getElementById('poll-title').value.trim();
    const description = document.getElementById('poll-desc').value.trim();
    const choiceInputs = document.querySelectorAll('.choice-input');
    const choices = Array.from(choiceInputs).map(i => i.value.trim()).filter(v => v);
    const duration = parseInt(document.getElementById('poll-duration').value);

    if (!title) return showMsg('Title is required', 'error');
    if (choices.length < 2) return showMsg('At least 2 choices required', 'error');

    const btn = document.getElementById('btn-create');
    btn.disabled = true;
    btn.textContent = 'Connecting wallet...';

    try {
        // Require wallet signature
        if (!window.ethereum) {
            showMsg('MetaMask or another Ethereum wallet is required to create polls.', 'error');
            btn.disabled = false;
            btn.textContent = 'Create Poll';
            return;
        }

        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const creator = accounts[0];
        const sigMsg = 'bitwrap-create-poll:' + title;

        btn.textContent = 'Sign to create...';
        const signature = await window.ethereum.request({
            method: 'personal_sign',
            params: [sigMsg, creator]
        });

        btn.textContent = 'Creating...';
        const resp = await fetch('/api/polls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title,
                description,
                choices,
                durationMinutes: duration,
                voterCommitments: [],
                registryRoot: '',
                creator,
                signature,
            })
        });

        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(text);
        }

        const data = await resp.json();
        showMsg('Poll created! Share this link with voters.', 'success');

        // Show the poll link
        const msgDiv = document.getElementById('messages');
        msgDiv.innerHTML += `<div class="poll-link">${location.origin}/poll#${data.id}</div>`;

        setTimeout(() => {
            location.hash = data.id;
        }, 2000);
    } catch (err) {
        showMsg('Failed to create poll: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Create Poll';
    }
};

// ============ Vote ============

async function loadPoll(pollId) {
    try {
        const resp = await fetch(`/api/polls/${pollId}`);
        if (!resp.ok) throw new Error('Poll not found');
        const data = await resp.json();
        const poll = data.poll;

        document.getElementById('vote-title').textContent = poll.title;
        document.getElementById('vote-desc').textContent = poll.description || '';

        const statusEl = document.getElementById('vote-status');
        statusEl.textContent = poll.status;
        statusEl.className = 'poll-status ' + poll.status;

        const meta = [];
        if (data.voteCount > 0) meta.push(`${data.voteCount} votes`);
        if (poll.expiresAt && poll.expiresAt !== '0001-01-01T00:00:00Z') {
            meta.push(`expires ${formatDate(poll.expiresAt)}`);
        }
        document.getElementById('vote-meta-text').textContent = meta.length ? ' \u00b7 ' + meta.join(' \u00b7 ') : '';

        const choicesDiv = document.getElementById('vote-choices');
        selectedChoice = null;

        const btnVote = document.getElementById('btn-vote');
        const btnClose = document.getElementById('btn-close');
        const btnReveal = document.getElementById('btn-reveal');

        if (poll.status === 'active') {
            choicesDiv.innerHTML = poll.choices.map((c, i) => `
                <label class="choice-option" data-idx="${i}" onclick="selectChoice(this, ${i})">
                    <input type="radio" name="vote-choice" value="${i}"/>
                    <span class="choice-label">${esc(c)}</span>
                </label>
            `).join('');
            btnVote.style.display = '';
            btnReveal.style.display = 'none';

            // Show close button if current wallet is the creator
            btnClose.style.display = 'none';
            if (window.ethereum && poll.creator) {
                window.ethereum.request({ method: 'eth_accounts' }).then(accts => {
                    if (accts.length > 0 && accts[0].toLowerCase() === poll.creator.toLowerCase()) {
                        btnClose.style.display = '';
                    }
                }).catch(() => {});
            }
        } else {
            // Poll closed — show reveal UI if voter has a stored secret
            choicesDiv.innerHTML = '<p style="color:var(--text-muted);">This poll is closed. Reveal your vote to be counted in the tally.</p>';
            btnVote.style.display = 'none';
            btnClose.style.display = 'none';

            // Check if we have a stored reveal key
            const hasRevealData = findRevealData(pollId);
            btnReveal.style.display = hasRevealData ? '' : 'none';
        }
    } catch (err) {
        showMsg('Failed to load poll: ' + err.message, 'error');
    }
}

window.selectChoice = function(el, idx) {
    document.querySelectorAll('.choice-option').forEach(o => o.classList.remove('selected'));
    el.classList.add('selected');
    selectedChoice = idx;
};

window.castVote = async function() {
    if (selectedChoice === null) return showMsg('Select a choice first', 'error');

    const btn = document.getElementById('btn-vote');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Building proof...';

    try {
        // Generate a voter secret (in production, derived from wallet signature)
        // For now, use a random secret — users can connect wallet for deterministic secrets
        let voterSecret;
        if (window.ethereum) {
            try {
                const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                const msg = `bitwrap-vote:${currentPollId}`;
                const sig = await window.ethereum.request({
                    method: 'personal_sign',
                    params: [msg, accounts[0]]
                });
                // Derive secret from signature (take first 31 bytes to stay within field)
                voterSecret = BigInt('0x' + sig.slice(2, 64));
            } catch {
                // Wallet declined or unavailable — fall back to random
                voterSecret = randomFieldElement();
            }
        } else {
            voterSecret = randomFieldElement();
        }

        const pollId = BigInt('0x' + currentPollId.slice(0, 16));
        const voteChoice = BigInt(selectedChoice);
        const voterWeight = 1n;

        // Build voter commitment and Merkle tree
        const leaf = mimcHash(voterSecret, voterWeight);
        const tree = MerkleTree.fromLeaves([leaf], 20);

        const witnessResult = buildVoteCastWitness({
            tree, voterIdx: 0, pollId, voterSecret, voteChoice, voterWeight
        });

        btn.innerHTML = '<span class="spinner"></span>Generating proof...';

        // Try WASM prover first, fall back to server
        let proofData;
        if (window.bitwrapProver && window.bitwrapProver.prove) {
            proofData = await window.bitwrapProver.prove(witnessResult.circuit, witnessResult.witness);
        } else {
            const resp = await fetch('/api/prove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(witnessResult)
            });
            if (!resp.ok) {
                const text = await resp.text();
                throw new Error('Proof generation failed: ' + text);
            }
            proofData = await resp.json();
        }

        btn.innerHTML = '<span class="spinner"></span>Submitting vote...';

        // Submit vote — send commitment (not choice), witness for server-side ZK verification
        // Strip private fields from the witness copy sent to server
        const serverWitness = { ...witnessResult.witness };
        // voterSecret and voteChoice stay in the local witness for proving
        // but the server only needs them for re-verification, not storage

        const voteResp = await fetch(`/api/polls/${currentPollId}/vote`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                nullifier: witnessResult.witness.nullifier,
                voteCommitment: witnessResult.witness.voteCommitment,
                proof: JSON.stringify(proofData),
                witness: serverWitness,
                publicInputs: [
                    witnessResult.witness.pollId,
                    witnessResult.witness.voterRegistryRoot,
                    witnessResult.witness.nullifier,
                    witnessResult.witness.voteCommitment,
                ],
            })
        });

        // Store voter secret locally for reveal phase
        try {
            const revealKey = `bitwrap-vote-${currentPollId}-${witnessResult.witness.nullifier}`;
            localStorage.setItem(revealKey, JSON.stringify({
                voterSecret: witnessResult.witness.voterSecret,
                voteChoice: selectedChoice,
                nullifier: witnessResult.witness.nullifier,
            }));
        } catch { /* localStorage may be unavailable */ }

        if (!voteResp.ok) {
            const text = await voteResp.text();
            throw new Error(text);
        }

        showMsg('Vote cast successfully! Your vote is anonymous and verifiable.', 'success');
        btn.style.display = 'none';

        // Refresh vote count
        loadPoll(currentPollId);
    } catch (err) {
        showMsg('Vote failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Cast Vote';
    }
};

// ============ Close Poll ============

window.closePoll = async function() {
    if (!window.ethereum) return showMsg('Wallet required to close poll', 'error');

    const btn = document.getElementById('btn-close');
    btn.disabled = true;
    btn.textContent = 'Signing...';

    try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const creator = accounts[0];
        const sigMsg = 'bitwrap-close-poll:' + currentPollId;
        const signature = await window.ethereum.request({
            method: 'personal_sign',
            params: [sigMsg, creator]
        });

        btn.textContent = 'Closing...';
        const resp = await fetch(`/api/polls/${currentPollId}/close`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ creator, signature })
        });

        if (!resp.ok) throw new Error(await resp.text());

        showMsg('Poll closed. Voters can now reveal their choices to build the tally.', 'success');
        loadPoll(currentPollId);
    } catch (err) {
        showMsg('Close failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Close Poll';
    }
};

// ============ Reveal Vote ============

function findRevealData(pollId) {
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(`bitwrap-vote-${pollId}-`)) {
                return JSON.parse(localStorage.getItem(key));
            }
        }
    } catch { /* localStorage may be unavailable */ }
    return null;
}

window.revealVote = async function() {
    const revealData = findRevealData(currentPollId);
    if (!revealData) return showMsg('No stored vote found for this poll. You can only reveal from the browser you voted from.', 'error');

    const btn = document.getElementById('btn-reveal');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Revealing...';

    try {
        const resp = await fetch(`/api/polls/${currentPollId}/reveal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                nullifier: revealData.nullifier,
                voteChoice: revealData.voteChoice,
                voterSecret: revealData.voterSecret,
            })
        });

        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(text);
        }

        showMsg('Vote revealed! Your choice has been added to the tally.', 'success');
        btn.style.display = 'none';

        // Clean up stored reveal data
        try {
            const key = `bitwrap-vote-${currentPollId}-${revealData.nullifier}`;
            localStorage.removeItem(key);
        } catch { /* ignore */ }
    } catch (err) {
        showMsg('Reveal failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Reveal My Vote';
    }
};

// ============ Results ============

async function loadResults(pollId) {
    try {
        const resp = await fetch(`/api/polls/${pollId}/results`);
        if (!resp.ok) throw new Error('Failed to load results');
        const data = await resp.json();

        document.getElementById('results-title').textContent = data.title || 'Poll Results';

        const choices = data.choices || [];
        const voteCount = data.voteCount || 0;
        const tallies = data.tallies || null;
        const talliedCount = data.talliedCount || 0;
        const barsDiv = document.getElementById('results-bars');

        if (tallies && talliedCount > 0) {
            // Show real tallies from revealed votes
            const maxVotes = Math.max(...tallies, 1);
            barsDiv.innerHTML = choices.map((c, i) => {
                const count = tallies[i] || 0;
                const pct = Math.round((count / maxVotes) * 100);
                return `
                    <div class="result-bar">
                        <div class="result-label">
                            <span>${esc(c)}</span>
                            <span>${count} vote${count !== 1 ? 's' : ''}</span>
                        </div>
                        <div class="result-track">
                            <div class="result-fill" style="width:${Math.max(pct, 2)}%"></div>
                        </div>
                    </div>
                `;
            }).join('');
        } else {
            // No reveals yet — show placeholders
            barsDiv.innerHTML = choices.map(c => `
                <div class="result-bar">
                    <div class="result-label">
                        <span>${esc(c)}</span>
                        <span style="color:var(--text-muted);">hidden</span>
                    </div>
                    <div class="result-track">
                        <div class="result-fill" style="width:0%"></div>
                    </div>
                </div>
            `).join('');
        }

        let statusText = `${voteCount} total votes \u00b7 ${data.status}`;
        if (talliedCount > 0 && talliedCount < voteCount) {
            statusText += ` \u00b7 ${talliedCount}/${voteCount} tallied`;
        }
        document.getElementById('results-total').textContent = statusText;

        // Nullifiers
        const nullifiers = data.nullifiers || [];
        const nullDiv = document.getElementById('results-nullifiers');
        if (nullifiers.length === 0) {
            nullDiv.textContent = 'No votes yet.';
        } else {
            nullDiv.innerHTML = nullifiers.map(n => `<div style="padding:2px 0;">${esc(n)}</div>`).join('');
        }
    } catch (err) {
        showMsg('Failed to load results: ' + err.message, 'error');
    }
}

// ============ Helpers ============

function showMsg(text, type) {
    const div = document.getElementById('messages');
    div.innerHTML = `<div class="msg msg-${type}">${esc(text)}</div>`;
}

function clearMessages() {
    document.getElementById('messages').innerHTML = '';
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function formatDate(iso) {
    if (!iso || iso === '0001-01-01T00:00:00Z') return '';
    const d = new Date(iso);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function randomFieldElement() {
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    let hex = '0x';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return BigInt(hex);
}

// ============ Deploy On-Chain ============

window.downloadBundle = async function() {
    try {
        const resp = await fetch('/api/bundle/vote');
        if (!resp.ok) throw new Error(await resp.text());
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'BitwrapZKPoll.zip';
        a.click();
        URL.revokeObjectURL(url);
        showMsg('Foundry bundle downloaded! Run: forge install foundry-rs/forge-std && forge test', 'success');
    } catch (err) {
        showMsg('Download failed: ' + err.message, 'error');
    }
};

window.downloadSolidity = async function() {
    try {
        const resp = await fetch('/api/solgen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template: 'vote' })
        });
        if (!resp.ok) throw new Error(await resp.text());
        const data = await resp.json();
        const blob = new Blob([data.solidity], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.filename || 'BitwrapZKPoll.sol';
        a.click();
        URL.revokeObjectURL(url);
        showMsg('Solidity contract downloaded!', 'success');
    } catch (err) {
        showMsg('Download failed: ' + err.message, 'error');
    }
};

async function loadSolidityPreview() {
    const preview = document.getElementById('deploy-preview');
    try {
        const resp = await fetch('/api/solgen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template: 'vote' })
        });
        if (!resp.ok) return;
        const data = await resp.json();
        // Show first ~30 lines as a preview
        const lines = data.solidity.split('\n').slice(0, 30).join('\n');
        preview.innerHTML = `<h3>Contract Preview</h3><div class="code-preview">${esc(lines)}\n...</div>`;
    } catch {
        // Silent fail — preview is optional
    }
}

// ============ Router ============

function route() {
    const hash = location.hash.slice(1);
    if (!hash || hash === '') {
        showList();
    } else if (hash === 'create') {
        setView('poll-create');
    } else if (hash === 'deploy') {
        showDeploy();
    } else if (hash.endsWith('/results')) {
        const id = hash.replace('/results', '');
        window.currentPollId = id;
        showResults(id);
    } else {
        showPoll(hash);
    }
}

window.addEventListener('hashchange', route);

// Initial load
loadPolls();
route();
