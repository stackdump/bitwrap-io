// poll.js — ZK Poll creation, voting, and results UI

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';
import { buildVoteCastWitness } from './witness-builder.js';
import { prove as workerProve, loadKeys, initProver } from './prover.js';

// Current poll context
window.currentPollId = null;
let currentPollData = null; // cached poll data from loadPoll
let selectedChoice = null;

// ============ Wallet Provider ============
// EIP-6963 multi-provider discovery. When multiple wallets (MetaMask, Trust,
// Coinbase) are installed, window.ethereum is last-writer-wins and may point
// at the wrong wallet. EIP-6963 lets each wallet announce itself so we can
// pick deterministically. Providers are collected eagerly at module load.

const eip6963Providers = [];
if (typeof window !== 'undefined') {
    window.addEventListener('eip6963:announceProvider', (e) => {
        eip6963Providers.push(e.detail);
    });
    window.dispatchEvent(new Event('eip6963:requestProvider'));
}

function getWalletProvider() {
    // Prefer EIP-6963 announced providers; fall back to window.ethereum.
    if (eip6963Providers.length > 0) return eip6963Providers[0].provider;
    return window.ethereum || null;
}

function walletIdentity(provider) {
    if (!provider) return 'none';
    const tags = [];
    if (provider.isMetaMask) tags.push('MetaMask');
    if (provider.isTrust || provider.isTrustWallet) tags.push('Trust');
    if (provider.isCoinbaseWallet) tags.push('Coinbase');
    if (provider.isRabby) tags.push('Rabby');
    if (provider.isDevWallet) tags.push('DevWallet');
    return tags.length ? tags.join('+') : 'unknown';
}

function walletError(err, context) {
    const code = err && err.code != null ? err.code : 'n/a';
    const msg = err && err.message ? err.message : String(err);
    console.error(`[wallet:${context}] code=${code} wallet=${walletIdentity(getWalletProvider())}`, err);
    // EIP-1193 well-known codes
    const hint = {
        4001: 'user rejected',
        4100: 'unauthorized',
        4200: 'method not supported',
        4900: 'wallet disconnected',
        [-32602]: 'invalid params',
        [-32603]: 'internal error',
    }[code];
    return hint ? `${msg} (code ${code}: ${hint})` : `${msg}${code !== 'n/a' ? ` (code ${code})` : ''}`;
}

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
        const provider = getWalletProvider();
        if (!provider) {
            showMsg('MetaMask, Trust Wallet, or another Ethereum wallet is required to create polls.', 'error');
            btn.disabled = false;
            btn.textContent = 'Create Poll';
            return;
        }

        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        const creator = accounts[0];
        const sigMsg = 'bitwrap-create-poll:' + title;

        btn.textContent = 'Sign to create...';
        const signature = await provider.request({
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
        showMsg('Failed to create poll: ' + walletError(err, 'createPoll'), 'error');
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
        currentPollData = poll;

        document.getElementById('vote-title').textContent = poll.title;
        document.getElementById('vote-desc').textContent = poll.description || '';

        // Update "View Petri Net Model" links to include this poll's ID
        document.querySelectorAll('#view-model-link').forEach(el => {
            el.href = `/editor?template=vote&poll=${pollId}`;
        });

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

        // Load registry info — always show the bar for active polls so the first
        // voter has a way to register. Server rejects vote attempts on empty registries.
        const regBar = document.getElementById('registry-bar');
        const btnRegister = document.getElementById('btn-register');
        if (poll.status === 'active') {
            regBar.style.display = 'flex';
            fetch(`/api/polls/${pollId}/registry`).then(r => r.json()).then(reg => {
                const signedCount = (poll.registryRootSigs && poll.registryRootSigs.length)
                    ? poll.registryRootSigs[poll.registryRootSigs.length - 1].count
                    : 0;
                const pending = Math.max(0, reg.count - signedCount);
                const base = `${reg.count} registered voter${reg.count !== 1 ? 's' : ''}`;
                document.getElementById('registry-info').textContent = pending > 0
                    ? `${base} \u00b7 ${pending} awaiting creator sign-off`
                    : base;
                // If the current wallet's commitment is already in the registry,
                // mark the button as already-registered so we don't re-sign.
                markAlreadyRegisteredIfPossible(pollId, reg.commitments || [], btnRegister);
                // Surface a "Sign current registry" button to the creator
                // when there are pending registrations not yet covered by
                // a sign-off. Voter-side UI shows a passive warning only.
                renderRegistrySignButton(poll, reg, pending);
            }).catch(() => {
                document.getElementById('registry-info').textContent = '0 registered voters';
            });
        } else {
            regBar.style.display = 'none';
        }

        if (poll.status === 'active') {
            choicesDiv.innerHTML = poll.choices.map((c, i) => `
                <label class="choice-option" data-idx="${i}" onclick="selectChoice(this, ${i})">
                    <input type="radio" name="vote-choice" value="${i}"/>
                    <span class="choice-label">${esc(c)}</span>
                </label>
            `).join('');
            btnVote.style.display = '';
            btnReveal.style.display = 'none';
            // Schema-version banner: explain the backup requirement up front.
            const banner = document.getElementById('v2-backup-banner');
            if (banner) banner.style.display = ((poll.voteSchemaVersion || 1) >= 2) ? 'block' : 'none';

            // Show close button if current wallet is the creator
            btnClose.style.display = 'none';
            const provider = getWalletProvider();
            if (provider && poll.creator) {
                provider.request({ method: 'eth_accounts' }).then(accts => {
                    if (accts.length > 0 && accts[0].toLowerCase() === poll.creator.toLowerCase()) {
                        btnClose.style.display = '';
                    }
                }).catch(() => {});
            }
        } else {
            // Poll closed — always show the Reveal button. If localStorage
            // has the voterSecret we submit it directly; otherwise we fall
            // through to a re-sign recovery flow (wallet re-signs the
            // bitwrap-vote message; voter picks which choice they cast;
            // server verifies mimcHash(secret, choice) == commitment).
            choicesDiv.innerHTML = '<p style="color:var(--text-muted);">This poll is closed. Reveal your vote to add it to the tally.</p>';
            btnVote.style.display = 'none';
            btnClose.style.display = 'none';
            btnReveal.style.display = '';
            if (findRevealData(pollId)) {
                btnReveal.textContent = 'Reveal My Vote';
            } else if ((poll.voteSchemaVersion || 1) >= 2) {
                btnReveal.textContent = 'Reveal My Vote (upload backup)';
            } else {
                btnReveal.textContent = 'Reveal My Vote (re-sign to recover)';
            }
        }
    } catch (err) {
        showMsg('Failed to load poll: ' + err.message, 'error');
    }
}

// renderRegistrySignButton toggles the creator-only "Sign Current
// Registry" button visibility. Shows when the connected wallet is the
// poll creator AND there are pending registrations not yet covered by
// a signature. Voters never see this — they only see the pending count
// in the registry-info line.
function renderRegistrySignButton(poll, registry, pending) {
    const btn = document.getElementById('btn-sign-registry');
    if (!btn) return;
    btn.style.display = 'none';
    if (!poll || poll.status !== 'active' || pending <= 0) return;
    const provider = getWalletProvider();
    if (!provider || !poll.creator) return;
    provider.request({ method: 'eth_accounts' }).then(accts => {
        if (accts.length > 0 && accts[0].toLowerCase() === poll.creator.toLowerCase()) {
            btn.style.display = '';
            btn.dataset.pending = String(pending);
            btn.dataset.root = registry.root;
            btn.dataset.count = String(registry.count);
        }
    }).catch(() => {});
}

window.signRegistryRoot = async function() {
    const pollId = window.currentPollId;
    const btn = document.getElementById('btn-sign-registry');
    if (!pollId || !btn) return;
    const root = btn.dataset.root;
    const count = btn.dataset.count;
    if (!root || !count) return;

    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Signing...';
    try {
        const provider = getWalletProvider();
        if (!provider) throw new Error('wallet unavailable');
        const accts = await provider.request({ method: 'eth_requestAccounts' });
        const msg = `bitwrap-registry-root:${pollId}:${root}:${count}`;
        const sig = await provider.request({
            method: 'personal_sign',
            params: [msg, accts[0]],
        });
        const resp = await fetch(`/api/polls/${pollId}/sign-registry-root`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ signature: sig }),
        });
        const text = await resp.text();
        if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`);
        showMsg('Registry signed — voters can now cast ballots.', 'success');
        loadPoll(pollId);
    } catch (err) {
        showMsg('Sign failed: ' + (err.message || err), 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = orig;
    }
};

window.selectChoice = function(el, idx) {
    document.querySelectorAll('.choice-option').forEach(o => o.classList.remove('selected'));
    el.classList.add('selected');
    selectedChoice = idx;
};

// Vote progress — four stages, rendered as pills under the button so users
// can see the flow instead of staring at a spinner for ~10 seconds.
const VOTE_STAGES = ['Sign', 'Witness', 'Prove', 'Submit'];
function showVoteProgress(stage) {
    let bar = document.getElementById('vote-progress');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = 'vote-progress';
        bar.className = 'vote-progress';
        bar.innerHTML = VOTE_STAGES.map((s, i) =>
            `<span class="vote-stage" data-stage="${i}"><span class="vote-stage-dot"></span>${s}</span>`
        ).join('');
        const btn = document.getElementById('btn-vote');
        btn.parentElement.insertBefore(bar, btn.nextSibling);
    }
    bar.querySelectorAll('.vote-stage').forEach(el => {
        const s = parseInt(el.dataset.stage, 10);
        el.classList.remove('active', 'done');
        if (s < stage) el.classList.add('done');
        else if (s === stage) el.classList.add('active');
    });
    bar.style.display = 'flex';
}
function hideVoteProgress() {
    const bar = document.getElementById('vote-progress');
    if (bar) bar.style.display = 'none';
}

window.castVote = async function() {
    if (selectedChoice === null) return showMsg('Select a choice first', 'error');

    const btn = document.getElementById('btn-vote');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing…';
    showVoteProgress(0);

    try {
        // voterSecret derivation is schema-version gated. For v2 polls we
        // combine the wallet signature with a per-voter nonce read from
        // localStorage (created at registration time). v1 polls keep the
        // legacy sig.slice derivation for backward compatibility.
        let voterSecret;
        let wallet = 'anon';
        const schemaVersion = (currentPollData && currentPollData.voteSchemaVersion) || 1;
        const provider = getWalletProvider();
        if (provider) {
            try {
                const accounts = await provider.request({ method: 'eth_requestAccounts' });
                wallet = accounts[0];
                const msg = `bitwrap-vote:${currentPollId}`;
                const sig = await provider.request({
                    method: 'personal_sign',
                    params: [msg, accounts[0]]
                });
                const sigDerived = BigInt('0x' + sig.slice(2, 64));
                voterSecret = deriveVoterSecret(schemaVersion, currentPollId, wallet, sigDerived);
            } catch (e) {
                // Wallet declined or unavailable — fall back to random
                walletError(e, 'castVote:sign');
                voterSecret = deriveVoterSecret(schemaVersion, currentPollId, wallet, randomFieldElement());
            }
        } else {
            voterSecret = deriveVoterSecret(schemaVersion, currentPollId, wallet, randomFieldElement());
        }

        const pollId = BigInt('0x' + currentPollId.slice(0, 16));
        const voteChoice = BigInt(selectedChoice);
        const voterWeight = 1n;

        // Build voter commitment and Merkle tree.
        // If the poll has a voter registry, use the shared tree.
        // Otherwise, create a single-leaf tree (open poll).
        const leaf = mimcHash(voterSecret, voterWeight);
        let tree, voterIdx = 0;
        try {
            const regResp = await fetch(`/api/polls/${currentPollId}/registry`);
            const regData = await regResp.json();
            if (regData.commitments && regData.commitments.length > 0) {
                const commitments = regData.commitments.map(c => BigInt(c));
                tree = MerkleTree.fromLeaves(commitments, 20);
                voterIdx = commitments.findIndex(c => c === leaf);
                if (voterIdx < 0) {
                    throw new Error('You are not registered for this poll. Register first.');
                }
            } else {
                tree = MerkleTree.fromLeaves([leaf], 20);
            }
        } catch (e) {
            if (e.message.includes('not registered')) throw e;
            tree = MerkleTree.fromLeaves([leaf], 20);
        }

        btn.innerHTML = '<span class="spinner"></span>Building witness…';
        showVoteProgress(1);

        const maxChoices = BigInt(currentPollData ? currentPollData.choices.length : 256);
        const witnessResult = buildVoteCastWitness({
            tree, voterIdx, pollId, voterSecret, voteChoice, voterWeight, maxChoices
        });

        btn.innerHTML = '<span class="spinner"></span>Generating proof…';
        showVoteProgress(2);

        // Try WASM prover in Web Worker first (non-blocking), fall back to server
        let proofData;
        let clientSideProved = false;
        try {
            await initProver();
            proofData = await workerProve(witnessResult.circuit, witnessResult.witness);
            clientSideProved = true;
        } catch (e) {
            console.warn('Client-side proving failed, falling back to server:', e);
        }
        if (!clientSideProved) {
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

        btn.innerHTML = '<span class="spinner"></span>Submitting vote…';
        showVoteProgress(3);

        // Build vote submission — when client proved, send only proof bytes (server
        // never sees voterSecret or voteChoice). Server fallback sends full witness.
        const voteBody = {
            nullifier: witnessResult.witness.nullifier,
            voteCommitment: witnessResult.witness.voteCommitment,
            publicInputs: [
                witnessResult.witness.pollId,
                witnessResult.witness.voterRegistryRoot,
                witnessResult.witness.nullifier,
                witnessResult.witness.voteCommitment,
                witnessResult.witness.maxChoices,
            ],
        };

        if (clientSideProved && proofData.proof && proofData.publicWitness) {
            // Privacy path: send raw proof bytes, no witness
            voteBody.proofBytes = uint8ToBase64(proofData.proof);
            voteBody.publicWitnessBytes = uint8ToBase64(proofData.publicWitness);
        } else {
            // Fallback: server needs full witness for re-verification
            voteBody.proof = JSON.stringify(proofData);
            voteBody.witness = { ...witnessResult.witness };
        }

        const voteResp = await fetch(`/api/polls/${currentPollId}/vote`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(voteBody)
        });

        // Store voter secret locally for reveal phase
        try {
            const revealKey = `bitwrap-vote-${currentPollId}-${witnessResult.witness.nullifier}`;
            localStorage.setItem(revealKey, JSON.stringify({
                voterSecret: witnessResult.witness.voterSecret,
                voteChoice: selectedChoice,
                nullifier: witnessResult.witness.nullifier,
                schemaVersion,
            }));
        } catch { /* localStorage may be unavailable */ }

        if (!voteResp.ok) {
            const text = await voteResp.text();
            throw new Error(text);
        }

        // v2 polls: auto-download a backup containing the nonce + reveal
        // payload. This is the ONLY path to recover the vote if localStorage
        // is cleared — the legacy re-sign-to-recover flow is removed so a
        // coerced wallet signature cannot be used to deanonymize the vote.
        if (schemaVersion >= 2) {
            try {
                downloadVoteBackup({
                    pollId: currentPollId,
                    wallet,
                    voteChoice: selectedChoice,
                    voterNonce: getOrCreateVoterNonce(currentPollId, wallet).toString(10),
                    voterSecret: witnessResult.witness.voterSecret,
                    nullifier: witnessResult.witness.nullifier,
                    voteCommitment: witnessResult.witness.voteCommitment,
                    schemaVersion: 2,
                    timestamp: new Date().toISOString(),
                });
            } catch (e) {
                console.warn('vote backup download failed', e);
            }
        }

        showMsg('Vote cast successfully! Your vote is anonymous and verifiable.' +
            (schemaVersion >= 2 ? ' A recovery backup has been downloaded — keep it safe.' : ''),
            'success');
        btn.style.display = 'none';
        hideVoteProgress();

        // Refresh vote count
        loadPoll(currentPollId);
    } catch (err) {
        showMsg('Vote failed: ' + walletError(err, 'castVote'), 'error');
        hideVoteProgress();
    } finally {
        btn.disabled = false;
        btn.textContent = 'Cast Vote';
    }
};

// ============ Close Poll ============

window.closePoll = async function() {
    const provider = getWalletProvider();
    if (!provider) return showMsg('Wallet required to close poll', 'error');

    const btn = document.getElementById('btn-close');
    btn.disabled = true;
    btn.textContent = 'Signing...';

    try {
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        const creator = accounts[0];
        const sigMsg = 'bitwrap-close-poll:' + currentPollId;
        const signature = await provider.request({
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
        showMsg('Close failed: ' + walletError(err, 'closePoll'), 'error');
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
    const btn = document.getElementById('btn-reveal');
    const schemaVersion = (currentPollData && currentPollData.voteSchemaVersion) || 1;

    // Path A: localStorage has the voter's secret + choice — submit directly.
    const cached = findRevealData(currentPollId);
    if (cached) {
        return submitReveal(btn, cached.nullifier, cached.voteChoice, cached.voterSecret, true);
    }

    // v2 polls: re-sign recovery is REMOVED because a recomputable secret
    // from the wallet signature alone would reintroduce the coercion gap.
    // The backup JSON auto-downloaded at vote time is the only recovery path.
    if (schemaVersion >= 2) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>Waiting for backup…';
        try {
            const payload = await readVoteBackupFile();
            if (!payload) {
                btn.disabled = false;
                btn.textContent = 'Reveal My Vote';
                return;
            }
            if (payload.pollId !== currentPollId) {
                throw new Error('Backup is for a different poll.');
            }
            // Re-seed localStorage so future reveals use the fast path.
            try {
                if (payload.wallet) {
                    localStorage.setItem(nonceKey(currentPollId, payload.wallet), payload.voterNonce);
                }
                localStorage.setItem(
                    `bitwrap-vote-${currentPollId}-${payload.nullifier}`,
                    JSON.stringify({
                        voterSecret: payload.voterSecret,
                        voteChoice: payload.voteChoice,
                        nullifier: payload.nullifier,
                        schemaVersion: 2,
                    })
                );
            } catch {}
            return submitReveal(btn, payload.nullifier, payload.voteChoice, payload.voterSecret, false);
        } catch (err) {
            showMsg('Backup load failed: ' + (err.message || err), 'error');
            btn.disabled = false;
            btn.textContent = 'Reveal My Vote';
            return;
        }
    }

    // v1 legacy recovery: re-sign with the wallet, ask for the choice,
    // let the server verify mimcHash(secret, choice) == commitment.
    const provider = getWalletProvider();
    if (!provider) {
        return showMsg('No stored vote and no wallet available. Connect the wallet you voted with to recover.', 'error');
    }

    const choiceIdx = await promptForChoice(currentPollData ? currentPollData.choices : []);
    if (choiceIdx === null) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing…';
    try {
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        const sig = await provider.request({
            method: 'personal_sign',
            params: [`bitwrap-vote:${currentPollId}`, accounts[0]],
        });
        const voterSecret = BigInt('0x' + sig.slice(2, 64));
        const pollIdBig = BigInt('0x' + currentPollId.slice(0, 16));
        const nullifier = mimcHash(voterSecret, pollIdBig).toString(10);

        await submitReveal(btn, nullifier, choiceIdx, voterSecret.toString(), false);
    } catch (err) {
        showMsg('Reveal failed: ' + walletError(err, 'revealRecover'), 'error');
        btn.disabled = false;
        btn.textContent = 'Reveal My Vote';
    }
};

// submitReveal POSTs to /reveal and handles success/error UI.
async function submitReveal(btn, nullifier, voteChoice, voterSecret, fromCache) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Revealing…';
    try {
        const resp = await fetch(`/api/polls/${currentPollId}/reveal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nullifier, voteChoice, voterSecret }),
        });
        if (!resp.ok) throw new Error(await resp.text());

        showMsg('Vote revealed! Your choice has been added to the tally.', 'success');
        btn.style.display = 'none';

        if (fromCache) {
            // Clean up stored reveal data once the server confirms.
            try { localStorage.removeItem(`bitwrap-vote-${currentPollId}-${nullifier}`); } catch {}
        }
    } catch (err) {
        // Most common recovery failure: the voter picked the wrong choice
        // (server returns "commitment mismatch"). Make the error actionable.
        const msg = err.message || String(err);
        if (msg.toLowerCase().includes('commitment')) {
            showMsg('That choice doesn\'t match your commitment. Click Reveal again and pick a different option.', 'error');
        } else {
            showMsg('Reveal failed: ' + msg, 'error');
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Reveal My Vote';
    }
}

// promptForChoice shows an inline radio selector in the choices area and
// resolves with the picked index (or null if the user cancels). Used only
// in the recovery path.
function promptForChoice(choices) {
    return new Promise(resolve => {
        const div = document.getElementById('vote-choices');
        div.innerHTML = `
          <p style="color:var(--text-muted);margin-bottom:12px;">
            Which choice did you vote for? Your wallet will sign to re-derive the secret; the server will verify the match.
          </p>
          ${choices.map((c, i) => `
            <label class="choice-option" data-idx="${i}">
              <input type="radio" name="reveal-choice" value="${i}"/>
              <span class="choice-label">${esc(c)}</span>
            </label>`).join('')}
          <div style="margin-top:16px;display:flex;gap:12px;">
            <button class="btn-primary" id="btn-confirm-recover">Confirm</button>
            <button class="btn-secondary" id="btn-cancel-recover">Cancel</button>
          </div>`;
        div.querySelectorAll('.choice-option').forEach(el => {
            el.addEventListener('click', () => {
                div.querySelectorAll('.choice-option').forEach(o => o.classList.remove('selected'));
                el.classList.add('selected');
            });
        });
        document.getElementById('btn-confirm-recover').addEventListener('click', () => {
            const picked = div.querySelector('input[name="reveal-choice"]:checked');
            if (!picked) return showMsg('Pick the choice you cast first.', 'error');
            resolve(parseInt(picked.value, 10));
        });
        document.getElementById('btn-cancel-recover').addEventListener('click', () => resolve(null));
    });
}

// ============ Results ============

async function loadResults(pollId) {
    try {
        const resp = await fetch(`/api/polls/${pollId}/results`);
        if (!resp.ok) throw new Error('Failed to load results');
        const data = await resp.json();

        document.getElementById('results-title').textContent = data.title || 'Poll Results';

        const choices = data.choices || [];
        const voteCount = data.voteCount || 0;
        const barsDiv = document.getElementById('results-bars');

        if (data.status === 'active') {
            // Poll is still open — tallies are hidden to prevent vote correlation
            barsDiv.innerHTML = choices.map(c => `
                <div class="result-bar">
                    <div class="result-label">
                        <span>${esc(c)}</span>
                        <span style="color:var(--text-muted);">sealed</span>
                    </div>
                    <div class="result-track">
                        <div class="result-fill" style="width:0%"></div>
                    </div>
                </div>
            `).join('');
            document.getElementById('results-total').textContent =
                `${voteCount} vote${voteCount !== 1 ? 's' : ''} cast \u00b7 results sealed until poll closes`;
            document.getElementById('results-nullifiers').textContent =
                'Nullifiers hidden while poll is active.';
            return;
        }

        // Poll is closed — show full results
        const tallies = data.tallies || null;
        const talliedCount = data.talliedCount || 0;

        if (tallies && talliedCount > 0) {
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
            barsDiv.innerHTML = choices.map(c => `
                <div class="result-bar">
                    <div class="result-label">
                        <span>${esc(c)}</span>
                        <span style="color:var(--text-muted);">no tallied votes</span>
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

        // Tally proof section — only meaningful after close.
        await refreshTallyProofUI(pollId, data);
    } catch (err) {
        showMsg('Failed to load results: ' + err.message, 'error');
    }
}

// refreshTallyProofUI checks for a cached tally proof and updates the
// results view's proof controls. The Generate button appears only when
// the poll is closed, has at least one tallied reveal, and no proof has
// been cached yet. Download + VK link appear once a proof exists.
async function refreshTallyProofUI(pollId, resultsData) {
    const statusEl = document.getElementById('tally-proof-status');
    const btnGen = document.getElementById('btn-gen-tally-proof');
    const btnVerify = document.getElementById('btn-verify-tally-proof');
    const btnDL = document.getElementById('btn-dl-tally-proof');
    const vkLink = document.getElementById('link-tally-vk');
    const details = document.getElementById('tally-proof-details');
    const verifyResult = document.getElementById('tally-proof-verify-result');

    btnGen.style.display = 'none';
    btnVerify.style.display = 'none';
    btnDL.style.display = 'none';
    vkLink.style.display = 'none';
    details.style.display = 'none';
    verifyResult.style.display = 'none';

    if (!resultsData || resultsData.status !== 'closed') {
        statusEl.textContent = 'Available once the poll is closed.';
        return;
    }

    try {
        const resp = await fetch(`/api/polls/${pollId}/tally-proof`);
        if (resp.ok) {
            const proof = await resp.json();
            window.__tallyProofCache = proof;
            const ts = proof.generatedAt ? ` \u00b7 generated ${formatDate(proof.generatedAt)}` : '';
            statusEl.innerHTML = `<span style="color:var(--accent);">&#10003; Proof generated</span> &middot; ${proof.numReveals} reveals folded${ts}`;
            btnVerify.style.display = '';
            btnDL.style.display = '';
            // Only show the VK link when the server actually persists keys; in
            // dev mode without -key-dir the endpoint returns 503.
            try {
                const vkCheck = await fetch('/api/vk/' + proof.circuitName, { method: 'HEAD' });
                if (vkCheck.ok) {
                    vkLink.href = '/api/vk/' + proof.circuitName + '/solidity';
                    vkLink.style.display = '';
                } else {
                    btnVerify.disabled = true;
                    btnVerify.title = 'Server is not persisting verifying keys (dev mode — start with -key-dir to enable local verification).';
                }
            } catch {
                btnVerify.disabled = true;
            }
            details.style.display = '';
            details.textContent = formatTallyProofSummary(proof);
            return;
        }
        if (resp.status !== 404) {
            statusEl.textContent = 'Proof status unavailable.';
            return;
        }
    } catch {
        statusEl.textContent = 'Proof status unavailable.';
        return;
    }

    // 404: no proof yet. Offer generation if there's something to prove.
    const tallied = resultsData.talliedCount || 0;
    if (tallied === 0) {
        statusEl.textContent = 'No reveals recorded yet — voters must reveal before a tally proof can be built.';
        return;
    }
    statusEl.textContent = 'No tally proof generated yet.';
    btnGen.style.display = '';
}

// formatTallyProofSummary produces a compact human-readable dump of the
// proof artifact — tallies, truncated proof bytes, public inputs.
function formatTallyProofSummary(proof) {
    const lines = [];
    lines.push(`pollId: ${proof.pollId}`);
    lines.push(`circuit: ${proof.circuitName}`);
    lines.push(`numReveals: ${proof.numReveals}`);
    lines.push(`tallies: [${(proof.tallies || []).join(', ')}]`);
    const bytes = proof.proofBytes || '';
    lines.push(`proofBytes (base64, ${bytes.length} chars): ${bytes.slice(0, 64)}${bytes.length > 64 ? '...' : ''}`);
    const pubs = proof.publicInputs || [];
    lines.push(`publicInputs (${pubs.length}):`);
    pubs.forEach((p, i) => lines.push(`  [${i}] ${p}`));
    return lines.join('\n');
}

window.generateTallyProof = async function() {
    const pollId = window.currentPollId;
    if (!pollId) return;
    const btn = document.getElementById('btn-gen-tally-proof');
    const statusEl = document.getElementById('tally-proof-status');
    const orig = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Proving...';
    statusEl.textContent = 'Running Groth16 prover over the castVote Petri net transition...';
    try {
        const resp = await fetch(`/api/polls/${pollId}/tally-proof`, { method: 'POST' });
        const text = await resp.text();
        if (!resp.ok) {
            throw new Error(text || `HTTP ${resp.status}`);
        }
        // Refresh the panel by calling loadResults so everything re-pulls.
        await loadResults(pollId);
        showMsg('Tally proof generated.', 'success');
    } catch (err) {
        showMsg('Proof generation failed: ' + err.message, 'error');
        statusEl.textContent = 'No tally proof generated yet.';
    } finally {
        btn.disabled = false;
        btn.textContent = orig;
    }
};

window.downloadTallyProof = function() {
    const proof = window.__tallyProofCache;
    if (!proof) return;
    const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tally-proof-${proof.pollId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// verifyTallyProof runs groth16.Verify in the browser via WASM. Fetches
// the verifying key from /api/vk/{circuitName}, loads it verify-only into
// the WASM prover (no proving key download — can be megabytes), then
// calls verify() against the cached proof + public-witness bytes.
// Updates the inline result area with a pass/fail indicator.
window.verifyTallyProof = async function() {
    const proof = window.__tallyProofCache;
    const resultEl = document.getElementById('tally-proof-verify-result');
    const btn = document.getElementById('btn-verify-tally-proof');
    if (!proof) return;

    if (!proof.publicWitnessBytes) {
        resultEl.style.display = '';
        resultEl.innerHTML = '<span style="color:#ff4444;">&#10007; Proof artifact missing publicWitnessBytes &mdash; re-generate the proof.</span>';
        return;
    }

    const orig = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Verifying...';
    resultEl.style.display = '';
    resultEl.innerHTML = '<span style="color:var(--text-muted);">Loading WASM verifier...</span>';

    try {
        const { initProver, loadVerifyOnly, verify } = await import('./prover.js');
        await initProver();
        await loadVerifyOnly(proof.circuitName, '/api/vk/' + proof.circuitName);

        const proofBytes = base64ToBytes(proof.proofBytes);
        const pubWitnessBytes = base64ToBytes(proof.publicWitnessBytes);

        const result = await verify(proof.circuitName, proofBytes, pubWitnessBytes);
        if (result && result.valid) {
            resultEl.innerHTML = '<span style="color:var(--accent);">&#10003; Verified locally against ' + esc(proof.circuitName) + ' verifying key.</span> Nothing trusts the server.';
        } else {
            const errMsg = (result && result.error) ? result.error : 'verification returned false';
            resultEl.innerHTML = '<span style="color:#ff4444;">&#10007; Verification FAILED: ' + esc(errMsg) + '</span>';
        }
    } catch (err) {
        resultEl.innerHTML = '<span style="color:#ff4444;">&#10007; Verification error: ' + esc(err.message || String(err)) + '</span>';
    } finally {
        btn.disabled = false;
        btn.textContent = orig;
    }
};

function base64ToBytes(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
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

// ============ Coercion-resistant secret derivation (v2) ============
// In v2 polls, voterSecret = mimcHash(sigDerived, voterNonce) where
// voterNonce is a voter-chosen random field element. The nonce is
// stored in localStorage keyed by (pollId, wallet) AND included in the
// auto-downloaded vote-backup JSON. A coercer who obtains the wallet
// signature alone cannot recompute the secret without the nonce.

function nonceKey(pollId, wallet) {
    return `bitwrap-nonce-${pollId}-${(wallet || '').toLowerCase()}`;
}

// getOrCreateVoterNonce returns the stored nonce for (poll, wallet) or
// creates a new one. The nonce is persisted BEFORE being returned so
// repeated calls across register/vote are deterministic.
function getOrCreateVoterNonce(pollId, wallet) {
    const key = nonceKey(pollId, wallet);
    try {
        const existing = localStorage.getItem(key);
        if (existing) return BigInt(existing);
    } catch {}
    const fresh = randomFieldElement();
    try { localStorage.setItem(key, fresh.toString(10)); } catch {}
    return fresh;
}

// deriveVoterSecret yields the voterSecret for the given schema version.
// v2 mixes a voter-chosen nonce into the sig-derived entropy; v1 uses
// the raw signature slice (legacy, coercion-exposed).
function deriveVoterSecret(schemaVersion, pollId, wallet, sigDerived) {
    if (schemaVersion >= 2) {
        const nonce = getOrCreateVoterNonce(pollId, wallet);
        return mimcHash(sigDerived, nonce);
    }
    return sigDerived;
}

// downloadVoteBackup drops a small JSON file into the user's Downloads
// so their nonce+choice+secret survive a localStorage wipe. The only
// recovery path for v2 polls — the re-sign route is removed because it
// would reintroduce coercion.
function downloadVoteBackup(payload) {
    const name = `vote-backup-${payload.pollId}-${payload.nullifier.slice(0, 12)}.json`;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// readVoteBackupFile prompts for a JSON file and returns the parsed
// reveal payload. Used on the v2 reveal path when localStorage has
// been cleared but the voter kept the auto-downloaded backup.
function readVoteBackupFile() {
    return new Promise((resolve, reject) => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'application/json,.json';
        input.onchange = () => {
            const file = input.files && input.files[0];
            if (!file) return resolve(null);
            const reader = new FileReader();
            reader.onload = () => {
                try {
                    resolve(JSON.parse(reader.result));
                } catch (e) {
                    reject(new Error('Could not parse backup JSON: ' + e.message));
                }
            };
            reader.onerror = () => reject(reader.error || new Error('Backup read failed'));
            reader.readAsText(file);
        };
        input.click();
    });
}

// Mark the Register button as already-done if we've previously registered
// this wallet for this poll (tracked in localStorage). Avoids re-signing just
// to detect registration — the server returns 409 on duplicate commitments
// if the user does click Register again.
function markAlreadyRegisteredIfPossible(pollId, commitments, btn) {
    if (!btn) return;
    try {
        if (localStorage.getItem(`bitwrap-registered-${pollId}`) === '1') {
            btn.disabled = true;
            btn.textContent = 'Registered';
            btn.style.opacity = '0.5';
        }
    } catch { /* localStorage may be unavailable */ }
}

window.registerForPoll = async function() {
    if (!currentPollId) return showMsg('No poll selected', 'error');

    const btn = document.getElementById('btn-register');
    if (btn) { btn.disabled = true; btn.textContent = 'Registering...'; }

    try {
        let voterSecret;
        let wallet = 'anon';
        const provider = getWalletProvider();
        const schemaVersion = (currentPollData && currentPollData.voteSchemaVersion) || 1;
        if (provider) {
            const accounts = await provider.request({ method: 'eth_requestAccounts' });
            wallet = accounts[0];
            const msg = `bitwrap-vote:${currentPollId}`;
            const sig = await provider.request({
                method: 'personal_sign',
                params: [msg, accounts[0]]
            });
            const sigDerived = BigInt('0x' + sig.slice(2, 64));
            voterSecret = deriveVoterSecret(schemaVersion, currentPollId, wallet, sigDerived);
        } else {
            // No wallet — we still need a deterministic secret for v2 across
            // register and vote. randomFieldElement would not be stable.
            voterSecret = deriveVoterSecret(schemaVersion, currentPollId, wallet, randomFieldElement());
        }

        const voterWeight = 1n;
        const commitment = mimcHash(voterSecret, voterWeight);

        const resp = await fetch(`/api/polls/${currentPollId}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ commitment: commitment.toString() })
        });

        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(text);
        }

        const data = await resp.json();
        const hint = schemaVersion >= 2
            ? ` Your per-poll nonce is saved in this browser; a backup file will be offered when you vote.`
            : '';
        showMsg(`Registered! ${data.count} voter${data.count !== 1 ? 's' : ''} in registry.${hint}`, 'success');

        try { localStorage.setItem(`bitwrap-registered-${currentPollId}`, '1'); } catch {}

        // Update UI
        const regInfo = document.getElementById('registry-info');
        if (regInfo) regInfo.textContent = `${data.count} registered voter${data.count !== 1 ? 's' : ''}`;
        if (btn) { btn.textContent = 'Registered'; btn.style.opacity = '0.5'; }
    } catch (err) {
        showMsg('Registration failed: ' + walletError(err, 'register'), 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Register to Vote'; }
    }
};

function uint8ToBase64(u8) {
    let binary = '';
    for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
    return btoa(binary);
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
