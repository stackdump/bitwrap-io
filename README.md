# bitwrap

[![CI](https://github.com/stackdump/bitwrap-io/actions/workflows/ci.yml/badge.svg)](https://github.com/stackdump/bitwrap-io/actions/workflows/ci.yml)
[![jsDelivr](https://data.jsdelivr.com/v1/package/gh/stackdump/bitwrap-io/badge)](https://www.jsdelivr.com/package/gh/stackdump/bitwrap-io)

**Anonymous on-chain voting with ZK proofs.**

Create polls where every vote is backed by a Groth16 proof. No one sees how you voted. Everyone can verify the result is correct. Deploy to any EVM chain.

**[bitwrap.io](https://bitwrap.io)** | **[Polls](https://bitwrap.io/poll)** | **[Editor](https://app.bitwrap.io)** | **[Docs](https://book.pflow.xyz)**

## Quick start

```bash
git clone https://github.com/stackdump/bitwrap-io.git
cd bitwrap-io
make run    # serves on :8088
```

Three API calls to create a poll, cast a vote, and read results:

```bash
# Create a poll (requires wallet signature)
curl -X POST https://api.bitwrap.io/api/polls \
  -H "Content-Type: application/json" \
  -d '{"title":"Board Vote","choices":["Approve","Reject","Abstain"],...}'

# Cast a ZK-proven vote
curl -X POST https://api.bitwrap.io/api/polls/{id}/vote \
  -H "Content-Type: application/json" \
  -d '{"nullifier":"0x...","voteCommitment":"0x...","proof":"..."}'

# Get results (sealed while active, visible when closed)
curl https://api.bitwrap.io/api/polls/{id}/results
```

## How it works

**Vote.** Voters register with a commitment hash. When they cast a ballot, a nullifier (derived from `mimcHash(voterSecret, pollId)`) prevents double-voting without revealing identity.

**Prove.** Each vote generates a Groth16 proof attesting the voter is registered and the ballot is valid — without revealing the choice. The circuit verifies Merkle inclusion in the voter registry, nullifier binding, and vote range.

**Tally.** Results stay sealed until the poll closes. Once closed, the final tally is publicly verifiable — anyone can audit the proofs without accessing individual ballots.

### Sealed results

While a poll is active, the results endpoint only returns the vote count. Tallies, nullifiers, and commitments are hidden to prevent observers from diffing the tally after each vote and correlating timing to de-anonymize voters. Full results are exposed only after the poll is closed.

### Wallet-native auth

Poll creation requires an EIP-191 `personal_sign` signature from MetaMask or any Ethereum wallet. Voting secrets can be derived from wallet signatures, making the nullifier deterministic per voter per poll — no accounts, no passwords.

## What it does

- **ZK voting** — anonymous polls with nullifier-based double-vote prevention and on-chain proof verification. Sealed results prevent vote-timing correlation.
- **Visual editor** — draw places, transitions, and arcs in the browser. Models are stored as content-addressed JSON-LD.
- **Solidity generation** — produce deployable contracts and Foundry test suites from any template.
- **ZK circuits** — Groth16 circuits for transfer, mint, burn, approve, transferFrom, vestClaim, and voteCast. Merkle proofs verify state inclusion.
- **Deploy bundle** — download a complete Foundry project (`BitwrapZKPoll.sol` + `Verifier.sol` + tests + deploy script) from `GET /api/bundle/vote`.
- **ERC templates** — start from ERC-20, ERC-721, ERC-1155, or a Vote template. Each is a complete Petri net with guards, arcs, and events.
- **`.btw` DSL** — a compact schema language for defining Petri net models.
- **Remix IDE plugin** — generate and deploy contracts inside Remix at [solver.bitwrap.io](https://solver.bitwrap.io).

## API

### Polls

```
POST /api/polls              Create poll (wallet signature required)
GET  /api/polls              List polls
GET  /api/polls/{id}         Get poll details
POST /api/polls/{id}/vote    Cast ZK-proven vote
POST /api/polls/{id}/close   Close poll (creator signature required)
POST /api/polls/{id}/reveal  Reveal vote choice (post-close)
GET  /api/polls/{id}/results Poll results (sealed while active)
```

### Models & templates

```
POST /api/save               Save JSON-LD model, returns {"cid": "..."}
GET  /o/{cid}                Load model by CID
GET  /img/{cid}.svg          Render model as SVG
POST /api/svg                Generate SVG from posted JSON-LD
GET  /api/templates          List ERC templates
GET  /api/templates/{id}     Get full template model
POST /api/solgen             Generate Solidity from template
POST /api/testgen            Generate Foundry tests from template
POST /api/compile            Compile .btw DSL to schema JSON
GET  /api/bundle/{template}  Download Foundry project (ZIP)
```

### ZK prover

```
GET  /api/circuits              List available circuits
POST /api/prove                 Submit witness for proof generation
GET  /api/vk/{circuit}          Download verifying key (binary)
GET  /api/vk/{circuit}/solidity Download Solidity verifier contract
```

## CDN

Client-side modules are available via jsDelivr:

```html
<script type="module">
import { mimcHash } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/public/mimc.js';
import { MerkleTree } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/public/merkle.js';
import { buildVoteCastWitness } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/public/witness-builder.js';
</script>
```

| Module | Description |
|--------|-------------|
| `mimc.js` | MiMC-BN254 hash (pure BigInt, zero deps) |
| `merkle.js` | Fixed-depth binary Merkle tree with proof generation |
| `witness-builder.js` | Witness builders for all 7 ZK circuits |
| `petri-view.js` | `<petri-view>` web component for Petri net editing |

## Architecture

Single Go binary. Vanilla JS frontend. No npm, no React, no build step.

```
cmd/bitwrap/       Entry point with -port, -data, -compile flags
dsl/               .btw lexer, parser, AST, builder
erc/               ERC token standard templates (020, 721, 1155, vote)
prover/            ZK circuits (Groth16 via gnark)
solidity/          Solidity contract + test generation
arc/               Arc-level execution (MiMC Merkle state trees, firing)
internal/
  server/          HTTP handlers + poll lifecycle + wallet auth
  petri/           Petri net model types + execution engine
  metamodel/       Schema types (states, actions, arcs, events, constraints)
  seal/            CID computation (JSON-LD canonicalization via URDNA2015)
  store/           Filesystem storage (polls, votes, events)
  svg/             SVG rendering
public/            Frontend JS/CSS/HTML (go:embed)
```

## .btw schema language

```
schema ERC20 {
  version "1.0.0"

  register ASSETS.AVAILABLE map[address]uint256 observable
  register ASSETS.TOTAL_SUPPLY uint256 observable

  event TransferBalanceChange {
    from: address indexed
    to: address indexed
    amount: uint256
  }

  fn(transfer) {
    var from address
    var to address
    var amount amount

    require(ASSETS.AVAILABLE[from] >= amount && amount > 0)
    @event TransferBalanceChange

    ASSETS.AVAILABLE[from] -|amount|> transfer
    transfer -|amount|> ASSETS.AVAILABLE[to]
  }
}
```

Compile to JSON: `bitwrap -compile token.btw`

## License

MIT
