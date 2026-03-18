# bitwrap

[![jsDelivr](https://data.jsdelivr.com/v1/package/gh/stackdump/bitwrap-io/badge)](https://www.jsdelivr.com/package/gh/stackdump/bitwrap-io)

**Petri nets as ZK containers.**

bitwrap is a tool for modeling state machines as Petri nets and compiling them into ZK proofs and Solidity smart contracts. One model produces the editor view, the circuit constraints, and the contract code.

**[bitwrap.io](https://bitwrap.io)** | **[Editor](https://app.bitwrap.io)** | **[Remix Plugin](https://solver.bitwrap.io)**

## Why Petri nets?

A Petri net is a directed bipartite graph: places hold tokens, transitions move them, arcs define the rules. This structure is simple enough to draw on a napkin but formal enough to prove properties about.

Every token standard is a Petri net. ERC-20 has three places (balances, allowances, totalSupply) and five transitions (transfer, approve, transferFrom, mint, burn). The arcs encode which maps get decremented and incremented. Guards express the `require` statements. Invariants express conservation laws.

The same model that a human reads in the editor is the same model that generates the Solidity contract and the same model that compiles to ZK circuit constraints. There's no translation layer, no impedance mismatch, no spec-to-implementation gap.

## Two angles

**Model to proof.** Petri net structure maps directly to ZK circuit constraints. Guards become arithmetic checks (`balance >= amount` becomes a range proof). Arc weights become balance equations. Invariants become circuit assertions. The topology of the net *is* the specification of the circuit.

**Verifiable execution.** Run a Petri net state machine where each transition firing produces a Groth16 proof. The proof attests that the state change was valid without revealing the full state. Token movements are private but provably correct. The model becomes its own audit trail.

## What it does

- **Visual editor** — draw places, transitions, and arcs in the browser. Models are stored as content-addressed JSON-LD (CID = hash of canonicalized RDF).
- **ERC templates** — start from ERC-20, ERC-721, ERC-1155, or ERC-4626. Each template is a complete Petri net with guards, arcs, and events already wired.
- **Solidity generation** — produce a deployable `.sol` contract from any template. Guards become `require` statements, arcs become storage operations, events are emitted automatically.
- **ZK circuits** — Groth16 circuits for each transition type (transfer, mint, burn, approve). Merkle proofs verify state inclusion without revealing balances.
- **Remix IDE plugin** — generate and deploy contracts directly inside the Remix editor at [solver.bitwrap.io](https://solver.bitwrap.io).
- **`.btw` DSL** — a compact schema language for defining Petri net models with registers, events, guards, and arc syntax.

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

  fn(mint) {
    var to address
    var amount amount

    require(amount > 0)

    mint -|amount|> ASSETS.AVAILABLE[to]
    mint -|amount|> ASSETS.TOTAL_SUPPLY
  }
}
```

Compile to JSON schema: `bitwrap -compile token.btw`

## Quick start

```bash
git clone https://github.com/stackdump/bitwrap-io.git
cd bitwrap-io
make run    # serves on :8088
```

Open [localhost:8088](http://localhost:8088) for the landing page, [localhost:8088/editor](http://localhost:8088/editor) for the visual editor.

## API

```
GET  /                    Landing page
GET  /editor              Visual Petri net editor
GET  /remix               Remix IDE plugin

POST /api/save            Save JSON-LD model, returns {"cid": "..."}
GET  /o/{cid}             Load model by CID
GET  /img/{cid}.svg       Render model as SVG
POST /api/svg             Generate SVG from posted JSON-LD

GET  /api/templates       List ERC templates
GET  /api/templates/{id}  Get full template model (states, actions, arcs)
POST /api/solgen          Generate Solidity from template ID
POST /api/compile         Compile .btw DSL source to schema JSON

GET  /api/circuits        List available ZK circuits
POST /api/prove           Submit witness for ZK proof generation
```

## CDN

Client-side modules are available via jsDelivr:

```html
<script type="module">
import { mimcHash } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/lib/mimc.js';
import { MerkleTree } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/lib/merkle.js';
import { buildTransferWitness } from 'https://cdn.jsdelivr.net/gh/stackdump/bitwrap-io@latest/lib/witness-builder.js';
</script>
```

| Module | Description |
|--------|-------------|
| `mimc.js` | MiMC-BN254 hash (pure BigInt, zero deps) |
| `merkle.js` | Fixed-depth binary Merkle tree |
| `witness-builder.js` | Witness builders for all 6 ZK circuits |
| `petri-view.js` | `<petri-view>` web component for Petri net editing |

## Architecture

Single Go binary. Vanilla JS frontend. No npm, no React, no build step.

```
cmd/bitwrap/       Entry point with -port, -data, -compile flags
dsl/               .btw lexer, parser, AST, builder
erc/               ERC token standard templates (020, 721, 1155, 4626)
prover/            ZK circuits (Groth16 via gnark)
solidity/          Solidity contract generation
internal/
  server/          HTTP handlers
  petri/           Petri net model types + execution engine
  metamodel/       Schema types (states, actions, arcs, events, constraints)
  seal/            CID computation (JSON-LD canonicalization via URDNA2015)
  store/           Filesystem storage
  svg/             SVG rendering
  arc/             Arc-level execution (Merkle state, firing)
  static/          Embedded public files (go:embed)
```

## Subdomains

| URL | Purpose |
|-----|---------|
| [bitwrap.io](https://bitwrap.io) | Landing page |
| [app.bitwrap.io](https://app.bitwrap.io) | Visual editor |
| [api.bitwrap.io](https://api.bitwrap.io) | API |
| [solver.bitwrap.io](https://solver.bitwrap.io) | Remix IDE plugin |
| [prover.bitwrap.io](https://prover.bitwrap.io) | ZK prover |

## License

MIT
