# bitwrap-io

Petri Nets as ZK Containers. Visual editor + ZK prover + Solidity generation + .btw DSL.

## Quick Start

```bash
make run              # Serves on :8088
make build            # Build binary only
make test             # Run tests
```

## Flags

```
-port 8088                  HTTP port (default 8088)
-data ./data                Data directory for CID storage
-no-prover                  Disable ZK prover (faster startup)
-solgen                     Enable Solidity generation endpoints
-compile path/to/file.btw   Compile .btw file to JSON schema on stdout
```

## Architecture

- `cmd/bitwrap/main.go` — single binary entry point
- `dsl/` — .btw DSL lexer, parser, AST, builder
- `erc/` — ERC token standard templates (020, 0721, 01155, 04626, 05725)
- `prover/` — ZK circuits (Groth16 via gnark, re-exports from go-pflow)
- `solidity/` — Solidity contract generation from metamodel schemas
- `internal/server/` — HTTP handlers
- `internal/petri/` — Petri net model types + execution engine
- `internal/metamodel/` — Schema types (states, actions, arcs, events, constraints)
- `internal/metamodel/guard/` — Guard expression parser + evaluator
- `internal/arc/` — Arc-level execution (Merkle state, firing)
- `internal/seal/` — CID computation (JSON-LD canonicalization)
- `internal/store/` — Filesystem storage
- `internal/svg/` — SVG generation from Petri net models
- `internal/static/` — go:embed for public/
- `public/` → symlink to `internal/static/public/`

## API

- `GET /` — landing page
- `GET /editor` — visual Petri net editor
- `GET /remix` — Remix IDE plugin
- `POST /api/save` — save JSON-LD, returns `{"cid": "..."}`
- `GET /o/{cid}` — get stored model by CID
- `GET /img/{cid}.svg` — render model as SVG
- `POST /api/svg` — generate SVG from posted JSON-LD
- `GET /api/templates` — list ERC templates
- `GET /api/templates/{id}` — get full template model
- `POST /api/solgen` — generate Solidity from template ID
- `POST /api/compile` — compile .btw DSL source to schema JSON
- `GET /api/circuits` — list available ZK circuits
- `POST /api/prove` — submit witness for ZK proof generation

## Dependencies

- `github.com/pflow-xyz/go-pflow` — core prover infrastructure
- `github.com/consensys/gnark` — ZK proof system (Groth16)
- `github.com/ipfs/go-cid` — content addressing
- `github.com/piprate/json-gold` — JSON-LD canonicalization (URDNA2015)
- `github.com/holiman/uint256` — safe 256-bit arithmetic

## Subdomains

| URL | Port | Purpose |
|-----|------|---------|
| bitwrap.io | 8088 | Landing page |
| app.bitwrap.io | 8088 | Editor (redirects to /editor) |
| api.bitwrap.io | 8088 | API endpoints |
| solver.bitwrap.io | 8088 | Remix IDE plugin (redirects to /remix) |
| prover.bitwrap.io | 8088 | ZK prover |

## Deployment

```bash
ssh pflow.dev "cd ~/Workspace/bitwrap-io && git pull && make build && ~/services restart bitwrap"
```
