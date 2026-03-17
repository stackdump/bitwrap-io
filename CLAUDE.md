# bitwrap-io

Petri Nets as ZK Containers. Visual editor for Petri nets with ZK proof generation and Solidity contract generation.

## Quick Start

```bash
make run              # Serves on :8088
make build            # Build binary only
make test             # Run tests
```

## Flags

```
-port 8088        # HTTP port (default 8088)
-data ./data      # Data directory for CID storage
-no-prover        # Disable ZK prover (faster startup)
-solgen           # Enable Solidity generation endpoints
```

## Architecture

- `cmd/bitwrap/main.go` — single binary entry point
- `internal/server/` — HTTP handlers
- `internal/seal/` — CID computation (JSON-LD canonicalization)
- `internal/store/` — Filesystem storage
- `internal/static/` — go:embed for public/
- `internal/svg/` — SVG generation from Petri net models
- `internal/petri/` — Petri net model types + execution
- `prover/` — ZK circuits (Groth16 via gnark)
- `solidity/` — Solidity contract generation from metamodel schemas
- `erc/` — ERC token standard templates (020, 0721, 01155, 04626)
- `public/` → symlink to `internal/static/public/`

## API

- `GET /` — landing page
- `GET /editor` — visual Petri net editor
- `POST /api/save` — save JSON-LD, returns `{"cid": "..."}`
- `GET /o/{cid}` — get stored model by CID
- `GET /img/{cid}.svg` — render model as SVG
- `POST /api/svg` — generate SVG from posted JSON-LD
- `GET /api/templates` — list ERC templates
- `GET /api/templates/{id}` — get template as JSON-LD

## Dependencies

- `github.com/stackdump/arcnet` (local replace) — metamodel, guard, vm
- `github.com/pflow-xyz/go-pflow` — core prover infrastructure
- `github.com/consensys/gnark` — ZK proof system
- `github.com/ipfs/go-cid` — content addressing
- `github.com/piprate/json-gold` — JSON-LD canonicalization

## Deployment

Port: 8088 on pflow.dev

```bash
ssh pflow.dev "cd ~/Workspace/bitwrap-io && git pull && make build && ~/services restart bitwrap"
```
